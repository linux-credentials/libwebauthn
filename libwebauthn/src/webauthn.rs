pub mod error;
pub mod pin_uv_auth_token;

use async_trait::async_trait;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::fido::FidoProtocol;
use crate::ops::u2f::{RegisterRequest, SignRequest, UpgradableResponse};
use crate::ops::webauthn::{DowngradableRequest, GetAssertionRequest, GetAssertionResponse};
use crate::ops::webauthn::{MakeCredentialRequest, MakeCredentialResponse};
use crate::proto::ctap1::Ctap1;
use crate::proto::ctap2::preflight::{ctap2_preflight, ctap2_preflight_with_appid};
use crate::proto::ctap2::{
    Ctap2, Ctap2ClientPinRequest, Ctap2GetAssertionRequest, Ctap2MakeCredentialRequest,
    Ctap2UserVerificationOperation,
};
pub use crate::transport::error::TransportError;
use crate::transport::Channel;
pub use crate::webauthn::error::{CtapError, Error, PlatformError};
use crate::UvUpdate;

use pin_uv_auth_token::{user_verification, UsedPinUvAuthToken};

macro_rules! handle_errors {
    ($channel: expr, $resp: expr, $uv_auth_used: expr, $timeout: expr) => {
        match $resp {
            Err(Error::Ctap(CtapError::PINAuthInvalid))
                if $uv_auth_used == UsedPinUvAuthToken::FromStorage =>
            {
                info!("PINAuthInvalid: Clearing auth token storage and trying again.");
                $channel.clear_uv_auth_token_store();
                continue;
            }
            Err(Error::Ctap(CtapError::UVInvalid)) => {
                let attempts_left = $channel
                    .ctap2_client_pin(&Ctap2ClientPinRequest::new_get_uv_retries(), $timeout)
                    .await
                    .map(|x| x.uv_retries)
                    .ok() // It's optional, so soft-error here
                    .flatten();
                $channel
                    .send_ux_update(UvUpdate::UvRetry { attempts_left }.into())
                    .await;
                break Err(Error::Ctap(CtapError::UVInvalid));
            }
            x => {
                break x;
            }
        }
    };
}
pub(crate) use handle_errors;

#[async_trait]
pub trait WebAuthn {
    async fn webauthn_make_credential(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error>;
    async fn webauthn_get_assertion(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error>;
}

#[async_trait]
impl<C> WebAuthn for C
where
    C: Channel,
{
    #[instrument(skip_all, fields(dev = % self))]
    async fn webauthn_make_credential(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        trace!(?op, "WebAuthn MakeCredential request");
        let protocol = negotiate_protocol(self, op.is_downgradable()).await?;
        match protocol {
            FidoProtocol::FIDO2 => make_credential_fido2(self, op).await,
            FidoProtocol::U2F => make_credential_u2f(self, op).await,
        }
    }

    #[instrument(skip_all, fields(dev = % self))]
    async fn webauthn_get_assertion(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Error> {
        trace!(?op, "WebAuthn GetAssertion request");
        let protocol = negotiate_protocol(self, op.is_downgradable()).await?;
        match protocol {
            FidoProtocol::FIDO2 => get_assertion_fido2(self, op).await,
            FidoProtocol::U2F => get_assertion_u2f(self, op).await,
        }
    }
}

async fn make_credential_fido2<C: Channel>(
    channel: &mut C,
    op: &MakeCredentialRequest,
) -> Result<MakeCredentialResponse, Error> {
    let get_info_response = channel.ctap2_get_info().await?;
    let mut ctap2_request =
        Ctap2MakeCredentialRequest::from_webauthn_request(op, &get_info_response)?;
    if C::supports_preflight() {
        if let Some(exclude_list) = &op.exclude {
            // FIDO AppID Exclusion (WebAuthn L3 §10.1.2): if the relying
            // party supplied a legacy AppID, the preflight must test
            // each excludeList entry against both `SHA-256(rp.id)` and
            // `SHA-256(appidExclude)` so that legacy U2F-keyed
            // credentials are correctly detected.
            let appid_exclude = op
                .extensions
                .as_ref()
                .and_then(|e| e.appid_exclude.as_deref());
            let filtered_exclude_list = ctap2_preflight_with_appid(
                channel,
                exclude_list,
                &op.client_data_hash(),
                &op.relying_party.id,
                appid_exclude,
            )
            .await;
            ctap2_request.exclude = Some(filtered_exclude_list);
        }
    }
    let response = loop {
        let uv_auth_used = user_verification(
            channel,
            op.user_verification,
            &mut ctap2_request,
            op.timeout,
        )
        .await?;

        // We've already sent out this update, in case we used builtin UV
        // but in all other cases, we need to touch the device now.
        if uv_auth_used
            != UsedPinUvAuthToken::NewlyCalculated(
                Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions,
            )
        {
            channel
                .send_ux_update(UvUpdate::PresenceRequired.into())
                .await;
        }
        handle_errors!(
            channel,
            channel
                .ctap2_make_credential(&ctap2_request, op.timeout)
                .await,
            uv_auth_used,
            op.timeout
        )
    }?;
    let make_cred = response.into_make_credential_output(op, Some(&get_info_response));
    Ok(make_cred)
}

async fn make_credential_u2f<C: Channel>(
    channel: &mut C,
    op: &MakeCredentialRequest,
) -> Result<MakeCredentialResponse, Error> {
    let register_request: RegisterRequest = op.try_downgrade()?;

    channel
        .ctap1_register(&register_request)
        .await?
        .try_upgrade(op)
}

async fn get_assertion_fido2<C: Channel>(
    channel: &mut C,
    op: &GetAssertionRequest,
) -> Result<GetAssertionResponse, Error> {
    let get_info_response = channel.ctap2_get_info().await?;
    let mut ctap2_request =
        Ctap2GetAssertionRequest::from_webauthn_request(op, &get_info_response)?;

    if C::supports_preflight() {
        let filtered_allow_list = ctap2_preflight(
            channel,
            &op.allow,
            &op.client_data_hash(),
            &op.relying_party_id,
        )
        .await;
        if filtered_allow_list.is_empty() && !op.allow.is_empty() {
            // We filtered out everything in preflight, meaning none of the allowed
            // credentials are present on this device. So we error out here
            // But the spec requires some form of user interaction, so we run a
            // dummy request, ignore the result and error out.
            warn!("Preflight removed all credentials from the allow-list. Sending dummy request and erroring out.");
            let dummy_request: Ctap2MakeCredentialRequest = Ctap2MakeCredentialRequest::dummy();
            channel
                .send_ux_update(UvUpdate::PresenceRequired.into())
                .await;
            let _ = channel
                .ctap2_make_credential(&dummy_request, op.timeout)
                .await;
            return Err(Error::Ctap(CtapError::NoCredentials));
        }
        ctap2_request.allow = filtered_allow_list;
    }

    let response = loop {
        let uv_auth_used = user_verification(
            channel,
            op.user_verification,
            &mut ctap2_request,
            op.timeout,
        )
        .await?;
        // Order is important here!
        // We can error out in calculate_hmac() with PlatformError's,
        // so only send out the UvUpdate after we are done with hmac.
        if let Some(auth_data) = channel.get_auth_data() {
            if let Some(e) = ctap2_request.extensions.as_mut() {
                e.calculate_hmac(&op.allow, auth_data)?;
            }
        }

        // We've already sent out this update, in case we used builtin UV
        // but in all other cases, we need to touch the device now.
        if uv_auth_used
            != UsedPinUvAuthToken::NewlyCalculated(
                Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions,
            )
        {
            channel
                .send_ux_update(UvUpdate::PresenceRequired.into())
                .await;
        }

        handle_errors!(
            channel,
            channel
                .ctap2_get_assertion(&ctap2_request, op.timeout)
                .await,
            uv_auth_used,
            op.timeout
        )
    }?;
    let count = response.credentials_count.unwrap_or(1);
    let mut assertions = vec![response.into_assertion_output(op, channel.get_auth_data())];
    for i in 1..count {
        debug!({ i }, "Fetching additional credential");
        // GetNextAssertion doesn't use PinUVAuthToken, so we don't need to check uv_auth_used here
        let response = channel.ctap2_get_next_assertion(op.timeout).await?;
        assertions.push(response.into_assertion_output(op, channel.get_auth_data()));
    }
    Ok(assertions.as_slice().into())
}

async fn get_assertion_u2f<C: Channel>(
    channel: &mut C,
    op: &GetAssertionRequest,
) -> Result<GetAssertionResponse, Error> {
    use sha2::{Digest, Sha256};

    let sign_requests: Vec<SignRequest> = op.try_downgrade()?;

    // Precompute the AppID-derived application parameter so we can
    // distinguish a match-by-rpId from a match-by-appid for the
    // `clientExtensionResults.appid` output. The downgrade path emits
    // both forms of SignRequest when `appid` is set.
    let appid_hash: Option<Vec<u8>> =
        op.extensions
            .as_ref()
            .and_then(|e| e.appid.as_ref())
            .map(|appid| {
                let mut hasher = Sha256::default();
                hasher.update(appid.as_bytes());
                hasher.finalize().to_vec()
            });

    for sign_request in sign_requests {
        match channel.ctap1_sign(&sign_request).await {
            Ok(response) => {
                debug!("Found successful candidate in allowList");
                let mut upgraded = response.try_upgrade(&sign_request)?;
                // Surface the FIDO AppID extension output in the
                // assertion's clientExtensionResults.
                if let Some(ref appid_hash) = appid_hash {
                    let used_appid = sign_request.app_id_hash == *appid_hash;
                    for assertion in upgraded.assertions.iter_mut() {
                        let unsigned = assertion
                            .unsigned_extensions_output
                            .get_or_insert_with(Default::default);
                        unsigned.appid = Some(used_appid);
                    }
                }
                return Ok(upgraded);
            }
            Err(Error::Ctap(CtapError::NoCredentials)) => {
                debug!("No credentials found, trying with the next.");
            }
            Err(err) => {
                error!(
                    ?err,
                    "Unexpected error whilst trying each credential in allowList."
                );
                return Err(err);
            }
        }
    }
    warn!("None of the credentials in the original request's allowList were found.");
    Err(Error::Ctap(CtapError::NoCredentials))
}

#[instrument(skip_all)]
async fn negotiate_protocol<C: Channel>(
    channel: &mut C,
    allow_u2f: bool,
) -> Result<FidoProtocol, Error> {
    let supported = channel.supported_protocols().await?;
    if !supported.u2f && !supported.fido2 {
        return Err(Error::Transport(TransportError::NegotiationFailed));
    }

    if !allow_u2f && !supported.fido2 {
        return Err(Error::Transport(TransportError::NegotiationFailed));
    }

    let fido_protocol = if supported.fido2 {
        FidoProtocol::FIDO2
    } else {
        // Ensure CTAP1 version is reported correctly.
        channel.ctap1_version().await?;
        FidoProtocol::U2F
    };

    if fido_protocol == FidoProtocol::U2F {
        warn!("Negotiated protocol downgrade from FIDO2 to FIDO U2F");
    } else {
        debug!("Selected protocol: {:?}", fido_protocol);
    }
    Ok(fido_protocol)
}
