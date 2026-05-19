//! High-level FIDO2 (CTAP2) client API for WebAuthn ceremonies. The [`WebAuthn`]
//! trait is blanket-implemented for any [`Channel`]. Its
//! [`webauthn_make_credential`](WebAuthn::webauthn_make_credential) and
//! [`webauthn_get_assertion`](WebAuthn::webauthn_get_assertion) methods run the
//! full CTAP2 make-credential and get-assertion ceremonies, including the user
//! verification flow, PIN and biometric token handling, credential filtering via
//! preflight, and extension support. When a device does not support FIDO2, the
//! ceremony falls back to U2F (CTAP1).
//!
//! User verification is handled internally by the [`pin_uv_auth_token`] module,
//! which manages PIN and biometric UV, reuse of a cached pinUvAuthToken, shared
//! secret establishment, and the fallback from biometric to PIN. Failures are
//! reported as [`Error`], which distinguishes CTAP protocol errors
//! ([`CtapError`]), transport errors, and platform errors.

pub mod error;
pub mod pin_uv_auth_token;

use async_trait::async_trait;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::fido::FidoProtocol;
use crate::ops::u2f::{RegisterRequest, SignRequest, UpgradableResponse};
use crate::ops::webauthn::{
    decrypt_first_matching, delete_authenticator_large_blob, fetch_large_blob_entries,
    max_fragment_length, write_authenticator_large_blob, DowngradableRequest,
    GetAssertionLargeBlobExtension,
    GetAssertionLargeBlobExtensionOutput, GetAssertionRequest, GetAssertionResponse,
    GetAssertionResponseUnsignedExtensions, UserVerificationRequirement,
};
use crate::ops::webauthn::{MakeCredentialRequest, MakeCredentialResponse};
use crate::proto::ctap1::Ctap1;
use crate::proto::ctap2::preflight::{ctap2_preflight, ctap2_preflight_with_appid};
use crate::proto::ctap2::{
    Ctap2, Ctap2ClientPinRequest, Ctap2GetAssertionRequest, Ctap2GetAssertionResponse,
    Ctap2MakeCredentialRequest, Ctap2UserVerificationOperation,
};
pub use crate::transport::error::TransportError;
use crate::transport::{AuthTokenData, Channel};
pub use crate::webauthn::error::{CtapError, Error, PlatformError};
use crate::UvUpdate;

use pin_uv_auth_token::{user_verification, UsedPinUvAuthToken};

// See W3C webauthn#2337.
fn prf_forces_uv_upgrade(prf_present: bool, uv: UserVerificationRequirement) -> bool {
    prf_present && !uv.is_required()
}

macro_rules! handle_errors {
    // Callers that never reuse a persistent token (make-credential, get-assertion,
    // authenticator-config, bio-enrollment): nothing to notify on a persistent rejection.
    ($channel: expr, $resp: expr, $uv_auth_used: expr, $timeout: expr) => {
        handle_errors!(@inner $channel, $resp, $uv_auth_used, $timeout, {})
    };
    // Credential-management callers pass their request so a rejected persistent token is
    // marked on it, forcing the retry to mint a fresh token instead of reusing the same
    // stale record. This keeps loop termination independent of the best-effort store delete.
    ($channel: expr, $resp: expr, $uv_auth_used: expr, $timeout: expr, $request: expr) => {
        handle_errors!(@inner $channel, $resp, $uv_auth_used, $timeout, {
            $request.note_persistent_token_rejected();
        })
    };
    (@inner $channel: expr, $resp: expr, $uv_auth_used: expr, $timeout: expr, $on_persistent_reject: block) => {
        match $resp {
            Err(Error::Ctap(CtapError::PINAuthInvalid))
                if $uv_auth_used == UsedPinUvAuthToken::FromEphemeralStorage =>
            {
                info!("PINAuthInvalid: Clearing auth token storage and trying again.");
                $channel.clear_uv_auth_token_store();
                continue;
            }
            Err(Error::Ctap(CtapError::PINAuthInvalid))
                if matches!($uv_auth_used, UsedPinUvAuthToken::FromPersistentStorage(_)) =>
            {
                info!("PINAuthInvalid on a persistent token: evicting the record and retrying.");
                if let UsedPinUvAuthToken::FromPersistentStorage(id) = &$uv_auth_used {
                    if let Some(store) = $channel.persistent_token_store() {
                        store.delete(id).await;
                    }
                }
                $on_persistent_reject
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
        let upgraded;
        let prf_present = op.extensions.as_ref().is_some_and(|e| e.prf.is_some());
        let op = if prf_forces_uv_upgrade(prf_present, op.user_verification) {
            debug!("PRF requested: forcing userVerification=required (W3C webauthn#2337)");
            upgraded = MakeCredentialRequest {
                user_verification: UserVerificationRequirement::Required,
                ..op.clone()
            };
            &upgraded
        } else {
            op
        };
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
        let upgraded;
        let prf_present = op.extensions.as_ref().is_some_and(|e| e.prf.is_some());
        let op = if prf_forces_uv_upgrade(prf_present, op.user_verification) {
            debug!("PRF requested: forcing userVerification=required (W3C webauthn#2337)");
            upgraded = GetAssertionRequest {
                user_verification: UserVerificationRequirement::Required,
                ..op.clone()
            };
            &upgraded
        } else {
            op
        };
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

        // Encrypt hmac-secret-mc before PresenceRequired (mirrors GA below).
        if let Some(auth_data) = channel.get_auth_data() {
            if let Some(ext) = ctap2_request.extensions.as_mut() {
                ext.calculate_hmac_secret_mc(auth_data)?;
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
                .ctap2_make_credential(&ctap2_request, op.timeout)
                .await,
            uv_auth_used,
            op.timeout
        )
    }?;
    let make_cred =
        response.into_make_credential_output(op, Some(&get_info_response), channel.get_auth_data());
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
    // WebAuthn L3 §10.1.5: largeBlob.write/delete requires exactly one allowCredentials entry.
    let large_blob_ext = op.extensions.as_ref().and_then(|e| e.large_blob.as_ref());
    if matches!(
        large_blob_ext,
        Some(GetAssertionLargeBlobExtension::Write(_))
            | Some(GetAssertionLargeBlobExtension::Delete)
    ) && op.allow.len() != 1
    {
        warn!(
            count = op.allow.len(),
            "largeBlob.write/delete requires exactly one allowCredentials entry"
        );
        return Err(Error::Platform(PlatformError::NotSupported));
    }

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
    let mut ctap_responses = vec![response];
    for i in 1..count {
        debug!({ i }, "Fetching additional credential");
        // GetNextAssertion doesn't use PinUVAuthToken, so we don't need to check uv_auth_used here
        ctap_responses.push(channel.ctap2_get_next_assertion(op.timeout).await?);
    }

    // largeBlob extension (WebAuthn L3 §10.1.5):
    //   Read   → authenticatorLargeBlobs(get): decrypt and surface the per-credential blob.
    //   Write  → authenticatorLargeBlobs(get+set): RMW + chunked upload of the updated array.
    //   Delete → same as Write but with the entry erased (no new entry appended).
    // Failures are non-fatal: per L3, `blob` is absent on read failure and
    // `written` is `false` on write/delete failure. Resolved here before the
    // CTAP responses are converted to Assertion so the largeBlobKey stays
    // within this scope.
    let max_fragment = max_fragment_length(get_info_response.max_msg_size);
    let large_blob_outputs = match large_blob_ext {
        Some(GetAssertionLargeBlobExtension::Read) => {
            // The largeBlobArray is device-wide: fetch and parse once, decrypt per credential.
            let entries = if ctap_responses.iter().any(|r| r.large_blob_key.is_some()) {
                match fetch_large_blob_entries(channel, max_fragment, op.timeout).await {
                    Ok(entries) => Some(entries),
                    Err(e) => {
                        warn!(?e, "authenticatorLargeBlobs(get) failed; no blob returned");
                        None
                    }
                }
            } else {
                None
            };
            ctap_responses
                .iter()
                .map(|resp| {
                    let blob = match (entries.as_ref(), extract_large_blob_key(resp)) {
                        (Some(entries), Some(key)) => match decrypt_first_matching(entries, &key) {
                            Ok(blob) => blob,
                            Err(e) => {
                                warn!(?e, "largeBlob decrypt failed; no blob returned");
                                None
                            }
                        },
                        _ => None,
                    };
                    GetAssertionLargeBlobExtensionOutput { blob, written: None }
                })
                .collect::<Vec<_>>()
        }
        Some(GetAssertionLargeBlobExtension::Write(payload)) => {
            // L3 §10.1.5: write applies to the single matched credential. We
            // enforced allow.len()==1 above, and ctap_responses then has
            // exactly one element.
            let auth_data = channel.get_auth_data().cloned();
            let written = match ctap_responses.first() {
                Some(resp) => {
                    write_or_delete_for_first(
                        channel,
                        resp,
                        auth_data,
                        max_fragment,
                        op.timeout,
                        WriteOrDelete::Write(payload.as_slice()),
                    )
                    .await
                }
                None => false,
            };
            let mut outs: Vec<_> = vec![
                GetAssertionLargeBlobExtensionOutput {
                    blob: None,
                    written: Some(written),
                };
                ctap_responses.len()
            ];
            // Only the first (and only) assertion carries the `written` flag.
            for o in outs.iter_mut().skip(1) {
                o.written = None;
            }
            outs
        }
        Some(GetAssertionLargeBlobExtension::Delete) => {
            let auth_data = channel.get_auth_data().cloned();
            let written = match ctap_responses.first() {
                Some(resp) => {
                    write_or_delete_for_first(
                        channel,
                        resp,
                        auth_data,
                        max_fragment,
                        op.timeout,
                        WriteOrDelete::Delete,
                    )
                    .await
                }
                None => false,
            };
            let mut outs: Vec<_> = vec![
                GetAssertionLargeBlobExtensionOutput {
                    blob: None,
                    written: Some(written),
                };
                ctap_responses.len()
            ];
            for o in outs.iter_mut().skip(1) {
                o.written = None;
            }
            outs
        }
        None => Vec::new(),
    };

    let mut assertions: Vec<_> = ctap_responses
        .into_iter()
        .map(|r| r.into_assertion_output(op, channel.get_auth_data()))
        .collect();
    if !large_blob_outputs.is_empty() {
        for (assertion, entry) in assertions.iter_mut().zip(large_blob_outputs) {
            match assertion.unsigned_extensions_output.as_mut() {
                Some(unsigned) => unsigned.large_blob = Some(entry),
                None => {
                    assertion.unsigned_extensions_output =
                        Some(GetAssertionResponseUnsignedExtensions {
                            large_blob: Some(entry),
                            ..Default::default()
                        });
                }
            }
        }
    }

    Ok(assertions.as_slice().into())
}

enum WriteOrDelete<'a> {
    Write(&'a [u8]),
    Delete,
}

fn extract_large_blob_key(resp: &Ctap2GetAssertionResponse) -> Option<[u8; 32]> {
    let buf = resp.large_blob_key.as_ref()?;
    match <[u8; 32]>::try_from(buf.as_slice()) {
        Ok(k) => Some(k),
        Err(_) => {
            warn!(
                len = buf.len(),
                "largeBlobKey has unexpected length (expected 32); skipping"
            );
            None
        }
    }
}

/// Drive `write_authenticator_large_blob` / `delete_authenticator_large_blob` for the single
/// credential of a write/delete assertion. Returns the `written` flag per WebAuthn L3 §10.1.5.
async fn write_or_delete_for_first<C: Channel>(
    channel: &mut C,
    resp: &Ctap2GetAssertionResponse,
    auth_data: Option<AuthTokenData>,
    max_fragment: u32,
    timeout: std::time::Duration,
    op: WriteOrDelete<'_>,
) -> bool {
    let Some(key) = extract_large_blob_key(resp) else {
        warn!("largeBlobKey absent from assertion; cannot write/delete");
        return false;
    };
    // CTAP 2.2 §6.10.2 lines 100-115: the authenticator enforces pinUvAuthParam
    // only if it is UV-protected. On an unprotected authenticator (no clientPin,
    // no built-in UV) user_verification stores no token, so we send the chunks
    // without auth params and let the authenticator's "skip auth block" path run.
    let pin_uv_auth: Option<(&[u8], _)> = auth_data.as_ref().and_then(|d| {
        d.pin_uv_auth_token
            .as_deref()
            .map(|t| (t, d.protocol_version))
    });
    let result = match op {
        WriteOrDelete::Write(payload) => {
            write_authenticator_large_blob(
                channel,
                &key,
                payload,
                max_fragment,
                pin_uv_auth,
                timeout,
            )
            .await
        }
        WriteOrDelete::Delete => {
            delete_authenticator_large_blob(channel, &key, max_fragment, pin_uv_auth, timeout).await
        }
    };
    match result {
        Ok(()) => true,
        Err(e) => {
            warn!(?e, "authenticatorLargeBlobs(set) failed; written=false");
            false
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_absent_no_upgrade() {
        assert!(!prf_forces_uv_upgrade(
            false,
            UserVerificationRequirement::Discouraged
        ));
        assert!(!prf_forces_uv_upgrade(
            false,
            UserVerificationRequirement::Preferred
        ));
        assert!(!prf_forces_uv_upgrade(
            false,
            UserVerificationRequirement::Required
        ));
    }

    #[test]
    fn prf_present_upgrades_when_not_required() {
        assert!(prf_forces_uv_upgrade(
            true,
            UserVerificationRequirement::Discouraged
        ));
        assert!(prf_forces_uv_upgrade(
            true,
            UserVerificationRequirement::Preferred
        ));
    }

    #[test]
    fn prf_present_no_change_when_already_required() {
        assert!(!prf_forces_uv_upgrade(
            true,
            UserVerificationRequirement::Required
        ));
    }
}
