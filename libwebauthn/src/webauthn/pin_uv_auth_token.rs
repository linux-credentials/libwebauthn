use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, instrument, warn};

use cosey::PublicKey;

use crate::ops::webauthn::UserVerificationRequirement;
use crate::pin::{
    pin_hash, PinRequestReason, PinUvAuthProtocol, PinUvAuthProtocolOne, PinUvAuthProtocolTwo,
};
use crate::proto::ctap2::{
    Ctap2, Ctap2ClientPinRequest, Ctap2GetInfoResponse, Ctap2PinUvAuthProtocol,
    Ctap2UserVerifiableRequest, Ctap2UserVerificationOperation,
};
pub use crate::transport::error::TransportError;
use crate::transport::{AuthTokenData, Channel, Ctap2AuthTokenPermission};
pub use crate::webauthn::error::{CtapError, Error, PlatformError};
use crate::{PinRequiredUpdate, UvUpdate};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]

pub(crate) enum UsedPinUvAuthToken {
    FromStorage,
    NewlyCalculated,
    LegacyUV,
    SharedSecretOnly,
    None,
}

pub(crate) async fn select_uv_proto(
    get_info_response: &Ctap2GetInfoResponse,
) -> Option<Box<dyn PinUvAuthProtocol>> {
    for &protocol in get_info_response.pin_auth_protos.iter().flatten() {
        match protocol {
            1 => return Some(Box::new(PinUvAuthProtocolOne::new())),
            2 => return Some(Box::new(PinUvAuthProtocolTwo::new())),
            _ => (),
        };
    }

    warn!(?get_info_response.pin_auth_protos, "No supported PIN/UV auth protocols found");
    None
}

#[instrument(skip_all)]
pub(crate) async fn user_verification<R, C>(
    channel: &mut C,
    user_verification: UserVerificationRequirement,
    ctap2_request: &mut R,
    timeout: Duration,
) -> Result<UsedPinUvAuthToken, Error>
where
    C: Channel,
    R: Ctap2UserVerifiableRequest,
{
    let get_info_response = channel.ctap2_get_info().await?;
    ctap2_request.handle_legacy_preview(&get_info_response);
    let maybe_uv_proto = select_uv_proto(&get_info_response).await;

    if let Some(uv_proto) = maybe_uv_proto {
        let token_identifier = Ctap2AuthTokenPermission::new(
            uv_proto.version(),
            ctap2_request.permissions(),
            ctap2_request.permissions_rpid(),
        );
        if let Some(uv_auth_token) = channel.get_uv_auth_token(&token_identifier) {
            ctap2_request.calculate_and_set_uv_auth(&uv_proto, uv_auth_token);
            return Ok(UsedPinUvAuthToken::FromStorage);
        }
    }

    user_verification_helper(channel, user_verification, ctap2_request, timeout).await
}

#[instrument(skip_all)]
async fn user_verification_helper<R, C>(
    channel: &mut C,
    user_verification: UserVerificationRequirement,
    ctap2_request: &mut R,
    timeout: Duration,
) -> Result<UsedPinUvAuthToken, Error>
where
    C: Channel,
    R: Ctap2UserVerifiableRequest,
{
    let get_info_response = channel.ctap2_get_info().await?;

    let rp_uv_preferred = user_verification.is_preferred();
    let dev_uv_protected = get_info_response.is_uv_protected();
    let can_establish_shared_secret = get_info_response.can_establish_shared_secret();
    let needs_shared_secret = ctap2_request.needs_shared_secret(&get_info_response);
    let uv = rp_uv_preferred || dev_uv_protected;

    debug!(%rp_uv_preferred, %dev_uv_protected, %uv, %needs_shared_secret, %can_establish_shared_secret, "Checking if user verification is required");
    // If we do not need to create a shared secret, we can error out here early
    if !needs_shared_secret {
        if !uv {
            debug!("User verification not requested by either RP nor authenticator. Ignoring.");
            return Ok(UsedPinUvAuthToken::None);
        }

        if !dev_uv_protected && user_verification.is_required() {
            error!(
                "Request requires user verification, but device user verification is not available."
            );
            return Err(Error::Ctap(CtapError::PINNotSet));
        };

        if !dev_uv_protected && user_verification.is_preferred() {
            warn!("User verification is preferred, but device user verification is not available. Ignoring.");
            return Ok(UsedPinUvAuthToken::None);
        }
    } else {
        // We need a shared secret, but the device does not support any form of query-able UV, so we can't establish a
        // shared secret that is needed
        if !can_establish_shared_secret {
            warn!(
                "Request requires a shared secret, but device is not capable of establishing one. Skipping UV."
            );
            // We treat this currently as a non-fatal error as this is only for HMAC-calculations, which
            // we can drop
            return Ok(UsedPinUvAuthToken::None);
        }
    }

    let skip_uv = !ctap2_request.can_use_uv(&get_info_response);

    let mut uv_blocked = false;
    let (uv_proto, shared_secret, public_key, uv_operation, token_response) = loop {
        let uv_operation = get_info_response
            .uv_operation(uv_blocked || skip_uv)
            .ok_or({
                if uv_blocked {
                    Error::Ctap(CtapError::UvBlocked)
                } else {
                    Error::Platform(PlatformError::NoUvAvailable)
                }
            })?;
        if let Ctap2UserVerificationOperation::LegacyUv = uv_operation {
            debug!("No client operation. Setting deprecated request options.uv flag to true.");
            ctap2_request.ensure_uv_set();
            // If the device is UV protected, but has no fitting operation, we have to use the legacy UV option.
            // If we don't have to establish a shared secret, we can return right here
            if !needs_shared_secret {
                return Ok(UsedPinUvAuthToken::LegacyUV);
            }
        }

        let Some(uv_proto) = select_uv_proto(&get_info_response).await else {
            error!("No supported PIN/UV auth protocols found");
            return Err(Error::Ctap(CtapError::Other));
        };

        // For operations that include a PIN, we want to fetch one before obtaining a shared secret.
        // This prevents the shared secret from expiring whilst we wait for the user to enter a PIN.
        let pin = match uv_operation {
            Ctap2UserVerificationOperation::LegacyUv
            | Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret => None,
            Ctap2UserVerificationOperation::GetPinToken
            | Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions => {
                let reason = if uv_blocked {
                    PinRequestReason::FallbackFromUV
                } else if rp_uv_preferred {
                    PinRequestReason::RelyingPartyRequest
                } else {
                    PinRequestReason::AuthenticatorPolicy
                };

                Some(
                    obtain_pin(
                        channel,
                        &get_info_response,
                        uv_proto.version(),
                        reason,
                        timeout,
                    )
                    .await?,
                )
            }
            Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions => {
                None // TODO probably?
            }
        };

        // In preparation for obtaining pinUvAuthToken, the platform:
        // * Obtains a shared secret.
        let (public_key, shared_secret) = obtain_shared_secret(channel, &uv_proto, timeout).await?;

        // Then the platform obtains a pinUvAuthToken from the authenticator, with the mc (and likely also with the ga)
        // permission (see "pre-flight", mentioned above), using the selected operation.
        let token_request = match uv_operation {
            // We can't create a pinUvAuthToken with these two options, because the device doesn't support it
            // But we have the shared secret, which we will store for later usage (mostly for hmac calculation)
            Ctap2UserVerificationOperation::LegacyUv
            | Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret => {
                break (uv_proto, shared_secret, public_key, uv_operation, None)
            }

            Ctap2UserVerificationOperation::GetPinToken => {
                Ctap2ClientPinRequest::new_get_pin_token(
                    uv_proto.version(),
                    public_key.clone(),
                    &uv_proto.encrypt(&shared_secret, &pin_hash(&pin.unwrap()))?,
                )
            }
            Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions => {
                Ctap2ClientPinRequest::new_get_pin_token_with_perm(
                    uv_proto.version(),
                    public_key.clone(),
                    &uv_proto.encrypt(&shared_secret, &pin_hash(&pin.unwrap()))?,
                    ctap2_request.permissions(),
                    ctap2_request.permissions_rpid(),
                )
            }
            Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions => {
                channel
                    .send_ux_update(UvUpdate::PresenceRequired.into())
                    .await;
                Ctap2ClientPinRequest::new_get_uv_token_with_perm(
                    uv_proto.version(),
                    public_key.clone(),
                    ctap2_request.permissions(),
                    ctap2_request.permissions_rpid(),
                )
            }
        };

        match channel.ctap2_client_pin(&token_request, timeout).await {
            Ok(t) => {
                break (uv_proto, shared_secret, public_key, uv_operation, Some(t));
            }
            // Internal retry, because we otherwise can't fall back to PIN, if the UV is blocked
            Err(Error::Ctap(CtapError::UvBlocked)) => {
                warn!("UV failed too many times and is now blocked. Trying to fall back to PIN.");
                uv_blocked = true;
                continue;
            }
            Err(Error::Ctap(CtapError::UVInvalid)) => {
                let attempts_left = channel
                    .ctap2_client_pin(&Ctap2ClientPinRequest::new_get_uv_retries(), timeout)
                    .await
                    .map(|x| x.uv_retries)
                    .ok() // It's optional, so soft-error here
                    .flatten();
                channel
                    .send_ux_update(UvUpdate::UvRetry { attempts_left }.into())
                    .await;
                if let Some(attempts) = attempts_left {
                    // The spec says: "If the platform receives CTAP2ERRUV_BLOCKED **or** uvRetries <= 0"
                    // So, this check MAY prevent one additional fingerprint scan for the user,
                    // that is going to fail with UvBlocked.
                    if attempts == 0 {
                        warn!("UV failed too many times and is now blocked. Trying to fall back to PIN.");
                        uv_blocked = true;
                        continue;
                    }
                }
                return Err(Error::Ctap(CtapError::UVInvalid));
            }
            Err(x) => {
                return Err(x);
            }
        }
    };

    // Package the results, based on what we did
    match uv_operation {
        // We only established a shared secret
        Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret
        | Ctap2UserVerificationOperation::LegacyUv => {
            // Storing shared secret for later (re)use, such as calculating HMAC secrects, etc.
            let auth_token_data = AuthTokenData {
                shared_secret: shared_secret.to_vec(),
                permission: None,
                pin_uv_auth_token: None,
                protocol_version: uv_proto.version(),
                key_agreement: public_key,
                uv_operation,
            };
            channel.store_auth_data(auth_token_data);
            if uv_operation == Ctap2UserVerificationOperation::LegacyUv {
                Ok(UsedPinUvAuthToken::LegacyUV)
            } else {
                Ok(UsedPinUvAuthToken::SharedSecretOnly)
            }
        }

        // We established a full pinUvAuthToken
        Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions
        | Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions
        | Ctap2UserVerificationOperation::GetPinToken => {
            {
                let token_response = token_response.unwrap();
                let Some(encrypted_pin_uv_auth_token) = token_response.pin_uv_auth_token else {
                    error!("Client PIN response did not include a PIN UV auth token");
                    return Err(Error::Ctap(CtapError::Other));
                };

                let uv_auth_token =
                    uv_proto.decrypt(&shared_secret, &encrypted_pin_uv_auth_token)?;

                let token_identifier = Ctap2AuthTokenPermission::new(
                    uv_proto.version(),
                    ctap2_request.permissions(),
                    ctap2_request.permissions_rpid(),
                );

                // Storing auth token for later (re)use
                let auth_token_data = AuthTokenData {
                    shared_secret: shared_secret.to_vec(),
                    permission: Some(token_identifier),
                    pin_uv_auth_token: Some(uv_auth_token.clone()),
                    protocol_version: uv_proto.version(),
                    key_agreement: public_key,
                    uv_operation,
                };
                channel.store_auth_data(auth_token_data);

                // If successful, the platform creates the pinUvAuthParam parameter by calling
                // authenticate(pinUvAuthToken, clientDataHash), and goes to Step 1.1.1.
                // Sets the pinUvAuthProtocol parameter to the value as selected when it obtained the shared secret.
                ctap2_request.calculate_and_set_uv_auth(&uv_proto, uv_auth_token.as_slice());

                Ok(UsedPinUvAuthToken::NewlyCalculated)
            }
        }
    }
}

pub(crate) async fn obtain_shared_secret<C>(
    channel: &mut C,
    pin_proto: &Box<dyn PinUvAuthProtocol>,
    timeout: Duration,
) -> Result<(PublicKey, Vec<u8>), Error>
where
    C: Channel,
{
    let client_pin_request = Ctap2ClientPinRequest::new_get_key_agreement(pin_proto.version());
    let client_pin_response = channel
        .ctap2_client_pin(&client_pin_request, timeout)
        .await?;
    let Some(public_key) = client_pin_response.key_agreement else {
        error!("Missing public key from Client PIN response");
        return Err(Error::Ctap(CtapError::Other));
    };
    pin_proto.encapsulate(&public_key)
}

pub(crate) async fn obtain_pin<C>(
    channel: &mut C,
    info: &Ctap2GetInfoResponse,
    pin_proto: Ctap2PinUvAuthProtocol,
    reason: PinRequestReason,
    timeout: Duration,
) -> Result<Vec<u8>, Error>
where
    C: Channel,
{
    // FIDO 2.0 requires PIN protocol, 2.1 does not anymore
    let pin_protocol = if info.supports_fido_2_1() {
        None
    } else {
        Some(pin_proto)
    };

    let attempts_left = channel
        .ctap2_client_pin(
            &Ctap2ClientPinRequest::new_get_pin_retries(pin_protocol),
            timeout,
        )
        .await
        .map(|x| x.pin_retries)
        .ok() // It's optional, so soft-error here
        .flatten();

    let (tx, rx) = tokio::sync::oneshot::channel();
    channel
        .send_ux_update(
            UvUpdate::PinRequired(PinRequiredUpdate {
                reply_to: Arc::new(tx),
                reason,
                attempts_left,
            })
            .into(),
        )
        .await;
    let pin = match rx.await {
        Ok(pin) => pin,
        Err(_) => {
            info!("User cancelled operation: no PIN provided");
            return Err(Error::Ctap(CtapError::PINRequired));
        }
    };
    Ok(pin.as_bytes().to_owned())
}
