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
    NewlyCalculated(Ctap2UserVerificationOperation),
    LegacyUV,
    SharedSecretOnly,
    None,
}

pub(crate) async fn select_uv_proto(
    #[cfg(test)] override_protocol: Option<Ctap2PinUvAuthProtocol>,
    get_info_response: &Ctap2GetInfoResponse,
) -> Option<Box<dyn PinUvAuthProtocol>> {
    #[cfg(test)]
    if let Some(proto) = override_protocol {
        return Some(proto.create_protocol_object());
    }
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
    let maybe_uv_proto = select_uv_proto(
        #[cfg(test)]
        channel.get_forced_pin_protocol(),
        &get_info_response,
    )
    .await;
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

    user_verification_helper(
        channel,
        &get_info_response,
        user_verification,
        ctap2_request,
        timeout,
    )
    .await
}

#[instrument(skip_all)]
async fn user_verification_helper<R, C>(
    channel: &mut C,
    get_info_response: &Ctap2GetInfoResponse,
    user_verification: UserVerificationRequirement,
    ctap2_request: &mut R,
    timeout: Duration,
) -> Result<UsedPinUvAuthToken, Error>
where
    C: Channel,
    R: Ctap2UserVerifiableRequest,
{
    let rp_uv_preferred = user_verification.is_preferred();
    let rp_uv_discouraged = user_verification.is_discouraged();
    let dev_uv_protected = get_info_response.is_uv_protected();
    let can_establish_shared_secret = get_info_response.can_establish_shared_secret();
    let needs_shared_secret = ctap2_request.needs_shared_secret(get_info_response);
    // If it is not discouraged and either RP or device requires it.
    let uv = !rp_uv_discouraged && (rp_uv_preferred || dev_uv_protected);

    debug!(%rp_uv_preferred, %rp_uv_discouraged, %dev_uv_protected, %uv, %needs_shared_secret, %can_establish_shared_secret, "Checking if user verification is required");
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
    } else if !can_establish_shared_secret && !uv {
        // We need a shared secret, but the device does not support any form of query-able UV, so we can't establish a
        // shared secret that is needed
        warn!(
            "Request requires a shared secret, but device is not capable of establishing one. Skipping UV."
        );
        // We treat this currently as a non-fatal error as this is only for HMAC-calculations, which
        // we can drop
        //
        // If we have UV but it's only the LegacyUV, we'll drop out a bit lower down.
        return Ok(UsedPinUvAuthToken::None);
    }

    let skip_uv = !ctap2_request.can_use_uv(get_info_response);

    let mut uv_blocked = false;
    let (uv_proto, shared_secret, public_key, uv_operation, token_response) = loop {
        let mut uv_operation = get_info_response
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
            // If we don't have to or we can't establish a shared secret, we can return right here
            // and potentially drop the extension
            if !needs_shared_secret || !can_establish_shared_secret {
                return Ok(UsedPinUvAuthToken::LegacyUV);
            }
        } else if rp_uv_discouraged && needs_shared_secret {
            // We are not using LegacyUV, but have full support, however RP
            // discouraged UV, but the request requires a shared secret.
            // Then we are downgrading the 'supported' uv_operation to OnlyForSharedSecret
            uv_operation = Ctap2UserVerificationOperation::OnlyForSharedSecret;
        }

        let Some(uv_proto) = select_uv_proto(
            #[cfg(test)]
            channel.get_forced_pin_protocol(),
            get_info_response,
        )
        .await
        else {
            error!("No supported PIN/UV auth protocols found");
            return Err(Error::Ctap(CtapError::Other));
        };

        // For operations that include a PIN, we want to fetch one before obtaining a shared secret.
        // This prevents the shared secret from expiring whilst we wait for the user to enter a PIN.
        let pin = match uv_operation {
            Ctap2UserVerificationOperation::LegacyUv
            | Ctap2UserVerificationOperation::OnlyForSharedSecret => None,
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
                        get_info_response,
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
            | Ctap2UserVerificationOperation::OnlyForSharedSecret => {
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
        Ctap2UserVerificationOperation::OnlyForSharedSecret
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

                Ok(UsedPinUvAuthToken::NewlyCalculated(uv_operation))
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

#[cfg(test)]
mod test {

    use std::{collections::HashMap, time::Duration};

    use serde_bytes::ByteBuf;

    use crate::{
        ops::webauthn::{
            GetAssertionHmacOrPrfInput, GetAssertionRequest, GetAssertionRequestExtensions,
            HMACGetSecretInput, UserVerificationRequirement,
        },
        pin::{pin_hash, PinUvAuthProtocol, PinUvAuthProtocolOne},
        proto::{
            ctap2::{
                cbor::{to_vec, CborRequest, CborResponse},
                Ctap2ClientPinRequest, Ctap2ClientPinResponse, Ctap2CommandCode,
                Ctap2GetAssertionRequest, Ctap2GetInfoResponse, Ctap2PinUvAuthProtocol,
                Ctap2UserVerifiableRequest, Ctap2UserVerificationOperation,
            },
            CtapError,
        },
        transport::{mock::channel::MockChannel, Channel, Ctap2AuthTokenStore},
        webauthn::UsedPinUvAuthToken,
        UvUpdate,
    };

    use super::{user_verification, Error};
    const TIMEOUT: Duration = Duration::from_secs(1);

    fn create_info(
        options: &[(&'static str, bool)],
        extensions: Option<&[&'static str]>,
    ) -> Ctap2GetInfoResponse {
        let mut info = Ctap2GetInfoResponse::default();
        let mut input = HashMap::new();
        for (key, val) in options {
            input.insert(key.to_string(), *val);
        }
        info.options = Some(input);
        if let Some(extensions) = extensions {
            let mut ext_res = Vec::new();
            for extension in extensions {
                ext_res.push(extension.to_string());
            }
            info.extensions = Some(ext_res);
        }
        info
    }

    fn create_get_assertion(
        info: &Ctap2GetInfoResponse,
        extensions: Option<GetAssertionRequestExtensions>,
    ) -> Ctap2GetAssertionRequest {
        Ctap2GetAssertionRequest::from_webauthn_request(
            &GetAssertionRequest {
                relying_party_id: String::from("example.com"),
                hash: vec![9; 32],
                allow: vec![],
                extensions,
                user_verification: UserVerificationRequirement::Preferred,
                timeout: TIMEOUT,
            },
            info,
        )
        .unwrap()
    }

    async fn test_early_exits(
        info_options: &[(&'static str, bool)],
        info_extensions: Option<&[&'static str]>,
        uv_requirement: UserVerificationRequirement,
        extensions: Option<GetAssertionRequestExtensions>,
        expected_result: Result<UsedPinUvAuthToken, Error>,
    ) {
        let mut channel = MockChannel::new();
        let status_recv = channel.get_ux_update_receiver();
        let info = create_info(info_options, info_extensions);
        let info_req = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
        let info_resp = CborResponse::new_success_from_slice(to_vec(&info).unwrap().as_slice());

        channel.push_command_pair(info_req, info_resp);

        let mut getassertion = create_get_assertion(&info, extensions);

        // We should early return here right at the start and not send a ClientPIN-request
        let resp =
            user_verification(&mut channel, uv_requirement, &mut getassertion, TIMEOUT).await;

        assert_eq!(resp, expected_result);
        // Nothing ended up in the auth store
        assert!(channel.get_auth_data().is_none());
        // No updates should be sent, since we are exiting early
        assert!(status_recv.is_empty());
    }

    #[tokio::test]
    async fn early_exit_device_no_options() {
        test_early_exits(
            &[],
            None,
            UserVerificationRequirement::Preferred,
            None,
            Ok(UsedPinUvAuthToken::None),
        )
        .await;
    }

    #[tokio::test]
    async fn early_exit_device_client_pin_but_uv_discouraged() {
        test_early_exits(
            &[("clientPin", true)],
            None,
            UserVerificationRequirement::Discouraged,
            None,
            Ok(UsedPinUvAuthToken::None),
        )
        .await;
    }

    #[tokio::test]
    async fn early_exit_device_client_pin_not_set() {
        test_early_exits(
            &[("clientPin", false)],
            None,
            UserVerificationRequirement::Preferred,
            None,
            Ok(UsedPinUvAuthToken::None),
        )
        .await;
    }

    #[tokio::test]
    async fn early_exit_device_client_pin_not_set_but_uv_required() {
        let testcases = vec![
            vec![],
            // Should be the same as above
            vec![("clientPin", false)],
        ];
        for testcase in testcases {
            test_early_exits(
                &testcase,
                None,
                UserVerificationRequirement::Required,
                None,
                Err(Error::Ctap(CtapError::PINNotSet)),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn early_exit_device_client_shared_secret_required_but_not_supported() {
        let testcases = vec![
            // Device does not support shared secret operations AND does not support hmac-secret
            (vec![], None),
            (vec![("uv", false)], None),
            // UV but not pinUvAuth supported, so we can't establish a shared secret
            (vec![("uv", true)], None),
            (vec![("uv", true), ("pinUvAuthToken", false)], None),
            // Device does not support shared secret operations but DOES support hmac-secret
            (vec![], Some(vec!["hmac-secret"])),
            (
                vec![("uv", false)],
                Some(vec!["hmac-secret", "credProtect"]),
            ),
            (vec![("uv", true)], Some(vec!["hmac-secret"])),
            (
                vec![("uv", true), ("pinUvAuthToken", false)],
                Some(vec!["hmac-secret"]),
            ),
            // Device DOES support shared secret operations but does NOT support hmac-secret
            (vec![("clientPin", true)], None),
            (vec![("uv", true), ("pinUvAuthToken", true)], None),
            (vec![("clientPin", true), ("pinUvAuthToken", true)], None),
            (
                vec![("clientPin", true), ("pinUvAuthToken", true), ("uv", true)],
                None,
            ),
        ];
        for (testcase, info_extensions) in testcases {
            test_early_exits(
                &testcase,
                info_extensions.as_deref(),
                UserVerificationRequirement::Discouraged,
                Some(GetAssertionRequestExtensions {
                    hmac_or_prf: Some(GetAssertionHmacOrPrfInput::HmacGetSecret(
                        HMACGetSecretInput {
                            salt1: [0; 32],
                            salt2: None,
                        },
                    )),
                    ..Default::default()
                }),
                Ok(UsedPinUvAuthToken::None),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn early_exit_legacy_uv() {
        let testcases = vec![
            vec![("uv", true)],
            vec![("uv", true), ("pinUvAuthToken", false)],
        ];
        for testcase in testcases {
            test_early_exits(
                &testcase,
                None,
                UserVerificationRequirement::Preferred,
                None,
                Ok(UsedPinUvAuthToken::LegacyUV),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn early_exit_legacy_uv_with_required_shared_secret() {
        let testcases = vec![
            vec![("uv", true)],
            vec![("uv", true), ("pinUvAuthToken", false)],
        ];
        // HMAC will be dropped
        for testcase in testcases {
            test_early_exits(
                &testcase,
                Some(&["hmac-secret"]),
                UserVerificationRequirement::Preferred,
                Some(GetAssertionRequestExtensions {
                    hmac_or_prf: Some(GetAssertionHmacOrPrfInput::HmacGetSecret(
                        HMACGetSecretInput {
                            salt1: [0; 32],
                            salt2: None,
                        },
                    )),
                    ..Default::default()
                }),
                Ok(UsedPinUvAuthToken::LegacyUV),
            )
            .await;
        }
    }

    fn get_key_agreement() -> cosey::PublicKey {
        // Self generated key
        //
        // -> Secret key sec1-DER: 306b0201010420ef614223f3c4c45ca9c7a1bc917d7096de91da43116a48b1fe66eb3068f1a0a0a14403420004326ce69b9e8766cc3e9dfad45e62173ffec90ed1c1c5eabe8d43f2add3d86c0cc21c4f54c9aef343bc701e84ff8e3bb50ad089a0849167b514098bfacc185044
        //  -> Generated X: 326ce69b9e8766cc3e9dfad45e62173ffec90ed1c1c5eabe8d43f2add3d86c0c
        //  -> Generated Y: c21c4f54c9aef343bc701e84ff8e3bb50ad089a0849167b514098bfacc185044
        let pub_key_x =
            hex::decode("326ce69b9e8766cc3e9dfad45e62173ffec90ed1c1c5eabe8d43f2add3d86c0c")
                .unwrap();
        let pub_key_y =
            hex::decode("c21c4f54c9aef343bc701e84ff8e3bb50ad089a0849167b514098bfacc185044")
                .unwrap();

        cosey::PublicKey::EcdhEsHkdf256Key(cosey::EcdhEsHkdf256PublicKey {
            x: cosey::Bytes::from_slice(&pub_key_x).unwrap(),
            y: cosey::Bytes::from_slice(&pub_key_y).unwrap(),
        })
    }

    #[tokio::test]
    async fn shared_secret_only() {
        let testcases = vec![
            (
                // PIN supported, but not set. We can establish a shared secret, but not a full pinUvAuthToken
                vec![("clientPin", false)],
                UserVerificationRequirement::Discouraged,
            ),
            (
                // Should be same for uv="preferred"
                vec![("clientPin", false)],
                UserVerificationRequirement::Preferred,
            ),
            (
                // PIN supported, but not requested. We have to establish a shared secret anyways
                vec![("clientPin", true)],
                UserVerificationRequirement::Discouraged,
            ),
            (
                // biometrics supported, but not set. We can establish a shared secret, using "pinUvAuthToken"-command
                vec![("uv", false), ("pinUvAuthToken", true)],
                UserVerificationRequirement::Discouraged,
            ),
            (
                vec![("uv", false), ("pinUvAuthToken", true)],
                UserVerificationRequirement::Preferred,
            ),
            (
                // biometrics supported, but not requested. We can establish a shared secret, using "pinUvAuthToken"-command
                vec![("uv", true), ("pinUvAuthToken", true)],
                UserVerificationRequirement::Discouraged,
            ),
        ];

        let expected_result = Ok(UsedPinUvAuthToken::SharedSecretOnly);

        for (info_options, uv_requirement) in testcases {
            let extensions = Some(GetAssertionRequestExtensions {
                hmac_or_prf: Some(GetAssertionHmacOrPrfInput::HmacGetSecret(
                    HMACGetSecretInput {
                        salt1: [0; 32],
                        salt2: None,
                    },
                )),
                ..Default::default()
            });

            let mut channel = MockChannel::new();
            let status_recv = channel.get_ux_update_receiver();
            let mut info = create_info(&info_options, Some(&["hmac-secret"]));
            info.pin_auth_protos = Some(vec![1]);
            let info_req = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
            let info_resp = CborResponse::new_success_from_slice(to_vec(&info).unwrap().as_slice());
            channel.push_command_pair(info_req, info_resp);

            let pin_req = CborRequest::from(&Ctap2ClientPinRequest::new_get_key_agreement(
                Ctap2PinUvAuthProtocol::One,
            ));
            let pin_resp = CborResponse::new_success_from_slice(
                to_vec(&Ctap2ClientPinResponse {
                    key_agreement: Some(get_key_agreement()),
                    pin_uv_auth_token: None,
                    pin_retries: None,
                    power_cycle_state: None,
                    uv_retries: None,
                })
                .unwrap()
                .as_slice(),
            );
            channel.push_command_pair(pin_req, pin_resp);

            let mut getassertion = create_get_assertion(&info, extensions);

            // We should early return here right at the start and not send a second ClientPIN-request
            // after requesting the key-agreement
            let resp =
                user_verification(&mut channel, uv_requirement, &mut getassertion, TIMEOUT).await;

            assert_eq!(resp, expected_result);
            // Something ended up in the auth store
            assert!(channel.get_auth_data().is_some());
            assert!(channel.get_auth_data().unwrap().pin_uv_auth_token.is_none());
            assert!(!channel.get_auth_data().unwrap().shared_secret.is_empty());
            // No updates should be sent, since we are only doing shared_secret
            assert!(status_recv.is_empty());
        }
    }

    #[tokio::test]
    async fn full_ceremony_using_uv() {
        let testcases = vec![
            (
                vec![("uv", true), ("pinUvAuthToken", true)],
                UserVerificationRequirement::Preferred,
            ),
            (
                vec![("uv", true), ("pinUvAuthToken", true)],
                UserVerificationRequirement::Required,
            ),
        ];

        let expected_result = Ok(UsedPinUvAuthToken::NewlyCalculated(
            Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions,
        ));

        for (info_options, uv_requirement) in testcases {
            let extensions = Some(GetAssertionRequestExtensions {
                hmac_or_prf: Some(GetAssertionHmacOrPrfInput::HmacGetSecret(
                    HMACGetSecretInput {
                        salt1: [0; 32],
                        salt2: None,
                    },
                )),
                ..Default::default()
            });

            let mut channel = MockChannel::new();

            let mut status_recv = channel.get_ux_update_receiver();

            // Queueing GetInfo request and response
            let mut info = create_info(&info_options, Some(&["hmac-secret"]));
            info.pin_auth_protos = Some(vec![1]);
            let info_req = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
            let info_resp = CborResponse::new_success_from_slice(to_vec(&info).unwrap().as_slice());
            channel.push_command_pair(info_req, info_resp);

            // Queueing KeyAgreement request and response
            let key_agreement_req = CborRequest::from(
                &Ctap2ClientPinRequest::new_get_key_agreement(Ctap2PinUvAuthProtocol::One),
            );
            let key_agreement_resp = CborResponse::new_success_from_slice(
                to_vec(&Ctap2ClientPinResponse {
                    key_agreement: Some(get_key_agreement()),
                    pin_uv_auth_token: None,
                    pin_retries: None,
                    power_cycle_state: None,
                    uv_retries: None,
                })
                .unwrap()
                .as_slice(),
            );
            channel.push_command_pair(key_agreement_req, key_agreement_resp);

            let mut getassertion = create_get_assertion(&info, extensions);

            // Queueing getPinUvAuth request and response
            let pin_protocol = PinUvAuthProtocolOne::new();
            let (public_key, shared_secret) =
                pin_protocol.encapsulate(&get_key_agreement()).unwrap();
            let pin_req = CborRequest::from(&Ctap2ClientPinRequest::new_get_uv_token_with_perm(
                Ctap2PinUvAuthProtocol::One,
                public_key,
                getassertion.permissions(),
                getassertion.permissions_rpid(),
            ));
            // We do here what the device would need to do, i.e. generate a new random
            // pinUvAuthToken (here all 5's), then encrypt it using the shared_secret.
            let token = [5; 32];
            let encrypted_token = pin_protocol.encrypt(&shared_secret, &token).unwrap();
            let pin_resp = CborResponse::new_success_from_slice(
                to_vec(&Ctap2ClientPinResponse {
                    key_agreement: None,
                    pin_uv_auth_token: Some(ByteBuf::from(encrypted_token)),
                    pin_retries: None,
                    power_cycle_state: None,
                    uv_retries: None,
                })
                .unwrap()
                .as_slice(),
            );
            channel.push_command_pair(pin_req, pin_resp);

            let mut recv = channel.get_ux_update_receiver();
            tokio::task::spawn(async move {
                let req = recv.recv().await.unwrap();
                assert!(matches!(req, UvUpdate::PresenceRequired));
            });

            let resp =
                user_verification(&mut channel, uv_requirement, &mut getassertion, TIMEOUT).await;

            assert_eq!(resp, expected_result);
            // Something ended up in the auth store
            assert!(channel.get_auth_data().is_some());
            assert_eq!(
                channel
                    .get_auth_data()
                    .as_ref()
                    .unwrap()
                    .pin_uv_auth_token
                    .as_ref()
                    .unwrap(),
                &token
            );
            assert_eq!(
                channel.get_auth_data().unwrap().shared_secret,
                shared_secret
            );
            // No updates should be sent, since we are exiting early
            assert_eq!(status_recv.recv().await, Ok(UvUpdate::PresenceRequired));
        }
    }

    #[tokio::test]
    async fn full_ceremony_using_pin() {
        let testcases = vec![
            (
                vec![("clientPin", true), ("pinUvAuthToken", true)],
                UserVerificationRequirement::Preferred,
            ),
            (
                vec![("clientPin", true), ("pinUvAuthToken", true)],
                UserVerificationRequirement::Required,
            ),
        ];

        let expected_result = Ok(UsedPinUvAuthToken::NewlyCalculated(
            Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions,
        ));

        for (info_options, uv_requirement) in testcases {
            let extensions = Some(GetAssertionRequestExtensions {
                hmac_or_prf: Some(GetAssertionHmacOrPrfInput::HmacGetSecret(
                    HMACGetSecretInput {
                        salt1: [0; 32],
                        salt2: None,
                    },
                )),
                ..Default::default()
            });

            let mut channel = MockChannel::new();

            // Queueing GetInfo request and response
            let mut info = create_info(&info_options, Some(&["hmac-secret"]));
            info.pin_auth_protos = Some(vec![1]);
            let info_req = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
            let info_resp = CborResponse::new_success_from_slice(to_vec(&info).unwrap().as_slice());
            channel.push_command_pair(info_req, info_resp);

            // Queueing PinRetries request and response
            let pin_retries_req = CborRequest::from(&Ctap2ClientPinRequest::new_get_pin_retries(
                Some(Ctap2PinUvAuthProtocol::One),
            ));
            let pin_retries_resp = CborResponse::new_success_from_slice(
                to_vec(&Ctap2ClientPinResponse {
                    key_agreement: None,
                    pin_uv_auth_token: None,
                    pin_retries: Some(5),
                    power_cycle_state: None,
                    uv_retries: None,
                })
                .unwrap()
                .as_slice(),
            );
            channel.push_command_pair(pin_retries_req, pin_retries_resp);

            // Queueing KeyAgreement request and response
            let key_agreement_req = CborRequest::from(
                &Ctap2ClientPinRequest::new_get_key_agreement(Ctap2PinUvAuthProtocol::One),
            );
            let key_agreement_resp = CborResponse::new_success_from_slice(
                to_vec(&Ctap2ClientPinResponse {
                    key_agreement: Some(get_key_agreement()),
                    pin_uv_auth_token: None,
                    pin_retries: None,
                    power_cycle_state: None,
                    uv_retries: None,
                })
                .unwrap()
                .as_slice(),
            );
            channel.push_command_pair(key_agreement_req, key_agreement_resp);

            let mut getassertion = create_get_assertion(&info, extensions);

            // Queueing getPinUvAuth request and response
            let pin_protocol = PinUvAuthProtocolOne::new();
            let (public_key, shared_secret) =
                pin_protocol.encapsulate(&get_key_agreement()).unwrap();
            let pin_hash_enc = pin_protocol
                .encrypt(&shared_secret, &pin_hash("1234".as_bytes()))
                .unwrap();
            let pin_req = CborRequest::from(&Ctap2ClientPinRequest::new_get_pin_token_with_perm(
                Ctap2PinUvAuthProtocol::One,
                public_key,
                &pin_hash_enc,
                getassertion.permissions(),
                getassertion.permissions_rpid(),
            ));
            // We do here what the device would need to do, i.e. generate a new random
            // pinUvAuthToken (here all 5's), then encrypt it using the shared_secret.
            let token = [5; 32];
            let encrypted_token = pin_protocol.encrypt(&shared_secret, &token).unwrap();
            let pin_resp = CborResponse::new_success_from_slice(
                to_vec(&Ctap2ClientPinResponse {
                    key_agreement: None,
                    pin_uv_auth_token: Some(ByteBuf::from(encrypted_token)),
                    pin_retries: None,
                    power_cycle_state: None,
                    uv_retries: None,
                })
                .unwrap()
                .as_slice(),
            );
            channel.push_command_pair(pin_req, pin_resp);

            let mut recv = channel.get_ux_update_receiver();
            let recv_handle = tokio::task::spawn(async move {
                let req = recv.recv().await.unwrap();
                if let UvUpdate::PinRequired(update) = req {
                    update.send_pin("1234").unwrap();
                } else {
                    panic!("Wrong UxUpdate received! Expected PinRequired");
                }
                recv
            });

            let resp =
                user_verification(&mut channel, uv_requirement, &mut getassertion, TIMEOUT).await;

            assert_eq!(resp, expected_result);
            // Something ended up in the auth store
            assert!(channel.get_auth_data().is_some());
            assert_eq!(
                channel
                    .get_auth_data()
                    .as_ref()
                    .unwrap()
                    .pin_uv_auth_token
                    .as_ref()
                    .unwrap(),
                &token
            );
            assert_eq!(
                channel.get_auth_data().unwrap().shared_secret,
                shared_secret
            );
            let recv = recv_handle.await.expect("Failed to join update thread");
            // No more updates should be sent
            assert!(recv.is_empty());
        }
    }
}
