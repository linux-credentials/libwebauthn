use serde_bytes::ByteBuf;
use std::time::Duration;
use tracing::{debug, info};

use super::{Ctap2GetAssertionRequest, Ctap2PublicKeyCredentialDescriptor};
use crate::{
    proto::ctap2::{model::Ctap2GetAssertionOptions, Ctap2},
    transport::Channel,
    webauthn::error::{CtapError, WebAuthnError},
};

/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pre-flight
/// pre-flight
///
/// In order to determine whether authenticatorMakeCredential's excludeList or
/// authenticatorGetAssertion's allowList contain credential IDs that are already present on an
/// authenticator, a platform typically invokes authenticatorGetAssertion with the "up" option
/// key set to false and optionally pinUvAuthParam one or more times. If a credential is found an
/// assertion is returned. If a valid pinUvAuthParam was also provided, the response will contain
/// "up"=0 and "uv"=1 within the "flags bits" of the authenticator data structure, otherwise the
/// "flag bits" will contain "up"=0 and "uv"=0.
pub async fn ctap2_preflight<C: Channel>(
    channel: &mut C,
    credentials: &[Ctap2PublicKeyCredentialDescriptor],
    client_data_hash: &[u8],
    rp: &str,
) -> Result<Vec<Ctap2PublicKeyCredentialDescriptor>, WebAuthnError<C::TransportError>> {
    ctap2_preflight_with_appid(channel, credentials, client_data_hash, rp, None).await
}

/// Like [`ctap2_preflight`] but additionally tests each credential against an
/// extra "appid" relying-party identifier, per the WebAuthn L3 §10.1.2 FIDO
/// AppID Exclusion extension. If a credential is found under either the
/// canonical `rpId` or under the legacy `appidExclude`, it is kept in the
/// filtered list so the caller can refuse registration.
pub async fn ctap2_preflight_with_appid<C: Channel>(
    channel: &mut C,
    credentials: &[Ctap2PublicKeyCredentialDescriptor],
    client_data_hash: &[u8],
    rp: &str,
    appid_exclude: Option<&str>,
) -> Result<Vec<Ctap2PublicKeyCredentialDescriptor>, WebAuthnError<C::TransportError>> {
    info!("Credential list BEFORE preflight: {credentials:?}");
    let mut filtered_list = Vec::new();
    for credential in credentials {
        // Test against the canonical rpId first.
        if let Some(matched) = preflight_one(channel, credential, client_data_hash, rp).await? {
            debug!("Pre-flight: Found already known credential under rpId {credential:?}");
            filtered_list.push(matched);
            continue;
        }
        // FIDO AppID Exclusion (WebAuthn L3 §10.1.2): if the caller supplied
        // a legacy AppID, also test the credential against the AppID-derived
        // application parameter. CTAP authenticators key by rpId so we pass
        // the AppID URL as the rpId here; the authenticator hashes it the
        // same way the U2F device hashed the original AppID.
        if let Some(appid) = appid_exclude {
            if let Some(matched) =
                preflight_one(channel, credential, client_data_hash, appid).await?
            {
                debug!(
                    "Pre-flight: Found already known credential under appidExclude {credential:?}"
                );
                filtered_list.push(matched);
                continue;
            }
        }
        debug!("Pre-flight: Filtering out {credential:?}");
    }
    info!("Credential list AFTER preflight: {filtered_list:?}");
    Ok(filtered_list)
}

async fn preflight_one<C: Channel>(
    channel: &mut C,
    credential: &Ctap2PublicKeyCredentialDescriptor,
    client_data_hash: &[u8],
    rp: &str,
) -> Result<Option<Ctap2PublicKeyCredentialDescriptor>, WebAuthnError<C::TransportError>> {
    let preflight_request = Ctap2GetAssertionRequest {
        relying_party_id: rp.to_string(),
        client_data_hash: ByteBuf::from(client_data_hash),
        allow: vec![credential.clone()],
        extensions: None,
        options: Some(Ctap2GetAssertionOptions {
            require_user_presence: false,
            require_user_verification: false,
        }),
        pin_auth_param: None,
        pin_auth_proto: None,
    };
    match channel
        .ctap2_get_assertion(&preflight_request, Duration::from_secs(2))
        .await
    {
        Ok(resp) => {
            // This credential is known to the device under this rpId.
            // Now we have to figure out its ID. There are 3 options:
            let id = resp
                // 1. Directly in the response "credential_id"
                .credential_id
                // 2. In the attested_credential
                .or(resp
                    .authenticator_data
                    .attested_credential
                    .map(|x| Ctap2PublicKeyCredentialDescriptor::from(&x)))
                // 3. Neither, which is allowed, if the allow_list was of length 1, then
                //    we have to copy it ourselfs from the input
                .unwrap_or(credential.clone());
            Ok(Some(id))
        }
        // Only CTAP2_ERR_NO_CREDENTIALS proves the credential is absent.
        Err(WebAuthnError::Ctap(CtapError::NoCredentials)) => {
            debug!("Pre-flight: Not found under {rp:?}");
            Ok(None)
        }
        // Any other error is transient or unexpected, not absence: propagate it.
        Err(e) => {
            debug!("Pre-flight: Error testing under {rp:?}: {e:?}");
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_bytes::ByteBuf;

    use super::ctap2_preflight;
    use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
    use crate::proto::ctap2::model::Ctap2GetAssertionOptions;
    use crate::proto::ctap2::{
        Ctap2GetAssertionRequest, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialType,
    };
    use crate::transport::mock::channel::MockChannel;
    use crate::webauthn::error::{CtapError, WebAuthnError};

    fn credential(id: &[u8]) -> Ctap2PublicKeyCredentialDescriptor {
        Ctap2PublicKeyCredentialDescriptor {
            r#type: Ctap2PublicKeyCredentialType::PublicKey,
            id: ByteBuf::from(id),
            transports: None,
        }
    }

    fn expected_preflight_request(
        cred: &Ctap2PublicKeyCredentialDescriptor,
        hash: &[u8],
        rp: &str,
    ) -> CborRequest {
        let request = Ctap2GetAssertionRequest {
            relying_party_id: rp.to_string(),
            client_data_hash: ByteBuf::from(hash),
            allow: vec![cred.clone()],
            extensions: None,
            options: Some(Ctap2GetAssertionOptions {
                require_user_presence: false,
                require_user_verification: false,
            }),
            pin_auth_param: None,
            pin_auth_proto: None,
        };
        (&request).try_into().expect("encode preflight request")
    }

    #[tokio::test]
    async fn preflight_propagates_non_no_credentials_error() {
        let cred = credential(&[1, 2, 3, 4]);
        let hash = [0u8; 32];
        let mut channel = MockChannel::new();
        channel.push_command_pair(
            expected_preflight_request(&cred, &hash, "example.org"),
            CborResponse {
                status_code: CtapError::OperationDenied,
                data: None,
            },
        );

        let result = ctap2_preflight(&mut channel, &[cred], &hash, "example.org").await;
        assert!(matches!(
            result.err(),
            Some(WebAuthnError::Ctap(CtapError::OperationDenied))
        ));
    }

    #[tokio::test]
    async fn preflight_treats_no_credentials_as_absence() {
        let cred = credential(&[1, 2, 3, 4]);
        let hash = [0u8; 32];
        let mut channel = MockChannel::new();
        channel.push_command_pair(
            expected_preflight_request(&cred, &hash, "example.org"),
            CborResponse {
                status_code: CtapError::NoCredentials,
                data: None,
            },
        );

        let filtered = ctap2_preflight(&mut channel, &[cred], &hash, "example.org")
            .await
            .expect("preflight should succeed on NoCredentials");
        assert!(filtered.is_empty());
    }
}
