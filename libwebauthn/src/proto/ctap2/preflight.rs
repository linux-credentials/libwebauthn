use serde_bytes::ByteBuf;
use std::time::Duration;
use tracing::{debug, info};

use super::{Ctap2GetAssertionRequest, Ctap2PublicKeyCredentialDescriptor};
use crate::{
    proto::ctap2::{model::Ctap2GetAssertionOptions, Ctap2},
    transport::Channel,
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
pub(crate) async fn ctap2_preflight<C: Channel>(
    channel: &mut C,
    credentials: &[Ctap2PublicKeyCredentialDescriptor],
    client_data_hash: &[u8],
    rp: &str,
) -> Vec<Ctap2PublicKeyCredentialDescriptor> {
    info!("Credential list BEFORE preflight: {credentials:?}");
    let mut filtered_list = Vec::new();
    for credential in credentials {
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
                debug!("Pre-flight: Found already known credential {credential:?}");
                // This credential is known to the device
                // Now we have to figure out it's ID. There are 3 options:
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
                filtered_list.push(id);
            }
            Err(e) => {
                debug!("Pre-flight: Filtering out {credential:?}, because of error: {e:?}");
                // This credential is unknown to the device. So we can filter it out.
                // NOTE: According to spec a CTAP2_ERR_NO_CREDENTIALS should be returned, other return values have been observed.
                continue;
            }
        }
    }
    info!("Credential list AFTER preflight: {filtered_list:?}");
    filtered_list
}
