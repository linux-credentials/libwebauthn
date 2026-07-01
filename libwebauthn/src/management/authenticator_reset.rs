use std::time::Duration;

use async_trait::async_trait;
use tracing::warn;

use crate::pin::persistent_token::recognize_authenticator;
use crate::proto::ctap2::Ctap2;
use crate::transport::Channel;
use crate::webauthn::error::WebAuthnError;

#[async_trait]
pub trait AuthenticatorReset: Channel {
    /// Reset the authenticator to factory defaults, evicting any stored persistent token.
    async fn reset(&mut self, timeout: Duration)
        -> Result<(), WebAuthnError<Self::TransportError>>;
}

#[async_trait]
impl<C> AuthenticatorReset for C
where
    C: Channel,
{
    async fn reset(
        &mut self,
        timeout: Duration,
    ) -> Result<(), WebAuthnError<Self::TransportError>> {
        // Recognize before reset, while the device identifier is still derivable.
        let record_id = match self.persistent_token_store() {
            Some(store) => match self.ctap2_get_info().await {
                Ok(info) => recognize_authenticator(store.as_ref(), &info)
                    .await
                    .map(|(id, _)| id),
                Err(error) => {
                    warn!(
                        ?error,
                        "getInfo before reset failed; cannot evict persistent token"
                    );
                    None
                }
            },
            None => None,
        };

        self.ctap2_authenticator_reset(timeout).await?;

        if let (Some(store), Some(id)) = (self.persistent_token_store(), record_id) {
            store.delete(&id).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_bytes::ByteBuf;

    use super::AuthenticatorReset;
    use crate::pin::persistent_token::{
        build_enc_identifier, MemoryPersistentTokenStore, PersistentTokenRecord,
        PersistentTokenStore,
    };
    use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
    use crate::proto::ctap2::{Ctap2CommandCode, Ctap2GetInfoResponse, Ctap2PinUvAuthProtocol};
    use crate::transport::mock::channel::MockChannel;
    use crate::webauthn::error::{CtapError, WebAuthnError};

    const TIMEOUT: Duration = Duration::from_secs(1);

    fn ok_response(data: Option<Vec<u8>>) -> CborResponse {
        CborResponse {
            status_code: CtapError::Ok,
            data,
        }
    }

    #[tokio::test]
    async fn reset_evicts_recognized_persistent_token() {
        let token = vec![0x07; 32];
        let device_identifier = [0x42; 16];

        let store = MemoryPersistentTokenStore::new();
        store
            .put(
                &"id-1".to_string(),
                &PersistentTokenRecord {
                    persistent_token: token.clone(),
                    pin_uv_auth_protocol: Ctap2PinUvAuthProtocol::Two,
                    device_identifier,
                    aaguid: [0x22; 16],
                },
            )
            .await;

        let info = Ctap2GetInfoResponse {
            enc_identifier: Some(ByteBuf::from(build_enc_identifier(
                &token,
                &device_identifier,
                &[0x33; 16],
            ))),
            ..Default::default()
        };
        let info_bytes = crate::proto::ctap2::cbor::to_vec(&info).unwrap();

        let mut channel = MockChannel::new();
        channel.set_persistent_token_store(Arc::new(store.clone()));
        channel.push_command_pair(
            CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo),
            ok_response(Some(info_bytes)),
        );
        channel.push_command_pair(
            CborRequest::new(Ctap2CommandCode::AuthenticatorReset),
            ok_response(None),
        );

        channel.reset(TIMEOUT).await.unwrap();

        assert!(
            store.list().await.is_empty(),
            "reset must evict the recognized persistent token record"
        );
    }

    #[tokio::test]
    async fn reset_propagates_non_ok_status() {
        let mut channel = MockChannel::new();
        channel.push_command_pair(
            CborRequest::new(Ctap2CommandCode::AuthenticatorReset),
            CborResponse {
                status_code: CtapError::OperationDenied,
                data: None,
            },
        );

        let result = channel.reset(TIMEOUT).await;
        assert!(matches!(
            result.unwrap_err(),
            WebAuthnError::Ctap(CtapError::OperationDenied)
        ));
    }
}
