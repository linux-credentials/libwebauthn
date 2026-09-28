use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use libwebauthn_pxp::TunnelHandle;
use tokio::sync::broadcast;
use tokio::time;
use tracing::error;

use crate::pin::persistent_token::PersistentTokenStore;
use crate::proto::{
    ctap1::apdu::{ApduRequest, ApduResponse},
    ctap2::cbor::{CborRequest, CborResponse},
};
use crate::transport::AuthTokenData;
use crate::transport::{
    channel::ChannelStatus, device::SupportedProtocols, Channel, Ctap2AuthTokenStore,
};
use crate::webauthn::error::WebAuthnError;
use crate::Transport;
use crate::UvUpdate;

use super::error::PxpError;
use super::known_devices::PxpKnownDevice;
use super::qr_code_device::PxpQrCodeDevice;

pub use libwebauthn_pxp::{ConnectionState, PxpUpdate};

#[derive(Debug)]
pub enum HybridChannelDevice<'d> {
    QrCode(&'d PxpQrCodeDevice),
    Known(&'d PxpKnownDevice),
}

#[derive(Debug)]
pub struct HybridChannel {
    pub(crate) tunnel: TunnelHandle,
    pub(crate) ux_update_sender: broadcast::Sender<HybridUxUpdate>,
    pub(crate) persistent_token_store: Option<Arc<dyn PersistentTokenStore>>,
}

impl Display for HybridChannel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridChannel")
    }
}

#[derive(Debug, Clone)]
pub enum HybridUxUpdate {
    UvUpdate(UvUpdate),
    PxpUpdate(PxpUpdate),
}

impl From<UvUpdate> for HybridUxUpdate {
    fn from(update: UvUpdate) -> Self {
        HybridUxUpdate::UvUpdate(update)
    }
}

#[async_trait]
impl Channel for HybridChannel {
    type UxUpdate = HybridUxUpdate;
    type TransportError = PxpError;

    fn transport(&self) -> Transport {
        Transport::Hybrid
    }

    async fn supported_protocols(&self) -> Result<SupportedProtocols, WebAuthnError<PxpError>> {
        Ok(SupportedProtocols::fido2_only())
    }

    async fn status(&self) -> ChannelStatus {
        match self.tunnel.task.is_finished() {
            true => ChannelStatus::Closed,
            false => ChannelStatus::Ready,
        }
    }

    async fn close(&mut self) {
        // TODO Send PxpTunnelMessageType#Shutdown and drop the connection
    }

    async fn apdu_send(
        &mut self,
        _request: &ApduRequest,
        _timeout: Duration,
    ) -> Result<(), PxpError> {
        error!("APDU send not supported in caBLE transport");
        Err(PxpError::TransportUnavailable)
    }

    async fn apdu_recv(&mut self, _timeout: Duration) -> Result<ApduResponse, PxpError> {
        error!("APDU recv not supported in caBLE transport");
        Err(PxpError::TransportUnavailable)
    }

    async fn cbor_send(
        &mut self,
        request: &CborRequest,
        timeout: Duration,
    ) -> Result<(), PxpError> {
        // First, wait for connection to be established (no timeout for handshake)
        self.tunnel.wait_for_connection().await?;

        // Now apply timeout only to the actual CBOR operation
        let frame = request.ctap_hid_data();
        match time::timeout(timeout, self.tunnel.ctap_sender.send(frame)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => {
                error!(%error, "CBOR request send failure");
                Err(PxpError::TransportUnavailable)
            }
            Err(elapsed) => {
                error!({ %elapsed, ?timeout }, "CBOR request send timeout");
                Err(PxpError::Timeout)
            }
        }
    }

    async fn cbor_recv(&mut self, timeout: Duration) -> Result<CborResponse, PxpError> {
        // First, wait for connection to be established (no timeout for handshake)
        self.tunnel.wait_for_connection().await?;

        // Now apply timeout only to the actual CBOR operation
        match time::timeout(timeout, self.tunnel.ctap_receiver.recv()).await {
            Ok(Some(frame)) => CborResponse::try_from(&frame).map_err(|e| {
                error!(%e, "Malformed CTAP response frame");
                PxpError::InvalidFraming
            }),
            Ok(None) => Err(PxpError::TransportUnavailable),
            Err(elapsed) => {
                error!({ %elapsed, ?timeout }, "CBOR response recv timeout");
                Err(PxpError::Timeout)
            }
        }
    }

    fn get_ux_update_sender(&self) -> &broadcast::Sender<HybridUxUpdate> {
        &self.ux_update_sender
    }

    fn supports_preflight() -> bool {
        // Disable pre-flight requests, as hybrid transport authenticators do not support silent requests.
        false
    }
}

impl Ctap2AuthTokenStore for HybridChannel {
    fn store_auth_data(&mut self, _auth_token_data: AuthTokenData) {}

    fn get_auth_data(&self) -> Option<&AuthTokenData> {
        None
    }

    fn clear_uv_auth_token_store(&mut self) {}

    fn set_cred_mgmt_preview(&mut self, _uses_preview: bool) {}

    fn cred_mgmt_preview(&self) -> bool {
        false
    }

    fn persistent_token_store(&self) -> Option<Arc<dyn PersistentTokenStore>> {
        self.persistent_token_store.clone()
    }
}
