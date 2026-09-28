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

use super::error::CableError;
use super::known_devices::CableKnownDevice;
use super::qr_code_device::CableQrCodeDevice;

pub use libwebauthn_pxp::{CableUpdate, ConnectionState};

#[derive(Debug)]
pub enum CableChannelDevice<'d> {
    QrCode(&'d CableQrCodeDevice),
    Known(&'d CableKnownDevice),
}

#[derive(Debug)]
pub struct CableChannel {
    pub(crate) tunnel: TunnelHandle,
    pub(crate) ux_update_sender: broadcast::Sender<CableUxUpdate>,
    pub(crate) persistent_token_store: Option<Arc<dyn PersistentTokenStore>>,
}

impl Display for CableChannel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CableChannel")
    }
}

#[derive(Debug, Clone)]
pub enum CableUxUpdate {
    UvUpdate(UvUpdate),
    CableUpdate(CableUpdate),
}

impl From<UvUpdate> for CableUxUpdate {
    fn from(update: UvUpdate) -> Self {
        CableUxUpdate::UvUpdate(update)
    }
}

#[async_trait]
impl Channel for CableChannel {
    type UxUpdate = CableUxUpdate;
    type TransportError = CableError;

    fn transport(&self) -> Transport {
        Transport::Hybrid
    }

    async fn supported_protocols(&self) -> Result<SupportedProtocols, WebAuthnError<CableError>> {
        Ok(SupportedProtocols::fido2_only())
    }

    async fn status(&self) -> ChannelStatus {
        match self.tunnel.task.is_finished() {
            true => ChannelStatus::Closed,
            false => ChannelStatus::Ready,
        }
    }

    async fn close(&mut self) {
        // TODO Send CableTunnelMessageType#Shutdown and drop the connection
    }

    async fn apdu_send(
        &mut self,
        _request: &ApduRequest,
        _timeout: Duration,
    ) -> Result<(), CableError> {
        error!("APDU send not supported in caBLE transport");
        Err(CableError::TransportUnavailable)
    }

    async fn apdu_recv(&mut self, _timeout: Duration) -> Result<ApduResponse, CableError> {
        error!("APDU recv not supported in caBLE transport");
        Err(CableError::TransportUnavailable)
    }

    async fn cbor_send(
        &mut self,
        request: &CborRequest,
        timeout: Duration,
    ) -> Result<(), CableError> {
        // First, wait for connection to be established (no timeout for handshake)
        self.tunnel.wait_for_connection().await?;

        // Now apply timeout only to the actual CBOR operation
        let frame = request.ctap_hid_data();
        match time::timeout(timeout, self.tunnel.ctap_sender.send(frame)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => {
                error!(%error, "CBOR request send failure");
                Err(CableError::TransportUnavailable)
            }
            Err(elapsed) => {
                error!({ %elapsed, ?timeout }, "CBOR request send timeout");
                Err(CableError::Timeout)
            }
        }
    }

    async fn cbor_recv(&mut self, timeout: Duration) -> Result<CborResponse, CableError> {
        // First, wait for connection to be established (no timeout for handshake)
        self.tunnel.wait_for_connection().await?;

        // Now apply timeout only to the actual CBOR operation
        match time::timeout(timeout, self.tunnel.ctap_receiver.recv()).await {
            Ok(Some(frame)) => CborResponse::try_from(&frame).map_err(|e| {
                error!(%e, "Malformed CTAP response frame");
                CableError::InvalidFraming
            }),
            Ok(None) => Err(CableError::TransportUnavailable),
            Err(elapsed) => {
                error!({ %elapsed, ?timeout }, "CBOR response recv timeout");
                Err(CableError::Timeout)
            }
        }
    }

    fn get_ux_update_sender(&self) -> &broadcast::Sender<CableUxUpdate> {
        &self.ux_update_sender
    }

    fn supports_preflight() -> bool {
        // Disable pre-flight requests, as hybrid transport authenticators do not support silent requests.
        false
    }
}

impl Ctap2AuthTokenStore for CableChannel {
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
