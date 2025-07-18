use std::fmt::{Display, Formatter};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::{task, time};
use tracing::error;

use crate::proto::{
    ctap1::apdu::{ApduRequest, ApduResponse},
    ctap2::cbor::{CborRequest, CborResponse},
};
use crate::transport::error::TransportError;
use crate::transport::AuthTokenData;
use crate::transport::{
    channel::ChannelStatus, device::SupportedProtocols, Channel, Ctap2AuthTokenStore,
};
use crate::webauthn::error::Error;
use crate::UxUpdate;

use super::known_devices::CableKnownDevice;
use super::qr_code_device::CableQrCodeDevice;

#[derive(Debug)]
pub enum CableChannelDevice<'d> {
    QrCode(&'d CableQrCodeDevice),
    Known(&'d CableKnownDevice),
}

#[derive(Debug)]
pub struct CableChannel {
    /// The WebSocket stream used for communication.
    // pub(crate) ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,

    /// The noise state used for encryption over the WebSocket stream.
    // pub(crate) noise_state: TransportState,

    /// The device that this channel is connected to.
    pub(crate) handle_connection: task::JoinHandle<()>,
    pub(crate) cbor_sender: mpsc::Sender<CborRequest>,
    pub(crate) cbor_receiver: mpsc::Receiver<CborResponse>,
    pub(crate) tx: mpsc::Sender<UxUpdate>,
}

impl Display for CableChannel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CableChannel")
    }
}

impl Drop for CableChannel {
    fn drop(&mut self) {
        self.handle_connection.abort();
    }
}

#[async_trait]
impl<'d> Channel for CableChannel {
    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error> {
        Ok(SupportedProtocols::fido2_only())
    }

    async fn status(&self) -> ChannelStatus {
        match self.handle_connection.is_finished() {
            true => ChannelStatus::Closed,
            false => ChannelStatus::Ready,
        }
    }

    async fn close(&mut self) {
        // TODO Send CableTunnelMessageType#Shutdown and drop the connection
    }

    async fn apdu_send(&self, _request: &ApduRequest, _timeout: Duration) -> Result<(), Error> {
        error!("APDU send not supported in caBLE transport");
        Err(Error::Transport(TransportError::TransportUnavailable))
    }

    async fn apdu_recv(&self, _timeout: Duration) -> Result<ApduResponse, Error> {
        error!("APDU recv not supported in caBLE transport");
        Err(Error::Transport(TransportError::TransportUnavailable))
    }

    async fn cbor_send(&mut self, request: &CborRequest, timeout: Duration) -> Result<(), Error> {
        match time::timeout(timeout, self.cbor_sender.send(request.clone())).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => {
                error!(%error, "CBOR request send failure");
                Err(Error::Transport(TransportError::TransportUnavailable))
            }
            Err(elapsed) => {
                error!({ %elapsed, ?timeout }, "CBOR request send timeout");
                Err(Error::Transport(TransportError::Timeout))
            }
        }
    }

    async fn cbor_recv(&mut self, timeout: Duration) -> Result<CborResponse, Error> {
        match time::timeout(timeout, self.cbor_receiver.recv()).await {
            Ok(Some(response)) => Ok(response),
            Ok(None) => Err(Error::Transport(TransportError::TransportUnavailable)),
            Err(elapsed) => {
                error!({ %elapsed, ?timeout }, "CBOR response recv timeout");
                Err(Error::Transport(TransportError::Timeout))
            }
        }
    }

    fn get_state_sender(&self) -> &mpsc::Sender<UxUpdate> {
        &self.tx
    }

    fn supports_preflight() -> bool {
        // Disable pre-flight requests, as hybrid transport authenticators do not support silent requests.
        false
    }
}

impl<'d> Ctap2AuthTokenStore for CableChannel {
    fn store_auth_data(&mut self, _auth_token_data: AuthTokenData) {}

    fn get_auth_data(&self) -> Option<&AuthTokenData> {
        None
    }

    fn clear_uv_auth_token_store(&mut self) {}
}
