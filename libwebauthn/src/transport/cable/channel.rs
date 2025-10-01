use std::fmt::{Display, Formatter};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc, watch};
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
use crate::UvUpdate;

use super::known_devices::CableKnownDevice;
use super::qr_code_device::CableQrCodeDevice;

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    /// Connection is being established (proximity check, connecting, authenticating)
    Connecting,
    /// Connection is fully established and ready for operations
    Connected,
    /// Connection has terminated
    Terminated,
}

#[derive(Debug)]
pub enum CableChannelDevice<'d> {
    QrCode(&'d CableQrCodeDevice),
    Known(&'d CableKnownDevice),
}

#[derive(Debug)]
pub struct CableChannel {
    pub(crate) handle_connection: task::JoinHandle<()>,
    pub(crate) cbor_sender: mpsc::Sender<CborRequest>,
    pub(crate) cbor_receiver: mpsc::Receiver<CborResponse>,
    pub(crate) ux_update_sender: broadcast::Sender<CableUxUpdate>,
    pub(crate) connection_state_receiver: watch::Receiver<ConnectionState>,
}

impl CableChannel {
    async fn wait_for_connection(&self) -> Result<(), Error> {
        let mut rx = self.connection_state_receiver.clone();

        // If already connected, return immediately
        if *rx.borrow() == ConnectionState::Connected {
            return Ok(());
        }

        // If already terminated, return error immediately
        if *rx.borrow() == ConnectionState::Terminated {
            return Err(Error::Transport(TransportError::ConnectionLost));
        }

        // Wait for state change
        while rx.changed().await.is_ok() {
            match *rx.borrow() {
                ConnectionState::Connected => return Ok(()),
                ConnectionState::Terminated => {
                    return Err(Error::Transport(TransportError::ConnectionFailed))
                }
                ConnectionState::Connecting => continue,
            }
        }

        // If the sender was dropped, consider it a failure
        Err(Error::Transport(TransportError::ConnectionLost))
    }
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

#[derive(Debug, Clone)]
pub enum CableUxUpdate {
    UvUpdate(UvUpdate),
    CableUpdate(CableUpdate),
}

#[derive(Debug, Clone)]
pub enum CableUpdate {
    /// Waiting for proximity check user interaction (eg. scan a QR code, or confirm on the device).
    ProximityCheck,
    /// Connecting to the tunnel server.
    Connecting,
    /// Connected to the tunnel server, authenticating the channel.
    Authenticating,
    /// Connected to the authenticator device via the tunnel server.
    Connected,
    /// The connection to the authenticator device has failed.
    Error(TransportError),
}

impl From<UvUpdate> for CableUxUpdate {
    fn from(update: UvUpdate) -> Self {
        CableUxUpdate::UvUpdate(update)
    }
}

#[async_trait]
impl<'d> Channel for CableChannel {
    type UxUpdate = CableUxUpdate;

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

    async fn apdu_send(&mut self, _request: &ApduRequest, _timeout: Duration) -> Result<(), Error> {
        error!("APDU send not supported in caBLE transport");
        Err(Error::Transport(TransportError::TransportUnavailable))
    }

    async fn apdu_recv(&mut self, _timeout: Duration) -> Result<ApduResponse, Error> {
        error!("APDU recv not supported in caBLE transport");
        Err(Error::Transport(TransportError::TransportUnavailable))
    }

    async fn cbor_send(&mut self, request: &CborRequest, timeout: Duration) -> Result<(), Error> {
        // First, wait for connection to be established (no timeout for handshake)
        self.wait_for_connection().await?;

        // Now apply timeout only to the actual CBOR operation
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
        // First, wait for connection to be established (no timeout for handshake)
        self.wait_for_connection().await?;

        // Now apply timeout only to the actual CBOR operation
        match time::timeout(timeout, self.cbor_receiver.recv()).await {
            Ok(Some(response)) => Ok(response),
            Ok(None) => Err(Error::Transport(TransportError::TransportUnavailable)),
            Err(elapsed) => {
                error!({ %elapsed, ?timeout }, "CBOR response recv timeout");
                Err(Error::Transport(TransportError::Timeout))
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

impl<'d> Ctap2AuthTokenStore for CableChannel {
    fn store_auth_data(&mut self, _auth_token_data: AuthTokenData) {}

    fn get_auth_data(&self) -> Option<&AuthTokenData> {
        None
    }

    fn clear_uv_auth_token_store(&mut self) {}
}
