//! Public entry point: open a PXP connection to a CMHD and exchange opaque
//! CTAP frames over it.
use tokio::sync::{mpsc, watch};
use tokio::task;

use crate::connection_stages::{MpscUxUpdateSender, TunnelConnectionInput, UxUpdateSender};
use crate::error::PxpError;
use crate::known_devices::PxpKnownDevice;
use crate::protocol;
use crate::qr_code_device::PxpQrCodeDevice;

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    /// Connection is being established (proximity check, connecting, authenticating)
    Connecting,
    /// Connection is fully established and ready for operations
    Connected,
    /// Connection has terminated
    Terminated,
}

#[derive(Debug, Clone)]
pub enum PxpUpdate {
    /// Waiting for proximity check user interaction (eg. scan a QR code, or confirm on the device).
    ProximityCheck,
    /// Connecting to the tunnel server.
    Connecting,
    /// Connected to the tunnel server, authenticating the channel.
    Authenticating,
    /// Connected to the authenticator device via the tunnel server.
    Connected,
    /// The connection to the authenticator device has failed.
    Error(PxpError),
}

/// Receives connection progress updates from the connection task.
pub trait UpdateSink: Send + Sync + 'static {
    fn send_update(&self, update: PxpUpdate);
}

/// The CMHD to connect to.
#[derive(Debug, Clone)]
pub enum ConnectTarget {
    /// A new device, invoked by scanning a QR code.
    QrCode(PxpQrCodeDevice),
    /// A previously linked device, invoked state-assisted via the tunnel service.
    Known(PxpKnownDevice),
}

impl From<PxpQrCodeDevice> for ConnectTarget {
    fn from(device: PxpQrCodeDevice) -> Self {
        Self::QrCode(device)
    }
}

impl From<PxpKnownDevice> for ConnectTarget {
    fn from(device: PxpKnownDevice) -> Self {
        Self::Known(device)
    }
}

/// A running PXP connection. Dropping it aborts the connection task.
#[derive(Debug)]
pub struct TunnelHandle {
    /// The connection task: proximity check, handshake, then message exchange.
    pub task: task::JoinHandle<()>,
    /// Outbound CTAP frames: command byte followed by the CBOR payload.
    pub ctap_sender: mpsc::Sender<Vec<u8>>,
    /// Inbound CTAP frames: status byte followed by the CBOR payload.
    pub ctap_receiver: mpsc::Receiver<Vec<u8>>,
    pub connection_state: watch::Receiver<ConnectionState>,
}

impl TunnelHandle {
    /// Waits until the handshake completes, or fails if the connection terminates first.
    pub async fn wait_for_connection(&self) -> Result<(), PxpError> {
        let mut rx = self.connection_state.clone();

        // If already connected, return immediately
        if *rx.borrow() == ConnectionState::Connected {
            return Ok(());
        }

        // If already terminated, return error immediately. Mirror the
        // post-`changed()` branch below so that an early-terminated channel
        // surfaces the same variant as one that terminates while we wait;
        // the caller can't observe the timing difference and the asymmetry
        // was accidental.
        if *rx.borrow() == ConnectionState::Terminated {
            return Err(PxpError::ConnectionFailed);
        }

        // Wait for state change
        while rx.changed().await.is_ok() {
            match *rx.borrow() {
                ConnectionState::Connected => return Ok(()),
                ConnectionState::Terminated => return Err(PxpError::ConnectionFailed),
                ConnectionState::Connecting => continue,
            }
        }

        // If the sender was dropped, consider it a failure
        Err(PxpError::ConnectionLost)
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Spawns the connection task for `target`. Progress is reported to `updates`;
/// CTAP frames are exchanged through the returned handle once connected.
pub fn connect(target: impl Into<ConnectTarget>, updates: impl UpdateSink) -> TunnelHandle {
    let target = target.into();
    let (ctap_tx_send, ctap_tx_recv) = mpsc::channel(16);
    let (ctap_rx_send, ctap_rx_recv) = mpsc::channel(16);
    let (connection_state_sender, connection_state_receiver) =
        watch::channel(ConnectionState::Connecting);

    let task = task::spawn(async move {
        let ux_sender = MpscUxUpdateSender::new(Box::new(updates), connection_state_sender);

        let (handshake_output, store) = match &target {
            ConnectTarget::QrCode(device) => (
                PxpQrCodeDevice::connection(device, &ux_sender).await,
                device.store.clone(),
            ),
            ConnectTarget::Known(device) => (
                PxpKnownDevice::connection(device, &ux_sender).await,
                Some(device.store.clone()),
            ),
        };
        let handshake_output = match handshake_output {
            Ok(handshake_output) => handshake_output,
            Err(e) => {
                ux_sender.send_error(e).await;
                return;
            }
        };

        let tunnel_input = TunnelConnectionInput::from_handshake_output(
            handshake_output,
            store,
            ctap_tx_recv,
            ctap_rx_send,
        );
        match protocol::connection(tunnel_input).await {
            Ok(()) => {
                ux_sender
                    .set_connection_state(ConnectionState::Terminated)
                    .await;
            }
            Err(e) => {
                // send_error already transitions to Terminated.
                ux_sender.send_error(e).await;
            }
        }
    });

    TunnelHandle {
        task,
        ctap_sender: ctap_tx_send,
        ctap_receiver: ctap_rx_recv,
        connection_state: connection_state_receiver,
    }
}
