use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::{task, time};
use tracing::{debug, error, warn};

use crate::pin::persistent_token::PersistentTokenStore;
use crate::proto::{
    ctap1::apdu::{ApduRequest, ApduResponse},
    ctap2::cbor::{CborRequest, CborResponse},
};
use crate::transport::cable::error::CableError;
use crate::transport::AuthTokenData;
use crate::transport::{
    channel::ChannelStatus, device::SupportedProtocols, Channel, Ctap2AuthTokenStore,
};
use crate::webauthn::error::WebAuthnError;
use crate::Transport;
use crate::UvUpdate;

use super::known_devices::CableKnownDevice;
use super::linger::Teardown;
use super::qr_code_device::CableQrCodeDevice;

/// Bounds `close()`: the Shutdown send plus the task's return.
const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounds `cancel()`: one select hop plus a socket drop. Aborts on expiry.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ConnectionState {
    /// Connection is being established (proximity check, connecting, authenticating)
    Connecting,
    /// Connection is fully established and ready for operations
    Connected,
    /// Shutdown has been sent and the connection is only receiving a late
    /// linking update. No further operations are admitted.
    Lingering,
    /// Connection has terminated
    Terminated,
}

/// How [`CableChannel::close`] ends the connection. Both send Shutdown first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CableClose {
    /// Terminate as soon as Shutdown has been sent.
    Immediate,
    /// Keep receiving in the background to capture a late linking update.
    Linger,
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
    pub(crate) persistent_token_store: Option<Arc<dyn PersistentTokenStore>>,
    pub(crate) teardown: Arc<watch::Sender<Teardown>>,
    pub(crate) linger_eligible: bool,
}

impl CableChannel {
    /// Sends Shutdown, then ends the connection as `mode` says. The
    /// [`Channel::close`] of this channel is [`CableClose::Immediate`].
    ///
    /// [`CableClose::Immediate`] waits for the connection to terminate,
    /// cancelling it if that takes too long. A linger already under way is
    /// left alone.
    ///
    /// [`CableClose::Linger`] returns once the connection is lingering, not
    /// when the window ends, and the channel can then be dropped. Only a
    /// state-assisted QR connection opened with a
    /// [`CableLingerConfig`](super::CableLingerConfig) can linger, anything
    /// else closes immediately. The linger runs on the tokio runtime that
    /// opened the channel, which must outlive the window. Call
    /// [`CableLingerRegistry::close_lingering`](super::CableLingerRegistry::close_lingering)
    /// before shutting that runtime down.
    pub async fn close(&mut self, mode: CableClose) {
        match mode {
            CableClose::Immediate => self.close_immediately().await,
            CableClose::Linger if self.linger_eligible => self.linger().await,
            CableClose::Linger => self.close_immediately().await,
        }
    }

    async fn close_immediately(&mut self) {
        self.request_teardown(Teardown::Close);
        if *self.teardown.borrow() == Teardown::Linger {
            self.wait_for_state(CLOSE_FLUSH_TIMEOUT, |state| {
                matches!(
                    state,
                    ConnectionState::Lingering | ConnectionState::Terminated
                )
            })
            .await;
            return;
        }
        if !self
            .wait_for_state(CLOSE_FLUSH_TIMEOUT, |state| {
                *state == ConnectionState::Terminated
            })
            .await
        {
            warn!("Timed out waiting for the hybrid connection to close, cancelling it");
            self.cancel().await;
        }
    }

    async fn linger(&mut self) {
        self.request_teardown(Teardown::Linger);
        if !self
            .wait_for_state(CLOSE_FLUSH_TIMEOUT, |state| {
                matches!(
                    state,
                    ConnectionState::Lingering | ConnectionState::Terminated
                )
            })
            .await
        {
            warn!("Timed out waiting for the hybrid connection to start lingering");
        }
    }

    /// Sets the teardown intent if nobody has set one yet. Returns whether it did.
    fn request_teardown(&self, intent: Teardown) -> bool {
        self.teardown.send_if_modified(|current| {
            if *current == Teardown::Active {
                *current = intent;
                true
            } else {
                false
            }
        })
    }

    /// Waits until the connection reaches a state matching `done`, bounded by `timeout`.
    async fn wait_for_state(
        &self,
        timeout: Duration,
        done: impl FnMut(&ConnectionState) -> bool,
    ) -> bool {
        let mut rx = self.connection_state_receiver.clone();
        let reached = time::timeout(timeout, rx.wait_for(done)).await.is_ok();
        reached
    }

    async fn wait_for_connection(&self) -> Result<(), CableError> {
        let mut rx = self.connection_state_receiver.clone();

        // If already connected, return immediately
        if *rx.borrow() == ConnectionState::Connected {
            return Ok(());
        }

        // If already terminated, return error immediately. Mirror the
        // post-`changed()` branch below so that an early-terminated channel
        // surfaces the same variant as one that terminates while we wait;
        // the caller can't observe the timing difference and the asymmetry
        // was accidental.
        match *rx.borrow() {
            ConnectionState::Terminated => return Err(CableError::ConnectionFailed),
            ConnectionState::Lingering => return Err(CableError::ConnectionLost),
            _ => {}
        }

        // Wait for state change
        while rx.changed().await.is_ok() {
            match *rx.borrow() {
                ConnectionState::Connected => return Ok(()),
                ConnectionState::Terminated => return Err(CableError::ConnectionFailed),
                ConnectionState::Lingering => return Err(CableError::ConnectionLost),
                ConnectionState::Connecting => continue,
            }
        }

        // If the sender was dropped, consider it a failure
        Err(CableError::ConnectionLost)
    }
}

impl Display for CableChannel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CableChannel")
    }
}

impl Drop for CableChannel {
    fn drop(&mut self) {
        // An unattended drop is a hard cancel. A teardown already under way
        // (close, linger, cancel) is left to run its course.
        if self.request_teardown(Teardown::Cancel) {
            self.handle_connection.abort();
        }
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
    Error(CableError),
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
        if self.handle_connection.is_finished() {
            return ChannelStatus::Closed;
        }
        match *self.connection_state_receiver.borrow() {
            ConnectionState::Lingering | ConnectionState::Terminated => ChannelStatus::Closed,
            _ => ChannelStatus::Ready,
        }
    }

    async fn close(&mut self) {
        CableChannel::close(self, CableClose::Immediate).await
    }

    /// Drops the connection without sending Shutdown. Always wins over a
    /// graceful teardown already under way.
    async fn cancel(&mut self) {
        self.teardown.send_replace(Teardown::Cancel);
        if !self
            .wait_for_state(CANCEL_TIMEOUT, |state| {
                *state == ConnectionState::Terminated
            })
            .await
        {
            debug!("Aborting the hybrid connection task after cancel timeout");
            self.handle_connection.abort();
        }
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
        self.wait_for_connection().await?;

        // Now apply timeout only to the actual CBOR operation
        match time::timeout(timeout, self.cbor_sender.send(request.clone())).await {
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
        self.wait_for_connection().await?;

        // Now apply timeout only to the actual CBOR operation
        match time::timeout(timeout, self.cbor_receiver.recv()).await {
            Ok(Some(response)) => Ok(response),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn channel_in_state(state: ConnectionState) -> (CableChannel, watch::Sender<ConnectionState>) {
        let (ux_update_sender, _) = broadcast::channel(1);
        let (cbor_sender, _cbor_tx_recv) = mpsc::channel(1);
        let (_cbor_rx_send, cbor_receiver) = mpsc::channel(1);
        let (teardown, _teardown_rx) = watch::channel(Teardown::Active);
        let (state_tx, connection_state_receiver) = watch::channel(state);
        let channel = CableChannel {
            handle_connection: task::spawn(std::future::pending()),
            cbor_sender,
            cbor_receiver,
            ux_update_sender,
            connection_state_receiver,
            persistent_token_store: None,
            teardown: Arc::new(teardown),
            linger_eligible: true,
        };
        (channel, state_tx)
    }

    /// A channel whose task mimics the connection loop's teardown handling:
    /// it publishes `Terminated` on any intent and reports the intent seen.
    fn channel_with_teardown_task() -> (
        CableChannel,
        tokio::sync::oneshot::Receiver<Teardown>,
        Arc<watch::Sender<Teardown>>,
    ) {
        let (ux_update_sender, _) = broadcast::channel(1);
        let (cbor_sender, _cbor_tx_recv) = mpsc::channel(1);
        let (_cbor_rx_send, cbor_receiver) = mpsc::channel(1);
        let (teardown, mut teardown_rx) = watch::channel(Teardown::Active);
        let teardown = Arc::new(teardown);
        let (state_tx, connection_state_receiver) = watch::channel(ConnectionState::Connected);
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let handle_connection = task::spawn(async move {
            let intent = super::super::connection_stages::next_teardown(&mut teardown_rx).await;
            let _ = seen_tx.send(intent);
            let _ = state_tx.send(ConnectionState::Terminated);
        });
        let channel = CableChannel {
            handle_connection,
            cbor_sender,
            cbor_receiver,
            ux_update_sender,
            connection_state_receiver,
            persistent_token_store: None,
            teardown: teardown.clone(),
            linger_eligible: true,
        };
        (channel, seen_rx, teardown)
    }

    #[tokio::test]
    async fn linger_requests_linger_on_an_eligible_channel() {
        let (mut channel, seen_rx, teardown) = channel_with_teardown_task();
        channel.close(CableClose::Linger).await;
        assert_eq!(seen_rx.await.unwrap(), Teardown::Linger);
        assert_eq!(*teardown.borrow(), Teardown::Linger);
    }

    #[tokio::test]
    async fn linger_degrades_to_close_on_an_ineligible_channel() {
        let (mut channel, seen_rx, teardown) = channel_with_teardown_task();
        channel.linger_eligible = false;
        channel.close(CableClose::Linger).await;
        assert_eq!(seen_rx.await.unwrap(), Teardown::Close);
        assert_eq!(*teardown.borrow(), Teardown::Close);
    }

    #[tokio::test]
    async fn drop_after_linger_does_not_cancel() {
        let (mut channel, seen_rx, teardown) = channel_with_teardown_task();
        channel.close(CableClose::Linger).await;
        drop(channel);
        assert_eq!(*teardown.borrow(), Teardown::Linger);
        assert_eq!(seen_rx.await.unwrap(), Teardown::Linger);
    }

    #[tokio::test]
    async fn close_requests_graceful_close_and_waits_for_termination() {
        let (mut channel, seen_rx, teardown) = channel_with_teardown_task();
        channel.close(CableClose::Immediate).await;
        assert_eq!(
            *channel.connection_state_receiver.borrow(),
            ConnectionState::Terminated
        );
        assert_eq!(seen_rx.await.unwrap(), Teardown::Close);
        assert_eq!(*teardown.borrow(), Teardown::Close);
        assert!(matches!(channel.status().await, ChannelStatus::Closed));
    }

    #[tokio::test]
    async fn cancel_requests_hard_cancel() {
        let (mut channel, seen_rx, teardown) = channel_with_teardown_task();
        channel.cancel().await;
        assert_eq!(seen_rx.await.unwrap(), Teardown::Cancel);
        assert_eq!(*teardown.borrow(), Teardown::Cancel);
    }

    #[tokio::test]
    async fn cancel_overrides_a_close_in_progress() {
        let (mut channel, _seen_rx, teardown) = channel_with_teardown_task();
        assert!(channel.request_teardown(Teardown::Close));
        channel.cancel().await;
        assert_eq!(*teardown.borrow(), Teardown::Cancel);
    }

    #[tokio::test]
    async fn unattended_drop_cancels_and_aborts() {
        let (channel, seen_rx, teardown) = channel_with_teardown_task();
        drop(channel);
        assert_eq!(*teardown.borrow(), Teardown::Cancel);
        // The task was aborted, so it never reported the intent it saw.
        assert!(seen_rx.await.is_err());
    }

    #[tokio::test]
    async fn drop_after_close_does_not_downgrade_the_intent() {
        let (mut channel, seen_rx, teardown) = channel_with_teardown_task();
        channel.close(CableClose::Immediate).await;
        drop(channel);
        assert_eq!(*teardown.borrow(), Teardown::Close);
        assert_eq!(seen_rx.await.unwrap(), Teardown::Close);
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_aborts_a_task_that_ignores_the_intent() {
        let (mut channel, _state_tx) = channel_in_state(ConnectionState::Connected);
        let started = time::Instant::now();
        channel.cancel().await;
        assert_eq!(started.elapsed(), CANCEL_TIMEOUT);
        let joined = (&mut channel.handle_connection).await;
        assert!(joined.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn close_escalates_to_cancel_after_the_flush_timeout() {
        let (mut channel, _state_tx) = channel_in_state(ConnectionState::Connected);
        let started = time::Instant::now();
        channel.close(CableClose::Immediate).await;
        assert_eq!(started.elapsed(), CLOSE_FLUSH_TIMEOUT + CANCEL_TIMEOUT);
        assert_eq!(*channel.teardown.borrow(), Teardown::Cancel);
        let joined = (&mut channel.handle_connection).await;
        assert!(joined.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn linger_gives_up_after_the_flush_timeout_without_aborting() {
        let (mut channel, _state_tx) = channel_in_state(ConnectionState::Connected);
        let started = time::Instant::now();
        channel.close(CableClose::Linger).await;
        assert_eq!(started.elapsed(), CLOSE_FLUSH_TIMEOUT);
        assert_eq!(*channel.teardown.borrow(), Teardown::Linger);
        assert!(!channel.handle_connection.is_finished());
    }

    /// A channel whose task publishes `Lingering` on the linger intent and
    /// then stays alive, like the real linger phase.
    fn channel_with_lingering_task() -> (CableChannel, task::AbortHandle) {
        let (ux_update_sender, _) = broadcast::channel(1);
        let (cbor_sender, _cbor_tx_recv) = mpsc::channel(1);
        let (_cbor_rx_send, cbor_receiver) = mpsc::channel(1);
        let (teardown, mut teardown_rx) = watch::channel(Teardown::Active);
        let (state_tx, connection_state_receiver) = watch::channel(ConnectionState::Connected);
        let handle_connection = task::spawn(async move {
            let intent = super::super::connection_stages::next_teardown(&mut teardown_rx).await;
            if intent == Teardown::Linger {
                let _ = state_tx.send(ConnectionState::Lingering);
                std::future::pending::<()>().await;
            }
            let _ = state_tx.send(ConnectionState::Terminated);
        });
        let abort = handle_connection.abort_handle();
        let channel = CableChannel {
            handle_connection,
            cbor_sender,
            cbor_receiver,
            ux_update_sender,
            connection_state_receiver,
            persistent_token_store: None,
            teardown: Arc::new(teardown),
            linger_eligible: true,
        };
        (channel, abort)
    }

    #[tokio::test(start_paused = true)]
    async fn linger_returns_once_lingering_and_survives_drop() {
        let (mut channel, abort) = channel_with_lingering_task();
        let started = time::Instant::now();
        channel.close(CableClose::Linger).await;
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert!(matches!(channel.status().await, ChannelStatus::Closed));

        drop(channel);
        task::yield_now().await;
        assert!(!abort.is_finished(), "the linger outlives the channel");
        abort.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn close_after_linger_does_not_cut_the_linger_short() {
        let (mut channel, abort) = channel_with_lingering_task();
        channel.close(CableClose::Linger).await;
        let started = time::Instant::now();
        channel.close(CableClose::Immediate).await;
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(*channel.teardown.borrow(), Teardown::Linger);
        assert!(!abort.is_finished());
        abort.abort();
    }

    #[tokio::test]
    async fn wait_for_connection_rejects_lingering() {
        let (channel, _state_tx) = channel_in_state(ConnectionState::Lingering);
        assert!(matches!(
            channel.wait_for_connection().await,
            Err(CableError::ConnectionLost)
        ));
    }

    #[tokio::test]
    async fn wait_for_connection_rejects_transition_to_lingering() {
        let (channel, state_tx) = channel_in_state(ConnectionState::Connecting);
        let waiter = tokio::spawn(async move { channel.wait_for_connection().await });
        state_tx.send(ConnectionState::Lingering).unwrap();
        assert!(matches!(
            waiter.await.unwrap(),
            Err(CableError::ConnectionLost)
        ));
    }

    #[tokio::test]
    async fn status_maps_lingering_to_closed() {
        let (channel, _state_tx) = channel_in_state(ConnectionState::Lingering);
        assert!(matches!(channel.status().await, ChannelStatus::Closed));
    }

    #[tokio::test]
    async fn status_maps_connected_to_ready() {
        let (channel, _state_tx) = channel_in_state(ConnectionState::Connected);
        assert!(matches!(channel.status().await, ChannelStatus::Ready));
    }
}
