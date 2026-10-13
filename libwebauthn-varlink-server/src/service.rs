use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::Stream;
use libwebauthn_varlink_types::{
    new_completed_event, new_pin_not_set_event, new_pin_required_event, Event, EventKind,
    VarlinkAvailabilityReply, VarlinkCeremonyError, VarlinkCeremonyErrorKind,
    VarlinkCredentialPrepareError, VarlinkCredentialPrepareErrorKind, VarlinkError,
    VarlinkOperation, VarlinkPinNotSet, VarlinkPinNotSetReason, VarlinkPinRequestReason,
    VarlinkPinRequired, VarlinkQrCodeReply, VarlinkRequestOrigin, VarlinkRetry,
    VarlinkTransportError, VarlinkTransportErrorKind, VarlinkTransportMode,
};
use tokio::sync::broadcast::error::RecvError;
use zlink::Reply;

use libwebauthn::ops::webauthn::{
    JsonFormat, MakeCredentialRequest, OriginValidation, PublicSuffixList, RelatedOrigins,
    RequestSettings, WebAuthnIDLResponse as _,
};
use libwebauthn::transport::cable::channel::CableUxUpdate;
use libwebauthn::{PinNotSetUpdate, PinRequiredUpdate, UvUpdate};

use crate::provider::{CeremonyChannel, ChannelProvider};

/// A boxed, owned stream: required because zlink's generated streaming
/// methods must not borrow `&self`, and because the different code paths
/// (an immediate "unknown channel" error vs. the real `async_stream`
/// generator) produce different concrete `Stream` types that need unifying
/// behind a single `dyn Stream`.
type EventStream = Pin<Box<dyn Stream<Item = Result<Reply<Event>, VarlinkError>> + Send>>;

/// How long a `channels`/`pending_pins` entry may sit unclaimed before the
/// background reaper (see [`spawn_stale_entry_reaper`]) purges it.
///
/// zlink 0.7 gives services no way to observe a client disconnecting (no
/// `Drop` on `Connection`, no lifecycle hook on the `Service` trait), so an
/// abandoned `future_device_connection`/`webauthn_make_credential` call (the
/// client crashes, or simply never calls `close_channel`/`provide_pin`)
/// would otherwise leak its entry forever. A periodic TTL sweep bounds that
/// leak instead of eliminating it outright.
const STALE_ENTRY_TTL: Duration = Duration::from_secs(300);

/// Channels keyed by the id of the connection that opened them, with their
/// insertion time for the stale entry reaper and the operation their QR code
/// was generated for.
type Channels = Arc<Mutex<HashMap<usize, (Instant, VarlinkOperation, Box<dyn CeremonyChannel>)>>>;

/// Pending PIN requests keyed by token, with their insertion time and the id
/// of the connection whose ceremony raised them.
type PendingPins = Arc<Mutex<HashMap<String, (Instant, usize, PendingPin)>>>;

/// A PIN/UV update awaiting an interactive reply via `provide_pin`, parked
/// under a fresh token generated when the update is surfaced to the client
/// as a `pin_required`/`pin_not_set` event. Each variant's inner update
/// object must be resolved (`send_pin`/`set_pin`/`cancel`) exactly once.
enum PendingPin {
    Required(PinRequiredUpdate),
    NotSet(PinNotSetUpdate),
}

/// RAII guard held by a `webauthn_make_credential` stream: as soon as that
/// stream ends (ceremony resolved, request failed to prepare) *or* is
/// dropped early, this purges any `pending_pins` entries still owned by
/// `conn_id` - they can never be answered (the ceremony that would consume
/// the reply is gone).
///
/// zlink does not read a connection while one of its streaming calls runs,
/// so it only drops the stream of a disconnected client once sending the
/// next reply fails. A ceremony waiting on a PIN sends nothing, so in that
/// case the TTL reaper is what eventually cancels the PIN request, which
/// fails the ceremony and lets the stream end.
struct PendingPinsCleanupGuard {
    pending_pins: PendingPins,
    conn_id: usize,
}

impl Drop for PendingPinsCleanupGuard {
    fn drop(&mut self) {
        self.pending_pins
            .lock()
            .unwrap()
            .retain(|_, (_, owner, _)| *owner != self.conn_id);
    }
}

/// The `com.github.linux-credentials.webauthn` service.
///
/// Channels come from a [`ChannelProvider`], which is caBLE in the daemon.
///
/// Each channel is bound to the client connection that created it via
/// `future_device_connection` (keyed by [`zlink::Connection::id`]), rather than by
/// an id handed back to and re-supplied by the client: a Varlink connection
/// is inherently a single client session, so there is never more than one
/// in-flight channel per connection.
pub struct WebauthnService {
    psl: Arc<dyn PublicSuffixList>,
    provider: Arc<dyn ChannelProvider>,
    channels: Channels,
    pending_pins: PendingPins,
}

impl WebauthnService {
    pub fn new(psl: Arc<dyn PublicSuffixList>, provider: Arc<dyn ChannelProvider>) -> Self {
        Self::with_stale_entry_ttl(psl, provider, STALE_ENTRY_TTL)
    }

    /// Like [`WebauthnService::new`], but purges unclaimed entries after
    /// `ttl` instead of [`STALE_ENTRY_TTL`].
    pub fn with_stale_entry_ttl(
        psl: Arc<dyn PublicSuffixList>,
        provider: Arc<dyn ChannelProvider>,
        ttl: Duration,
    ) -> Self {
        let channels = Arc::new(Mutex::new(HashMap::new()));
        let pending_pins = Arc::new(Mutex::new(HashMap::new()));
        spawn_stale_entry_reaper(Arc::clone(&channels), Arc::clone(&pending_pins), ttl);
        Self {
            psl,
            provider,
            channels,
            pending_pins,
        }
    }

    /// Lets tests count the PIN requests waiting for `provide_pin`. Over the
    /// interface they can only be observed by answering them.
    #[cfg(test)]
    pub(crate) fn pending_pin_counter(&self) -> impl Fn() -> usize + Send + 'static {
        let pending_pins = Arc::clone(&self.pending_pins);
        move || pending_pins.lock().unwrap().len()
    }
}

fn err_stream(err: VarlinkError) -> EventStream {
    Box::pin(futures_util::stream::once(async move { Err(err) }))
}

/// Spawns a background task that periodically purges `channels`/
/// `pending_pins` entries older than `ttl` (see [`STALE_ENTRY_TTL`] and its doc
/// comment for why this is necessary). Runs for the lifetime of the
/// process; `WebauthnService` is never dropped before the server exits.
fn spawn_stale_entry_reaper(channels: Channels, pending_pins: PendingPins, ttl: Duration) {
    tokio::spawn(async move {
        // Sweep often enough that an entry outlives `ttl` by at most a tenth.
        let mut interval = tokio::time::interval(ttl / 10);
        loop {
            interval.tick().await;
            let now = Instant::now();
            channels.lock().unwrap().retain(|id, (inserted, _, _)| {
                let stale = now.duration_since(*inserted) >= ttl;
                if stale {
                    tracing::debug!(conn_id = id, "reaping stale channel");
                }
                !stale
            });
            pending_pins
                .lock()
                .unwrap()
                .retain(|token, (inserted, _, _)| {
                    let stale = now.duration_since(*inserted) >= ttl;
                    if stale {
                        tracing::debug!(token, "reaping stale pending PIN request");
                    }
                    !stale
                });
        }
    });
}

// Named types keep the interface description readable: without them, every
// type is spelled out inline wherever it is used.
#[zlink::service(types = [
    EventKind,
    VarlinkCeremonyError,
    VarlinkCeremonyErrorKind,
    VarlinkCredentialPrepareError,
    VarlinkCredentialPrepareErrorKind,
    VarlinkOperation,
    VarlinkPinNotSet,
    VarlinkPinNotSetReason,
    VarlinkPinRequestReason,
    VarlinkPinRequired,
    VarlinkRequestOrigin,
    VarlinkRetry,
    VarlinkTransportError,
    VarlinkTransportErrorKind,
    VarlinkTransportMode,
])]
impl<Sock> WebauthnService {
    /// Whether hybrid transport can be used on this system, that is whether a
    /// Bluetooth adapter is present.
    #[zlink(interface = "com.github.linux-credentials.webauthn")]
    #[tracing::instrument(level = "debug", skip_all)]
    async fn is_available(&self) -> VarlinkAvailabilityReply {
        VarlinkAvailabilityReply {
            available: self.provider.is_available().await,
        }
    }

    /// Opens a channel for an `operation` ceremony and returns the QR code to
    /// show the user. The channel belongs to this connection: an earlier one
    /// is replaced, and the other methods act on it.
    #[zlink(interface = "com.github.linux-credentials.webauthn")]
    #[tracing::instrument(level = "debug", skip_all, err(level = "debug", Debug), fields(conn_id = conn.id(), ?operation, ?transport))]
    async fn future_device_connection(
        &self,
        #[zlink(connection)] conn: &mut Connection<Sock>,
        operation: VarlinkOperation,
        transport: VarlinkTransportMode,
    ) -> Result<VarlinkQrCodeReply, VarlinkError> {
        let opened = self.provider.open(operation, transport).await?;
        self.channels
            .lock()
            .unwrap()
            .insert(conn.id(), (Instant::now(), operation, opened.channel));
        Ok(VarlinkQrCodeReply {
            qr_contents: opened.qr_contents,
        })
    }

    /// Streams progress events until the channel is connected, ending with a
    /// `Connected` event. On an error, the channel is closed.
    #[zlink(interface = "com.github.linux-credentials.webauthn", more)]
    #[tracing::instrument(level = "debug", skip_all, fields(conn_id = conn.id()))]
    async fn await_connecting(
        &self,
        more: bool,
        #[zlink(connection)] conn: &mut Connection<Sock>,
    ) -> impl Stream<Item = Result<Reply<Event>, VarlinkError>> {
        let _ = more;
        let id = conn.id();
        let mut rx = {
            let channels = self.channels.lock().unwrap();
            match channels.get(&id) {
                Some((_, _, channel)) => channel.updates(),
                None => {
                    return err_stream(VarlinkError::NoActiveConnection);
                }
            }
        };
        let channels = Arc::clone(&self.channels);

        Box::pin(async_stream::stream! {
            loop {
                let update = match rx.recv().await {
                    Ok(update) => update,
                    Err(_) => {
                        channels.lock().unwrap().remove(&id);
                        yield Err(VarlinkError::PrematureConnectionClose);
                        return;
                    }
                };
                let ev: Event = match update.try_into() {
                    Ok(ev) => ev,
                    Err(err) => {
                        channels.lock().unwrap().remove(&id);
                        yield Err(err);
                        return;
                    }
                };
                let is_terminal = ev.kind == EventKind::Connected;
                yield Ok(Reply::new(Some(ev)).set_continues(Some(!is_terminal)));
                if is_terminal {
                    return;
                }
            }
        })
    }

    /// Runs a registration ceremony on this connection's channel, streaming
    /// progress events and ending with a `Completed` event that carries the
    /// response. `request_json` is a WebAuthn IDL `PublicKeyCredentialCreationOptions`,
    /// checked against `origin`. The channel is used up, unless the request is
    /// invalid.
    #[zlink(interface = "com.github.linux-credentials.webauthn", more)]
    #[tracing::instrument(level = "debug", skip_all, fields(conn_id = conn.id(), origin = %origin.origin))]
    async fn webauthn_make_credential(
        &self,
        more: bool,
        #[zlink(connection)] conn: &mut Connection<Sock>,
        origin: VarlinkRequestOrigin,
        request_json: String,
    ) -> impl Stream<Item = Result<Reply<Event>, VarlinkError>> {
        let _ = more;
        let conn_id = conn.id();
        // Check for the channel first, but only take it once the request is
        // valid: a malformed request must not use up the channel, and with it
        // the QR code the user may already have scanned.
        match self.channels.lock().unwrap().get(&conn_id) {
            Some((_, VarlinkOperation::MakeCredential, _)) => {}
            Some((_, actual, _)) => {
                return err_stream(VarlinkError::OperationMismatch {
                    expected: VarlinkOperation::MakeCredential,
                    actual: *actual,
                });
            }
            None => return err_stream(VarlinkError::NoActiveConnection),
        }
        let origin = match libwebauthn::ops::webauthn::RequestOrigin::try_from(origin) {
            Ok(origin) => origin,
            Err(err) => {
                return err_stream(VarlinkError::InvalidRequest {
                    message: format!("invalid origin: {err}"),
                });
            }
        };
        let settings = RequestSettings {
            origin: OriginValidation::Validate {
                public_suffix_list: &*self.psl,
                related_origins: RelatedOrigins::Disabled,
            },
        };
        let request = match MakeCredentialRequest::prepare(&origin, &request_json, &settings).await
        {
            Ok(request) => request,
            Err(err) => return err_stream(err.into()),
        };
        // The reaper may have removed the channel in the meantime.
        let Some((_, _, mut channel)) = self.channels.lock().unwrap().remove(&conn_id) else {
            return err_stream(VarlinkError::NoActiveConnection);
        };
        let pending_pins = Arc::clone(&self.pending_pins);

        Box::pin(async_stream::stream! {
            let _pending_pins_cleanup = PendingPinsCleanupGuard {
                pending_pins: Arc::clone(&pending_pins),
                conn_id,
            };

            let mut rx = channel.updates();
            let mut ceremony = channel.make_credential(&request);
            // Once the update sender is gone, `recv()` returns `Closed`
            // immediately, so stop polling it and just await the ceremony.
            let mut updates_open = true;
            loop {
                // Biased towards updates, so the ones already queued reach the
                // client before the completion does.
                tokio::select! {
                    biased;
                    update = rx.recv(), if updates_open => {
                        match update {
                            Ok(update) => match update_to_event(&pending_pins, conn_id, update) {
                                Ok(event) => {
                                    yield Ok(Reply::new(Some(event)).set_continues(Some(true)));
                                }
                                Err(err) => {
                                    yield Err(err);
                                    break;
                                }
                            },
                            Err(RecvError::Lagged(skipped)) => {
                                tracing::warn!(skipped, "dropped UX updates");
                            }
                            Err(RecvError::Closed) => updates_open = false,
                        }
                    }
                    result = &mut ceremony => {
                        match result {
                            Ok(response) => {
                                match response.to_json_string(&request, JsonFormat::Prettified) {
                                    Ok(json) => {
                                        yield Ok(Reply::new(Some(new_completed_event(json)))
                                            .set_continues(Some(false)));
                                    }
                                    Err(err) => {
                                        yield Err(VarlinkError::from(err));
                                    }
                                }
                            }
                            Err(err) => {
                                yield Err(err);
                            }
                        }
                        break;
                    }
                }
            }
        })
    }

    /// Closes this connection's channel, if it has one.
    #[zlink(interface = "com.github.linux-credentials.webauthn")]
    #[tracing::instrument(level = "debug", skip_all, fields(conn_id = conn.id()))]
    async fn close_channel(&self, #[zlink(connection)] conn: &mut Connection<Sock>) {
        self.channels.lock().unwrap().remove(&conn.id());
    }

    /// Answers a `PinRequired` or `PinNotSet` event, identified by its
    /// `pin_token`. A null `pin` cancels the ceremony. Call this on a second
    /// connection: the one running the ceremony is busy streaming it.
    #[zlink(interface = "com.github.linux-credentials.webauthn")]
    // `skip_all`: the PIN and the token are secrets and must never be logged.
    #[tracing::instrument(level = "debug", skip_all, err(level = "debug", Debug))]
    async fn provide_pin(&self, token: String, pin: Option<String>) -> Result<(), VarlinkError> {
        let (_, _, pending) = self
            .pending_pins
            .lock()
            .unwrap()
            .remove(&token)
            .ok_or(VarlinkError::UnknownPinRequest)?;
        let result = match (pending, pin) {
            (PendingPin::Required(update), Some(pin)) => update.send_pin(&pin),
            (PendingPin::Required(update), None) => {
                update.cancel();
                Ok(())
            }
            (PendingPin::NotSet(update), Some(pin)) => update.set_pin(&pin),
            (PendingPin::NotSet(update), None) => {
                update.cancel();
                Ok(())
            }
        };
        result.map_err(|message| VarlinkError::InvalidRequest { message })
    }
}

/// Converts a raw caBLE UX update into the `Event` streamed to the client
/// during a ceremony. `PinRequired`/`PinNotSet` updates are parked in
/// `pending_pins` under a freshly generated token (see `Event::pin_token`),
/// tagged with the owning connection's id (see [`PendingPinsCleanupGuard`]),
/// so that `provide_pin` can resolve them later from a separate connection.
fn update_to_event(
    pending_pins: &PendingPins,
    conn_id: usize,
    update: CableUxUpdate,
) -> Result<Event, VarlinkError> {
    match update {
        CableUxUpdate::UvUpdate(UvUpdate::PinRequired(pin_update)) => {
            let token = uuid::Uuid::new_v4().to_string();
            let mut event = new_pin_required_event(pin_update.clone());
            event.pin_token = Some(token.clone());
            pending_pins.lock().unwrap().insert(
                token,
                (Instant::now(), conn_id, PendingPin::Required(pin_update)),
            );
            Ok(event)
        }
        CableUxUpdate::UvUpdate(UvUpdate::PinNotSet(pin_update)) => {
            let token = uuid::Uuid::new_v4().to_string();
            let mut event = new_pin_not_set_event(pin_update.clone());
            event.pin_token = Some(token.clone());
            pending_pins.lock().unwrap().insert(
                token,
                (Instant::now(), conn_id, PendingPin::NotSet(pin_update)),
            );
            Ok(event)
        }
        other => other.try_into(),
    }
}
