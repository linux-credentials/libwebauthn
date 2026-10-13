//! End-to-end tests: the real service on a Unix socket, driven through the
//! client proxy, with libwebauthn's virtual authenticator in place of caBLE.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::BoxFuture;
use futures_util::{Stream, StreamExt};
use libwebauthn::ops::webauthn::{MakeCredentialRequest, MakeCredentialResponse, PublicSuffixList};
use libwebauthn::pin::PinManagement as _;
use libwebauthn::transport::cable::channel::{CableUpdate, CableUxUpdate};
use libwebauthn::transport::cable::error::CableError;
use libwebauthn::transport::hid::channel::HidChannel;
use libwebauthn::transport::{Channel as _, ChannelSettings, Device as _};
use libwebauthn::webauthn::WebAuthn as _;
use libwebauthn_tests::virt::get_virtual_device;
use libwebauthn_varlink_client::WebauthnProxy;
use libwebauthn_varlink_types::{
    Event, EventKind, VarlinkCredentialPrepareErrorKind, VarlinkError, VarlinkOperation,
    VarlinkRequestOrigin, VarlinkTransportErrorKind, VarlinkTransportMode,
};
use tokio::sync::{broadcast, oneshot};
use zlink::tokio::unix;
use zlink::Server;

use crate::provider::{CeremonyChannel, ChannelProvider, OpenedChannel, UpdateReceiver};
use crate::service::WebauthnService;

const TIMEOUT: Duration = Duration::from_secs(30);
const PIN: &str = "1234";
const QR_CONTENTS: &str = "FIDO:/virtual";
const INTERFACE: &str = "com.github.linux-credentials.webauthn";

const REQUEST_JSON: &str = r#"{
    "rp": { "id": "example.org", "name": "Example" },
    "user": {
        "id": "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg",
        "name": "mario.rossi",
        "displayName": "Mario Rossi"
    },
    "challenge": "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg",
    "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
    "timeout": 30000,
    "authenticatorSelection": {
        "residentKey": "discouraged",
        "userVerification": "preferred"
    },
    "attestation": "none"
}"#;

/// Knows only `org`, which is all the requests here need.
struct TestPublicSuffixList;

impl PublicSuffixList for TestPublicSuffixList {
    fn public_suffix(&self, host: &str) -> Option<String> {
        (host == "org" || host.ends_with(".org")).then(|| "org".to_string())
    }
}

/// A virtual authenticator channel. Its UV updates are forwarded into
/// `updates`, which tests also use to inject the caBLE connection progress a
/// virtual device never sends.
struct VirtualChannel {
    channel: HidChannel<'static>,
    updates: broadcast::Sender<CableUxUpdate>,
}

impl CeremonyChannel for VirtualChannel {
    fn updates(&self) -> Box<dyn UpdateReceiver> {
        Box::new(self.updates.subscribe())
    }

    fn make_credential<'a>(
        &'a mut self,
        request: &'a MakeCredentialRequest,
    ) -> BoxFuture<'a, Result<MakeCredentialResponse, VarlinkError>> {
        Box::pin(async move {
            self.channel
                .webauthn_make_credential(request)
                .await
                .map_err(|err| VarlinkError::CeremonyFailed {
                    message: err.to_string(),
                })
        })
    }
}

/// Opens a channel to a fresh virtual authenticator, with `pin` set on it.
#[derive(Default)]
struct VirtualProvider {
    pin: Option<&'static str>,
    opened: Mutex<Vec<broadcast::Sender<CableUxUpdate>>>,
}

impl VirtualProvider {
    fn with_pin(pin: &'static str) -> Self {
        Self {
            pin: Some(pin),
            ..Self::default()
        }
    }

    /// Sends `update` on the most recently opened channel, once the service
    /// listens to it: updates sent before that would be lost.
    async fn inject(&self, update: CableUpdate) {
        let updates = self.opened.lock().unwrap().last().cloned().unwrap();
        tokio::time::timeout(TIMEOUT, async {
            while updates.receiver_count() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the service never listened to the channel");
        updates.send(CableUxUpdate::CableUpdate(update)).unwrap();
    }
}

impl ChannelProvider for VirtualProvider {
    fn is_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(async { true })
    }

    fn open(
        &self,
        _operation: VarlinkOperation,
        _transport: VarlinkTransportMode,
    ) -> BoxFuture<'_, Result<OpenedChannel, VarlinkError>> {
        Box::pin(async move {
            // A channel borrows its device, and the service needs a channel
            // that lives on its own. Leaking one device per test is fine.
            let device = Box::leak(Box::new(get_virtual_device()));
            let mut channel = device.channel(ChannelSettings::default()).await.unwrap();
            if let Some(pin) = self.pin {
                channel.change_pin(pin.to_string(), TIMEOUT).await.unwrap();
            }

            let (updates, _) = broadcast::channel(16);
            let mut uv_updates = channel.get_ux_update_receiver();
            let forward = updates.clone();
            tokio::spawn(async move {
                while let Ok(update) = uv_updates.recv().await {
                    let _ = forward.send(update.into());
                }
            });
            self.opened.lock().unwrap().push(updates.clone());

            Ok(OpenedChannel {
                qr_contents: QR_CONTENTS.to_string(),
                channel: Box::new(VirtualChannel { channel, updates }),
            })
        })
    }
}

/// The service, served on a socket in a temporary directory.
struct Harness {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    provider: Arc<VirtualProvider>,
    pending_pin_count: Box<dyn Fn() -> usize + Send>,
    stop: Option<oneshot::Sender<()>>,
    server: Option<std::thread::JoinHandle<()>>,
}

impl Harness {
    fn start(provider: VirtualProvider) -> Self {
        Self::start_with_stale_entry_ttl(provider, Duration::from_secs(300))
    }

    /// zlink's server future is not `Send`, so it cannot be spawned as a task.
    /// Like the daemon, it runs on a thread of its own, in its own runtime.
    fn start_with_stale_entry_ttl(provider: VirtualProvider, ttl: Duration) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("webauthd-link.sock");
        let provider = Arc::new(provider);
        let (pending_tx, pending_rx) = std::sync::mpsc::channel();
        let (stop, stopped) = oneshot::channel();
        let server = std::thread::spawn({
            let socket = socket.clone();
            let provider = Arc::clone(&provider);
            move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let listener = unix::bind(&socket).unwrap();
                    let service = WebauthnService::with_stale_entry_ttl(
                        Arc::new(TestPublicSuffixList),
                        provider,
                        ttl,
                    );
                    pending_tx
                        .send(Box::new(service.pending_pin_counter())
                            as Box<dyn Fn() -> usize + Send>)
                        .unwrap();
                    tokio::select! {
                        _ = Server::new(listener, service).run() => {}
                        _ = stopped => {}
                    }
                });
            }
        });
        Self {
            _dir: dir,
            socket,
            provider,
            pending_pin_count: pending_rx.recv().unwrap(),
            stop: Some(stop),
            server: Some(server),
        }
    }

    async fn connect(&self) -> unix::Connection {
        unix::connect(&self.socket).await.unwrap()
    }

    /// Connects and opens a channel for `operation` on that connection.
    async fn connect_with_channel(&self, operation: VarlinkOperation) -> unix::Connection {
        let mut conn = self.connect().await;
        let reply = conn
            .future_device_connection(operation, VarlinkTransportMode::CloudOnly)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.qr_contents, QR_CONTENTS);
        conn
    }

    fn pending_pin_count(&self) -> usize {
        (self.pending_pin_count)()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        let _ = self.server.take().unwrap().join();
    }
}

fn origin(origin: &str) -> VarlinkRequestOrigin {
    VarlinkRequestOrigin {
        origin: origin.to_string(),
        top_origin: None,
    }
}

/// The next item of a streaming call, or `None` once the call has ended.
async fn next<S>(stream: &mut S) -> Option<Result<Event, VarlinkError>>
where
    S: Stream<Item = zlink::Result<Result<Event, VarlinkError>>> + Unpin,
{
    tokio::time::timeout(TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the service")
        .map(|item| item.unwrap())
}

/// Reads events until the ceremony completes, answering a PIN prompt with
/// `pin` over a second connection, and returns the event kinds seen on the
/// way plus the response JSON.
async fn run_to_completion<S>(
    harness: &Harness,
    stream: &mut S,
    pin: Option<&str>,
) -> (Vec<EventKind>, serde_json::Value)
where
    S: Stream<Item = zlink::Result<Result<Event, VarlinkError>>> + Unpin,
{
    let mut kinds = Vec::new();
    loop {
        let event = next(stream).await.expect("stream ended early").unwrap();
        kinds.push(event.kind);
        match event.kind {
            EventKind::PinRequired => {
                let token = event.pin_token.expect("PIN event without a token");
                let mut pin_conn = harness.connect().await;
                pin_conn
                    .provide_pin(token, pin.map(str::to_string))
                    .await
                    .unwrap()
                    .unwrap();
            }
            EventKind::Completed => {
                let json = event.response_json.expect("completed without a response");
                assert!(
                    next(stream).await.is_none(),
                    "stream continued after completing"
                );
                return (kinds, serde_json::from_str(&json).unwrap());
            }
            _ => {}
        }
    }
}

/// A rejected request must leave the channel open: completes a registration
/// on it.
async fn assert_channel_still_works(harness: &Harness, conn: &mut unix::Connection) {
    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    let (_, response) = run_to_completion(harness, &mut stream, None).await;
    assert_registration_response(&response);
}

fn assert_registration_response(response: &serde_json::Value) {
    assert_eq!(response["type"], "public-key");
    assert!(response["id"].as_str().is_some_and(|id| !id.is_empty()));
    assert!(response["response"]["attestationObject"].is_string());
}

#[tokio::test]
async fn is_available_comes_from_the_provider() {
    let harness = Harness::start(VirtualProvider::default());
    let mut conn = harness.connect().await;
    assert!(conn.is_available().await.unwrap().unwrap().available);
}

#[tokio::test]
async fn calls_without_a_channel_fail() {
    let harness = Harness::start(VirtualProvider::default());
    let mut conn = harness.connect().await;

    let mut stream = Box::pin(conn.await_connecting().await.unwrap());
    assert!(matches!(
        next(&mut stream).await,
        Some(Err(VarlinkError::NoActiveConnection))
    ));
    drop(stream);

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    assert!(matches!(
        next(&mut stream).await,
        Some(Err(VarlinkError::NoActiveConnection))
    ));
    drop(stream);

    // Closing is idempotent, so it succeeds without a channel too.
    conn.close_channel().await.unwrap().unwrap();
}

#[tokio::test]
async fn registration_without_pin_completes_and_consumes_the_channel() {
    let harness = Harness::start(VirtualProvider::default());
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::MakeCredential)
        .await;

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    // No assertion on `PresenceRequired`: the virtual device completes right
    // after asking for presence, often before the update is forwarded.
    let (_, response) = run_to_completion(&harness, &mut stream, None).await;
    drop(stream);
    assert_registration_response(&response);

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    assert!(matches!(
        next(&mut stream).await,
        Some(Err(VarlinkError::NoActiveConnection))
    ));
}

#[tokio::test]
async fn operation_mismatch_keeps_the_channel() {
    let harness = Harness::start(VirtualProvider::default());
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::GetAssertion)
        .await;

    // Refused twice: the first refusal must not consume the channel.
    for _ in 0..2 {
        let mut stream = Box::pin(
            conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
                .await
                .unwrap(),
        );
        assert!(matches!(
            next(&mut stream).await,
            Some(Err(VarlinkError::OperationMismatch {
                expected: VarlinkOperation::MakeCredential,
                actual: VarlinkOperation::GetAssertion,
            }))
        ));
    }

    conn.close_channel().await.unwrap().unwrap();
    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    assert!(matches!(
        next(&mut stream).await,
        Some(Err(VarlinkError::NoActiveConnection))
    ));
}

#[tokio::test]
async fn await_connecting_ends_once_connected_and_keeps_the_channel() {
    let harness = Harness::start(VirtualProvider::default());
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::MakeCredential)
        .await;

    let mut stream = Box::pin(conn.await_connecting().await.unwrap());
    harness.provider.inject(CableUpdate::Connecting).await;
    harness.provider.inject(CableUpdate::Connected).await;
    assert_eq!(
        next(&mut stream).await.unwrap().unwrap().kind,
        EventKind::Connecting
    );
    assert_eq!(
        next(&mut stream).await.unwrap().unwrap().kind,
        EventKind::Connected
    );
    assert!(next(&mut stream).await.is_none());
    drop(stream);

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    let (_, response) = run_to_completion(&harness, &mut stream, None).await;
    assert_registration_response(&response);
}

#[tokio::test]
async fn await_connecting_error_drops_the_channel() {
    let harness = Harness::start(VirtualProvider::default());
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::MakeCredential)
        .await;

    let mut stream = Box::pin(conn.await_connecting().await.unwrap());
    harness
        .provider
        .inject(CableUpdate::Error(CableError::ConnectionLost))
        .await;
    match next(&mut stream).await {
        Some(Err(VarlinkError::TransportError { error })) => {
            assert!(matches!(
                error.kind,
                VarlinkTransportErrorKind::ConnectionLost
            ));
        }
        other => panic!("expected a transport error, got {other:?}"),
    }
    drop(stream);

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    assert!(matches!(
        next(&mut stream).await,
        Some(Err(VarlinkError::NoActiveConnection))
    ));
}

#[tokio::test]
async fn malformed_origin_is_rejected() {
    let harness = Harness::start(VirtualProvider::default());
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::MakeCredential)
        .await;

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("not an origin"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    assert!(matches!(
        next(&mut stream).await,
        Some(Err(VarlinkError::InvalidRequest { .. }))
    ));
    drop(stream);
    assert_channel_still_works(&harness, &mut conn).await;
}

#[tokio::test]
async fn origin_must_match_the_relying_party() {
    let harness = Harness::start(VirtualProvider::default());
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::MakeCredential)
        .await;

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://attacker.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    match next(&mut stream).await {
        Some(Err(VarlinkError::MakeCredentialPrepareError { error })) => {
            assert!(matches!(
                error.kind,
                VarlinkCredentialPrepareErrorKind::MismatchingRelyingPartyId
            ));
        }
        other => panic!("expected a prepare error, got {other:?}"),
    }
    drop(stream);
    assert_channel_still_works(&harness, &mut conn).await;
}

#[tokio::test]
async fn malformed_request_is_rejected() {
    let harness = Harness::start(VirtualProvider::default());
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::MakeCredential)
        .await;

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), "{".into())
            .await
            .unwrap(),
    );
    match next(&mut stream).await {
        Some(Err(VarlinkError::MakeCredentialPrepareError { error })) => {
            assert!(matches!(
                error.kind,
                VarlinkCredentialPrepareErrorKind::EncodingError
            ));
        }
        other => panic!("expected a prepare error, got {other:?}"),
    }
    drop(stream);
    assert_channel_still_works(&harness, &mut conn).await;
}

#[tokio::test]
async fn registration_with_pin_is_answered_over_a_second_connection() {
    let harness = Harness::start(VirtualProvider::with_pin(PIN));
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::MakeCredential)
        .await;

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    let (kinds, response) = run_to_completion(&harness, &mut stream, Some(PIN)).await;
    assert!(kinds.contains(&EventKind::PinRequired), "{kinds:?}");
    assert_registration_response(&response);
    assert_eq!(harness.pending_pin_count(), 0);
}

#[tokio::test]
async fn unknown_pin_token_is_rejected() {
    let harness = Harness::start(VirtualProvider::default());
    let mut conn = harness.connect().await;
    assert!(matches!(
        conn.provide_pin("no-such-token".into(), Some(PIN.into()))
            .await
            .unwrap(),
        Err(VarlinkError::UnknownPinRequest)
    ));
}

#[tokio::test]
async fn pin_token_can_be_answered_only_once() {
    let harness = Harness::start(VirtualProvider::with_pin(PIN));
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::MakeCredential)
        .await;

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    let token = loop {
        let event = next(&mut stream).await.unwrap().unwrap();
        if event.kind == EventKind::PinRequired {
            break event.pin_token.unwrap();
        }
    };
    let mut pin_conn = harness.connect().await;
    pin_conn
        .provide_pin(token.clone(), Some(PIN.into()))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        pin_conn.provide_pin(token, Some(PIN.into())).await.unwrap(),
        Err(VarlinkError::UnknownPinRequest)
    ));
}

#[tokio::test]
async fn cancelling_the_pin_fails_the_ceremony() {
    let harness = Harness::start(VirtualProvider::with_pin(PIN));
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::MakeCredential)
        .await;

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    let token = loop {
        let event = next(&mut stream).await.unwrap().unwrap();
        if event.kind == EventKind::PinRequired {
            break event.pin_token.unwrap();
        }
    };
    let mut pin_conn = harness.connect().await;
    pin_conn.provide_pin(token, None).await.unwrap().unwrap();

    loop {
        match next(&mut stream).await {
            Some(Ok(event)) => assert_ne!(event.kind, EventKind::Completed),
            Some(Err(_)) => break,
            None => panic!("stream ended without an error"),
        }
    }
    assert!(next(&mut stream).await.is_none());
}

/// zlink only notices a disconnected client once sending to it fails, and a
/// ceremony waiting on a PIN sends nothing. The reaper cancels the abandoned
/// PIN request, which ends the ceremony.
#[tokio::test]
async fn abandoned_pin_request_is_reaped() {
    let harness = Harness::start_with_stale_entry_ttl(
        VirtualProvider::with_pin(PIN),
        Duration::from_millis(500),
    );
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::MakeCredential)
        .await;

    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    loop {
        let event = next(&mut stream).await.unwrap().unwrap();
        if event.kind == EventKind::PinRequired {
            break;
        }
    }
    assert_eq!(harness.pending_pin_count(), 1);

    drop(stream);
    drop(conn);
    tokio::time::timeout(TIMEOUT, async {
        while harness.pending_pin_count() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the abandoned PIN request was never reaped");
}

#[tokio::test]
async fn unclaimed_channel_is_reaped() {
    let harness =
        Harness::start_with_stale_entry_ttl(VirtualProvider::default(), Duration::from_millis(500));
    let mut conn = harness
        .connect_with_channel(VarlinkOperation::MakeCredential)
        .await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut stream = Box::pin(
        conn.webauthn_make_credential(origin("https://example.org"), REQUEST_JSON.into())
            .await
            .unwrap(),
    );
    assert!(matches!(
        next(&mut stream).await,
        Some(Err(VarlinkError::NoActiveConnection))
    ));
}

/// The interface the service publishes must match the committed description,
/// so that interface changes show up in review. CI also checks the committed
/// file with `varlinkctl validate-idl`.
#[tokio::test]
async fn interface_description_matches_the_committed_file() {
    let harness = Harness::start(VirtualProvider::default());
    let socket = harness.socket.clone();
    let published = tokio::task::spawn_blocking(move || get_interface_description(&socket))
        .await
        .unwrap();
    let published = format!("{}\n", published.trim_end());

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("{INTERFACE}.varlink"));
    if std::env::var_os("UPDATE_VARLINK_INTERFACE").is_some() {
        std::fs::write(&path, &published).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == published,
        "{} does not match the published interface. If the change is intended, \
         update it with `UPDATE_VARLINK_INTERFACE=1 cargo test -p libwebauthn-varlink-server`.",
        path.display()
    );
}

/// Asks the service for its interface description with a plain varlink call,
/// so the text is exactly what any client receives.
fn get_interface_description(socket: &Path) -> String {
    use std::io::{Read, Write};

    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    let call = serde_json::json!({
        "method": "org.varlink.service.GetInterfaceDescription",
        "parameters": { "interface": INTERFACE },
    });
    let mut message = serde_json::to_vec(&call).unwrap();
    message.push(0);
    stream.write_all(&message).unwrap();

    let mut reply = Vec::new();
    let mut byte = [0];
    loop {
        stream.read_exact(&mut byte).unwrap();
        if byte[0] == 0 {
            break;
        }
        reply.push(byte[0]);
    }
    let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    reply["parameters"]["description"]
        .as_str()
        .expect("no interface description in the reply")
        .to_string()
}
