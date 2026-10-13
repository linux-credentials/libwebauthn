//! Shared helpers for the varlink client example programs.
//!
//! Imported from each example via `#[path = "common/mod.rs"] mod common;`.
//! Cargo does not auto-discover this module as an example because the
//! directory has no `main.rs`.

#![allow(dead_code)]

use std::error::Error;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::Duration;

use futures_util::{Stream, StreamExt};
use libwebauthn_varlink_client::WebauthnProxy;
use libwebauthn_varlink_types::{Event, EventKind, VarlinkError};
use qrcode::render::unicode;
use qrcode::QrCode;
use text_io::read;
use tokio::net::UnixStream;
use tokio::time::sleep;
use tracing_subscriber::EnvFilter;
use zlink::tokio::unix;

pub fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

/// Drives one of the streaming ceremony calls (`await_connecting` or
/// `webauthn_make_credential`) to its final event, printing progress along
/// the way. Returns the final (`connected`/`completed`) event on success, or
/// bubbles up a connection error or a `VarlinkError` method error as an
/// `Err` — the caller should propagate this with `?` rather than continue,
/// since e.g. the channel is no longer usable once the call has failed.
///
/// If a `pin_required`/`pin_not_set` event arrives, prompts for a PIN on
/// stdin and answers it via `provide_pin` over a *fresh* connection to
/// `socket_path` (the original connection is busy streaming this call's
/// replies and can't accept another call in the meantime).
pub async fn stream_ceremony(
    socket_path: &Path,
    mut stream: impl Stream<Item = zlink::Result<Result<Event, VarlinkError>>> + Unpin,
) -> Result<Event, Box<dyn Error>> {
    while let Some(item) = stream.next().await {
        let event = match item? {
            Ok(event) => event,
            Err(err) => return Err(format!("{err}").into()),
        };
        match event.kind {
            EventKind::ProximityCheck => println!("Proximity check in progress..."),
            EventKind::Connecting => println!("Connecting to the device..."),
            EventKind::Authenticating => println!("Authenticating with the device..."),
            EventKind::Connected => {
                println!("Tunnel established successfully!");
                return Ok(event);
            }
            EventKind::PresenceRequired => println!("Please touch your device!"),
            EventKind::Retry => {
                print!("UV failed.");
                if let Some(left) = event.retry.as_ref().and_then(|r| r.attempts_left) {
                    print!(" You have {left} attempts left.");
                }
                println!();
            }
            EventKind::PinRequired | EventKind::PinNotSet => {
                let token = event
                    .pin_token
                    .clone()
                    .ok_or("pin event missing pin_token")?;
                let pin = if event.kind == EventKind::PinNotSet {
                    prompt_pin("Set a new PIN: ")
                } else {
                    prompt_pin("PIN: ")
                };
                let mut pin_conn = unix::connect(socket_path).await?;
                let answer = if pin.is_empty() { None } else { Some(pin) };
                if let Err(err) = pin_conn.provide_pin(token, answer).await? {
                    return Err(format!("provide_pin failed: {err}").into());
                }
            }
            EventKind::Completed => return Ok(event),
        }
    }
    Err("stream ended without a final event".into())
}

/// A handle to a `webauthd-link` instance spawned by [`spawn_private_server`].
/// Killing the process and removing its socket file happen automatically on drop.
pub struct ServerHandle {
    child: Child,
    socket_path: PathBuf,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Spawns a fresh `webauthd-link` instance on a private, per-run Unix
/// socket (so examples don't collide with each other or with a real,
/// already-running system instance), waiting until it accepts connections.
/// The server is killed and its socket removed when the returned handle is
/// dropped. Returns the handle together with the socket path to connect to.
///
/// Launched via `cargo run --bin webauthd-link`, rather than locating the
/// previously-built binary directly, so the server is always rebuilt first:
/// running just `cargo run --example ...` alone doesn't rebuild other bin
/// targets, which previously let a stale server binary linger and answer
/// with the wrong (pre-rename) method names.
pub async fn spawn_private_server() -> Result<(ServerHandle, PathBuf), Box<dyn Error>> {
    let socket_path =
        std::env::temp_dir().join(format!("webauthd-link-example-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket_path);

    let child = std::process::Command::new(env!("CARGO"))
        .args(["run", "--quiet", "--bin", "webauthd-link", "--"])
        .arg(&socket_path)
        .spawn()?;

    for _ in 0..600 {
        if UnixStream::connect(&socket_path).await.is_ok() {
            return Ok((
                ServerHandle {
                    child,
                    socket_path: socket_path.clone(),
                },
                socket_path,
            ));
        }
        sleep(Duration::from_millis(50)).await;
    }

    Err("timed out waiting for webauthd-link to start".into())
}

pub fn print_qr_code(contents: &str) {
    let qr_code = QrCode::new(contents).unwrap();
    let image = qr_code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{image}");
}

fn prompt_pin(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().unwrap();
    read!("{}\n")
}
