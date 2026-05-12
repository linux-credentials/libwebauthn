//! Shared helpers used by the example programs.
//!
//! Imported from each example via `#[path = "../common/mod.rs"] mod common;`.
//! Cargo does not auto-discover this module as an example because the
//! directory has no `main.rs`.

#![allow(dead_code)]

use std::io::{self, Write};

use libwebauthn::pin::{PinNotSetReason, PinRequestReason};
use libwebauthn::transport::cable::channel::{CableUpdate, CableUxUpdate};
use libwebauthn::UvUpdate;
use text_io::read;
use tokio::sync::broadcast::Receiver;
use tracing_subscriber::{self, EnvFilter};

pub fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

/// Forwards UV updates to the user, prompting for PIN entry or PIN setup as
/// needed. Spawn this on a Tokio task with the channel's UX update receiver.
pub async fn handle_uv_updates(mut rx: Receiver<UvUpdate>) {
    while let Ok(update) = rx.recv().await {
        handle_uv_update(update);
    }
}

/// Like [`handle_uv_updates`], but for caBLE channels which surface both
/// transport-level updates and UV updates.
pub async fn handle_cable_updates(mut rx: Receiver<CableUxUpdate>) {
    while let Ok(update) = rx.recv().await {
        match update {
            CableUxUpdate::UvUpdate(uv) => handle_uv_update(uv),
            CableUxUpdate::CableUpdate(c) => match c {
                CableUpdate::ProximityCheck => println!("Proximity check in progress..."),
                CableUpdate::Connecting => println!("Connecting to the device..."),
                CableUpdate::Authenticating => println!("Authenticating with the device..."),
                CableUpdate::Connected => println!("Tunnel established successfully!"),
                CableUpdate::Error(err) => println!("Error during connection: {}", err),
            },
        }
    }
}

fn handle_uv_update(update: UvUpdate) {
    match update {
        UvUpdate::PresenceRequired => println!("Please touch your device!"),
        UvUpdate::PinNotSet(update) => {
            match update.reason {
                PinNotSetReason::PinNotSet => println!(
                    "RP required a PIN, but your device has none set. Please set one now \
                     (this will require a PIN on your device from now on if you continue; \
                     leave the entry empty to cancel)."
                ),
                PinNotSetReason::PinTooShort => println!("The provided PIN was too short."),
                PinNotSetReason::PinTooLong => println!("The provided PIN was too long."),
                PinNotSetReason::PinPolicyViolation => {
                    println!("The provided PIN violated the device's PIN policy.")
                }
            }
            print!("PIN: Please set a new PIN for your device: ");
            io::stdout().flush().unwrap();
            let pin: String = read!("{}\n");

            if pin.is_empty() {
                println!("PIN: No PIN provided, cancelling operation.");
                update.cancel();
            } else {
                let _ = update.set_pin(&pin);
            }
        }
        UvUpdate::UvRetry { attempts_left } => {
            print!("UV failed.");
            if let Some(attempts_left) = attempts_left {
                print!(" You have {attempts_left} attempts left.");
            }
            println!();
        }
        UvUpdate::PinRequired(update) => {
            let attempts_str = match update.attempts_left {
                Some(attempts) => format!(". You have {attempts} attempts left!"),
                None => String::new(),
            };

            match update.reason {
                PinRequestReason::RelyingPartyRequest => println!("RP required a PIN."),
                PinRequestReason::AuthenticatorPolicy => println!("Your device requires a PIN."),
                PinRequestReason::FallbackFromUV => {
                    println!("UV failed too often and is blocked. Falling back to PIN.")
                }
            }
            print!("PIN: Please enter the PIN for your authenticator{attempts_str}: ");
            io::stdout().flush().unwrap();
            let pin: String = read!("{}\n");

            if pin.is_empty() {
                println!("PIN: No PIN provided, cancelling operation.");
                update.cancel();
            } else {
                let _ = update.send_pin(&pin);
            }
        }
    }
}

/// Retries a `WebAuthn` call when the authenticator returns a retryable user
/// error (e.g. PIN auth invalid, user action timeout, no credentials yet).
///
/// Each iteration re-evaluates the expression, so it should be a method call
/// such as `channel.webauthn_make_credential(&request)` that can be issued
/// repeatedly.
#[macro_export]
macro_rules! retry_user_errors {
    ($call:expr) => {
        loop {
            match $call.await {
                Ok(response) => break Ok(response),
                Err(libwebauthn::webauthn::Error::Ctap(ctap_error)) => {
                    if ctap_error.is_retryable_user_error() {
                        println!("Oops, try again! Error: {}", ctap_error);
                        continue;
                    }
                    break Err(libwebauthn::webauthn::Error::Ctap(ctap_error));
                }
                Err(err) => break Err(err),
            }
        }
    };
}

/// Prompts the user with a yes/no question, defaulting to "no". Returns true
/// if the user answers "y" or "Y".
pub fn prompt_yes_no(question: &str) -> bool {
    print!("{question} [y/N]: ");
    io::stdout().flush().expect("Failed to flush stdout!");
    let input: String = read!("{}\n");
    matches!(input.trim(), "y" | "Y")
}

/// Prompts the user to pick one of `num_of_items` items by index. Re-asks on
/// invalid input.
pub fn prompt_index(num_of_items: usize) -> usize {
    loop {
        print!("Your choice: ");
        io::stdout().flush().expect("Failed to flush stdout!");
        let input: String = read!("{}\n");
        if let Ok(idx) = input.trim().parse::<usize>() {
            if idx < num_of_items {
                println!();
                return idx;
            }
        }
    }
}
