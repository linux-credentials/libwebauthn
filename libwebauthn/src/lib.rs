// Deny panic-inducing patterns in production code.
// Tests and the virt test-utility feature are allowed to use unwrap/expect/panic for convenience.
#![cfg_attr(not(any(test, feature = "virt")), deny(clippy::unwrap_used))]
#![cfg_attr(not(any(test, feature = "virt")), deny(clippy::expect_used))]
#![cfg_attr(not(any(test, feature = "virt")), deny(clippy::panic))]
#![cfg_attr(not(any(test, feature = "virt")), deny(clippy::todo))]
#![cfg_attr(not(any(test, feature = "virt")), deny(clippy::unreachable))]

#[cfg(all(feature = "nfc", not(any(feature = "pcsc", feature = "libnfc"))))]
compile_error!(
    "the `nfc` feature is an umbrella that requires at least one backend; enable `pcsc` and/or `libnfc`"
);

pub mod fido;
pub mod management;
pub mod ops;
pub mod pin;
pub mod proto;
pub mod transport;
pub mod u2f;
pub mod webauthn;

use std::sync::Arc;

use tokio::sync::oneshot;

#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate bitflags;

macro_rules! unwrap_field {
    ($field:expr) => {{
        if let Some(f) = $field {
            f
        } else {
            tracing::error!(
                "Device response did not contain expected field: {}",
                stringify!($field)
            );
            return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
        }
    }};
}
use pin::{PinNotSetReason, PinRequestReason};
pub(crate) use unwrap_field;

#[derive(Debug)]
pub enum Transport {
    Usb,
    Ble,
}

#[derive(Debug, Clone)]
#[cfg_attr(any(test, feature = "virt"), derive(PartialEq))]
pub enum UvUpdate {
    /// UV failed, but we can still retry. `attempts_left` optionally shows how many tries _in total_ are left.
    /// Builtin UV may still temporarily be blocked.
    UvRetry {
        attempts_left: Option<u32>,
    },
    /// The device requires a PIN. Use `send_pin()` method to answer the request.
    /// The ongoing operation may run into a timeout, no answer is provided in time.
    PinRequired(PinRequiredUpdate),
    PresenceRequired,
    PinNotSet(PinNotSetUpdate),
}

#[derive(Debug, Clone)]
pub struct PinRequiredUpdate {
    reply_to: Arc<oneshot::Sender<String>>,
    /// What caused the PIN request.
    pub reason: PinRequestReason,
    /// Optionally, how many PIN attempts are left _in total_.
    pub attempts_left: Option<u32>,
}

impl PinRequiredUpdate {
    /// This consumes `self`, because we should only ever send exactly one answer back.
    pub fn send_pin(self, pin: &str) -> Result<(), String> {
        match Arc::into_inner(self.reply_to) {
            Some(sender) => sender
                .send(pin.to_string())
                .map_err(|_| "Failed to send PIN".to_string()),
            None => Err("Multiple references to reply_to exist; cannot send PIN".to_string()),
        }
    }

    /// The user cancels the PIN entry, without making an attempt.
    pub fn cancel(self) {
        // We hang up to signal an abort
        drop(self.reply_to)
    }
}

#[derive(Debug, Clone)]
pub struct PinNotSetUpdate {
    reply_to: Arc<oneshot::Sender<String>>,
    /// What caused the PIN request.
    pub reason: PinNotSetReason,
}

impl PinNotSetUpdate {
    /// This consumes `self`, because we should only ever send exactly one answer back.
    pub fn set_pin(self, pin: &str) -> Result<(), String> {
        match Arc::into_inner(self.reply_to) {
            Some(sender) => sender
                .send(pin.to_string())
                .map_err(|_| "Failed to send PIN".to_string()),
            None => Err("Multiple references to reply_to exist; cannot send PIN".to_string()),
        }
    }

    /// The user cancels the PIN entry, without making an attempt.
    pub fn cancel(self) {
        // We hang up to signal an abort
        drop(self.reply_to)
    }
}

#[cfg(any(test, feature = "virt"))]
// This function is not _really_ `PartialEq`. We need it for testing purposes,
// but should not expose it like this to consumers
impl PartialEq for PinRequiredUpdate {
    fn eq(&self, other: &Self) -> bool {
        // We explicitly ignore `reply_to` and only compare the other fields.
        self.reason == other.reason && self.attempts_left == other.attempts_left
    }
}

#[cfg(any(test, feature = "virt"))]
// This function is not _really_ `PartialEq`. We need it for testing purposes,
// but should not expose it like this to consumers
impl PartialEq for PinNotSetUpdate {
    fn eq(&self, other: &Self) -> bool {
        // We explicitly ignore `reply_to` and only compare the other fields.
        self.reason == other.reason
    }
}

pub fn available_transports() -> Vec<Transport> {
    vec![Transport::Usb, Transport::Ble]
}
