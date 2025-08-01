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
use pin::PinRequestReason;
pub(crate) use unwrap_field;

#[derive(Debug)]
pub enum Transport {
    Usb,
    Ble,
}

#[derive(Debug, Clone)]
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

pub fn available_transports() -> Vec<Transport> {
    vec![Transport::Usb, Transport::Ble]
}
