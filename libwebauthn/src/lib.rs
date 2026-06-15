//! libwebauthn is a Linux platform library implementing the FIDO2/WebAuthn and
//! FIDO U2F specifications. It provides traits for performing WebAuthn
//! operations (make credential and get assertion) and U2F operations (register
//! and sign) against authenticator devices connected over USB, Bluetooth, or
//! optionally NFC. The core abstractions are the [`WebAuthn`](webauthn::WebAuthn)
//! and [`U2F`](u2f::U2F) traits that drive the protocol logic, and the
//! [`Channel`](transport::Channel) trait that abstracts communication with a
//! physical authenticator.
//!
//! While an operation runs, the library may need user verification. It surfaces
//! this through the [`UvUpdate`] enum and related types such as
//! [`PinRequiredUpdate`] and [`PinNotSetUpdate`], which let an application
//! collect input (PIN entry or a presence confirmation) and feed it back into
//! the ongoing operation. The [`transport`] module manages device discovery and
//! communication, and the [`pin`] module handles the cryptographic side of PIN
//! and user verification.
//!
//! # Getting started
//!
//! A typical flow is to enumerate devices on your transport of choice, open a
//! [`Channel`](transport::Channel) to each one, and run a ceremony on that
//! channel. The ceremony traits are blanket-implemented for every channel:
//! [`WebAuthn`](webauthn::WebAuthn) for make-credential and get-assertion, and
//! the [`management`] traits ([`CredentialManagement`](management::CredentialManagement),
//! [`AuthenticatorConfig`](management::AuthenticatorConfig),
//! [`BioEnrollment`](management::BioEnrollment)) for the administrative
//! ceremonies. The make-credential and get-assertion requests are built from
//! their WebAuthn IDL (the JSON the browser API speaks) with
//! [`MakeCredentialRequest::prepare`](ops::webauthn::MakeCredentialRequest::prepare)
//! and [`GetAssertionRequest::prepare`](ops::webauthn::GetAssertionRequest::prepare),
//! which validate the caller origin against the relying party ID.
//!
//! ```no_run
//! use libwebauthn::ops::webauthn::{
//!     MakeCredentialRequest, OriginValidation, RelatedOrigins, RequestOrigin, RequestSettings,
//!     SystemPublicSuffixList,
//! };
//! use libwebauthn::transport::hid::list_devices;
//! use libwebauthn::transport::{ChannelSettings, Device};
//! use libwebauthn::webauthn::WebAuthn;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Enumerate authenticators on your transport of choice (HID shown here).
//! let devices = list_devices().await?;
//!
//! for mut device in devices {
//!     // 2. Open a channel to the device.
//!     let mut channel = device.channel(ChannelSettings::default()).await?;
//!
//!     // 3. Build a request from its WebAuthn IDL JSON.
//!     let origin: RequestOrigin = "https://example.org".try_into().expect("invalid origin");
//!     let psl = SystemPublicSuffixList::auto().expect("public suffix list unavailable");
//!     let settings = RequestSettings {
//!         origin: OriginValidation::Validate {
//!             public_suffix_list: &psl,
//!             related_origins: RelatedOrigins::Disabled,
//!         },
//!     };
//!     let request_json = r#"{ "rp": { "id": "example.org", "name": "Example" } }"#; // abbreviated
//!     let request =
//!         MakeCredentialRequest::prepare(&origin, request_json, &settings).await?;
//!
//!     // 4. Run the ceremony on the channel.
//!     let _response = channel.webauthn_make_credential(&request).await?;
//! }
//! # Ok(())
//! # }
//! ```

// Production code must not panic. Tests keep unwrap/expect/panic latitude
// through `not(test)`, and the virt test-utility code through local allows.
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::todo))]
#![cfg_attr(not(test), deny(clippy::unreachable))]
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
#![cfg_attr(not(test), deny(clippy::unwrap_in_result))]

#[cfg(all(
    feature = "nfc",
    not(any(feature = "nfc-backend-pcsc", feature = "nfc-backend-libnfc"))
))]
compile_error!(
    "the `nfc` feature is an umbrella that requires at least one backend; enable `nfc-backend-pcsc` and/or `nfc-backend-libnfc`"
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
            tracing::warn!(
                field = stringify!($field),
                "Device response did not contain expected field"
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
