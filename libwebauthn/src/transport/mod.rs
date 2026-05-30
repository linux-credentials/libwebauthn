//! Transport layer that carries CTAP messages to FIDO2/WebAuthn authenticators.
//! It abstracts over several physical media: HID (USB), BLE (Bluetooth Low
//! Energy), caBLE (the cable/hybrid mode), and NFC (available when the
//! `nfc-backend-pcsc` or `nfc-backend-libnfc` feature is enabled). The two core
//! abstractions are [`Channel`], an open session with an authenticator that
//! sends and receives CTAP messages, and [`Device`], a discovered authenticator
//! from which a [`Channel`] can be opened.
//!
//! Supporting pieces include the [`Transport`] trait that identifies a specific
//! transport implementation and the [`Ctap2AuthTokenStore`] trait for caching
//! PIN/UV authentication tokens across operations. Each medium provides its own
//! channel and device adapters suited to its protocol and hardware constraints.

pub(crate) mod error;

pub mod ble;
pub mod cable;
pub mod device;
pub mod hid;
#[cfg(test)]
/// A mock channel that can be used in tests to
/// queue expected requests and responses in unittests
pub mod mock;
#[cfg(any(feature = "nfc-backend-pcsc", feature = "nfc-backend-libnfc"))]
pub mod nfc;

mod channel;
#[allow(clippy::module_inception)]
mod transport;

pub(crate) use channel::{AuthTokenData, Ctap2AuthTokenPermission};
pub use channel::{Channel, Ctap2AuthTokenStore};

#[cfg(test)]
pub use channel::ChannelStatus;

pub use device::Device;
pub use transport::Transport;
