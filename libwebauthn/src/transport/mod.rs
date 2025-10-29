pub(crate) mod error;

pub mod ble;
pub mod cable;
pub mod device;
pub mod hid;
#[cfg(feature = "nfc")]
pub mod nfc;
#[cfg(test)]
/// A mock channel that can be used in tests to
/// queue expected requests and responses in unittests
pub mod mock;
#[cfg(test)]
/// Fully fledged virtual device based on trussed
/// for end2end tests
pub mod virt;

mod channel;
mod transport;

pub(crate) use channel::{AuthTokenData, Ctap2AuthTokenPermission};
pub use channel::{Channel, Ctap2AuthTokenStore};

#[cfg(test)]
pub use channel::ChannelStatus;

pub use device::Device;
pub use transport::Transport;
