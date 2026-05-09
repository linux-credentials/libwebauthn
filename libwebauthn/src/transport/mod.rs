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
