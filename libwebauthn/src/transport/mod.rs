pub(crate) mod error;

pub mod ble;
pub mod cable;
pub mod device;
pub mod hid;
#[cfg(test)]
pub mod virt;

mod channel;
mod transport;

pub(crate) use channel::{AuthTokenData, Ctap2AuthTokenPermission};
pub use channel::{Channel, Ctap2AuthTokenStore};

#[cfg(test)]
pub use channel::ChannelStatus;

pub use device::Device;
pub use transport::Transport;
