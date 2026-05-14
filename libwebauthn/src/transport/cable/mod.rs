use std::fmt::Display;

mod crypto;
mod data_channel;
mod digit_encode;

pub mod advertisement;
pub mod channel;
pub mod connection_stages;
pub mod known_devices;
pub mod qr_code_device;
pub mod tunnel;

use super::Transport;
pub use digit_encode::digit_encode;

/// Checks if the Cable/Hybrid transport is available on the system.
/// Cable depends on a Bluetooth adapter for BLE advertisement discovery.
pub async fn is_available() -> bool {
    super::ble::is_available().await
}

pub struct Cable {}
impl Transport for Cable {}
unsafe impl Send for Cable {}
unsafe impl Sync for Cable {}

impl Display for Cable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cable")
    }
}
