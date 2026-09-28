//! Hybrid transport: `libwebauthn`'s `Channel` / `Device` adapter over the
//! Proximity Exchange Protocol implemented in [`libwebauthn_pxp`].
use std::fmt::Display;

mod device;

pub mod channel;

pub use libwebauthn_pxp::{
    advertisement, digit_encode, error, known_devices, qr_code_device, tunnel,
};

use super::Transport;

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
