use std::fmt::Display;

pub mod btleplug;
pub mod channel;
pub mod device;
pub mod error;
pub mod framing;

pub use device::is_available;
pub use device::list_devices;
pub use device::BleDevice;
pub use error::BleError;

use super::Transport;

pub struct Ble {}
impl Transport for Ble {}
unsafe impl Send for Ble {}
unsafe impl Sync for Ble {}

impl Display for Ble {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ble")
    }
}
