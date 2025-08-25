use std::fmt::Display;

pub mod channel;
pub mod device;
pub mod framing;
pub mod init;

#[cfg(test)]
pub use device::get_virtual_device;
pub use device::{list_devices, HidDevice};

use super::Transport;

pub struct Hid {}
impl Transport for Hid {}
unsafe impl Send for Hid {}
unsafe impl Sync for Hid {}

impl Display for Hid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hid")
    }
}
