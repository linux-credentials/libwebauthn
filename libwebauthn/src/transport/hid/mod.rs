use std::fmt::Display;

pub mod channel;
pub mod device;
pub mod framing;
pub mod init;

#[cfg(feature = "virt")]
pub use device::{virtual_device, HidPipeBackend};
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
