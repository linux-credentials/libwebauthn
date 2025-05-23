use std::fmt::Display;

mod crypto;
mod digit_encode;

pub mod advertisement;
pub mod channel;
pub mod known_devices;
pub mod qr_code_device;
pub mod tunnel;

use super::Transport;
pub use digit_encode::digit_encode;

pub struct Cable {}
impl Transport for Cable {}
unsafe impl Send for Cable {}
unsafe impl Sync for Cable {}

impl Display for Cable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cable")
    }
}
