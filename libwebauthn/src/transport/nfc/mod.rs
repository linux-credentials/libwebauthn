use std::fmt::{Display, Formatter};

pub mod channel;
pub mod commands;
pub mod device;
#[cfg(feature = "pcsc")]
pub mod pcsc;

pub use device::list_devices;

use super::Transport;

pub struct Nfc {}
impl Transport for Nfc {}
unsafe impl Send for Nfc {}
unsafe impl Sync for Nfc {}

impl Display for Nfc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NFC")
    }
}

#[derive(Clone, Debug)]
pub struct Context {}

impl Display for Context {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "context")
    }
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}
impl Copy for Context {}
