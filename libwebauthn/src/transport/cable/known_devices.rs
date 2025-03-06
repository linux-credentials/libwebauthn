use std::fmt::{Debug, Display};

use crate::transport::error::Error;
use crate::transport::Device;
use crate::StateUpdate;

use async_trait::async_trait;
use tokio::sync::mpsc;

use super::channel::CableChannel;
use super::Cable;

#[async_trait]
pub trait CableKnownDeviceInfoStore: Debug + Send {
    /// Called whenever a known device should be added.
    async fn put_known_device(&mut self, device: &CableKnownDeviceInfo);
    /// Called whenever a known device becomes permanently unavailable.
    async fn delete_known_device(&mut self, device_id: String);
}

/// A no-op known-device store for ephemeral-only implementations.
#[derive(Debug, Default, Clone)]
pub struct EphemeralDeviceInfoStore {
    pub last_device_info: Option<CableKnownDeviceInfo>,
}

unsafe impl Send for EphemeralDeviceInfoStore {}

#[async_trait]
impl CableKnownDeviceInfoStore for EphemeralDeviceInfoStore {
    async fn put_known_device(&mut self, device: &CableKnownDeviceInfo) {
        self.last_device_info = Some(device.clone())
    }

    async fn delete_known_device(&mut self, device_id: String) {
        if let Some(last_device_info) = &self.last_device_info {
            if last_device_info.device_id == device_id {
                self.last_device_info = None
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CableKnownDeviceInfo {
    pub device_id: String,
    pub contact_id: Vec<u8>,
    pub link_id: [u8; 8],
    pub link_secret: [u8; 32],
    pub public_key: [u8; 65],
    pub name: String,
}

#[derive(Debug)]
pub struct CableKnownDevice<'d> {
    pub device_info: CableKnownDeviceInfo,
    _store: &'d mut Box<dyn CableKnownDeviceInfoStore>,
}

impl<'d> Display for CableKnownDevice<'d> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({})",
            self.device_info.name, self.device_info.device_id
        )
    }
}

unsafe impl<'d> Send for CableKnownDevice<'d> {}
unsafe impl<'d> Sync for CableKnownDevice<'d> {}

#[async_trait]
impl<'d> Device<'d, Cable, CableChannel<'d>> for CableKnownDevice<'d> {
    async fn channel(&'d mut self) -> Result<(CableChannel, mpsc::Receiver<StateUpdate>), Error> {
        todo!()
    }

    // #[instrument(skip_all)]
    // async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
    //     todo!()
    // }
}

#[cfg(test)]
mod tests {
    use crate::transport::cable::tunnel::KNOWN_TUNNEL_DOMAINS;

    #[test]
    fn known_tunnels_domains_count() {
        assert!(
            KNOWN_TUNNEL_DOMAINS.len() < 25,
            "KNOWN_TUNNEL_DOMAINS must be encoded as a single byte."
        )
    }
}
