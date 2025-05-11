use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::sync::Arc;

use crate::transport::error::Error;
use crate::transport::Device;
use crate::webauthn::TransportError;
use crate::UxUpdate;

use async_trait::async_trait;
use futures::lock::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use super::channel::CableChannel;
use super::tunnel::CableLinkingInfo;
use super::Cable;

#[async_trait]
pub trait CableKnownDeviceInfoStore: Debug + Send + Sync {
    /// Called whenever a known device should be added or updated.
    async fn put_known_device(&self, device_id: &CableKnownDeviceId, device: &CableKnownDeviceInfo);
    /// Called whenever a known device becomes permanently unavailable.
    async fn delete_known_device(&self, device_id: &CableKnownDeviceId);
}

/// An in-memory store for testing purposes.
#[derive(Debug, Default, Clone)]
pub struct EphemeralDeviceInfoStore {
    pub known_devices: Arc<Mutex<HashMap<CableKnownDeviceId, CableKnownDeviceInfo>>>,
}

impl EphemeralDeviceInfoStore {
    pub fn new() -> Self {
        Self {
            known_devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

unsafe impl Send for EphemeralDeviceInfoStore {}

#[async_trait]
impl CableKnownDeviceInfoStore for EphemeralDeviceInfoStore {
    async fn put_known_device(
        &self,
        device_id: &CableKnownDeviceId,
        device: &CableKnownDeviceInfo,
    ) {
        debug!(?device_id, "Inserting or updating known device");
        trace!(?device);
        let mut known_devices = self.known_devices.lock().await;
        known_devices.insert(device_id.clone(), device.clone());
    }

    async fn delete_known_device(&self, device_id: &CableKnownDeviceId) {
        debug!(?device_id, "Deleting known device");
        let mut known_devices = self.known_devices.lock().await;
        known_devices.remove(device_id);
    }
}

pub type CableKnownDeviceId = String;

#[derive(Debug, Clone)]
pub struct CableKnownDeviceInfo {
    pub contact_id: Vec<u8>,
    pub link_id: [u8; 8],
    pub link_secret: [u8; 32],
    pub public_key: [u8; 65],
    pub name: String,
    pub tunnel_domain: String,
}

impl From<&CableLinkingInfo> for CableKnownDeviceId {
    fn from(linking_info: &CableLinkingInfo) -> Self {
        hex::encode(&linking_info.authenticator_public_key)
    }
}

impl CableKnownDeviceInfo {
    pub(crate) fn new(tunnel_domain: &str, linking_info: &CableLinkingInfo) -> Result<Self, Error> {
        let info = Self {
            contact_id: linking_info.contact_id.to_vec(),
            link_id: linking_info
                .link_id
                .clone()
                .try_into()
                .map_err(|_| Error::Transport(TransportError::InvalidFraming))?,
            link_secret: linking_info
                .link_secret
                .clone()
                .try_into()
                .map_err(|_| Error::Transport(TransportError::InvalidFraming))?,
            public_key: linking_info
                .authenticator_public_key
                .clone()
                .try_into()
                .map_err(|_| Error::Transport(TransportError::InvalidFraming))?,
            name: linking_info.authenticator_name.clone(),
            tunnel_domain: tunnel_domain.to_string(),
        };
        Ok(info)
    }
}

#[derive(Debug)]
pub struct CableKnownDevice {
    pub device_info: CableKnownDeviceInfo,
    _store: Arc<dyn CableKnownDeviceInfoStore>,
}

impl Display for CableKnownDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({})",
            &self.device_info.name,
            hex::encode(&self.device_info.public_key)
        )
    }
}

unsafe impl Send for CableKnownDevice {}
unsafe impl Sync for CableKnownDevice {}

#[async_trait]
impl<'d> Device<'d, Cable, CableChannel<'d>> for CableKnownDevice {
    async fn channel(&'d mut self) -> Result<(CableChannel, mpsc::Receiver<UxUpdate>), Error> {
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
