use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::sync::Arc;

use crate::connection_stages::{
    connection_stage, handshake_stage, proximity_check_stage, ConnectionInput, HandshakeInput,
    HandshakeOutput, MpscUxUpdateSender, ProximityCheckInput,
};
use crate::error::PxpError;

use async_trait::async_trait;
use futures::lock::Mutex;
use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_indexed::SerializeIndexed;
use tracing::{debug, instrument, trace};

use super::protocol::PxpLinkingInfo;

#[async_trait]
pub trait PxpKnownDeviceInfoStore: Debug + Send + Sync {
    /// Called whenever a known device should be added or updated.
    async fn put_known_device(&self, device_id: &PxpKnownDeviceId, device: &PxpKnownDeviceInfo);
    /// Called whenever a known device becomes permanently unavailable.
    async fn delete_known_device(&self, device_id: &PxpKnownDeviceId);
}

/// An in-memory store for testing purposes.
#[derive(Debug, Default, Clone)]
pub struct EphemeralDeviceInfoStore {
    pub known_devices: Arc<Mutex<HashMap<PxpKnownDeviceId, PxpKnownDeviceInfo>>>,
}

impl EphemeralDeviceInfoStore {
    pub fn new() -> Self {
        Self {
            known_devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn list_all(&self) -> Vec<(PxpKnownDeviceId, PxpKnownDeviceInfo)> {
        debug!("Listing all known devices");
        let known_devices = self.known_devices.lock().await;
        known_devices
            .iter()
            .map(|(id, info)| (id.clone(), info.clone()))
            .collect()
    }
}

unsafe impl Send for EphemeralDeviceInfoStore {}

#[async_trait]
impl PxpKnownDeviceInfoStore for EphemeralDeviceInfoStore {
    async fn put_known_device(&self, device_id: &PxpKnownDeviceId, device: &PxpKnownDeviceInfo) {
        debug!(?device_id, "Inserting or updating known device");
        trace!(?device);
        let mut known_devices = self.known_devices.lock().await;
        known_devices.insert(device_id.clone(), device.clone());
    }

    async fn delete_known_device(&self, device_id: &PxpKnownDeviceId) {
        debug!(?device_id, "Deleting known device");
        let mut known_devices = self.known_devices.lock().await;
        known_devices.remove(device_id);
    }
}

pub type PxpKnownDeviceId = String;

#[derive(Debug, Clone)]
pub struct PxpKnownDeviceInfo {
    pub contact_id: Vec<u8>,
    pub link_id: [u8; 8],
    pub link_secret: [u8; 32],
    pub public_key: [u8; 65],
    pub name: String,
    pub tunnel_domain: String,
}

impl From<&PxpLinkingInfo> for PxpKnownDeviceId {
    fn from(linking_info: &PxpLinkingInfo) -> Self {
        hex::encode(linking_info.authenticator_public_key.as_slice())
    }
}

impl PxpKnownDeviceInfo {
    pub(crate) fn new(
        tunnel_domain: &str,
        linking_info: &PxpLinkingInfo,
    ) -> Result<Self, PxpError> {
        let info = Self {
            contact_id: linking_info.contact_id.to_vec(),
            link_id: linking_info
                .link_id
                .clone()
                .try_into()
                .map_err(|_| PxpError::InvalidFraming)?,
            link_secret: linking_info
                .link_secret
                .clone()
                .try_into()
                .map_err(|_| PxpError::InvalidFraming)?,
            public_key: linking_info
                .authenticator_public_key
                .clone()
                .try_into()
                .map_err(|_| PxpError::InvalidFraming)?,
            name: linking_info.authenticator_name.clone(),
            tunnel_domain: tunnel_domain.to_string(),
        };
        Ok(info)
    }
}

#[derive(Debug, Clone)]
pub struct PxpKnownDevice {
    pub hint: ClientPayloadHint,
    pub device_info: PxpKnownDeviceInfo,
    pub(crate) store: Arc<dyn PxpKnownDeviceInfoStore>,
}

impl Display for PxpKnownDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({})",
            self.device_info.name,
            hex::encode(self.device_info.public_key)
        )
    }
}

unsafe impl Send for PxpKnownDevice {}
unsafe impl Sync for PxpKnownDevice {}

impl PxpKnownDevice {
    pub async fn new(
        hint: ClientPayloadHint,
        device_info: &PxpKnownDeviceInfo,
        store: Arc<dyn PxpKnownDeviceInfoStore>,
    ) -> Result<PxpKnownDevice, PxpError> {
        let device = PxpKnownDevice {
            hint,
            device_info: device_info.clone(),
            store,
        };
        Ok(device)
    }

    #[instrument(skip_all, err)]
    pub(crate) async fn connection(
        known_device: &PxpKnownDevice,
        ux_sender: &MpscUxUpdateSender,
    ) -> Result<HandshakeOutput, PxpError> {
        let client_nonce = rand::random::<ClientNonce>();

        // Stage 1: Connection (no proximity check needed for known devices)
        let connection_input = ConnectionInput::new_for_known_device(known_device, &client_nonce);
        let connection_output = connection_stage(connection_input.clone(), ux_sender).await?;

        // Stage 2: Proximity check (after connection for known devices)
        let proximity_input =
            ProximityCheckInput::new_for_known_device(known_device, &client_nonce)?;
        let proximity_output = proximity_check_stage(proximity_input, ux_sender).await?;

        // Stage 3: Handshake
        let handshake_input = HandshakeInput::new_for_known_device(
            known_device,
            connection_output,
            proximity_output,
        )?;
        let handshake_output = handshake_stage(handshake_input, ux_sender).await?;

        Ok(handshake_output)
    }
}

pub(crate) type ClientNonce = [u8; 16];

// Key 3: either the string “ga” to hint that a getAssertion will follow, or “mc” to hint that a makeCredential will follow.
#[derive(Clone, Debug, SerializeIndexed)]
pub struct ClientPayload {
    #[serde(index = 0x01)]
    pub link_id: ByteBuf,

    #[serde(index = 0x02)]
    pub client_nonce: ByteBuf,

    #[serde(index = 0x03)]
    pub hint: ClientPayloadHint,
}

#[derive(Debug, Copy, Clone, Serialize, PartialEq)]
pub enum ClientPayloadHint {
    #[serde(rename = "ga")]
    GetAssertion,
    #[serde(rename = "mc")]
    MakeCredential,
}

#[cfg(test)]
mod tests {
    use crate::tunnel::KNOWN_TUNNEL_DOMAINS;

    #[test]
    fn known_tunnels_domains_count() {
        assert!(
            KNOWN_TUNNEL_DOMAINS.len() < 25,
            "KNOWN_TUNNEL_DOMAINS must be encoded as a single byte."
        )
    }
}
