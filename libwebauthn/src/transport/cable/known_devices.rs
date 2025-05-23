use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::sync::Arc;

use crate::transport::cable::advertisement::await_advertisement;
use crate::transport::cable::crypto::{derive, KeyPurpose};
use crate::transport::error::Error;
use crate::transport::Device;
use crate::webauthn::TransportError;
use crate::UxUpdate;

use async_trait::async_trait;
use futures::lock::Mutex;
use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_indexed::SerializeIndexed;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use super::channel::CableChannel;
use super::tunnel::{self, CableLinkingInfo};
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

    pub async fn list_all(&self) -> Vec<(CableKnownDeviceId, CableKnownDeviceInfo)> {
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
    pub hint: ClientPayloadHint,
    pub device_info: CableKnownDeviceInfo,
    pub(crate) store: Arc<dyn CableKnownDeviceInfoStore>,
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

impl CableKnownDevice {
    pub async fn new(
        hint: ClientPayloadHint,
        device_info: &CableKnownDeviceInfo,
        store: Arc<dyn CableKnownDeviceInfoStore>,
    ) -> Result<CableKnownDevice, Error> {
        let device = CableKnownDevice {
            hint,
            device_info: device_info.clone(),
            store: store,
        };
        Ok(device)
    }
}

#[async_trait]
impl<'d> Device<'d, Cable, CableChannel> for CableKnownDevice {
    async fn channel(&'d mut self) -> Result<(CableChannel, mpsc::Receiver<UxUpdate>), Error> {
        debug!(?self.device_info.tunnel_domain, "Creating channel to tunnel server");

        let (client_nonce, client_payload) =
            construct_client_payload(self.hint, self.device_info.link_id);
        let contact_id = base64_url::encode(&self.device_info.contact_id);

        let connection_type = tunnel::CableTunnelConnectionType::KnownDevice {
            contact_id: contact_id,
            authenticator_public_key: self.device_info.public_key.to_vec(),
            client_payload,
        };
        let mut ws_stream =
            tunnel::connect(&self.device_info.tunnel_domain, &connection_type).await?;

        let eid_key: [u8; 64] = derive(
            &self.device_info.link_secret,
            Some(&client_nonce),
            KeyPurpose::EIDKey,
        );

        let (_device, advert) = await_advertisement(&eid_key).await?;

        let mut psk: [u8; 32] = [0u8; 32];
        psk.copy_from_slice(
            &derive(
                &self.device_info.link_secret,
                Some(&advert.plaintext),
                KeyPurpose::PSK,
            )[..32],
        );

        let noise_state = tunnel::do_handshake(&mut ws_stream, psk, &connection_type).await?;

        tunnel::channel(
            &connection_type,
            noise_state,
            &self.device_info.tunnel_domain,
            &Some(self.store.clone()),
            ws_stream,
        )
        .await
    }
}

type ClientNonce = [u8; 16];

// Key 3: either the string “ga” to hint that a getAssertion will follow, or “mc” to hint that a makeCredential will follow.
#[derive(Clone, Debug, SerializeIndexed)]
#[serde(offset = 1)]
pub struct ClientPayload {
    pub link_id: ByteBuf,
    pub client_nonce: ByteBuf,
    pub hint: ClientPayloadHint,
}

#[derive(Debug, Copy, Clone, Serialize, PartialEq)]
pub enum ClientPayloadHint {
    #[serde(rename = "ga")]
    GetAssertion,
    #[serde(rename = "mc")]
    MakeCredential,
}

fn construct_client_payload(
    hint: ClientPayloadHint,
    link_id: [u8; 8],
) -> (ClientNonce, ClientPayload) {
    let client_nonce = rand::random::<ClientNonce>();
    let client_payload = {
        ClientPayload {
            link_id: ByteBuf::from(link_id),
            client_nonce: ByteBuf::from(client_nonce),
            hint,
        }
    };
    (client_nonce, client_payload)
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
