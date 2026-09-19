use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::sync::Arc;

use crate::transport::cable::channel::ConnectionState;
use crate::transport::cable::connection_stages::{
    connection_stage, handshake_stage, proximity_check_stage, until_teardown, ConnectionInput,
    HandshakeInput, HandshakeOutput, MpscUxUpdateSender, ProximityCheckInput,
    TunnelConnectionInput, UxUpdateSender,
};

use crate::transport::cable::error::CableError;
use crate::transport::ChannelSettings;
use crate::transport::Device;
use crate::webauthn::error::WebAuthnError;

use async_trait::async_trait;
use futures::lock::Mutex;
use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_indexed::SerializeIndexed;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task;
use tracing::{debug, instrument, trace};

use super::channel::CableChannel;
use super::linger::Teardown;
use super::protocol::{self, CableLinkingInfo};
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
        hex::encode(linking_info.authenticator_public_key.as_slice())
    }
}

impl CableKnownDeviceInfo {
    pub(crate) fn new(
        tunnel_domain: &str,
        linking_info: &CableLinkingInfo,
    ) -> Result<Self, CableError> {
        let info = Self {
            contact_id: linking_info.contact_id.to_vec(),
            link_id: linking_info
                .link_id
                .clone()
                .try_into()
                .map_err(|_| CableError::InvalidFraming)?,
            link_secret: linking_info
                .link_secret
                .clone()
                .try_into()
                .map_err(|_| CableError::InvalidFraming)?,
            public_key: linking_info
                .authenticator_public_key
                .clone()
                .try_into()
                .map_err(|_| CableError::InvalidFraming)?,
            name: linking_info.authenticator_name.clone(),
            tunnel_domain: tunnel_domain.to_string(),
        };
        Ok(info)
    }
}

#[derive(Debug, Clone)]
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
            self.device_info.name,
            hex::encode(self.device_info.public_key)
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
    ) -> Result<CableKnownDevice, CableError> {
        let device = CableKnownDevice {
            hint,
            device_info: device_info.clone(),
            store,
        };
        Ok(device)
    }

    #[instrument(skip_all, err)]
    async fn connection(
        known_device: &CableKnownDevice,
        ux_sender: &super::connection_stages::MpscUxUpdateSender,
    ) -> Result<HandshakeOutput, CableError> {
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

#[async_trait]
impl<'d> Device<'d, Cable, CableChannel> for CableKnownDevice {
    async fn channel(
        &'d mut self,
        settings: ChannelSettings,
    ) -> Result<CableChannel, WebAuthnError<CableError>> {
        debug!(?self.device_info.tunnel_domain, "Creating channel to tunnel server");

        let (ux_update_sender, _) = broadcast::channel(16);
        let (cbor_tx_send, cbor_tx_recv) = mpsc::channel(16);
        let (cbor_rx_send, cbor_rx_recv) = mpsc::channel(16);
        let (connection_state_sender, connection_state_receiver) =
            watch::channel(ConnectionState::Connecting);
        let (teardown_tx, teardown_rx) = watch::channel(Teardown::Active);
        let teardown_tx = Arc::new(teardown_tx);
        let mut teardown_rx_connect = teardown_rx.clone();

        // A new connection supersedes any connection still lingering. Known
        // device connections never linger themselves: their linking update
        // cannot be verified and is discarded.
        if let Some(config) = &settings.cable_linger {
            config.registry.close_lingering();
        }

        let ux_update_sender_clone = ux_update_sender.clone();
        let known_device: CableKnownDevice = self.clone();

        let handle_connection = task::spawn(async move {
            let ux_sender =
                MpscUxUpdateSender::new(ux_update_sender_clone, connection_state_sender);

            let connecting = Self::connection(&known_device, &ux_sender);
            let handshake_output = match until_teardown(connecting, &mut teardown_rx_connect).await
            {
                Some(Ok(handshake_output)) => handshake_output,
                Some(Err(e)) => {
                    ux_sender.send_error(e).await;
                    return;
                }
                None => {
                    debug!("Hybrid connection torn down before the handshake completed");
                    ux_sender
                        .set_connection_state(ConnectionState::Terminated)
                        .await;
                    return;
                }
            };

            let tunnel_input = TunnelConnectionInput::from_handshake_output(
                handshake_output,
                Some(known_device.store),
                cbor_tx_recv,
                cbor_rx_send,
                teardown_rx,
                None,
            );

            match protocol::connection(tunnel_input, &ux_sender).await {
                Ok(()) => {
                    ux_sender
                        .set_connection_state(ConnectionState::Terminated)
                        .await;
                }
                Err(e) => {
                    // send_error already transitions to Terminated.
                    ux_sender.send_error(e).await;
                }
            }
        });

        Ok(CableChannel {
            handle_connection,
            cbor_sender: cbor_tx_send,
            cbor_receiver: cbor_rx_recv,
            ux_update_sender,
            connection_state_receiver,
            persistent_token_store: settings.persistent_token_store,
            teardown: teardown_tx,
            linger_eligible: false,
        })
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
    use crate::transport::cable::tunnel::KNOWN_TUNNEL_DOMAINS;

    #[test]
    fn known_tunnels_domains_count() {
        assert!(
            KNOWN_TUNNEL_DOMAINS.len() < 25,
            "KNOWN_TUNNEL_DOMAINS must be encoded as a single byte."
        )
    }
}
