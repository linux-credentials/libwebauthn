use ::btleplug::api::{AddressType, BDAddr, PeripheralProperties};
use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, instrument, trace, warn};

use super::advertisement::{await_advertisement, DecryptedAdvert};
use super::connection::{ConnectionState, PxpUpdate, UpdateSink};
use super::crypto::{derive, KeyPurpose};
use super::data_channel::{PxpDataChannel, WebSocketDataChannel};
use super::known_devices::{ClientNonce, PxpKnownDevice, PxpKnownDeviceInfoStore};
use super::l2cap::L2capDataChannel;
use super::protocol::{self, PxpTunnelConnectionType, TunnelNoiseState};
use super::qr_code_device::PxpQrCodeDevice;
use super::tunnel;
use crate::error::PxpError;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct ProximityCheckInput {
    pub eid_key: [u8; 64],
}

impl ProximityCheckInput {
    pub fn new_for_qr_code(qr_device: &PxpQrCodeDevice) -> Result<Self, PxpError> {
        let eid_key: [u8; 64] = derive(
            qr_device.qr_code.qr_secret.as_ref(),
            None,
            KeyPurpose::EIDKey,
        )?;
        Ok(Self { eid_key })
    }

    pub fn new_for_known_device(
        known_device: &PxpKnownDevice,
        client_nonce: &ClientNonce,
    ) -> Result<Self, PxpError> {
        let eid_key: [u8; 64] = derive(
            &known_device.device_info.link_secret,
            Some(client_nonce),
            KeyPurpose::EIDKey,
        )?;
        Ok(Self { eid_key })
    }
}

#[derive(Debug)]
pub(crate) struct ProximityCheckOutput {
    pub device: PeripheralProperties,
    pub advert: DecryptedAdvert,
}

/// L2CAP parameters from the advertisement suffix, for a BLE data channel.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BleConnectionParams {
    pub address: BDAddr,
    pub address_type: Option<AddressType>,
    pub psm: u16,
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectionInput {
    pub tunnel_domain: String,
    pub connection_type: PxpTunnelConnectionType,
    /// Some if the CMHD offered a BLE L2CAP channel; None selects WebSocket.
    pub ble: Option<BleConnectionParams>,
    /// Present for known-device connections, so a 410 Gone can forget the record.
    pub known_device_store: Option<Arc<dyn PxpKnownDeviceInfoStore>>,
}

impl ConnectionInput {
    #[instrument(skip_all, err)]
    pub fn new_for_qr_code(
        qr_device: &PxpQrCodeDevice,
        proximity_output: &ProximityCheckOutput,
    ) -> Result<Self, PxpError> {
        let tunnel_domain = decode_tunnel_domain_from_advert(&proximity_output.advert)?;

        let routing_id_str = hex::encode(proximity_output.advert.routing_id);
        let tunnel_id_full = derive(
            qr_device.qr_code.qr_secret.as_ref(),
            None,
            KeyPurpose::TunnelID,
        )
        .map_err(|_| PxpError::InvalidKey)?;
        let tunnel_id = tunnel_id_full.get(..16).ok_or(PxpError::InvalidKey)?;
        let tunnel_id_str = hex::encode(tunnel_id);

        let connection_type = PxpTunnelConnectionType::QrCode {
            routing_id: routing_id_str,
            tunnel_id: tunnel_id_str,
            private_key: qr_device.private_key,
        };

        let ble = proximity_output
            .advert
            .suffix
            .as_ref()
            .and_then(|suffix| suffix.ble_psm())
            .map(|psm| BleConnectionParams {
                address: proximity_output.device.address,
                address_type: proximity_output.device.address_type,
                psm,
            });

        Ok(Self {
            tunnel_domain,
            connection_type,
            ble,
            known_device_store: None,
        })
    }

    pub fn new_for_known_device(
        known_device: &super::known_devices::PxpKnownDevice,
        client_nonce: &ClientNonce,
    ) -> Self {
        use super::known_devices::ClientPayload;
        use serde_bytes::ByteBuf;

        let client_payload = ClientPayload {
            link_id: ByteBuf::from(known_device.device_info.link_id),
            client_nonce: ByteBuf::from(*client_nonce),
            hint: known_device.hint,
        };
        let contact_id = base64_url::encode(&known_device.device_info.contact_id);
        let connection_type = PxpTunnelConnectionType::KnownDevice {
            contact_id,
            authenticator_public_key: known_device.device_info.public_key.to_vec(),
            client_payload,
        };

        Self {
            tunnel_domain: known_device.device_info.tunnel_domain.clone(),
            connection_type,
            ble: None,
            known_device_store: Some(known_device.store.clone()),
        }
    }
}

pub(crate) struct ConnectionOutput {
    pub data_channel: Box<dyn PxpDataChannel>,
    pub connection_type: PxpTunnelConnectionType,
    pub tunnel_domain: String,
}

pub(crate) struct HandshakeInput {
    pub data_channel: Box<dyn PxpDataChannel>,
    pub psk: [u8; 32],
    pub connection_type: PxpTunnelConnectionType,
    pub tunnel_domain: String,
}

impl HandshakeInput {
    pub fn new_for_qr_code(
        qr_device: &PxpQrCodeDevice,
        connection_output: ConnectionOutput,
        proximity_output: ProximityCheckOutput,
    ) -> Result<Self, PxpError> {
        let advert_plaintext = &proximity_output.advert.plaintext;
        let psk = derive_psk(qr_device.qr_code.qr_secret.as_ref(), advert_plaintext)?;
        Ok(Self {
            data_channel: connection_output.data_channel,
            psk,
            connection_type: connection_output.connection_type,
            tunnel_domain: connection_output.tunnel_domain,
        })
    }

    pub fn new_for_known_device(
        known_device: &PxpKnownDevice,
        connection_output: ConnectionOutput,
        proximity_output: ProximityCheckOutput,
    ) -> Result<Self, PxpError> {
        let link_secret = known_device.device_info.link_secret;
        let advert_plaintext = proximity_output.advert.plaintext;
        let psk = derive_psk(&link_secret, &advert_plaintext)?;
        Ok(Self {
            data_channel: connection_output.data_channel,
            psk,
            connection_type: connection_output.connection_type,
            tunnel_domain: connection_output.tunnel_domain,
        })
    }
}

pub(crate) struct HandshakeOutput {
    pub data_channel: Box<dyn PxpDataChannel>,
    pub noise_state: TunnelNoiseState,
    pub connection_type: PxpTunnelConnectionType,
    pub tunnel_domain: String,
}

pub(crate) struct TunnelConnectionInput {
    pub connection_type: PxpTunnelConnectionType,
    pub tunnel_domain: String,
    pub known_device_store: Option<Arc<dyn PxpKnownDeviceInfoStore>>,
    pub data_channel: Box<dyn PxpDataChannel>,
    pub noise_state: TunnelNoiseState,
    pub ctap_tx_recv: mpsc::Receiver<Vec<u8>>,
    pub ctap_rx_send: mpsc::Sender<Vec<u8>>,
}

impl TunnelConnectionInput {
    pub fn from_handshake_output(
        handshake_output: HandshakeOutput,
        known_device_store: Option<Arc<dyn PxpKnownDeviceInfoStore>>,
        ctap_tx_recv: mpsc::Receiver<Vec<u8>>,
        ctap_rx_send: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            connection_type: handshake_output.connection_type,
            tunnel_domain: handshake_output.tunnel_domain,
            known_device_store,
            data_channel: handshake_output.data_channel,
            noise_state: handshake_output.noise_state,
            ctap_tx_recv,
            ctap_rx_send,
        }
    }
}

#[async_trait]
pub(crate) trait UxUpdateSender: Send + Sync {
    async fn send_update(&self, update: PxpUpdate);
    async fn send_error(&self, error: PxpError);
    async fn set_connection_state(&self, state: ConnectionState);
}

pub(crate) struct MpscUxUpdateSender {
    sender: Box<dyn UpdateSink>,
    connection_state_tx: watch::Sender<ConnectionState>,
}

impl MpscUxUpdateSender {
    pub fn new(
        sender: Box<dyn UpdateSink>,
        connection_state_tx: watch::Sender<ConnectionState>,
    ) -> Self {
        Self {
            sender,
            connection_state_tx,
        }
    }
}

#[async_trait]
impl UxUpdateSender for MpscUxUpdateSender {
    #[instrument(skip(self))]
    async fn send_update(&self, update: PxpUpdate) {
        trace!("Sending UX update");
        self.sender.send_update(update);
    }

    async fn send_error(&self, error: PxpError) {
        self.send_update(PxpUpdate::Error(error)).await;
        let _ = self.connection_state_tx.send(ConnectionState::Terminated);
    }

    async fn set_connection_state(&self, state: ConnectionState) {
        let _ = self.connection_state_tx.send(state);
    }
}

#[instrument(skip_all, err)]
pub(crate) async fn proximity_check_stage(
    input: ProximityCheckInput,
    ux_sender: &dyn UxUpdateSender,
) -> Result<ProximityCheckOutput, PxpError> {
    debug!("Starting proximity check stage");

    ux_sender.send_update(PxpUpdate::ProximityCheck).await;

    let (device, advert) = await_advertisement(&input.eid_key).await?;

    debug!("Proximity check completed successfully");
    Ok(ProximityCheckOutput { device, advert })
}

#[instrument(skip_all, err)]
pub(crate) async fn connection_stage(
    input: ConnectionInput,
    ux_sender: &dyn UxUpdateSender,
) -> Result<ConnectionOutput, PxpError> {
    debug!(?input.tunnel_domain, "Starting connection stage");

    ux_sender.send_update(PxpUpdate::Connecting).await;

    let data_channel = connect_data_channel(&input).await?;

    debug!("Connection stage completed successfully");
    Ok(ConnectionOutput {
        data_channel,
        connection_type: input.connection_type,
        tunnel_domain: input.tunnel_domain,
    })
}

/// Connects the data transfer channel: a direct BLE L2CAP channel if the CMHD
/// offered one, otherwise the WebSocket tunnel. A failed L2CAP attempt falls
/// back to the tunnel, whose routing details are always present in the advert.
async fn connect_data_channel(
    input: &ConnectionInput,
) -> Result<Box<dyn PxpDataChannel>, PxpError> {
    if let Some(ble) = input.ble {
        match L2capDataChannel::connect(ble.address, ble.address_type, ble.psm).await {
            Ok(channel) => {
                info!(psm = ble.psm, "Connected over BLE L2CAP");
                return Ok(Box::new(channel));
            }
            Err(e) => {
                warn!(
                    ?e,
                    "BLE L2CAP connection failed, falling back to WebSocket tunnel"
                );
            }
        }
    }

    let ws_stream = match tunnel::connect(&input.tunnel_domain, &input.connection_type).await {
        Ok(ws_stream) => ws_stream,
        Err(error) => {
            if let Some(device_id) =
                tunnel::known_device_id_to_forget(&error, &input.connection_type)
            {
                if let Some(store) = &input.known_device_store {
                    warn!(
                        ?device_id,
                        "Tunnel server returned 410 Gone; forgetting known device"
                    );
                    store.delete_known_device(&device_id).await;
                }
            }
            return Err(error);
        }
    };
    info!(tunnel_domain = %input.tunnel_domain, "Connected over WebSocket tunnel");
    Ok(Box::new(WebSocketDataChannel::new(ws_stream)))
}

#[instrument(skip_all, err)]
pub(crate) async fn handshake_stage(
    input: HandshakeInput,
    ux_sender: &dyn UxUpdateSender,
) -> Result<HandshakeOutput, PxpError> {
    debug!("Starting handshake stage");

    ux_sender.send_update(PxpUpdate::Authenticating).await;

    let mut data_channel = input.data_channel;
    let noise_state =
        protocol::do_handshake(&mut *data_channel, input.psk, &input.connection_type).await?;

    debug!("Handshake stage completed successfully");
    ux_sender.send_update(PxpUpdate::Connected).await;

    ux_sender
        .set_connection_state(ConnectionState::Connected)
        .await;

    Ok(HandshakeOutput {
        data_channel,
        noise_state,
        connection_type: input.connection_type,
        tunnel_domain: input.tunnel_domain,
    })
}

fn derive_psk(secret: &[u8], advert_plaintext: &[u8]) -> Result<[u8; 32], PxpError> {
    let derived = derive(secret, Some(advert_plaintext), KeyPurpose::Psk)?;
    let mut psk: [u8; 32] = [0u8; 32];
    psk.copy_from_slice(derived.get(..32).ok_or(PxpError::InvalidKey)?);
    Ok(psk)
}

pub(crate) fn decode_tunnel_domain_from_advert(
    advert: &DecryptedAdvert,
) -> Result<String, PxpError> {
    tunnel::decode_tunnel_server_domain(advert.encoded_tunnel_server_domain)
        .ok_or_else(|| {
            error!({ encoded = %advert.encoded_tunnel_server_domain }, "Failed to decode tunnel server domain");
            PxpError::InvalidFraming
        })
}
