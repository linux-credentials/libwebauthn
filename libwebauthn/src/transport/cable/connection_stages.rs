use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, instrument, trace, warn};

use super::advertisement::{await_advertisement, DecryptedAdvert};
use super::channel::{CableUpdate, CableUxUpdate, ConnectionState};
use super::crypto::{derive, KeyPurpose};
use super::known_devices::{CableKnownDevice, CableKnownDeviceInfoStore, ClientNonce};
use super::qr_code_device::CableQrCodeDevice;
use super::tunnel::{self, CableTunnelConnectionType, TunnelNoiseState};
use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
use crate::transport::ble::btleplug::FidoDevice;
use crate::transport::error::TransportError;
use crate::webauthn::error::Error;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct ProximityCheckInput {
    pub eid_key: [u8; 64],
}

impl ProximityCheckInput {
    pub fn new_for_qr_code(qr_device: &CableQrCodeDevice) -> Self {
        let eid_key: [u8; 64] = derive(
            qr_device.qr_code.qr_secret.as_ref(),
            None,
            KeyPurpose::EIDKey,
        );
        Self { eid_key }
    }

    pub fn new_for_known_device(
        known_device: &CableKnownDevice,
        client_nonce: &ClientNonce,
    ) -> Self {
        let eid_key: [u8; 64] = derive(
            &known_device.device_info.link_secret,
            Some(client_nonce),
            KeyPurpose::EIDKey,
        );
        Self { eid_key }
    }
}

#[derive(Debug)]
pub(crate) struct ProximityCheckOutput {
    pub _device: FidoDevice,
    pub advert: DecryptedAdvert,
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectionInput {
    pub tunnel_domain: String,
    pub connection_type: CableTunnelConnectionType,
}

impl ConnectionInput {
    #[instrument(skip_all, err)]
    pub fn new_for_qr_code(
        qr_device: &CableQrCodeDevice,
        proximity_output: &ProximityCheckOutput,
    ) -> Result<Self, Error> {
        let tunnel_domain = decode_tunnel_domain_from_advert(&proximity_output.advert)?;

        let routing_id_str = hex::encode(&proximity_output.advert.routing_id);
        let tunnel_id = &derive(
            qr_device.qr_code.qr_secret.as_ref(),
            None,
            KeyPurpose::TunnelID,
        )[..16];
        let tunnel_id_str = hex::encode(&tunnel_id);

        let connection_type = CableTunnelConnectionType::QrCode {
            routing_id: routing_id_str,
            tunnel_id: tunnel_id_str,
            private_key: qr_device.private_key,
        };
        Ok(Self {
            tunnel_domain,
            connection_type,
        })
    }

    pub fn new_for_known_device(
        known_device: &super::known_devices::CableKnownDevice,
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
        let connection_type = CableTunnelConnectionType::KnownDevice {
            contact_id,
            authenticator_public_key: known_device.device_info.public_key.to_vec(),
            client_payload,
        };

        Self {
            tunnel_domain: known_device.device_info.tunnel_domain.clone(),
            connection_type,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionOutput {
    pub ws_stream: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    pub connection_type: CableTunnelConnectionType,
    pub tunnel_domain: String,
}

pub(crate) struct HandshakeInput {
    pub ws_stream: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    pub psk: [u8; 32],
    pub connection_type: CableTunnelConnectionType,
    pub tunnel_domain: String,
}

impl HandshakeInput {
    pub fn new_for_qr_code(
        qr_device: &CableQrCodeDevice,
        connection_output: ConnectionOutput,
        proximity_output: ProximityCheckOutput,
    ) -> Self {
        let advert_plaintext = &proximity_output.advert.plaintext;
        let psk = derive_psk(qr_device.qr_code.qr_secret.as_ref(), advert_plaintext);
        Self {
            ws_stream: connection_output.ws_stream,
            psk,
            connection_type: connection_output.connection_type,
            tunnel_domain: connection_output.tunnel_domain,
        }
    }

    pub fn new_for_known_device(
        known_device: &CableKnownDevice,
        connection_output: ConnectionOutput,
        proximity_output: ProximityCheckOutput,
    ) -> Self {
        let link_secret = known_device.device_info.link_secret;
        let advert_plaintext = proximity_output.advert.plaintext;
        let psk = derive_psk(&link_secret, &advert_plaintext);
        Self {
            ws_stream: connection_output.ws_stream,
            psk,
            connection_type: connection_output.connection_type,
            tunnel_domain: connection_output.tunnel_domain,
        }
    }
}

pub(crate) struct HandshakeOutput {
    pub ws_stream: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    pub noise_state: TunnelNoiseState,
    pub connection_type: CableTunnelConnectionType,
    pub tunnel_domain: String,
}

pub(crate) struct TunnelConnectionInput {
    pub connection_type: CableTunnelConnectionType,
    pub tunnel_domain: String,
    pub known_device_store: Option<Arc<dyn CableKnownDeviceInfoStore>>,
    pub ws_stream: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    pub noise_state: TunnelNoiseState,
    pub cbor_tx_recv: mpsc::Receiver<CborRequest>,
    pub cbor_rx_send: mpsc::Sender<CborResponse>,
}

impl TunnelConnectionInput {
    pub fn from_handshake_output(
        handshake_output: HandshakeOutput,
        known_device_store: Option<Arc<dyn CableKnownDeviceInfoStore>>,
        cbor_tx_recv: mpsc::Receiver<CborRequest>,
        cbor_rx_send: mpsc::Sender<CborResponse>,
    ) -> Self {
        Self {
            connection_type: handshake_output.connection_type,
            tunnel_domain: handshake_output.tunnel_domain,
            known_device_store,
            ws_stream: handshake_output.ws_stream,
            noise_state: handshake_output.noise_state,
            cbor_tx_recv,
            cbor_rx_send,
        }
    }
}

#[async_trait]
pub(crate) trait UxUpdateSender: Send + Sync {
    async fn send_update(&self, update: CableUxUpdate);
    async fn send_error(&self);
    async fn set_connection_state(&self, state: ConnectionState);
}

pub(crate) struct MpscUxUpdateSender {
    sender: broadcast::Sender<CableUxUpdate>,
    connection_state_tx: watch::Sender<ConnectionState>,
}

impl MpscUxUpdateSender {
    pub fn new(
        sender: broadcast::Sender<CableUxUpdate>,
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
    async fn send_update(&self, update: CableUxUpdate) {
        trace!("Sending UX update");
        if let Err(err) = self.sender.send(update) {
            warn!(?err, "No receivers found for UX update.");
        }
    }

    async fn send_error(&self) {
        self.send_update(CableUxUpdate::CableUpdate(CableUpdate::Failed))
            .await;
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
) -> Result<ProximityCheckOutput, Error> {
    debug!("Starting proximity check stage");

    ux_sender
        .send_update(CableUxUpdate::CableUpdate(CableUpdate::ProximityCheck))
        .await;

    let (device, advert) = await_advertisement(&input.eid_key).await?;

    debug!("Proximity check completed successfully");
    Ok(ProximityCheckOutput {
        _device: device,
        advert,
    })
}

#[instrument(skip_all, err)]
pub(crate) async fn connection_stage(
    input: ConnectionInput,
    ux_sender: &dyn UxUpdateSender,
) -> Result<ConnectionOutput, Error> {
    debug!(?input.tunnel_domain, "Starting connection stage");

    ux_sender
        .send_update(CableUxUpdate::CableUpdate(CableUpdate::Connecting))
        .await;

    let ws_stream = tunnel::connect(&input.tunnel_domain, &input.connection_type).await?;

    debug!("Connection stage completed successfully");
    Ok(ConnectionOutput {
        ws_stream,
        connection_type: input.connection_type,
        tunnel_domain: input.tunnel_domain,
    })
}

#[instrument(skip_all, err)]
pub(crate) async fn handshake_stage(
    input: HandshakeInput,
    ux_sender: &dyn UxUpdateSender,
) -> Result<HandshakeOutput, Error> {
    debug!("Starting handshake stage");

    ux_sender
        .send_update(CableUxUpdate::CableUpdate(CableUpdate::Authenticating))
        .await;

    let mut ws_stream = input.ws_stream;
    let noise_state =
        tunnel::do_handshake(&mut ws_stream, input.psk, &input.connection_type).await?;

    debug!("Handshake stage completed successfully");
    ux_sender
        .send_update(CableUxUpdate::CableUpdate(CableUpdate::Connected))
        .await;

    ux_sender
        .set_connection_state(ConnectionState::Connected)
        .await;

    Ok(HandshakeOutput {
        ws_stream,
        noise_state,
        connection_type: input.connection_type,
        tunnel_domain: input.tunnel_domain,
    })
}

fn derive_psk(secret: &[u8], advert_plaintext: &[u8]) -> [u8; 32] {
    let mut psk: [u8; 32] = [0u8; 32];
    psk.copy_from_slice(&derive(secret, Some(advert_plaintext), KeyPurpose::PSK)[..32]);
    psk
}

pub(crate) fn decode_tunnel_domain_from_advert(advert: &DecryptedAdvert) -> Result<String, Error> {
    tunnel::decode_tunnel_server_domain(advert.encoded_tunnel_server_domain)
        .ok_or_else(|| {
            error!({ encoded = %advert.encoded_tunnel_server_domain }, "Failed to decode tunnel server domain");
            Error::Transport(TransportError::InvalidFraming)
        })
}
