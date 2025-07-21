use std::collections::BTreeMap;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use p256::{ecdh, NonZeroScalar};
use p256::{PublicKey, SecretKey};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use serde_indexed::DeserializeIndexed;
use sha2::{Digest, Sha256};
use snow::{Builder, TransportState};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, trace, warn};
use tungstenite::client::IntoClientRequest;

use super::known_devices::ClientPayload;
use super::known_devices::{CableKnownDeviceInfo, CableKnownDeviceInfoStore};
use crate::proto::ctap2::cbor::{self, CborRequest, CborResponse, Value};
use crate::proto::ctap2::{Ctap2CommandCode, Ctap2GetInfoResponse};
use crate::transport::cable::connection_stages::TunnelConnectionInput;
use crate::transport::cable::known_devices::CableKnownDeviceId;
use crate::transport::error::TransportError;
use crate::webauthn::error::Error;

fn ensure_rustls_crypto_provider() {
    use std::sync::Once;
    static RUSTLS_INIT: Once = Once::new();
    RUSTLS_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub(crate) const KNOWN_TUNNEL_DOMAINS: &[&str] = &["cable.ua5v.com", "cable.auth.com"];
const SHA_INPUT: &[u8] = b"caBLEv2 tunnel server domain";
const BASE32_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const TLDS: &[&str] = &[".com", ".org", ".net", ".info"];
const P256_X962_LENGTH: usize = 65;
const MAX_CBOR_SIZE: usize = 1024 * 1024;
const PADDING_GRANULARITY: usize = 32;

const CABLE_PROLOGUE_STATE_ASSISTED: &[u8] = &[0u8];
const CABLE_PROLOGUE_QR_INITIATED: &[u8] = &[1u8];

#[derive(Debug, Clone)]
struct CableTunnelMessage {
    message_type: CableTunnelMessageType,
    payload: ByteBuf,
}

impl CableTunnelMessage {
    pub fn new(message_type: CableTunnelMessageType, payload: &[u8]) -> Self {
        Self {
            message_type,
            payload: ByteBuf::from(payload.to_vec()),
        }
    }
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() < 2 {
            return Err(Error::Transport(TransportError::InvalidFraming));
        }

        let message_type = match slice[0] {
            0 => CableTunnelMessageType::Shutdown,
            1 => CableTunnelMessageType::Ctap,
            2 => CableTunnelMessageType::Update,
            _ => {
                return Err(Error::Transport(TransportError::InvalidFraming));
            }
        };

        Ok(Self {
            message_type,
            payload: ByteBuf::from(slice[1..].to_vec()),
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        // TODO: multiple versions
        vec.push(self.message_type as u8);
        vec.extend(self.payload.iter());
        vec
    }
}

#[derive(Clone, Debug, DeserializeIndexed)]
struct CableInitialMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x00)]
    pub _padding: Option<ByteBuf>,

    #[serde(index = 0x01)]
    pub info: ByteBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    pub _supported_features: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub(crate) struct CableLinkingInfo {
    /// Used by the tunnel to identify the authenticator (eg. Android FCM token)
    pub contact_id: Vec<u8>,
    /// Used by the authenticator to identify the client platform
    pub link_id: Vec<u8>,
    /// Shared secret between authenticator and client platform
    pub link_secret: Vec<u8>,
    /// Authenticator's public key, X9.62 uncompressed format
    pub authenticator_public_key: Vec<u8>,
    /// User-friendly name of the authenticator
    pub authenticator_name: String,
    /// HMAC of the handshake hash (Noise's channel binding value) using the
    /// shared secret (link_secret) as key
    #[allow(dead_code)]
    pub handshake_signature: Vec<u8>,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Deserialize)]
enum CableTunnelMessageType {
    Shutdown = 0,
    Ctap = 1,
    Update = 2,
}

pub fn decode_tunnel_server_domain(encoded: u16) -> Option<String> {
    if encoded < 256 {
        if encoded as usize >= KNOWN_TUNNEL_DOMAINS.len() {
            return None;
        }
        return Some(KNOWN_TUNNEL_DOMAINS[encoded as usize].to_string());
    }

    let mut sha_input = SHA_INPUT.to_vec();
    sha_input.push(encoded as u8);
    sha_input.push((encoded >> 8) as u8);
    sha_input.push(0);
    let mut hasher = Sha256::default();
    hasher.update(&sha_input);
    let digest = hasher.finalize();

    let mut v = u64::from_le_bytes(digest[..8].try_into().unwrap());
    let tld_index = v & 3;
    v >>= 2;

    let mut ret = String::from("cable.");
    while v != 0 {
        ret.push(BASE32_CHARS[(v & 31) as usize] as char);
        v >>= 5;
    }

    ret.push_str(TLDS[tld_index as usize]);
    Some(ret)
}

#[derive(Clone)]
pub(crate) enum CableTunnelConnectionType {
    QrCode {
        routing_id: String,
        tunnel_id: String,
        private_key: NonZeroScalar,
    },
    KnownDevice {
        contact_id: String,
        authenticator_public_key: Vec<u8>,
        client_payload: ClientPayload,
    },
}

impl std::fmt::Debug for CableTunnelConnectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QrCode {
                routing_id,
                tunnel_id,
                private_key: _,
            } => f
                .debug_struct("QrCode")
                .field("routing_id", routing_id)
                .field("tunnel_id", tunnel_id)
                .field("private_key", &"[REDACTED]")
                .finish(),
            Self::KnownDevice {
                contact_id,
                authenticator_public_key,
                client_payload,
            } => f
                .debug_struct("KnownDevice")
                .field("contact_id", contact_id)
                .field("authenticator_public_key", authenticator_public_key)
                .field("client_payload", client_payload)
                .finish(),
        }
    }
}

pub(crate) async fn connect<'d>(
    tunnel_domain: &str,
    connection_type: &CableTunnelConnectionType,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, TransportError> {
    ensure_rustls_crypto_provider();

    let connect_url = match connection_type {
        CableTunnelConnectionType::QrCode {
            routing_id,
            tunnel_id,
            ..
        } => format!(
            "wss://{}/cable/connect/{}/{}",
            tunnel_domain, routing_id, tunnel_id
        ),
        CableTunnelConnectionType::KnownDevice { contact_id, .. } => {
            format!("wss://{}/cable/contact/{}", tunnel_domain, contact_id)
        }
    };
    debug!(?connect_url, "Connecting to tunnel server");
    let mut request = connect_url
        .into_client_request()
        .or(Err(TransportError::InvalidEndpoint))?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "fido.cable"
            .parse()
            .or(Err(TransportError::InvalidEndpoint))?,
    );

    if let CableTunnelConnectionType::KnownDevice { client_payload, .. } = connection_type {
        let client_payload =
            cbor::to_vec(client_payload).or(Err(TransportError::InvalidEndpoint))?;
        request.headers_mut().insert(
            "X-caBLE-Client-Payload",
            hex::encode(&client_payload)
                .parse()
                .or(Err(TransportError::InvalidEndpoint))?,
        );
    }
    trace!(?request);

    let (ws_stream, response) = match connect_async(request).await {
        Ok((ws_stream, response)) => (ws_stream, response),
        Err(e) => {
            error!(?e, "Failed to connect to tunnel server");
            return Err(TransportError::ConnectionFailed);
        }
    };
    debug!(?response, "Connected to tunnel server");

    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        error!(?response, "Failed to switch to websocket protocol");
        return Err(TransportError::ConnectionFailed);
    }
    debug!("Tunnel server returned success");

    Ok(ws_stream)
}

pub(crate) struct TunnelNoiseState {
    pub transport_state: TransportState,
    #[allow(dead_code)]
    pub handshake_hash: Vec<u8>,
}

pub(crate) async fn do_handshake(
    ws_stream: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    psk: [u8; 32],
    connection_type: &CableTunnelConnectionType,
) -> Result<TunnelNoiseState, TransportError> {
    let noise_handshake = match connection_type {
        CableTunnelConnectionType::QrCode { private_key, .. } => {
            let local_private_key = private_key.to_owned().to_bytes();
            Builder::new("Noise_KNpsk0_P256_AESGCM_SHA256".parse()?)
                .prologue(CABLE_PROLOGUE_QR_INITIATED)?
                .local_private_key(local_private_key.as_slice())?
                .psk(0, &psk)?
                .build_initiator()
        }
        CableTunnelConnectionType::KnownDevice {
            authenticator_public_key,
            ..
        } => Builder::new("Noise_NKpsk0_P256_AESGCM_SHA256".parse()?)
            .prologue(CABLE_PROLOGUE_STATE_ASSISTED)?
            .remote_public_key(&authenticator_public_key)?
            .psk(0, &psk)?
            .build_initiator(),
    };

    // Build the Noise handshake as the initiator
    let mut noise_handshake = match noise_handshake {
        Ok(handshake) => handshake,
        Err(e) => {
            error!(?e, "Failed to build Noise handshake");
            return Err(TransportError::ConnectionFailed);
        }
    };

    let mut initial_msg_buffer = vec![0u8; 1024];
    let initial_msg_len = match noise_handshake.write_message(&[], &mut initial_msg_buffer) {
        Ok(msg_len) => msg_len,
        Err(e) => {
            error!(?e, "Failed to write initial handshake message");
            return Err(TransportError::ConnectionFailed);
        }
    };

    let initial_msg: Vec<u8> = initial_msg_buffer[..initial_msg_len].into();
    trace!(
        { handshake = ?initial_msg },
        "Sending initial handshake message"
    );

    if let Err(e) = ws_stream.send(Message::Binary(initial_msg.into())).await {
        error!(?e, "Failed to send initial handshake message");
        return Err(TransportError::ConnectionFailed);
    }
    debug!("Sent initial handshake message");

    // Read the response from the server and process it
    let response = match ws_stream.next().await {
        Some(Ok(Message::Binary(response))) => {
            debug!(response_len = response.len(), "Received handshake response");
            trace!(?response);
            response
        }

        Some(Ok(msg)) => {
            error!(?msg, "Unexpected message type received");
            return Err(TransportError::ConnectionFailed);
        }
        Some(Err(e)) => {
            error!(?e, "Failed to read handshake response");
            return Err(TransportError::ConnectionFailed);
        }
        None => {
            error!("Connection was closed before handshake was complete");
            return Err(TransportError::ConnectionFailed);
        }
    };

    /* output:
       keys trafficKeys,
       handshakeHash [32]byte) {
    */
    if response.len() < P256_X962_LENGTH {
        error!(
            { len = response.len() },
            "Peer handshake message is too short"
        );
        return Err(TransportError::ConnectionFailed);
    }

    let mut payload = [0u8; 1024];
    let payload_len = noise_handshake
        .read_message(&response, &mut payload)
        .unwrap();

    debug!(
        { handshake = ?payload[..payload_len] },
        "Received handshake response"
    );

    if !noise_handshake.is_handshake_finished() {
        error!("Handshake did not complete");
        return Err(TransportError::ConnectionFailed);
    }

    Ok(TunnelNoiseState {
        handshake_hash: noise_handshake.get_handshake_hash().to_vec(),
        transport_state: noise_handshake.into_transport_mode()?,
    })
}

pub(crate) async fn connection(mut input: TunnelConnectionInput) {
    // Fetch the inital message
    let get_info_response_serialized: Vec<u8> = match input.ws_stream.next().await {
        Some(Ok(message)) => match connection_recv_initial(message, &mut input.noise_state).await {
            Ok(initial) => initial,
            Err(e) => {
                error!(?e, "Failed to process initial message");
                return;
            }
        },
        Some(Err(e)) => {
            error!(?e, "Failed to read initial message");
            return;
        }
        None => {
            error!("Connection closed before initial message was received");
            return;
        }
    };
    debug!(?get_info_response_serialized, "Received initial message");

    loop {
        // Wait for a message on ws_stream, or a request to send on cbor_rx_send
        tokio::select! {
            Some(message) = input.ws_stream.next() => {
                match message {
                    Err(e) => {
                        error!(?e, "Failed to read encrypted CBOR message");
                        return;
                    }
                    Ok(message) => {
                        debug!("Received WSS message");
                        trace!(?message);
                        let _ = connection_recv(&input.connection_type, &input.tunnel_domain, &input.known_device_store, message, &input.cbor_rx_send, &mut input.noise_state).await;
                    }
                };
            }
            Some(request) = input.cbor_tx_recv.recv() => {
                match request.command {
                    // Optimisation: respond to GetInfo requests immediately with the cached response
                    Ctap2CommandCode::AuthenticatorGetInfo => {
                        debug!("Responding to GetInfo request with cached response");
                        let response = CborResponse::new_success_from_slice(&get_info_response_serialized);
                        let _ = input.cbor_rx_send.send(response).await;
                    }
                    _ => {
                        debug!(?request.command, "Sending CBOR request");
                        let _ = connection_send(request, &mut input.ws_stream, &mut input.noise_state).await;
                    }
                }
            }
            else => {
                // The sender has been dropped, so we should exit
                debug!("Sender dropped, closing connection");
                return;
            }
        };
    }
}

async fn connection_send(
    request: CborRequest,
    ws_stream: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    noise_state: &mut TunnelNoiseState,
) -> Result<(), Error> {
    debug!("Sending CBOR request");
    trace!(?request);

    let cbor_request = request
        .raw_long()
        .map_err(|e| TransportError::IoError(e.kind()))?;
    if cbor_request.len() > MAX_CBOR_SIZE {
        error!(
            cbor_request_len = cbor_request.len(),
            "CBOR request too large"
        );
        return Err(Error::Transport(TransportError::InvalidFraming));
    }
    trace!(?cbor_request, cbor_request_len = cbor_request.len());

    let extra_bytes = PADDING_GRANULARITY - (cbor_request.len() % PADDING_GRANULARITY);
    let padded_len = cbor_request.len() + extra_bytes;

    let mut padded_cbor_request = cbor_request.clone();
    padded_cbor_request.resize(padded_len, 0u8);
    padded_cbor_request[padded_len - 1] = (extra_bytes - 1) as u8;

    let frame = CableTunnelMessage::new(CableTunnelMessageType::Ctap, &padded_cbor_request);
    let frame_serialized = frame.to_vec();
    trace!(?frame_serialized);

    let mut encrypted_frame = vec![0u8; MAX_CBOR_SIZE + 1];
    match noise_state
        .transport_state
        .write_message(&frame_serialized, &mut encrypted_frame)
    {
        Ok(size) => {
            encrypted_frame.resize(size, 0u8);
        }
        Err(e) => {
            error!(?e, "Failed to encrypt frame");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    }

    debug!("Sending encrypted frame");
    trace!(?encrypted_frame);

    if let Err(e) = ws_stream.send(encrypted_frame.into()).await {
        error!(?e, "Failed to send encrypted frame");
        return Err(Error::Transport(TransportError::ConnectionFailed));
    }

    Ok(())
}

async fn connection_recv_binary_frame(message: Message) -> Result<Option<Vec<u8>>, Error> {
    match message {
        Message::Ping(_) | Message::Pong(_) => {
            debug!("Received keepalive message");
            Ok(None)
        }
        Message::Close(close_frame) => {
            debug!(?close_frame, "Received close frame");
            Err(Error::Transport(TransportError::ConnectionFailed))
        }
        Message::Binary(encrypted_frame) => {
            let encrypted_frame: Vec<u8> = encrypted_frame.into();
            debug!(
                frame_len = encrypted_frame.len(),
                "Received encrypted CBOR response"
            );
            trace!(?encrypted_frame);
            Ok(Some(encrypted_frame))
        }
        _ => {
            error!(?message, "Unexpected message type received");
            Err(Error::Transport(TransportError::ConnectionFailed))
        }
    }
}

async fn decrypt_frame(
    encrypted_frame: Vec<u8>,
    noise_state: &mut TunnelNoiseState,
) -> Result<Vec<u8>, Error> {
    let mut decrypted_frame = vec![0u8; MAX_CBOR_SIZE];
    match noise_state
        .transport_state
        .read_message(&encrypted_frame, &mut decrypted_frame)
    {
        Ok(size) => {
            debug!(decrypted_frame_len = size, "Decrypted CBOR response");
            decrypted_frame.resize(size, 0u8);
            trace!(?decrypted_frame);
        }
        Err(e) => {
            error!(?e, "Failed to decrypt CBOR response");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    }

    let padding_len = decrypted_frame[decrypted_frame.len() - 1] as usize;
    decrypted_frame.truncate(decrypted_frame.len() - (padding_len + 1));
    trace!(
        ?decrypted_frame,
        decrypted_frame_len = decrypted_frame.len(),
        "Trimmed padding"
    );

    Ok(decrypted_frame)
}

async fn connection_recv_initial(
    message: Message,
    noise_state: &mut TunnelNoiseState,
) -> Result<Vec<u8>, Error> {
    let Some(encrypted_frame) = connection_recv_binary_frame(message).await? else {
        return Err(Error::Transport(TransportError::ConnectionFailed));
    };

    let decrypted_frame = decrypt_frame(encrypted_frame, noise_state).await?;

    let initial_message: CableInitialMessage = match cbor::from_slice(&decrypted_frame) {
        Ok(initial_message) => initial_message,
        Err(e) => {
            error!(?e, "Failed to decode initial message");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };

    let _: Ctap2GetInfoResponse = match cbor::from_slice(&initial_message.info) {
        Ok(get_info_response) => get_info_response,
        Err(e) => {
            error!(?e, "Failed to decode GetInfo response");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };

    Ok(initial_message.info.to_vec())
}

async fn connection_recv_update(message: &[u8]) -> Result<Option<CableLinkingInfo>, Error> {
    // TODO(#66): Android adds a 999-key to the end the message, which is not part of the standard.
    // For now, we parse the message to a map and manuually import fields.

    let update_message: BTreeMap<Value, Value> = match serde_cbor::from_slice(&message) {
        Ok(update_message) => update_message,
        Err(e) => {
            error!(?e, "Failed to decode update message");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };

    let Some(Value::Map(linking_info_map)) = update_message.get(&Value::Integer(0x01)) else {
        warn!("Empty linking info map");
        return Ok(None);
    };

    trace!(?linking_info_map);

    let Some(Value::Bytes(contact_id)) = linking_info_map.get(&Value::Integer(0x01)) else {
        warn!("Missing contact ID");
        return Ok(None);
    };

    let Some(Value::Bytes(link_id)) = linking_info_map.get(&Value::Integer(0x02)) else {
        warn!("Missing link ID");
        return Ok(None);
    };

    let Some(Value::Bytes(link_secret)) = linking_info_map.get(&Value::Integer(0x03)) else {
        warn!("Missing link secret");
        return Ok(None);
    };

    let Some(Value::Bytes(authenticator_public_key)) = linking_info_map.get(&Value::Integer(0x04))
    else {
        warn!("Missing authenticator public key");
        return Ok(None);
    };

    let Some(Value::Text(authenticator_name)) = linking_info_map.get(&Value::Integer(0x05)) else {
        warn!("Missing authenticator name");
        return Ok(None);
    };

    let Some(Value::Bytes(handshake_signature)) = linking_info_map.get(&Value::Integer(0x06))
    else {
        warn!("Missing handshake_signature");
        return Ok(None);
    };

    let linking_info = CableLinkingInfo {
        contact_id: contact_id.clone(),
        link_id: link_id.clone(),
        link_secret: link_secret.clone(),
        authenticator_public_key: authenticator_public_key.clone(),
        authenticator_name: authenticator_name.clone(),
        handshake_signature: handshake_signature.clone(),
    };

    Ok(Some(linking_info))
}

async fn connection_recv(
    connection_type: &CableTunnelConnectionType,
    tunnel_domain: &str,
    known_device_store: &Option<Arc<dyn CableKnownDeviceInfoStore>>,
    message: Message,
    cbor_rx_send: &Sender<CborResponse>,
    noise_state: &mut TunnelNoiseState,
) -> Result<(), Error> {
    let Some(encrypted_frame) = connection_recv_binary_frame(message).await? else {
        return Ok(());
    };

    let decrypted_frame = decrypt_frame(encrypted_frame, noise_state).await?;

    // TODO handle the decrypted frame
    let cable_message: CableTunnelMessage = match CableTunnelMessage::from_slice(&decrypted_frame) {
        Ok(cable_message) => cable_message,
        Err(e) => {
            error!(?e, "Failed to decode CABLE tunnel message");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };

    trace!(?cable_message);
    match cable_message.message_type {
        CableTunnelMessageType::Shutdown => {
            // Unexpected shutdown message
            error!("Received unexpected shutdown message");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
        CableTunnelMessageType::Ctap => {
            // Handle the CTAP message
            let cbor_response: CborResponse = (&cable_message.payload.to_vec())
                .try_into()
                .or(Err(TransportError::InvalidFraming))?;

            debug!("Received CBOR response");
            trace!(?cbor_response);
            cbor_rx_send
                .send(cbor_response)
                .await
                .or(Err(TransportError::ConnectionFailed))?;
        }
        CableTunnelMessageType::Update => {
            // Handle the update message
            let maybe_update_message: Option<CableLinkingInfo> =
                connection_recv_update(&cable_message.payload).await?;

            let Some(linking_info) = maybe_update_message else {
                warn!("Ignoring update message without linking info");
                return Ok(());
            };

            let CableTunnelConnectionType::QrCode { private_key, .. } = connection_type else {
                warn!("Ignoring update message for non-QR code connection");
                return Ok(());
            };

            debug!("Received update message with linking info");
            trace!(?linking_info);

            let device_id: CableKnownDeviceId = (&linking_info).into();
            match known_device_store {
                Some(store) => {
                    match parse_known_device(
                        private_key,
                        tunnel_domain,
                        &linking_info,
                        &noise_state,
                    ) {
                        Ok(known_device) => {
                            debug!(?device_id, "Updating known device");
                            trace!(?known_device);
                            store.put_known_device(&device_id, &known_device).await;
                        }
                        Err(e) => {
                            error!(
                                ?e,
                                "Invalid update message from authenticator, forgetting device"
                            );
                            store.delete_known_device(&device_id).await;
                            return Err(Error::Transport(TransportError::TransportUnavailable));
                        }
                    }
                }
                None => {
                    warn!("Ignoring update message without a device store");
                }
            };
        }
    };

    Ok(())
}

/// Validation requires a shared key computed on the QR code ephemeral identity key (private_key here).
/// We're currently unable to validate the signature on linking information received for state-assisted transactions,
/// so these should be discarded. This is the same Chrome currently does, although it may change in future spec versions.
/// See: https://github.com/chromium/chromium/blob/88e250200e59daf52554bcc74870138143a830c4/device/fido/cable/fido_tunnel_device.cc#L547-L549
fn parse_known_device(
    private_key: &NonZeroScalar,
    tunnel_domain: &str,
    linking_info: &CableLinkingInfo,
    noise_state: &TunnelNoiseState,
) -> Result<CableKnownDeviceInfo, Error> {
    let known_device = CableKnownDeviceInfo::new(tunnel_domain, linking_info)?;
    let secret_key = SecretKey::from(private_key);

    let Ok(authenticator_public_key) =
        PublicKey::from_sec1_bytes(&linking_info.authenticator_public_key)
    else {
        error!("Failed to parse public key.");
        return Err(Error::Transport(TransportError::InvalidKey));
    };

    let shared_secret: Vec<u8> = ecdh::diffie_hellman(
        secret_key.to_nonzero_scalar(),
        authenticator_public_key.as_affine(),
    )
    .raw_secret_bytes()
    .to_vec();

    let mut hmac = Hmac::<Sha256>::new_from_slice(&shared_secret).expect("Any key size is valid");
    hmac.update(&noise_state.handshake_hash);
    let expected_mac = hmac.finalize().into_bytes().to_vec();

    if expected_mac != linking_info.handshake_signature {
        error!("Invalid handshake signature, rejecting update message");
        trace!(?expected_mac, ?linking_info.handshake_signature);
        return Err(Error::Transport(TransportError::InvalidSignature));
    }

    debug!("Parsed known device with valid signature");
    Ok(known_device)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decode_tunnel_server_domain_known() {
        assert_eq!(
            decode_tunnel_server_domain(0).unwrap(),
            "cable.ua5v.com".to_string()
        );
        assert_eq!(
            decode_tunnel_server_domain(1).unwrap(),
            "cable.auth.com".to_string()
        );
    }

    // TODO: test the non-known case
}
