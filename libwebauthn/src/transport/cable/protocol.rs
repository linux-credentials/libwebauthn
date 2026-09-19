//! Transport-agnostic Noise handshake and encrypted CTAP framing for the
//! hybrid transport. Runs over any [`CableDataChannel`].
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use p256::{ecdh, NonZeroScalar};
use p256::{PublicKey, SecretKey};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use serde_cbor_2 as serde_cbor;
use serde_indexed::DeserializeIndexed;
use sha2::Sha256;
use snow::{Builder, TransportState};
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, trace, warn};

use super::data_channel::CableDataChannel;
use super::known_devices::ClientPayload;
use super::known_devices::{CableKnownDeviceInfo, CableKnownDeviceInfoStore};
use crate::proto::ctap2::cbor::{self, CborRequest, CborResponse, Value};
use crate::proto::ctap2::{Ctap2CommandCode, Ctap2GetInfoResponse};
use crate::transport::cable::channel::ConnectionState;
use crate::transport::cable::connection_stages::{
    next_teardown, TunnelConnectionInput, UxUpdateSender,
};
use crate::transport::cable::error::CableError;
use crate::transport::cable::known_devices::CableKnownDeviceId;
use crate::transport::cable::linger::{CableLingerConfig, LingerParams, Teardown};

const P256_X962_LENGTH: usize = 65;
const MAX_CBOR_SIZE: usize = 1024 * 1024;
const PADDING_GRANULARITY: usize = 32;

/// Bounds every outbound send, so a dead socket cannot stall teardown.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Poll granularity of the linger receive, so the deadline and teardown are re-checked.
const LINGER_RECV_POLL: Duration = Duration::from_secs(30);
/// Bounds the processing of one linger frame, including the caller's store write.
const STORE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Consecutive undecryptable frames before a lingering connection gives up.
const DECRYPT_FAILURE_BUDGET: u32 = 3;

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
    pub fn from_slice(slice: &[u8]) -> Result<Self, CableError> {
        let (type_byte, payload) = slice.split_first().ok_or(CableError::InvalidFraming)?;

        let message_type = match *type_byte {
            0 => CableTunnelMessageType::Shutdown,
            1 => CableTunnelMessageType::Ctap,
            2 => CableTunnelMessageType::Update,
            _ => {
                return Err(CableError::InvalidFraming);
            }
        };

        // Shutdown is the type byte alone. Ctap and Update must carry a payload.
        if payload.is_empty() && message_type != CableTunnelMessageType::Shutdown {
            return Err(CableError::InvalidFraming);
        }

        Ok(Self {
            message_type,
            payload: ByteBuf::from(payload.to_vec()),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum CableTunnelMessageType {
    Shutdown = 0,
    Ctap = 1,
    Update = 2,
}

/// Result of processing a single inbound tunnel frame.
enum RecvOutcome {
    /// Frame handled, keep the loop running.
    Continue,
    /// Peer sent a `Shutdown` control message; close the channel cleanly.
    PeerShutdown,
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

pub(crate) struct TunnelNoiseState {
    pub transport_state: TransportState,
    #[allow(dead_code)]
    pub handshake_hash: Vec<u8>,
}

pub(crate) async fn do_handshake(
    data_channel: &mut dyn CableDataChannel,
    psk: [u8; 32],
    connection_type: &CableTunnelConnectionType,
) -> Result<TunnelNoiseState, CableError> {
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
            .remote_public_key(authenticator_public_key)?
            .psk(0, &psk)?
            .build_initiator(),
    };

    // Build the Noise handshake as the initiator
    let mut noise_handshake = match noise_handshake {
        Ok(handshake) => handshake,
        Err(e) => {
            error!(?e, "Failed to build Noise handshake");
            return Err(CableError::ConnectionFailed);
        }
    };

    let mut initial_msg_buffer = vec![0u8; 1024];
    let initial_msg_len = match noise_handshake.write_message(&[], &mut initial_msg_buffer) {
        Ok(msg_len) => msg_len,
        Err(e) => {
            error!(?e, "Failed to write initial handshake message");
            return Err(CableError::ConnectionFailed);
        }
    };

    let initial_msg: Vec<u8> = initial_msg_buffer
        .get(..initial_msg_len)
        .map(<[u8]>::to_vec)
        .ok_or(CableError::ConnectionFailed)?;
    trace!(
        { handshake = ?initial_msg },
        "Sending initial handshake message"
    );

    data_channel.send(&initial_msg).await?;
    debug!("Sent initial handshake message");

    // Read the response from the peer and process it
    let response = match data_channel.recv().await {
        Ok(Some(response)) => {
            debug!(response_len = response.len(), "Received handshake response");
            trace!(?response);
            response
        }
        Ok(None) => {
            error!("Connection was closed before handshake was complete");
            return Err(CableError::ConnectionFailed);
        }
        Err(e) => {
            error!(?e, "Failed to read handshake response");
            return Err(e);
        }
    };

    if response.len() < P256_X962_LENGTH {
        error!(
            { len = response.len() },
            "Peer handshake message is too short"
        );
        return Err(CableError::ConnectionFailed);
    }

    let mut payload = [0u8; 1024];
    let payload_len = match noise_handshake.read_message(&response, &mut payload) {
        Ok(len) => len,
        Err(e) => {
            error!(?e, "Failed to read handshake response message");
            return Err(CableError::ConnectionFailed);
        }
    };

    debug!(
        { handshake = ?payload.get(..payload_len) },
        "Received handshake response"
    );

    if !noise_handshake.is_handshake_finished() {
        error!("Handshake did not complete");
        return Err(CableError::ConnectionFailed);
    }

    Ok(TunnelNoiseState {
        handshake_hash: noise_handshake.get_handshake_hash().to_vec(),
        transport_state: noise_handshake.into_transport_mode()?,
    })
}

/// Returns `Ok(())` on a clean close and `Err(_)` on any fault that leaves
/// the encrypted channel unusable; callers surface `Err(_)` via `send_error`.
pub(crate) async fn connection(
    mut input: TunnelConnectionInput,
    ux_sender: &dyn UxUpdateSender,
) -> Result<(), CableError> {
    // The secure channel exists, so a graceful teardown before the initial
    // message still gets a courtesy Shutdown.
    let get_info_response_serialized: Vec<u8> = loop {
        tokio::select! {
            biased;
            intent = next_teardown(&mut input.teardown_rx) => match intent {
                Teardown::Close | Teardown::Linger => {
                    send_shutdown_bounded(&mut *input.data_channel, &mut input.noise_state).await;
                    return Ok(());
                }
                Teardown::Cancel => return Ok(()),
                Teardown::Active => continue,
            },
            result = input.data_channel.recv() => match result {
                Ok(Some(message)) => {
                    match connection_recv_initial(message, &mut input.noise_state).await {
                        Ok(initial) => break initial,
                        Err(e) => {
                            error!(?e, "Failed to process initial message");
                            return Err(e);
                        }
                    }
                }
                Ok(None) => {
                    error!("Connection closed before initial message was received");
                    return Err(CableError::ConnectionLost);
                }
                Err(e) => {
                    error!(?e, "Failed to read initial message");
                    return Err(e);
                }
            },
        }
    };
    debug!(?get_info_response_serialized, "Received initial message");

    loop {
        tokio::select! {
            biased;
            intent = next_teardown(&mut input.teardown_rx) => match intent {
                Teardown::Close => {
                    debug!("Channel close requested, sending Shutdown control frame");
                    send_shutdown_bounded(&mut *input.data_channel, &mut input.noise_state).await;
                    return Ok(());
                }
                Teardown::Linger => {
                    debug!("Channel linger requested, sending Shutdown control frame");
                    send_shutdown_bounded(&mut *input.data_channel, &mut input.noise_state).await;
                    break;
                }
                Teardown::Cancel => {
                    debug!("Channel cancelled, dropping the connection");
                    return Ok(());
                }
                Teardown::Active => {}
            },
            result = input.data_channel.recv() => {
                match result {
                    Ok(Some(message)) => {
                        debug!("Received data channel message");
                        trace!(?message);
                        match connection_recv(
                            &input.connection_type,
                            &input.tunnel_domain,
                            &input.known_device_store,
                            message,
                            &input.cbor_rx_send,
                            &mut input.noise_state,
                        )
                        .await
                        {
                            Ok(RecvOutcome::Continue) => {}
                            Ok(RecvOutcome::PeerShutdown) => return Ok(()),
                            Err(e) => {
                                error!(?e, "Fatal error processing inbound frame");
                                return Err(e);
                            }
                        }
                    }
                    Ok(None) => {
                        debug!("Data channel closed, closing connection");
                        return Ok(());
                    }
                    Err(e) => {
                        error!(?e, "Failed to read encrypted CBOR message");
                        return Err(e);
                    }
                }
            }
            Some(request) = input.cbor_tx_recv.recv() => {
                match request.command {
                    // Optimisation: respond to GetInfo requests immediately with the cached response
                    Ctap2CommandCode::AuthenticatorGetInfo => {
                        debug!("Responding to GetInfo request with cached response");
                        let response = CborResponse::new_success_from_slice(&get_info_response_serialized);
                        if let Err(e) = input.cbor_rx_send.send(response).await {
                            error!(?e, "CBOR response receiver dropped");
                            return Err(CableError::ConnectionFailed);
                        }
                    }
                    _ => {
                        debug!(?request.command, "Sending CBOR request");
                        let send = connection_send(
                            request,
                            &mut *input.data_channel,
                            &mut input.noise_state,
                        );
                        match tokio::time::timeout(SEND_TIMEOUT, send).await {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                error!(?e, "Fatal error sending CBOR request");
                                return Err(e);
                            }
                            Err(_) => {
                                error!("Timed out sending CBOR request");
                                return Err(CableError::Timeout);
                            }
                        }
                    }
                }
            }
        };
    }

    // Only a QR-initiated connection with a store can use a linking update.
    let eligible = matches!(
        input.connection_type,
        CableTunnelConnectionType::QrCode { .. }
    ) && input.known_device_store.is_some();
    match input.linger.take() {
        Some(params) if eligible && params.guard.is_live() => {
            linger(input, params, ux_sender).await
        }
        _ => {}
    }
    Ok(())
}

/// Outcome of one frame received while lingering.
enum LingerStep {
    Keep,
    PeerClosed,
}

/// Keeps receiving after Shutdown to capture a late linking update. Detached
/// from the channel, so every await is bounded and the whole phase sits under
/// an absolute ceiling of [`CableLingerConfig::HARD_CAP`].
async fn linger(
    mut input: TunnelConnectionInput,
    params: LingerParams,
    ux_sender: &dyn UxUpdateSender,
) {
    ux_sender
        .set_connection_state(ConnectionState::Lingering)
        .await;
    debug!(linger_duration = ?params.linger_duration, "Lingering for a late linking update");

    let now = tokio::time::Instant::now();
    let deadline = now + params.linger_duration;
    let hard_cap = now + CableLingerConfig::HARD_CAP;
    let mut decrypt_failures = 0u32;

    let run = async {
        loop {
            tokio::select! {
                biased;
                _ = next_teardown(&mut input.teardown_rx) => {
                    debug!("Linger cancelled");
                    break;
                }
                _ = tokio::time::sleep_until(deadline) => {
                    debug!("Linger window elapsed");
                    break;
                }
                received = tokio::time::timeout(LINGER_RECV_POLL, input.data_channel.recv()) => {
                    let frame = match received {
                        Err(_elapsed) => continue,
                        Ok(Ok(Some(frame))) => frame,
                        Ok(Ok(None)) | Ok(Err(_)) => {
                            debug!("Peer closed the connection while lingering");
                            break;
                        }
                    };
                    let step = linger_recv(
                        &input.connection_type,
                        &input.tunnel_domain,
                        &input.known_device_store,
                        frame,
                        &mut input.noise_state,
                    );
                    match tokio::time::timeout(STORE_WRITE_TIMEOUT, step).await {
                        Ok(Ok(LingerStep::Keep)) => decrypt_failures = 0,
                        Ok(Ok(LingerStep::PeerClosed)) => break,
                        // A desynced peer fails every following frame. Anything
                        // else that decrypts is merely ignored.
                        Ok(Err(CableError::EncryptionFailed)) => {
                            decrypt_failures += 1;
                            warn!(decrypt_failures, "Undecryptable frame while lingering");
                            if decrypt_failures >= DECRYPT_FAILURE_BUDGET {
                                break;
                            }
                        }
                        Ok(Err(e)) => debug!(?e, "Ignoring undecodable frame while lingering"),
                        Err(_elapsed) => {
                            warn!("Timed out processing a frame while lingering");
                            break;
                        }
                    }
                }
            }
        }
    };
    if tokio::time::timeout_at(hard_cap, run).await.is_err() {
        warn!("Linger hit the hard cap");
    }
    // The registry guard drops with `params` here, deregistering the connection.
    drop(params);
}

/// Processes one frame received while lingering. Only a linking update has
/// any effect. Nothing is ever forwarded to the CBOR receiver.
async fn linger_recv(
    connection_type: &CableTunnelConnectionType,
    tunnel_domain: &str,
    known_device_store: &Option<Arc<dyn CableKnownDeviceInfoStore>>,
    encrypted_frame: Vec<u8>,
    noise_state: &mut TunnelNoiseState,
) -> Result<LingerStep, CableError> {
    let decrypted_frame = decrypt_frame(encrypted_frame, noise_state).await?;
    let cable_message = CableTunnelMessage::from_slice(&decrypted_frame)?;
    match cable_message.message_type {
        CableTunnelMessageType::Shutdown => Ok(LingerStep::PeerClosed),
        CableTunnelMessageType::Ctap => {
            debug!("Ignoring CTAP frame while lingering");
            Ok(LingerStep::Keep)
        }
        CableTunnelMessageType::Update => {
            handle_update_message(
                connection_type,
                tunnel_domain,
                known_device_store,
                &cable_message.payload,
                &noise_state.handshake_hash,
            )
            .await;
            Ok(LingerStep::Keep)
        }
    }
}

/// Best-effort Shutdown on a graceful teardown. A failure or timeout is
/// logged and otherwise ignored, since the connection is going away anyway.
async fn send_shutdown_bounded(
    data_channel: &mut dyn CableDataChannel,
    noise_state: &mut TunnelNoiseState,
) {
    let send = connection_send_shutdown(data_channel, noise_state);
    match tokio::time::timeout(SEND_TIMEOUT, send).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(?e, "Failed to send Shutdown control frame"),
        Err(_) => warn!("Timed out sending Shutdown control frame"),
    }
}

async fn connection_send(
    request: CborRequest,
    data_channel: &mut dyn CableDataChannel,
    noise_state: &mut TunnelNoiseState,
) -> Result<(), CableError> {
    debug!("Sending CBOR request");
    trace!(?request);

    let cbor_request = request.raw_long().map_err(CableError::from)?;
    if cbor_request.len() > MAX_CBOR_SIZE {
        error!(
            cbor_request_len = cbor_request.len(),
            "CBOR request too large"
        );
        return Err(CableError::InvalidFraming);
    }
    trace!(?cbor_request, cbor_request_len = cbor_request.len());

    send_tunnel_frame(
        CableTunnelMessageType::Ctap,
        &cbor_request,
        data_channel,
        noise_state,
    )
    .await
}

/// Sends an empty `Shutdown` control frame over the encrypted channel.
async fn connection_send_shutdown(
    data_channel: &mut dyn CableDataChannel,
    noise_state: &mut TunnelNoiseState,
) -> Result<(), CableError> {
    debug!("Sending Shutdown control frame");
    send_tunnel_frame(
        CableTunnelMessageType::Shutdown,
        &[],
        data_channel,
        noise_state,
    )
    .await
}

/// Pads `payload`, wraps it in a `CableTunnelMessage`, encrypts it, and sends it.
async fn send_tunnel_frame(
    message_type: CableTunnelMessageType,
    payload: &[u8],
    data_channel: &mut dyn CableDataChannel,
    noise_state: &mut TunnelNoiseState,
) -> Result<(), CableError> {
    let extra_bytes = PADDING_GRANULARITY - (payload.len() % PADDING_GRANULARITY);
    let padded_len = payload.len() + extra_bytes;

    let mut padded_payload = payload.to_vec();
    padded_payload.resize(padded_len, 0u8);
    if let Some(last) = padded_payload.last_mut() {
        *last = (extra_bytes - 1) as u8;
    }

    let frame = CableTunnelMessage::new(message_type, &padded_payload);
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
            return Err(CableError::EncryptionFailed);
        }
    }

    debug!("Sending encrypted frame");
    trace!(?encrypted_frame);

    data_channel.send(&encrypted_frame).await?;
    Ok(())
}

/// Strip the trailing padding-length byte and `padding_len` bytes of padding
/// from a decrypted Noise transport frame, returning `InvalidFraming` on an
/// empty plaintext or a declared padding length that exceeds the frame.
fn strip_frame_padding(mut decrypted_frame: Vec<u8>) -> Result<Vec<u8>, CableError> {
    let padding_len = match decrypted_frame.last() {
        Some(&b) => b as usize,
        None => {
            error!("Decrypted frame is empty; cannot read padding length");
            return Err(CableError::InvalidFraming);
        }
    };
    let new_len = decrypted_frame
        .len()
        .checked_sub(padding_len + 1)
        .ok_or_else(|| {
            error!(
                frame_len = decrypted_frame.len(),
                padding_len, "Padding length exceeds frame length"
            );
            CableError::InvalidFraming
        })?;
    decrypted_frame.truncate(new_len);
    Ok(decrypted_frame)
}

async fn decrypt_frame(
    encrypted_frame: Vec<u8>,
    noise_state: &mut TunnelNoiseState,
) -> Result<Vec<u8>, CableError> {
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
            return Err(CableError::EncryptionFailed);
        }
    }

    let decrypted_frame = strip_frame_padding(decrypted_frame)?;
    trace!(
        ?decrypted_frame,
        decrypted_frame_len = decrypted_frame.len(),
        "Trimmed padding"
    );

    Ok(decrypted_frame)
}

async fn connection_recv_initial(
    encrypted_frame: Vec<u8>,
    noise_state: &mut TunnelNoiseState,
) -> Result<Vec<u8>, CableError> {
    let decrypted_frame = decrypt_frame(encrypted_frame, noise_state).await?;

    let initial_message: CableInitialMessage = match cbor::from_slice(&decrypted_frame) {
        Ok(initial_message) => initial_message,
        Err(e) => {
            error!(?e, "Failed to decode initial message");
            return Err(CableError::InvalidFraming);
        }
    };

    let _: Ctap2GetInfoResponse = match cbor::from_slice(&initial_message.info) {
        Ok(get_info_response) => get_info_response,
        Err(e) => {
            error!(?e, "Failed to decode GetInfo response");
            return Err(CableError::InvalidFraming);
        }
    };

    Ok(initial_message.info.to_vec())
}

async fn connection_recv_update(message: &[u8]) -> Result<Option<CableLinkingInfo>, CableError> {
    // TODO(#66): Android adds a 999-key to the end the message, which is not part of the standard.
    // For now, we parse the message to a map and manuually import fields.

    let update_message: BTreeMap<Value, Value> = match serde_cbor::from_slice(message) {
        Ok(update_message) => update_message,
        Err(e) => {
            error!(?e, "Failed to decode update message");
            return Err(CableError::InvalidFraming);
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
    encrypted_frame: Vec<u8>,
    cbor_rx_send: &Sender<CborResponse>,
    noise_state: &mut TunnelNoiseState,
) -> Result<RecvOutcome, CableError> {
    let decrypted_frame = decrypt_frame(encrypted_frame, noise_state).await?;

    let cable_message: CableTunnelMessage = CableTunnelMessage::from_slice(&decrypted_frame)
        .inspect_err(|e| error!(?e, "Failed to decode CABLE tunnel message"))?;

    trace!(?cable_message);
    match cable_message.message_type {
        CableTunnelMessageType::Shutdown => {
            debug!("Peer sent Shutdown control message; closing connection cleanly");
            Ok(RecvOutcome::PeerShutdown)
        }
        CableTunnelMessageType::Ctap => {
            let cbor_response: CborResponse = (&cable_message.payload.to_vec())
                .try_into()
                .or(Err(CableError::InvalidFraming))?;

            debug!("Received CBOR response");
            trace!(?cbor_response);
            cbor_rx_send
                .send(cbor_response)
                .await
                .or(Err(CableError::ConnectionFailed))?;
            Ok(RecvOutcome::Continue)
        }
        CableTunnelMessageType::Update => {
            let update = handle_update_message(
                connection_type,
                tunnel_domain,
                known_device_store,
                &cable_message.payload,
                &noise_state.handshake_hash,
            );
            if tokio::time::timeout(STORE_WRITE_TIMEOUT, update)
                .await
                .is_err()
            {
                warn!("Timed out storing a linking update; ignoring it");
            }
            Ok(RecvOutcome::Continue)
        }
    }
}

/// Applies a linking update to the store. Malformed, unsigned, non-QR or
/// store-less updates are logged and dropped without affecting the channel.
async fn handle_update_message(
    connection_type: &CableTunnelConnectionType,
    tunnel_domain: &str,
    known_device_store: &Option<Arc<dyn CableKnownDeviceInfoStore>>,
    payload: &[u8],
    handshake_hash: &[u8],
) {
    let maybe_update_message = match connection_recv_update(payload).await {
        Ok(m) => m,
        Err(e) => {
            warn!(?e, "Malformed update message; ignoring");
            return;
        }
    };

    let Some(linking_info) = maybe_update_message else {
        warn!("Ignoring update message without linking info");
        return;
    };

    let CableTunnelConnectionType::QrCode { private_key, .. } = connection_type else {
        warn!("Ignoring update message for non-QR code connection");
        return;
    };

    debug!("Received update message with linking info");
    trace!(?linking_info);

    match known_device_store {
        Some(store) => {
            apply_linking_update(
                store,
                private_key,
                tunnel_domain,
                &linking_info,
                handshake_hash,
            )
            .await;
        }
        None => {
            warn!("Ignoring update message without a device store");
        }
    };
}

/// Stores the update only on a valid signature; invalid updates are dropped without evicting.
async fn apply_linking_update(
    store: &Arc<dyn CableKnownDeviceInfoStore>,
    private_key: &NonZeroScalar,
    tunnel_domain: &str,
    linking_info: &CableLinkingInfo,
    handshake_hash: &[u8],
) {
    let device_id: CableKnownDeviceId = linking_info.into();
    match parse_known_device(private_key, tunnel_domain, linking_info, handshake_hash) {
        Ok(known_device) => {
            debug!(?device_id, "Updating known device");
            trace!(?known_device);
            store.put_known_device(&device_id, &known_device).await;
        }
        Err(e) => {
            warn!(?e, "Ignoring invalid linking update from authenticator");
        }
    }
}

/// Validation requires a shared key computed on the QR code ephemeral identity key (private_key here).
/// We're currently unable to validate the signature on linking information received for state-assisted transactions,
/// so these should be discarded. This is the same Chrome currently does, although it may change in future spec versions.
/// See: https://github.com/chromium/chromium/blob/88e250200e59daf52554bcc74870138143a830c4/device/fido/cable/fido_tunnel_device.cc#L547-L549
fn parse_known_device(
    private_key: &NonZeroScalar,
    tunnel_domain: &str,
    linking_info: &CableLinkingInfo,
    handshake_hash: &[u8],
) -> Result<CableKnownDeviceInfo, CableError> {
    let known_device = CableKnownDeviceInfo::new(tunnel_domain, linking_info)?;
    let secret_key = SecretKey::from(private_key);

    let Ok(authenticator_public_key) =
        PublicKey::from_sec1_bytes(&linking_info.authenticator_public_key)
    else {
        error!("Failed to parse public key.");
        return Err(CableError::InvalidKey);
    };

    let shared_secret: Vec<u8> = ecdh::diffie_hellman(
        secret_key.to_nonzero_scalar(),
        authenticator_public_key.as_affine(),
    )
    .raw_secret_bytes()
    .to_vec();

    let mut hmac =
        Hmac::<Sha256>::new_from_slice(&shared_secret).map_err(|_| CableError::InvalidKey)?;
    hmac.update(handshake_hash);
    let expected_mac = hmac.finalize().into_bytes().to_vec();

    if expected_mac != linking_info.handshake_signature {
        error!("Invalid handshake signature, rejecting update message");
        trace!(?expected_mac, ?linking_info.handshake_signature);
        return Err(CableError::InvalidSignature);
    }

    debug!("Parsed known device with valid signature");
    Ok(known_device)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use async_trait::async_trait;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;

    #[derive(Debug, Default)]
    struct RecordingStore {
        puts: Mutex<Vec<CableKnownDeviceId>>,
        deletes: Mutex<Vec<CableKnownDeviceId>>,
    }

    #[async_trait]
    impl CableKnownDeviceInfoStore for RecordingStore {
        async fn put_known_device(
            &self,
            device_id: &CableKnownDeviceId,
            _device: &CableKnownDeviceInfo,
        ) {
            if let Ok(mut puts) = self.puts.lock() {
                puts.push(device_id.clone());
            }
        }
        async fn delete_known_device(&self, device_id: &CableKnownDeviceId) {
            if let Ok(mut deletes) = self.deletes.lock() {
                deletes.push(device_id.clone());
            }
        }
    }

    fn linking_info_with_authenticator_key(authenticator_public_key: Vec<u8>) -> CableLinkingInfo {
        CableLinkingInfo {
            contact_id: vec![0u8; 4],
            link_id: vec![0u8; 8],
            link_secret: vec![0u8; 32],
            authenticator_public_key,
            authenticator_name: "alice's authenticator".to_string(),
            handshake_signature: vec![0xFFu8; 32],
        }
    }

    #[tokio::test]
    async fn invalid_signature_does_not_evict() {
        let client_private_key = NonZeroScalar::random(&mut OsRng);
        let authenticator_secret = SecretKey::random(&mut OsRng);
        let authenticator_public_key = authenticator_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let linking_info = linking_info_with_authenticator_key(authenticator_public_key);

        let recording = Arc::new(RecordingStore::default());
        let store: Arc<dyn CableKnownDeviceInfoStore> = recording.clone();

        // Signature is intentionally bogus, so the update must be rejected.
        apply_linking_update(
            &store,
            &client_private_key,
            "example.com",
            &linking_info,
            &[0u8; 32],
        )
        .await;

        assert!(
            recording.deletes.lock().expect("deletes").is_empty(),
            "invalid update must not delete a known device"
        );
        assert!(
            recording.puts.lock().expect("puts").is_empty(),
            "invalid update must not store anything"
        );
    }

    #[test]
    fn from_slice_accepts_type_only_shutdown() {
        let message = CableTunnelMessage::from_slice(&[0]).unwrap();
        assert_eq!(message.message_type, CableTunnelMessageType::Shutdown);
        assert!(message.payload.is_empty());
    }

    #[test]
    fn from_slice_rejects_empty_ctap_and_update() {
        assert!(matches!(
            CableTunnelMessage::from_slice(&[1]),
            Err(CableError::InvalidFraming)
        ));
        assert!(matches!(
            CableTunnelMessage::from_slice(&[2]),
            Err(CableError::InvalidFraming)
        ));
    }

    #[test]
    fn from_slice_rejects_empty_frame_and_unknown_type() {
        assert!(matches!(
            CableTunnelMessage::from_slice(&[]),
            Err(CableError::InvalidFraming)
        ));
        assert!(matches!(
            CableTunnelMessage::from_slice(&[3, 0]),
            Err(CableError::InvalidFraming)
        ));
    }

    #[test]
    fn strip_frame_padding_rejects_empty() {
        let result = strip_frame_padding(Vec::new());
        assert!(matches!(result, Err(CableError::InvalidFraming)));
    }

    #[test]
    fn strip_frame_padding_rejects_overlong_padding() {
        // Length 1 + declared padding of 5 -> would require subtracting 6 from 1.
        let frame = vec![0x05u8];
        let result = strip_frame_padding(frame);
        assert!(matches!(result, Err(CableError::InvalidFraming)));
    }

    #[test]
    fn strip_frame_padding_strips_normal_padding() {
        // 4 bytes of payload, 3 bytes of zero padding, then padding-length 3.
        let frame = vec![0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x03];
        let stripped = strip_frame_padding(frame).unwrap();
        assert_eq!(stripped, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    use serde_indexed::SerializeIndexed;
    use tokio::sync::{mpsc, watch};

    use crate::transport::cable::channel::{CableUxUpdate, ConnectionState};
    use crate::transport::cable::linger::CableLingerRegistry;

    const DEFAULT_LINGER: Duration = CableLingerConfig::DEFAULT_DURATION;
    const HARD_CAP: Duration = CableLingerConfig::HARD_CAP;

    /// In-memory data channel: records outbound frames and replays queued inbound ones.
    struct TestDataChannel {
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
    }

    #[async_trait]
    impl CableDataChannel for TestDataChannel {
        async fn send(&mut self, message: &[u8]) -> Result<(), CableError> {
            let _ = self.outbound.send(message.to_vec());
            Ok(())
        }

        async fn recv(&mut self) -> Result<Option<Vec<u8>>, CableError> {
            Ok(self.inbound.recv().await)
        }
    }

    /// A data channel whose sends never complete, like a stalled socket.
    struct WedgedSendChannel {
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    #[async_trait]
    impl CableDataChannel for WedgedSendChannel {
        async fn send(&mut self, _message: &[u8]) -> Result<(), CableError> {
            std::future::pending().await
        }

        async fn recv(&mut self) -> Result<Option<Vec<u8>>, CableError> {
            Ok(self.inbound.recv().await)
        }
    }

    /// Publishes connection states on a watch so tests can observe phases.
    struct TestUxSender {
        state_tx: watch::Sender<ConnectionState>,
    }

    #[async_trait]
    impl UxUpdateSender for TestUxSender {
        async fn send_update(&self, _update: CableUxUpdate) {}
        async fn send_error(&self, _error: CableError) {
            let _ = self.state_tx.send(ConnectionState::Terminated);
        }
        async fn set_connection_state(&self, state: ConnectionState) {
            let _ = self.state_tx.send(state);
        }
    }

    /// Two Noise transport states that can encrypt/decrypt to each other.
    fn paired_transport_states() -> (TransportState, TransportState) {
        let mut initiator = Builder::new("Noise_NN_P256_AESGCM_SHA256".parse().unwrap())
            .build_initiator()
            .unwrap();
        let mut responder = Builder::new("Noise_NN_P256_AESGCM_SHA256".parse().unwrap())
            .build_responder()
            .unwrap();
        let mut a = [0u8; 1024];
        let mut b = [0u8; 1024];
        let n = initiator.write_message(&[], &mut a).unwrap();
        responder.read_message(&a[..n], &mut b).unwrap();
        let n = responder.write_message(&[], &mut a).unwrap();
        initiator.read_message(&a[..n], &mut b).unwrap();
        (
            initiator.into_transport_mode().unwrap(),
            responder.into_transport_mode().unwrap(),
        )
    }

    fn pad(mut payload: Vec<u8>) -> Vec<u8> {
        let extra = PADDING_GRANULARITY - (payload.len() % PADDING_GRANULARITY);
        let new_len = payload.len() + extra;
        payload.resize(new_len, 0u8);
        *payload.last_mut().unwrap() = (extra - 1) as u8;
        payload
    }

    fn encrypt(state: &mut TransportState, plaintext: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; plaintext.len() + 64];
        let n = state.write_message(plaintext, &mut out).unwrap();
        out.truncate(n);
        out
    }

    fn decrypt(state: &mut TransportState, ciphertext: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; ciphertext.len() + 64];
        let n = state.read_message(ciphertext, &mut out).unwrap();
        out.truncate(n);
        out
    }

    #[derive(SerializeIndexed)]
    struct TestInitialMessage {
        #[serde(index = 0x01)]
        info: ByteBuf,
    }

    /// Encrypted initial post-handshake message carrying a minimal GetInfo.
    fn encrypted_initial_message(responder: &mut TransportState) -> Vec<u8> {
        let get_info = Ctap2GetInfoResponse {
            versions: vec!["FIDO_2_0".to_string()],
            aaguid: ByteBuf::from(vec![0u8; 16]),
            ..Default::default()
        };
        let initial = TestInitialMessage {
            info: ByteBuf::from(cbor::to_vec(&get_info).unwrap()),
        };
        encrypt(responder, &pad(cbor::to_vec(&initial).unwrap()))
    }

    fn qr_connection_type() -> CableTunnelConnectionType {
        qr_connection_type_with(NonZeroScalar::random(&mut OsRng))
    }

    fn qr_connection_type_with(private_key: NonZeroScalar) -> CableTunnelConnectionType {
        CableTunnelConnectionType::QrCode {
            routing_id: "000000".to_string(),
            tunnel_id: "00000000000000000000000000000000".to_string(),
            private_key,
        }
    }

    fn known_device_connection_type() -> CableTunnelConnectionType {
        CableTunnelConnectionType::KnownDevice {
            contact_id: "contact".to_string(),
            authenticator_public_key: vec![0u8; 65],
            client_payload: ClientPayload {
                link_id: ByteBuf::from(vec![0u8; 8]),
                client_nonce: ByteBuf::from(vec![0u8; 16]),
                hint: crate::transport::cable::known_devices::ClientPayloadHint::GetAssertion,
            },
        }
    }

    /// A linking update signed by a fresh authenticator key for the QR
    /// private key of the connection. Returns the plaintext tunnel frame and
    /// the known device id the store will see.
    fn signed_update_payload(
        qr_private_key: &NonZeroScalar,
        handshake_hash: &[u8],
    ) -> (Vec<u8>, CableKnownDeviceId) {
        let authenticator_secret = SecretKey::random(&mut OsRng);
        let authenticator_public_key = authenticator_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let shared_secret = ecdh::diffie_hellman(
            qr_private_key,
            authenticator_secret.public_key().as_affine(),
        )
        .raw_secret_bytes()
        .to_vec();
        let mut hmac = Hmac::<Sha256>::new_from_slice(&shared_secret).unwrap();
        hmac.update(handshake_hash);
        let signature = hmac.finalize().into_bytes().to_vec();

        let mut info = BTreeMap::new();
        info.insert(Value::Integer(1), Value::Bytes(vec![0u8; 4]));
        info.insert(Value::Integer(2), Value::Bytes(vec![0u8; 8]));
        info.insert(Value::Integer(3), Value::Bytes(vec![0u8; 32]));
        info.insert(
            Value::Integer(4),
            Value::Bytes(authenticator_public_key.clone()),
        );
        info.insert(Value::Integer(5), Value::Text("alice's phone".to_string()));
        info.insert(Value::Integer(6), Value::Bytes(signature));
        let mut update = BTreeMap::new();
        update.insert(Value::Integer(1), Value::Map(info));

        let mut payload = vec![CableTunnelMessageType::Update as u8];
        payload.extend(serde_cbor::to_vec(&Value::Map(update)).unwrap());
        (payload, hex::encode(&authenticator_public_key))
    }

    /// Reports every stored device on a channel so tests can await the write.
    #[derive(Debug)]
    struct NotifyingStore {
        puts: mpsc::UnboundedSender<CableKnownDeviceId>,
    }

    #[async_trait]
    impl CableKnownDeviceInfoStore for NotifyingStore {
        async fn put_known_device(
            &self,
            device_id: &CableKnownDeviceId,
            _device: &CableKnownDeviceInfo,
        ) {
            let _ = self.puts.send(device_id.clone());
        }
        async fn delete_known_device(&self, _device_id: &CableKnownDeviceId) {}
    }

    /// A store whose writes never complete.
    #[derive(Debug)]
    struct WedgedStore;

    #[async_trait]
    impl CableKnownDeviceInfoStore for WedgedStore {
        async fn put_known_device(
            &self,
            _device_id: &CableKnownDeviceId,
            _device: &CableKnownDeviceInfo,
        ) {
            std::future::pending::<()>().await;
        }
        async fn delete_known_device(&self, _device_id: &CableKnownDeviceId) {}
    }

    /// Decrypts an outbound frame and returns its tunnel message type byte.
    fn outbound_message_type(frame: &[u8], responder: &mut TransportState) -> u8 {
        let stripped = strip_frame_padding(decrypt(responder, frame)).unwrap();
        *stripped.first().unwrap()
    }

    /// The peer side of a post-handshake connection plus every caller-side handle.
    struct Harness {
        responder: TransportState,
        inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
        outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        cbor_tx_send: mpsc::Sender<CborRequest>,
        cbor_rx_recv: mpsc::Receiver<CborResponse>,
        teardown_tx: Arc<watch::Sender<Teardown>>,
        state_rx: watch::Receiver<ConnectionState>,
        input: Option<TunnelConnectionInput>,
        ux_sender: Option<TestUxSender>,
    }

    impl Harness {
        fn new(connection_type: CableTunnelConnectionType) -> Self {
            let (initiator, responder) = paired_transport_states();
            let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let (cbor_tx_send, cbor_tx_recv) = mpsc::channel::<CborRequest>(4);
            let (cbor_rx_send, cbor_rx_recv) = mpsc::channel::<CborResponse>(4);
            let (teardown_tx, teardown_rx) = watch::channel(Teardown::Active);
            let (state_tx, state_rx) = watch::channel(ConnectionState::Connected);
            let input = TunnelConnectionInput {
                connection_type,
                tunnel_domain: "cable.example.com".to_string(),
                known_device_store: None,
                data_channel: Box::new(TestDataChannel {
                    inbound: inbound_rx,
                    outbound: outbound_tx,
                }),
                noise_state: TunnelNoiseState {
                    transport_state: initiator,
                    handshake_hash: vec![0u8; 32],
                },
                cbor_tx_recv,
                cbor_rx_send,
                teardown_rx,
                linger: None,
            };
            Self {
                responder,
                inbound_tx,
                outbound_rx,
                cbor_tx_send,
                cbor_rx_recv,
                teardown_tx: Arc::new(teardown_tx),
                state_rx,
                input: Some(input),
                ux_sender: Some(TestUxSender { state_tx }),
            }
        }

        fn qr() -> Self {
            Self::new(qr_connection_type())
        }

        fn input_mut(&mut self) -> &mut TunnelConnectionInput {
            self.input.as_mut().expect("not spawned yet")
        }

        fn with_store(mut self, store: Arc<dyn CableKnownDeviceInfoStore>) -> Self {
            self.input_mut().known_device_store = Some(store);
            self
        }

        /// Replaces the data channel with one whose sends stall forever.
        fn with_wedged_send(mut self) -> Self {
            let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            self.inbound_tx = inbound_tx;
            self.input_mut().data_channel = Box::new(WedgedSendChannel {
                inbound: inbound_rx,
            });
            self
        }

        /// Registers the connection with `registry` as an eligible lingerer.
        fn with_linger(
            mut self,
            registry: &CableLingerRegistry,
            linger_duration: Duration,
        ) -> Self {
            let guard = registry.register(self.teardown_tx.clone());
            self.input_mut().linger = Some(LingerParams {
                linger_duration,
                guard,
            });
            self
        }

        async fn wait_for_state(&mut self, state: ConnectionState) {
            self.state_rx
                .wait_for(|current| *current == state)
                .await
                .expect("state sender alive");
        }

        /// Round-trips a cached GetInfo, proving the loop has consumed the
        /// initial message and is in its active phase.
        async fn await_active(&mut self) {
            self.cbor_tx_send
                .send(CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo))
                .await
                .unwrap();
            self.cbor_rx_recv
                .recv()
                .await
                .expect("cached GetInfo response");
        }

        /// Sends the Linger intent from the active phase and waits for the
        /// Shutdown that precedes the linger.
        async fn start_linger(&mut self) {
            self.await_active().await;
            self.teardown(Teardown::Linger);
            assert_eq!(
                self.next_outbound_type().await,
                CableTunnelMessageType::Shutdown as u8
            );
        }

        /// Queues the peer's initial message, as sent right after the handshake.
        fn send_initial_message(&mut self) {
            let frame = encrypted_initial_message(&mut self.responder);
            self.inbound_tx.send(frame).unwrap();
        }

        fn send_peer_frame(&mut self, plaintext: Vec<u8>) {
            let frame = encrypt(&mut self.responder, &pad(plaintext));
            self.inbound_tx.send(frame).unwrap();
        }

        /// Runs the connection loop on its own task.
        fn spawn(&mut self) -> tokio::task::JoinHandle<Result<(), CableError>> {
            let input = self.input.take().expect("spawned once");
            let ux_sender = self.ux_sender.take().expect("spawned once");
            tokio::spawn(async move { connection(input, &ux_sender).await })
        }

        fn teardown(&self, intent: Teardown) {
            self.teardown_tx.send_replace(intent);
        }

        async fn next_outbound_type(&mut self) -> u8 {
            let frame = self.outbound_rx.recv().await.expect("an outbound frame");
            outbound_message_type(&frame, &mut self.responder)
        }
    }

    #[tokio::test]
    async fn connection_sends_shutdown_on_close() {
        let mut h = Harness::qr();
        h.send_initial_message();
        let handle = h.spawn();

        h.await_active().await;
        h.teardown(Teardown::Close);

        assert_eq!(
            h.next_outbound_type().await,
            CableTunnelMessageType::Shutdown as u8
        );
        assert!(handle.await.unwrap().is_ok());
        assert!(h.outbound_rx.try_recv().is_err(), "exactly one Shutdown");
    }

    #[tokio::test]
    async fn cancel_sends_nothing() {
        let mut h = Harness::qr();
        h.send_initial_message();
        let handle = h.spawn();

        h.await_active().await;
        h.teardown(Teardown::Cancel);

        assert!(handle.await.unwrap().is_ok());
        assert!(h.outbound_rx.try_recv().is_err(), "no Shutdown on cancel");
    }

    #[tokio::test]
    async fn close_before_initial_message_sends_shutdown() {
        let mut h = Harness::qr();
        let handle = h.spawn();

        // The peer never sends its initial message; the loop must still
        // honour the close promptly and say goodbye.
        h.teardown(Teardown::Close);

        assert_eq!(
            h.next_outbound_type().await,
            CableTunnelMessageType::Shutdown as u8
        );
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn cancel_before_initial_message_terminates_silently() {
        let mut h = Harness::qr();
        let handle = h.spawn();

        h.teardown(Teardown::Cancel);

        assert!(handle.await.unwrap().is_ok());
        assert!(h.outbound_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn every_sender_gone_counts_as_cancel() {
        let mut h = Harness::qr();
        h.send_initial_message();
        let handle = h.spawn();

        drop(h.teardown_tx);

        assert!(handle.await.unwrap().is_ok());
        assert!(h.outbound_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn peer_shutdown_ends_connection_cleanly() {
        let mut h = Harness::qr();
        h.send_initial_message();
        // A type-only Shutdown frame from the peer, padded like any other frame.
        h.send_peer_frame(vec![CableTunnelMessageType::Shutdown as u8]);
        let handle = h.spawn();

        assert!(handle.await.unwrap().is_ok());
        assert!(
            h.outbound_rx.try_recv().is_err(),
            "no frame is sent in reply"
        );
    }

    #[tokio::test]
    async fn ctap_request_is_forwarded_and_response_delivered() {
        let mut h = Harness::qr();
        h.send_initial_message();
        let handle = h.spawn();

        h.cbor_tx_send
            .send(CborRequest::new(Ctap2CommandCode::AuthenticatorClientPin))
            .await
            .unwrap();
        assert_eq!(
            h.next_outbound_type().await,
            CableTunnelMessageType::Ctap as u8
        );

        // A CTAP response frame: [Ctap type byte][CTAP status OK].
        h.send_peer_frame(vec![CableTunnelMessageType::Ctap as u8, 0x00]);
        h.cbor_rx_recv.recv().await.expect("a CTAP response");

        h.teardown(Teardown::Cancel);
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn linger_captures_a_late_linking_update() {
        let qr_private_key = NonZeroScalar::random(&mut OsRng);
        let (puts_tx, mut puts_rx) = mpsc::unbounded_channel();
        let registry = CableLingerRegistry::new();
        let mut h = Harness::new(qr_connection_type_with(qr_private_key))
            .with_store(Arc::new(NotifyingStore { puts: puts_tx }))
            .with_linger(&registry, DEFAULT_LINGER);
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        h.wait_for_state(ConnectionState::Lingering).await;

        let (payload, device_id) = signed_update_payload(&qr_private_key, &[0u8; 32]);
        h.send_peer_frame(payload);
        assert_eq!(puts_rx.recv().await.unwrap(), device_id);
        assert!(
            h.cbor_rx_recv.try_recv().is_err(),
            "nothing reaches the CBOR receiver"
        );

        h.teardown(Teardown::Cancel);
        assert!(handle.await.unwrap().is_ok());
        assert_eq!(registry.lingering_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn linger_window_elapses() {
        let registry = CableLingerRegistry::new();
        let mut h = Harness::qr()
            .with_store(Arc::new(RecordingStore::default()))
            .with_linger(&registry, Duration::from_secs(10));
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        h.wait_for_state(ConnectionState::Lingering).await;
        let started = tokio::time::Instant::now();

        assert!(handle.await.unwrap().is_ok());
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        assert_eq!(registry.lingering_count(), 0);
        assert!(h.outbound_rx.try_recv().is_err(), "no second Shutdown");
    }

    #[tokio::test(start_paused = true)]
    async fn hard_cap_bounds_an_overlong_window() {
        let registry = CableLingerRegistry::new();
        let mut h = Harness::qr()
            .with_store(Arc::new(RecordingStore::default()))
            .with_linger(&registry, HARD_CAP * 2);
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        h.wait_for_state(ConnectionState::Lingering).await;
        let started = tokio::time::Instant::now();

        assert!(handle.await.unwrap().is_ok());
        assert_eq!(started.elapsed(), HARD_CAP);
    }

    #[tokio::test(start_paused = true)]
    async fn close_lingering_evicts_a_lingerer() {
        let registry = CableLingerRegistry::new();
        let mut h = Harness::qr()
            .with_store(Arc::new(RecordingStore::default()))
            .with_linger(&registry, DEFAULT_LINGER);
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        h.wait_for_state(ConnectionState::Lingering).await;
        assert_eq!(registry.lingering_count(), 1);

        let started = tokio::time::Instant::now();
        assert_eq!(registry.close_lingering(), 1);
        assert!(handle.await.unwrap().is_ok());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(registry.lingering_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn wedged_store_write_is_preempted() {
        let qr_private_key = NonZeroScalar::random(&mut OsRng);
        let registry = CableLingerRegistry::new();
        let mut h = Harness::new(qr_connection_type_with(qr_private_key))
            .with_store(Arc::new(WedgedStore))
            .with_linger(&registry, DEFAULT_LINGER);
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        h.wait_for_state(ConnectionState::Lingering).await;
        let started = tokio::time::Instant::now();

        let (payload, _) = signed_update_payload(&qr_private_key, &[0u8; 32]);
        h.send_peer_frame(payload);

        assert!(handle.await.unwrap().is_ok());
        assert_eq!(started.elapsed(), STORE_WRITE_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn decrypt_failure_budget_ends_the_linger() {
        let registry = CableLingerRegistry::new();
        let mut h = Harness::qr()
            .with_store(Arc::new(RecordingStore::default()))
            .with_linger(&registry, DEFAULT_LINGER);
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        h.wait_for_state(ConnectionState::Lingering).await;

        for _ in 0..DECRYPT_FAILURE_BUDGET {
            h.inbound_tx.send(vec![0xFFu8; 48]).unwrap();
        }
        let started = tokio::time::Instant::now();
        assert!(handle.await.unwrap().is_ok());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn peer_shutdown_ends_the_linger() {
        let registry = CableLingerRegistry::new();
        let mut h = Harness::qr()
            .with_store(Arc::new(RecordingStore::default()))
            .with_linger(&registry, DEFAULT_LINGER);
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        h.wait_for_state(ConnectionState::Lingering).await;

        h.send_peer_frame(vec![CableTunnelMessageType::Shutdown as u8]);
        let started = tokio::time::Instant::now();
        assert!(handle.await.unwrap().is_ok());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn ctap_frames_are_ignored_while_lingering() {
        let registry = CableLingerRegistry::new();
        let mut h = Harness::qr()
            .with_store(Arc::new(RecordingStore::default()))
            .with_linger(&registry, Duration::from_secs(10));
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        h.wait_for_state(ConnectionState::Lingering).await;

        let started = tokio::time::Instant::now();
        h.send_peer_frame(vec![CableTunnelMessageType::Ctap as u8, 0x00]);
        assert!(handle.await.unwrap().is_ok());
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        assert!(h.cbor_rx_recv.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn linger_without_a_store_is_a_close() {
        let registry = CableLingerRegistry::new();
        let mut h = Harness::qr().with_linger(&registry, DEFAULT_LINGER);
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        assert!(handle.await.unwrap().is_ok());
        assert_ne!(*h.state_rx.borrow(), ConnectionState::Lingering);
        assert_eq!(registry.lingering_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn known_device_connection_never_lingers() {
        let registry = CableLingerRegistry::new();
        let mut h = Harness::new(known_device_connection_type())
            .with_store(Arc::new(RecordingStore::default()))
            .with_linger(&registry, DEFAULT_LINGER);
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        assert!(handle.await.unwrap().is_ok());
        assert_ne!(*h.state_rx.borrow(), ConnectionState::Lingering);
        assert_eq!(registry.lingering_count(), 0);
    }

    #[tokio::test]
    async fn linger_before_the_initial_message_is_a_close() {
        let registry = CableLingerRegistry::new();
        let mut h = Harness::qr()
            .with_store(Arc::new(RecordingStore::default()))
            .with_linger(&registry, DEFAULT_LINGER);
        let handle = h.spawn();

        h.teardown(Teardown::Linger);
        assert_eq!(
            h.next_outbound_type().await,
            CableTunnelMessageType::Shutdown as u8
        );
        assert!(handle.await.unwrap().is_ok());
        assert_ne!(*h.state_rx.borrow(), ConnectionState::Lingering);
        assert_eq!(registry.lingering_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn wedged_store_write_in_the_active_phase_does_not_block_close() {
        let qr_private_key = NonZeroScalar::random(&mut OsRng);
        let mut h =
            Harness::new(qr_connection_type_with(qr_private_key)).with_store(Arc::new(WedgedStore));
        h.send_initial_message();
        let handle = h.spawn();
        h.await_active().await;

        let (payload, _) = signed_update_payload(&qr_private_key, &[0u8; 32]);
        h.send_peer_frame(payload);
        tokio::task::yield_now().await;
        let started = tokio::time::Instant::now();
        h.teardown(Teardown::Close);

        assert_eq!(
            h.next_outbound_type().await,
            CableTunnelMessageType::Shutdown as u8
        );
        assert!(handle.await.unwrap().is_ok());
        assert_eq!(started.elapsed(), STORE_WRITE_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn close_with_a_wedged_socket_terminates_at_send_timeout() {
        let mut h = Harness::qr().with_wedged_send();
        h.send_initial_message();
        let handle = h.spawn();
        h.await_active().await;

        let started = tokio::time::Instant::now();
        h.teardown(Teardown::Close);
        assert!(handle.await.unwrap().is_ok());
        assert_eq!(started.elapsed(), SEND_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn cbor_send_on_a_wedged_socket_fails_at_send_timeout() {
        let mut h = Harness::qr().with_wedged_send();
        h.send_initial_message();
        let handle = h.spawn();
        h.await_active().await;

        let started = tokio::time::Instant::now();
        h.cbor_tx_send
            .send(CborRequest::new(Ctap2CommandCode::AuthenticatorClientPin))
            .await
            .unwrap();
        assert!(matches!(handle.await.unwrap(), Err(CableError::Timeout)));
        assert_eq!(started.elapsed(), SEND_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn decrypt_failures_below_the_budget_keep_the_linger_alive() {
        let qr_private_key = NonZeroScalar::random(&mut OsRng);
        let (puts_tx, mut puts_rx) = mpsc::unbounded_channel();
        let registry = CableLingerRegistry::new();
        let mut h = Harness::new(qr_connection_type_with(qr_private_key))
            .with_store(Arc::new(NotifyingStore { puts: puts_tx }))
            .with_linger(&registry, DEFAULT_LINGER);
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        h.wait_for_state(ConnectionState::Lingering).await;

        for _ in 0..DECRYPT_FAILURE_BUDGET - 1 {
            h.inbound_tx.send(vec![0xFFu8; 48]).unwrap();
        }
        // A good frame resets the count and is still applied.
        let (payload, device_id) = signed_update_payload(&qr_private_key, &[0u8; 32]);
        h.send_peer_frame(payload);
        assert_eq!(puts_rx.recv().await.unwrap(), device_id);
        assert_eq!(registry.lingering_count(), 1);

        for _ in 0..DECRYPT_FAILURE_BUDGET - 1 {
            h.inbound_tx.send(vec![0xFFu8; 48]).unwrap();
        }
        tokio::task::yield_now().await;
        assert_eq!(registry.lingering_count(), 1, "still under the budget");

        h.inbound_tx.send(vec![0xFFu8; 48]).unwrap();
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_frame_types_are_ignored_while_lingering() {
        let registry = CableLingerRegistry::new();
        let mut h = Harness::qr()
            .with_store(Arc::new(RecordingStore::default()))
            .with_linger(&registry, Duration::from_secs(10));
        h.send_initial_message();
        let handle = h.spawn();

        h.start_linger().await;
        h.wait_for_state(ConnectionState::Lingering).await;

        let started = tokio::time::Instant::now();
        for _ in 0..DECRYPT_FAILURE_BUDGET + 1 {
            // Decrypts fine, unknown type byte (e.g. a CTAP 2.3 JSON frame).
            h.send_peer_frame(vec![3, 0x00]);
        }
        assert!(handle.await.unwrap().is_ok());
        assert_eq!(started.elapsed(), Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn linger_with_a_dropped_registry_is_a_close() {
        let registry = CableLingerRegistry::new();
        let mut h = Harness::qr()
            .with_store(Arc::new(RecordingStore::default()))
            .with_linger(&registry, DEFAULT_LINGER);
        h.send_initial_message();
        let handle = h.spawn();
        h.await_active().await;

        drop(registry);
        h.start_linger().await;
        assert!(handle.await.unwrap().is_ok());
        assert_ne!(*h.state_rx.borrow(), ConnectionState::Lingering);
    }
}
