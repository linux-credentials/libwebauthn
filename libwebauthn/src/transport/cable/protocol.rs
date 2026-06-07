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
use crate::transport::cable::connection_stages::TunnelConnectionInput;
use crate::transport::cable::known_devices::CableKnownDeviceId;
use crate::transport::error::TransportError;

const P256_X962_LENGTH: usize = 65;
const MAX_CBOR_SIZE: usize = 1024 * 1024;
const PADDING_GRANULARITY: usize = 32;

/// How long to linger after the CTAP response to capture a late linking Update.
const POST_RESPONSE_LINGER: Duration = Duration::from_secs(120);

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
    pub fn from_slice(slice: &[u8]) -> Result<Self, TransportError> {
        let (type_byte, payload) = slice.split_first().ok_or(TransportError::InvalidFraming)?;
        if payload.is_empty() {
            return Err(TransportError::InvalidFraming);
        }

        let message_type = match *type_byte {
            0 => CableTunnelMessageType::Shutdown,
            1 => CableTunnelMessageType::Ctap,
            2 => CableTunnelMessageType::Update,
            _ => {
                return Err(TransportError::InvalidFraming);
            }
        };

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
#[derive(Debug, Clone, Copy, Deserialize)]
enum CableTunnelMessageType {
    Shutdown = 0,
    Ctap = 1,
    Update = 2,
}

/// Result of processing a single inbound tunnel frame.
enum RecvOutcome {
    /// Frame handled, keep the loop running.
    Continue,
    /// A CTAP response was delivered to the client, arming the linger window.
    ResponseDelivered,
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
            .remote_public_key(authenticator_public_key)?
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

    let initial_msg: Vec<u8> = initial_msg_buffer
        .get(..initial_msg_len)
        .map(<[u8]>::to_vec)
        .ok_or(TransportError::ConnectionFailed)?;
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
            return Err(TransportError::ConnectionFailed);
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
        return Err(TransportError::ConnectionFailed);
    }

    let mut payload = [0u8; 1024];
    let payload_len = match noise_handshake.read_message(&response, &mut payload) {
        Ok(len) => len,
        Err(e) => {
            error!(?e, "Failed to read handshake response message");
            return Err(TransportError::ConnectionFailed);
        }
    };

    debug!(
        { handshake = ?payload.get(..payload_len) },
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

/// Returns `Ok(())` on a clean close and `Err(_)` on any fault that leaves
/// the encrypted channel unusable; callers surface `Err(_)` via `send_error`.
pub(crate) async fn connection(mut input: TunnelConnectionInput) -> Result<(), TransportError> {
    let get_info_response_serialized: Vec<u8> = match input.data_channel.recv().await {
        Ok(Some(message)) => match connection_recv_initial(message, &mut input.noise_state).await {
            Ok(initial) => initial,
            Err(e) => {
                error!(?e, "Failed to process initial message");
                return Err(e);
            }
        },
        Ok(None) => {
            error!("Connection closed before initial message was received");
            return Err(TransportError::ConnectionLost);
        }
        Err(e) => {
            error!(?e, "Failed to read initial message");
            return Err(e);
        }
    };
    debug!(?get_info_response_serialized, "Received initial message");

    let linger = tokio::time::sleep(POST_RESPONSE_LINGER);
    tokio::pin!(linger);
    let mut lingering = false;

    loop {
        tokio::select! {
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
                            Ok(RecvOutcome::ResponseDelivered) => {
                                linger
                                    .as_mut()
                                    .reset(tokio::time::Instant::now() + POST_RESPONSE_LINGER);
                                lingering = true;
                            }
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
            _ = input.close_rx.recv() => {
                debug!("Channel close requested, sending Shutdown control frame");
                if let Err(e) =
                    connection_send_shutdown(&mut *input.data_channel, &mut input.noise_state).await
                {
                    warn!(?e, "Failed to send Shutdown control frame on close");
                }
                return Ok(());
            }
            _ = &mut linger, if lingering => {
                debug!("Linger window elapsed, sending Shutdown control frame");
                if let Err(e) =
                    connection_send_shutdown(&mut *input.data_channel, &mut input.noise_state).await
                {
                    warn!(?e, "Failed to send Shutdown control frame after linger");
                }
                return Ok(());
            }
            Some(request) = input.cbor_tx_recv.recv() => {
                match request.command {
                    // Optimisation: respond to GetInfo requests immediately with the cached response
                    Ctap2CommandCode::AuthenticatorGetInfo => {
                        debug!("Responding to GetInfo request with cached response");
                        let response = CborResponse::new_success_from_slice(&get_info_response_serialized);
                        if let Err(e) = input.cbor_rx_send.send(response).await {
                            error!(?e, "CBOR response receiver dropped");
                            return Err(TransportError::ConnectionFailed);
                        }
                    }
                    _ => {
                        // A new request is in flight; stop the linger so a slow
                        // response (eg. on-device UV) is not torn down early.
                        lingering = false;
                        debug!(?request.command, "Sending CBOR request");
                        if let Err(e) = connection_send(
                            request,
                            &mut *input.data_channel,
                            &mut input.noise_state,
                        )
                        .await
                        {
                            error!(?e, "Fatal error sending CBOR request");
                            return Err(e);
                        }
                    }
                }
            }
        };
    }
}

async fn connection_send(
    request: CborRequest,
    data_channel: &mut dyn CableDataChannel,
    noise_state: &mut TunnelNoiseState,
) -> Result<(), TransportError> {
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
        return Err(TransportError::InvalidFraming);
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
) -> Result<(), TransportError> {
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
) -> Result<(), TransportError> {
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
            return Err(TransportError::EncryptionFailed);
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
fn strip_frame_padding(mut decrypted_frame: Vec<u8>) -> Result<Vec<u8>, TransportError> {
    let padding_len = match decrypted_frame.last() {
        Some(&b) => b as usize,
        None => {
            error!("Decrypted frame is empty; cannot read padding length");
            return Err(TransportError::InvalidFraming);
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
            TransportError::InvalidFraming
        })?;
    decrypted_frame.truncate(new_len);
    Ok(decrypted_frame)
}

async fn decrypt_frame(
    encrypted_frame: Vec<u8>,
    noise_state: &mut TunnelNoiseState,
) -> Result<Vec<u8>, TransportError> {
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
            return Err(TransportError::EncryptionFailed);
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
) -> Result<Vec<u8>, TransportError> {
    let decrypted_frame = decrypt_frame(encrypted_frame, noise_state).await?;

    let initial_message: CableInitialMessage = match cbor::from_slice(&decrypted_frame) {
        Ok(initial_message) => initial_message,
        Err(e) => {
            error!(?e, "Failed to decode initial message");
            return Err(TransportError::InvalidFraming);
        }
    };

    let _: Ctap2GetInfoResponse = match cbor::from_slice(&initial_message.info) {
        Ok(get_info_response) => get_info_response,
        Err(e) => {
            error!(?e, "Failed to decode GetInfo response");
            return Err(TransportError::InvalidFraming);
        }
    };

    Ok(initial_message.info.to_vec())
}

async fn connection_recv_update(
    message: &[u8],
) -> Result<Option<CableLinkingInfo>, TransportError> {
    // TODO(#66): Android adds a 999-key to the end the message, which is not part of the standard.
    // For now, we parse the message to a map and manuually import fields.

    let update_message: BTreeMap<Value, Value> = match serde_cbor::from_slice(message) {
        Ok(update_message) => update_message,
        Err(e) => {
            error!(?e, "Failed to decode update message");
            return Err(TransportError::InvalidFraming);
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
) -> Result<RecvOutcome, TransportError> {
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
                .or(Err(TransportError::InvalidFraming))?;

            debug!("Received CBOR response");
            trace!(?cbor_response);
            cbor_rx_send
                .send(cbor_response)
                .await
                .or(Err(TransportError::ConnectionFailed))?;
            Ok(RecvOutcome::ResponseDelivered)
        }
        CableTunnelMessageType::Update => {
            // Malformed or unsigned update: log, drop the update, keep the channel.
            let maybe_update_message = match connection_recv_update(&cable_message.payload).await {
                Ok(m) => m,
                Err(e) => {
                    warn!(?e, "Malformed update message; ignoring");
                    return Ok(RecvOutcome::Continue);
                }
            };

            let Some(linking_info) = maybe_update_message else {
                warn!("Ignoring update message without linking info");
                return Ok(RecvOutcome::Continue);
            };

            let CableTunnelConnectionType::QrCode { private_key, .. } = connection_type else {
                warn!("Ignoring update message for non-QR code connection");
                return Ok(RecvOutcome::Continue);
            };

            debug!("Received update message with linking info");
            trace!(?linking_info);

            let device_id: CableKnownDeviceId = (&linking_info).into();
            match known_device_store {
                Some(store) => {
                    match parse_known_device(private_key, tunnel_domain, &linking_info, noise_state)
                    {
                        Ok(known_device) => {
                            debug!(?device_id, "Updating known device");
                            trace!(?known_device);
                            store.put_known_device(&device_id, &known_device).await;
                        }
                        Err(e) => {
                            warn!(
                                ?e,
                                "Invalid linking update from authenticator, forgetting device"
                            );
                            store.delete_known_device(&device_id).await;
                        }
                    }
                }
                None => {
                    warn!("Ignoring update message without a device store");
                }
            };
            Ok(RecvOutcome::Continue)
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
    noise_state: &TunnelNoiseState,
) -> Result<CableKnownDeviceInfo, TransportError> {
    let known_device = CableKnownDeviceInfo::new(tunnel_domain, linking_info)?;
    let secret_key = SecretKey::from(private_key);

    let Ok(authenticator_public_key) =
        PublicKey::from_sec1_bytes(&linking_info.authenticator_public_key)
    else {
        error!("Failed to parse public key.");
        return Err(TransportError::InvalidKey);
    };

    let shared_secret: Vec<u8> = ecdh::diffie_hellman(
        secret_key.to_nonzero_scalar(),
        authenticator_public_key.as_affine(),
    )
    .raw_secret_bytes()
    .to_vec();

    let mut hmac =
        Hmac::<Sha256>::new_from_slice(&shared_secret).map_err(|_| TransportError::InvalidKey)?;
    hmac.update(&noise_state.handshake_hash);
    let expected_mac = hmac.finalize().into_bytes().to_vec();

    if expected_mac != linking_info.handshake_signature {
        error!("Invalid handshake signature, rejecting update message");
        trace!(?expected_mac, ?linking_info.handshake_signature);
        return Err(TransportError::InvalidSignature);
    }

    debug!("Parsed known device with valid signature");
    Ok(known_device)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_frame_padding_rejects_empty() {
        let result = strip_frame_padding(Vec::new());
        assert!(matches!(result, Err(TransportError::InvalidFraming)));
    }

    #[test]
    fn strip_frame_padding_rejects_overlong_padding() {
        // Length 1 + declared padding of 5 -> would require subtracting 6 from 1.
        let frame = vec![0x05u8];
        let result = strip_frame_padding(frame);
        assert!(matches!(result, Err(TransportError::InvalidFraming)));
    }

    #[test]
    fn strip_frame_padding_strips_normal_padding() {
        // 4 bytes of payload, 3 bytes of zero padding, then padding-length 3.
        let frame = vec![0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x03];
        let stripped = strip_frame_padding(frame).unwrap();
        assert_eq!(stripped, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    use async_trait::async_trait;
    use rand::rngs::OsRng;
    use serde_indexed::SerializeIndexed;
    use tokio::sync::mpsc;

    /// In-memory data channel: records outbound frames and replays queued inbound ones.
    struct TestDataChannel {
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
    }

    #[async_trait]
    impl CableDataChannel for TestDataChannel {
        async fn send(&mut self, message: &[u8]) -> Result<(), TransportError> {
            let _ = self.outbound.send(message.to_vec());
            Ok(())
        }

        async fn recv(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
            Ok(self.inbound.recv().await)
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
        CableTunnelConnectionType::QrCode {
            routing_id: "000000".to_string(),
            tunnel_id: "00000000000000000000000000000000".to_string(),
            private_key: NonZeroScalar::random(&mut OsRng),
        }
    }

    /// Decrypts an outbound frame and returns its tunnel message type byte.
    fn outbound_message_type(frame: &[u8], responder: &mut TransportState) -> u8 {
        let stripped = strip_frame_padding(decrypt(responder, frame)).unwrap();
        *stripped.first().unwrap()
    }

    #[tokio::test]
    async fn connection_sends_shutdown_on_close() {
        let (initiator, mut responder) = paired_transport_states();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        inbound_tx
            .send(encrypted_initial_message(&mut responder))
            .unwrap();

        let (cbor_tx_send, cbor_tx_recv) = mpsc::channel::<CborRequest>(4);
        let (cbor_rx_send, cbor_rx_recv) = mpsc::channel::<CborResponse>(4);
        let (close_tx, close_rx) = mpsc::channel::<()>(1);

        let input = TunnelConnectionInput {
            connection_type: qr_connection_type(),
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
            close_rx,
        };

        let handle = tokio::spawn(connection(input));

        close_tx.send(()).await.unwrap();

        let frame = outbound_rx
            .recv()
            .await
            .expect("a frame on the outbound path");
        assert_eq!(
            outbound_message_type(&frame, &mut responder),
            CableTunnelMessageType::Shutdown as u8
        );
        assert!(handle.await.unwrap().is_ok());

        // Keep the channel ends alive until the loop has shut down.
        drop((inbound_tx, cbor_tx_send, cbor_rx_recv, close_tx));
    }

    #[tokio::test(start_paused = true)]
    async fn connection_lingers_then_sends_shutdown_after_response() {
        let (initiator, mut responder) = paired_transport_states();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        inbound_tx
            .send(encrypted_initial_message(&mut responder))
            .unwrap();
        // A CTAP response frame: [Ctap type byte][CTAP status OK], padded and encrypted.
        let ctap_frame = encrypt(
            &mut responder,
            &pad(vec![CableTunnelMessageType::Ctap as u8, 0x00]),
        );
        inbound_tx.send(ctap_frame).unwrap();

        let (cbor_tx_send, cbor_tx_recv) = mpsc::channel::<CborRequest>(4);
        let (cbor_rx_send, mut cbor_rx_recv) = mpsc::channel::<CborResponse>(4);
        let (close_tx, close_rx) = mpsc::channel::<()>(1);

        let input = TunnelConnectionInput {
            connection_type: qr_connection_type(),
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
            close_rx,
        };

        let handle = tokio::spawn(connection(input));

        // The delivered CTAP response arms the linger window.
        cbor_rx_recv.recv().await.expect("a CTAP response");

        // With time paused, the runtime advances to the linger deadline, after
        // which the loop emits a Shutdown frame instead of running indefinitely.
        let frame = outbound_rx
            .recv()
            .await
            .expect("a Shutdown frame after the linger window");
        assert_eq!(
            outbound_message_type(&frame, &mut responder),
            CableTunnelMessageType::Shutdown as u8
        );
        assert!(handle.await.unwrap().is_ok());

        // Keep the channel ends alive until the linger has fired.
        drop((inbound_tx, cbor_tx_send, close_tx));
    }

    #[tokio::test(start_paused = true)]
    async fn linger_does_not_terminate_while_request_in_flight() {
        let (initiator, mut responder) = paired_transport_states();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        inbound_tx
            .send(encrypted_initial_message(&mut responder))
            .unwrap();
        // A first CTAP response arms the linger.
        inbound_tx
            .send(encrypt(
                &mut responder,
                &pad(vec![CableTunnelMessageType::Ctap as u8, 0x00]),
            ))
            .unwrap();

        let (cbor_tx_send, cbor_tx_recv) = mpsc::channel::<CborRequest>(4);
        let (cbor_rx_send, mut cbor_rx_recv) = mpsc::channel::<CborResponse>(4);
        let (close_tx, close_rx) = mpsc::channel::<()>(1);

        let input = TunnelConnectionInput {
            connection_type: qr_connection_type(),
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
            close_rx,
        };

        let mut handle = tokio::spawn(connection(input));

        // Drain the first response, which armed the linger.
        cbor_rx_recv.recv().await.expect("first CTAP response");

        // The client sends a new request before the linger elapses. Draining its
        // outbound frame proves the loop processed it and disarmed the linger.
        cbor_tx_send
            .send(CborRequest::new(Ctap2CommandCode::AuthenticatorClientPin))
            .await
            .unwrap();
        let req_frame = outbound_rx.recv().await.expect("a request frame");
        assert_eq!(
            outbound_message_type(&req_frame, &mut responder),
            CableTunnelMessageType::Ctap as u8
        );

        // Advance well past the old linger deadline. A bounded join then drives
        // the loop: with the linger disarmed it stays alive (the join times out),
        // whereas an armed linger would have sent Shutdown and returned.
        tokio::time::advance(POST_RESPONSE_LINGER * 2).await;
        let still_running = tokio::time::timeout(Duration::from_secs(1), &mut handle)
            .await
            .is_err();
        assert!(
            still_running,
            "connection terminated while a request was in flight"
        );

        // An explicit close still shuts the loop down cleanly.
        close_tx.send(()).await.unwrap();
        let frame = outbound_rx.recv().await.expect("a Shutdown frame on close");
        assert_eq!(
            outbound_message_type(&frame, &mut responder),
            CableTunnelMessageType::Shutdown as u8
        );
        assert!(handle.await.unwrap().is_ok());

        drop((inbound_tx, cbor_tx_send));
    }

    #[test]
    fn post_response_linger_is_two_minutes() {
        assert_eq!(POST_RESPONSE_LINGER, Duration::from_secs(120));
    }
}
