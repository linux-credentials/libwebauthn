//! Transport-agnostic Noise handshake and encrypted CTAP framing for the
//! hybrid transport. Runs over any [`PxpDataChannel`].
use std::collections::BTreeMap;
use std::sync::Arc;

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

use super::data_channel::PxpDataChannel;
use super::known_devices::ClientPayload;
use super::known_devices::{PxpKnownDeviceInfo, PxpKnownDeviceInfoStore};
use crate::cbor::{self, Value};
use crate::connection_stages::TunnelConnectionInput;
use crate::error::PxpError;
use crate::get_info::GetInfoResponse;
use crate::known_devices::PxpKnownDeviceId;

const P256_X962_LENGTH: usize = 65;
const MAX_CBOR_SIZE: usize = 1024 * 1024;
const PADDING_GRANULARITY: usize = 32;

const PXP_PROLOGUE_STATE_ASSISTED: &[u8] = &[0u8];
const PXP_PROLOGUE_QR_INITIATED: &[u8] = &[1u8];

/// CTAP2 authenticatorGetInfo command byte. The only CTAP fact PXP relies on:
/// the post-handshake message already carries the getInfo response.
const CTAP2_GET_INFO: u8 = 0x04;
/// CTAP2 success status byte, prefixed to the cached getInfo response.
const CTAP2_OK: u8 = 0x00;

#[derive(Debug, Clone)]
struct PxpTunnelMessage {
    message_type: PxpTunnelMessageType,
    payload: ByteBuf,
}

impl PxpTunnelMessage {
    pub fn new(message_type: PxpTunnelMessageType, payload: &[u8]) -> Self {
        Self {
            message_type,
            payload: ByteBuf::from(payload.to_vec()),
        }
    }
    pub fn from_slice(slice: &[u8]) -> Result<Self, PxpError> {
        let (type_byte, payload) = slice.split_first().ok_or(PxpError::InvalidFraming)?;
        if payload.is_empty() {
            return Err(PxpError::InvalidFraming);
        }

        let message_type = match *type_byte {
            0 => PxpTunnelMessageType::Shutdown,
            1 => PxpTunnelMessageType::Ctap,
            2 => PxpTunnelMessageType::Update,
            _ => {
                return Err(PxpError::InvalidFraming);
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
struct PxpInitialMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x00)]
    pub _padding: Option<ByteBuf>,

    #[serde(index = 0x01)]
    pub info: ByteBuf,

    #[serde(skip_serializing_if = "SupportedFeatures::is_default")]
    #[serde(index = 0x03)]
    pub supported_features: SupportedFeatures,
}

/// Post-handshake message key 3. Its absence MUST be treated as `["ctap"]`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(transparent)]
struct SupportedFeatures(Vec<String>);

impl Default for SupportedFeatures {
    fn default() -> Self {
        Self(vec!["ctap".to_string()])
    }
}

impl SupportedFeatures {
    #[allow(dead_code)]
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PxpLinkingInfo {
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
enum PxpTunnelMessageType {
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
pub(crate) enum PxpTunnelConnectionType {
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

impl std::fmt::Debug for PxpTunnelConnectionType {
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
    data_channel: &mut dyn PxpDataChannel,
    psk: [u8; 32],
    connection_type: &PxpTunnelConnectionType,
) -> Result<TunnelNoiseState, PxpError> {
    let noise_handshake = match connection_type {
        PxpTunnelConnectionType::QrCode { private_key, .. } => {
            let local_private_key = private_key.to_owned().to_bytes();
            Builder::new("Noise_KNpsk0_P256_AESGCM_SHA256".parse()?)
                .prologue(PXP_PROLOGUE_QR_INITIATED)?
                .local_private_key(local_private_key.as_slice())?
                .psk(0, &psk)?
                .build_initiator()
        }
        PxpTunnelConnectionType::KnownDevice {
            authenticator_public_key,
            ..
        } => Builder::new("Noise_NKpsk0_P256_AESGCM_SHA256".parse()?)
            .prologue(PXP_PROLOGUE_STATE_ASSISTED)?
            .remote_public_key(authenticator_public_key)?
            .psk(0, &psk)?
            .build_initiator(),
    };

    // Build the Noise handshake as the initiator
    let mut noise_handshake = match noise_handshake {
        Ok(handshake) => handshake,
        Err(e) => {
            error!(?e, "Failed to build Noise handshake");
            return Err(PxpError::ConnectionFailed);
        }
    };

    let mut initial_msg_buffer = vec![0u8; 1024];
    let initial_msg_len = match noise_handshake.write_message(&[], &mut initial_msg_buffer) {
        Ok(msg_len) => msg_len,
        Err(e) => {
            error!(?e, "Failed to write initial handshake message");
            return Err(PxpError::ConnectionFailed);
        }
    };

    let initial_msg: Vec<u8> = initial_msg_buffer
        .get(..initial_msg_len)
        .map(<[u8]>::to_vec)
        .ok_or(PxpError::ConnectionFailed)?;
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
            return Err(PxpError::ConnectionFailed);
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
        return Err(PxpError::ConnectionFailed);
    }

    let mut payload = [0u8; 1024];
    let payload_len = match noise_handshake.read_message(&response, &mut payload) {
        Ok(len) => len,
        Err(e) => {
            error!(?e, "Failed to read handshake response message");
            return Err(PxpError::ConnectionFailed);
        }
    };

    debug!(
        { handshake = ?payload.get(..payload_len) },
        "Received handshake response"
    );

    if !noise_handshake.is_handshake_finished() {
        error!("Handshake did not complete");
        return Err(PxpError::ConnectionFailed);
    }

    Ok(TunnelNoiseState {
        handshake_hash: noise_handshake.get_handshake_hash().to_vec(),
        transport_state: noise_handshake.into_transport_mode()?,
    })
}

/// Returns `Ok(())` on a clean close and `Err(_)` on any fault that leaves
/// the encrypted channel unusable; callers surface `Err(_)` via `send_error`.
pub(crate) async fn connection(mut input: TunnelConnectionInput) -> Result<(), PxpError> {
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
            return Err(PxpError::ConnectionLost);
        }
        Err(e) => {
            error!(?e, "Failed to read initial message");
            return Err(e);
        }
    };
    debug!(?get_info_response_serialized, "Received initial message");

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
                            &input.ctap_rx_send,
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
            Some(request) = input.ctap_tx_recv.recv() => {
                match request.first() {
                    // Optimisation: respond to GetInfo requests immediately with the cached response
                    Some(&CTAP2_GET_INFO) => {
                        debug!("Responding to GetInfo request with cached response");
                        let mut response = vec![CTAP2_OK];
                        response.extend_from_slice(&get_info_response_serialized);
                        if let Err(e) = input.ctap_rx_send.send(response).await {
                            error!(?e, "CTAP response receiver dropped");
                            return Err(PxpError::ConnectionFailed);
                        }
                    }
                    command => {
                        debug!(?command, "Sending CTAP request");
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
    cbor_request: Vec<u8>,
    data_channel: &mut dyn PxpDataChannel,
    noise_state: &mut TunnelNoiseState,
) -> Result<(), PxpError> {
    debug!("Sending CBOR request");
    if cbor_request.len() > MAX_CBOR_SIZE {
        error!(
            cbor_request_len = cbor_request.len(),
            "CBOR request too large"
        );
        return Err(PxpError::InvalidFraming);
    }
    trace!(?cbor_request, cbor_request_len = cbor_request.len());

    let extra_bytes = PADDING_GRANULARITY - (cbor_request.len() % PADDING_GRANULARITY);
    let padded_len = cbor_request.len() + extra_bytes;

    let mut padded_cbor_request = cbor_request.clone();
    padded_cbor_request.resize(padded_len, 0u8);
    if let Some(last) = padded_cbor_request.last_mut() {
        *last = (extra_bytes - 1) as u8;
    }

    let frame = PxpTunnelMessage::new(PxpTunnelMessageType::Ctap, &padded_cbor_request);
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
            return Err(PxpError::EncryptionFailed);
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
fn strip_frame_padding(mut decrypted_frame: Vec<u8>) -> Result<Vec<u8>, PxpError> {
    let padding_len = match decrypted_frame.last() {
        Some(&b) => b as usize,
        None => {
            error!("Decrypted frame is empty; cannot read padding length");
            return Err(PxpError::InvalidFraming);
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
            PxpError::InvalidFraming
        })?;
    decrypted_frame.truncate(new_len);
    Ok(decrypted_frame)
}

async fn decrypt_frame(
    encrypted_frame: Vec<u8>,
    noise_state: &mut TunnelNoiseState,
) -> Result<Vec<u8>, PxpError> {
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
            return Err(PxpError::EncryptionFailed);
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
) -> Result<Vec<u8>, PxpError> {
    let decrypted_frame = decrypt_frame(encrypted_frame, noise_state).await?;

    let initial_message: PxpInitialMessage = match cbor::from_slice(&decrypted_frame) {
        Ok(initial_message) => initial_message,
        Err(e) => {
            error!(?e, "Failed to decode initial message");
            return Err(PxpError::InvalidFraming);
        }
    };

    if let Err(e) = cbor::from_slice::<GetInfoResponse>(&initial_message.info) {
        error!(?e, "Failed to decode GetInfo response");
        return Err(PxpError::InvalidFraming);
    }

    debug!(?initial_message.supported_features, "Received post-handshake message");

    Ok(initial_message.info.to_vec())
}

async fn connection_recv_update(message: &[u8]) -> Result<Option<PxpLinkingInfo>, PxpError> {
    // TODO(#66): Android adds a 999-key to the end the message, which is not part of the standard.
    // For now, we parse the message to a map and manuually import fields.

    let update_message: BTreeMap<Value, Value> = match serde_cbor::from_slice(message) {
        Ok(update_message) => update_message,
        Err(e) => {
            error!(?e, "Failed to decode update message");
            return Err(PxpError::InvalidFraming);
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

    let linking_info = PxpLinkingInfo {
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
    connection_type: &PxpTunnelConnectionType,
    tunnel_domain: &str,
    known_device_store: &Option<Arc<dyn PxpKnownDeviceInfoStore>>,
    encrypted_frame: Vec<u8>,
    ctap_rx_send: &Sender<Vec<u8>>,
    noise_state: &mut TunnelNoiseState,
) -> Result<RecvOutcome, PxpError> {
    let decrypted_frame = decrypt_frame(encrypted_frame, noise_state).await?;

    let pxp_message: PxpTunnelMessage = PxpTunnelMessage::from_slice(&decrypted_frame)
        .inspect_err(|e| error!(?e, "Failed to decode CABLE tunnel message"))?;

    trace!(?pxp_message);
    match pxp_message.message_type {
        PxpTunnelMessageType::Shutdown => {
            debug!("Peer sent Shutdown control message; closing connection cleanly");
            Ok(RecvOutcome::PeerShutdown)
        }
        PxpTunnelMessageType::Ctap => {
            debug!("Received CTAP response");
            trace!(?pxp_message.payload);
            ctap_rx_send
                .send(pxp_message.payload.into_vec())
                .await
                .or(Err(PxpError::ConnectionFailed))?;
            Ok(RecvOutcome::Continue)
        }
        PxpTunnelMessageType::Update => {
            // Malformed or unsigned update: log, drop the update, keep the channel.
            let maybe_update_message = match connection_recv_update(&pxp_message.payload).await {
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

            let PxpTunnelConnectionType::QrCode { private_key, .. } = connection_type else {
                warn!("Ignoring update message for non-QR code connection");
                return Ok(RecvOutcome::Continue);
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
                        &noise_state.handshake_hash,
                    )
                    .await;
                }
                None => {
                    warn!("Ignoring update message without a device store");
                }
            };
            Ok(RecvOutcome::Continue)
        }
    }
}

/// Stores the update only on a valid signature; invalid updates are dropped without evicting.
async fn apply_linking_update(
    store: &Arc<dyn PxpKnownDeviceInfoStore>,
    private_key: &NonZeroScalar,
    tunnel_domain: &str,
    linking_info: &PxpLinkingInfo,
    handshake_hash: &[u8],
) {
    let device_id: PxpKnownDeviceId = linking_info.into();
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
    linking_info: &PxpLinkingInfo,
    handshake_hash: &[u8],
) -> Result<PxpKnownDeviceInfo, PxpError> {
    let known_device = PxpKnownDeviceInfo::new(tunnel_domain, linking_info)?;
    let secret_key = SecretKey::from(private_key);

    let Ok(authenticator_public_key) =
        PublicKey::from_sec1_bytes(&linking_info.authenticator_public_key)
    else {
        error!("Failed to parse public key.");
        return Err(PxpError::InvalidKey);
    };

    let shared_secret: Vec<u8> = ecdh::diffie_hellman(
        secret_key.to_nonzero_scalar(),
        authenticator_public_key.as_affine(),
    )
    .raw_secret_bytes()
    .to_vec();

    let mut hmac =
        Hmac::<Sha256>::new_from_slice(&shared_secret).map_err(|_| PxpError::InvalidKey)?;
    hmac.update(handshake_hash);
    let expected_mac = hmac.finalize().into_bytes().to_vec();

    if expected_mac != linking_info.handshake_signature {
        error!("Invalid handshake signature, rejecting update message");
        trace!(?expected_mac, ?linking_info.handshake_signature);
        return Err(PxpError::InvalidSignature);
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
        puts: Mutex<Vec<PxpKnownDeviceId>>,
        deletes: Mutex<Vec<PxpKnownDeviceId>>,
    }

    #[async_trait]
    impl PxpKnownDeviceInfoStore for RecordingStore {
        async fn put_known_device(
            &self,
            device_id: &PxpKnownDeviceId,
            _device: &PxpKnownDeviceInfo,
        ) {
            if let Ok(mut puts) = self.puts.lock() {
                puts.push(device_id.clone());
            }
        }
        async fn delete_known_device(&self, device_id: &PxpKnownDeviceId) {
            if let Ok(mut deletes) = self.deletes.lock() {
                deletes.push(device_id.clone());
            }
        }
    }

    fn linking_info_with_authenticator_key(authenticator_public_key: Vec<u8>) -> PxpLinkingInfo {
        PxpLinkingInfo {
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
        let store: Arc<dyn PxpKnownDeviceInfoStore> = recording.clone();

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
    fn absent_supported_features_defaults_to_ctap() {
        let map = BTreeMap::from([(Value::Integer(1), Value::Bytes(vec![]))]);
        let bytes = cbor::to_vec(&map).unwrap();
        let message: PxpInitialMessage = cbor::from_slice(&bytes).unwrap();
        assert_eq!(message.supported_features.0, vec!["ctap"]);
    }

    #[test]
    fn strip_frame_padding_rejects_empty() {
        let result = strip_frame_padding(Vec::new());
        assert!(matches!(result, Err(PxpError::InvalidFraming)));
    }

    #[test]
    fn strip_frame_padding_rejects_overlong_padding() {
        // Length 1 + declared padding of 5 -> would require subtracting 6 from 1.
        let frame = vec![0x05u8];
        let result = strip_frame_padding(frame);
        assert!(matches!(result, Err(PxpError::InvalidFraming)));
    }

    #[test]
    fn strip_frame_padding_strips_normal_padding() {
        // 4 bytes of payload, 3 bytes of zero padding, then padding-length 3.
        let frame = vec![0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x03];
        let stripped = strip_frame_padding(frame).unwrap();
        assert_eq!(stripped, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
