use ctap_types::serde::cbor_deserialize;
use futures::{SinkExt, StreamExt};
use p256::NonZeroScalar;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use serde_indexed::DeserializeIndexed;
use sha2::{Digest, Sha256};
use snow::{Builder, TransportState};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::{self, JoinHandle};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, trace, warn};

use super::channel::{CableChannel, CableChannelDevice};
use super::qr_code_device::CableQrCodeDevice;
use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
use crate::proto::ctap2::{Ctap2CommandCode, Ctap2GetInfoResponse};
use crate::transport::error::Error;
use crate::webauthn::TransportError;
use crate::StateUpdate;

pub(crate) const KNOWN_TUNNEL_DOMAINS: &[&str] = &["cable.ua5v.com", "cable.auth.com"];
const SHA_INPUT: &[u8] = b"caBLEv2 tunnel server domain";
const BASE32_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const TLDS: &[&str] = &[".com", ".org", ".net", ".info"];
const P256_X962_LENGTH: usize = 65;
const MAX_CBOR_SIZE: usize = 1024 * 1024;
const PADDING_GRANULARITY: usize = 32;

// const CABLE_PROLOGUE_STATE_ASSISTED = [0 as u8];
const CABLE_PROLOGUE_QR_INITIATED: &[u8] = &[1 as u8];

enum TransactionType {
    #[allow(dead_code)] // TODO StateAssisted
    StateAssisted,
    QRInitiated,
}

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
#[serde_indexed(offset = 0)]
struct CableInitialMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _padding: Option<ByteBuf>,
    pub info: ByteBuf,
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

pub async fn connect<'d>(
    device: &'d CableQrCodeDevice<'d>,
    tunnel_domain: &str,
    routing_id: &str,
    tunnel_id: &str,
    psk: &[u8; 32],
    private_key: &NonZeroScalar,
) -> Result<(CableChannel<'d>, mpsc::Receiver<StateUpdate>), Error> {
    let connect_url = format!(
        "wss://{}/cable/connect/{}/{}",
        tunnel_domain, routing_id, tunnel_id
    );
    debug!(?connect_url, "Connecting to tunnel server");
    // TODO: set protocol: fido.cable

    let (mut ws_stream, response) = match connect_async(&connect_url).await {
        Ok((ws_stream, response)) => (ws_stream, response),
        Err(e) => {
            error!(?e, "Failed to connect to tunnel server");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };
    debug!(?response, "Connected to tunnel server");

    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        error!(?response, "Failed to switch to websocket protocol");
        return Err(Error::Transport(TransportError::ConnectionFailed));
    }
    debug!("Tunnel server returned success");

    let noise_state = do_handshake(
        &mut ws_stream,
        psk,
        private_key,
        TransactionType::QRInitiated,
    )
    .await?;

    // TODO: Handle the unsolicited GetInfo response upon connection

    // After this, the handshake should be complete and you can start sending/receiving encrypted messages.
    // ...

    let (cbor_sender, cbor_receiver, handle_connection) = task_connection(ws_stream, noise_state)?;

    let (send, recv) = mpsc::channel(1);
    Ok((
        CableChannel {
            device: CableChannelDevice::QrCode(device),
            handle_connection,
            cbor_sender,
            cbor_receiver,
            tx: send,
        },
        recv,
    ))
}

async fn do_handshake(
    ws_stream: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    psk: &[u8; 32],
    private_key: &NonZeroScalar,
    transaction_type: TransactionType,
) -> Result<TransportState, Error> {
    let local_private_key = private_key.to_bytes();

    let noise_builder = match transaction_type {
        TransactionType::QRInitiated => Builder::new("Noise_KNpsk0_P256_AESGCM_SHA256".parse()?)
            .prologue(CABLE_PROLOGUE_QR_INITIATED)?
            .local_private_key(&local_private_key.as_slice())?
            .psk(0, psk)?,
        TransactionType::StateAssisted => {
            // Builder::new("Noise_NKpsk0_P256_AESGCM_SHA256".parse().unwrap())
            todo!()
        }
    };

    // Build the Noise handshake as the initiator
    let mut noise_handshake = match noise_builder.build_initiator() {
        Ok(handshake) => handshake,
        Err(e) => {
            error!(?e, "Failed to build Noise handshake");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };

    let mut initial_msg_buffer = vec![0u8; 1024];
    let initial_msg_len = match noise_handshake.write_message(&[], &mut initial_msg_buffer) {
        Ok(msg_len) => msg_len,
        Err(e) => {
            error!(?e, "Failed to write initial handshake message");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };
    trace!(
        { handshake = ?initial_msg_buffer[..initial_msg_len] },
        "Sending initial handshake message"
    );

    if let Err(e) = ws_stream
        .send(Message::Binary(
            initial_msg_buffer[..initial_msg_len].into(),
        ))
        .await
    {
        error!(?e, "Failed to send initial handshake message");
        return Err(Error::Transport(TransportError::ConnectionFailed));
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
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
        Some(Err(e)) => {
            error!(?e, "Failed to read handshake response");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
        None => {
            error!("Connection was closed before handshake was complete");
            return Err(Error::Transport(TransportError::ConnectionFailed));
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
        return Err(Error::Transport(TransportError::ConnectionFailed));
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
        return Err(Error::Transport(TransportError::ConnectionFailed));
    }

    Ok(noise_handshake.into_transport_mode()?)
}

fn task_connection(
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    transport_state: TransportState,
) -> Result<(Sender<CborRequest>, Receiver<CborResponse>, JoinHandle<()>), Error> {
    let (cbor_tx_send, cbor_tx_recv) = mpsc::channel(16);
    let (cbor_rx_send, cbor_rx_recv) = mpsc::channel(16);

    let handle_connection = task::spawn(connection(
        ws_stream,
        transport_state,
        cbor_tx_recv,
        cbor_rx_send,
    ));

    Ok((cbor_tx_send, cbor_rx_recv, handle_connection))
}

async fn connection(
    mut ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    mut noise_state: TransportState,
    mut cbor_tx_recv: Receiver<CborRequest>,
    cbor_rx_send: Sender<CborResponse>,
) {
    // Fetch the inital message
    let get_info_response_serialized: Vec<u8> = match ws_stream.next().await {
        Some(Ok(message)) => match connection_recv_initial(message, &mut noise_state).await {
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
            Some(message) = ws_stream.next() => {
                match message {
                    Err(e) => {
                        error!(?e, "Failed to read encrypted CBOR message");
                        return;
                    }
                    Ok(message) => {
                        debug!("Received WSS message");
                        trace!(?message);
                        let _ = connection_recv(message, &cbor_rx_send, &mut noise_state).await;
                    }
                };
            }
            Some(request) = cbor_tx_recv.recv() => {
                match request.command {
                    // Optimisation: respond to GetInfo requests immediately with the cached response
                    Ctap2CommandCode::AuthenticatorGetInfo => {
                        debug!("Responding to GetInfo request with cached response");
                        let response = CborResponse::new_success_from_slice(&get_info_response_serialized);
                        let _ = cbor_rx_send.send(response).await;
                    }
                    _ => {
                        debug!(?request.command, "Sending CBOR request");
                        let _ = connection_send(request, &mut ws_stream, &mut noise_state).await;
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
    noise_state: &mut TransportState,
) -> Result<(), Error> {
    debug!("Sending CBOR request");
    trace!(?request);

    let cbor_request = request.raw_long().or(Err(TransportError::InvalidFraming))?;
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
    match noise_state.write_message(&frame_serialized, &mut encrypted_frame) {
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
    noise_state: &mut TransportState,
) -> Result<Vec<u8>, Error> {
    let mut decrypted_frame = vec![0u8; MAX_CBOR_SIZE];
    match noise_state.read_message(&encrypted_frame, &mut decrypted_frame) {
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
    noise_state: &mut TransportState,
) -> Result<Vec<u8>, Error> {
    let Some(encrypted_frame) = connection_recv_binary_frame(message).await? else {
        return Err(Error::Transport(TransportError::ConnectionFailed));
    };

    let decrypted_frame = decrypt_frame(encrypted_frame, noise_state).await?;

    let initial_message: CableInitialMessage = match cbor_deserialize(&decrypted_frame) {
        Ok(initial_message) => initial_message,
        Err(e) => {
            error!(?e, "Failed to decode initial message");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };

    let _: Ctap2GetInfoResponse = match cbor_deserialize(&initial_message.info) {
        Ok(get_info_response) => get_info_response,
        Err(e) => {
            error!(?e, "Failed to decode GetInfo response");
            return Err(Error::Transport(TransportError::ConnectionFailed));
        }
    };

    Ok(initial_message.info.to_vec())
}

async fn connection_recv(
    message: Message,
    cbor_rx_send: &Sender<CborResponse>,
    noise_state: &mut TransportState,
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
            warn!(?cable_message, "Received update message");
            // TODO: connection_recv_update(cable_message.payload).await?;
        }
    };

    Ok(())
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
