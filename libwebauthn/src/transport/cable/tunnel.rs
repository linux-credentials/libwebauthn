//! WebSocket tunnel-server transport for the caBLE hybrid protocol.
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, trace};
use tungstenite::client::IntoClientRequest;

use super::protocol::CableTunnelConnectionType;
use crate::proto::ctap2::cbor;
use crate::transport::error::TransportError;

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

pub fn decode_tunnel_server_domain(encoded: u16) -> Option<String> {
    if encoded < 256 {
        return KNOWN_TUNNEL_DOMAINS
            .get(encoded as usize)
            .map(|s| (*s).to_string());
    }

    let mut sha_input = SHA_INPUT.to_vec();
    sha_input.push(encoded as u8);
    sha_input.push((encoded >> 8) as u8);
    sha_input.push(0);
    let mut hasher = Sha256::default();
    hasher.update(&sha_input);
    // SHA-256 produces 32 bytes, so the first 8 bytes are always present.
    let digest: [u8; 32] = hasher.finalize().into();
    let mut digest_head = [0u8; 8];
    digest_head.copy_from_slice(digest.get(..8)?);
    let mut v = u64::from_le_bytes(digest_head);
    let tld_index = (v & 3) as usize;
    v >>= 2;

    let mut ret = String::from("cable.");
    while v != 0 {
        let ch = *BASE32_CHARS.get((v & 31) as usize)?;
        ret.push(ch as char);
        v >>= 5;
    }

    ret.push_str(TLDS.get(tld_index)?);
    Some(ret)
}

pub(crate) async fn connect(
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
            hex::encode(client_payload)
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
