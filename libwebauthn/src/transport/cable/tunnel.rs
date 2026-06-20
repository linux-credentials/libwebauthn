//! WebSocket tunnel-server transport for the caBLE hybrid protocol.
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::{header::LOCATION, StatusCode};
use tokio_tungstenite::tungstenite::Error as TungsteniteError;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, trace};
use tungstenite::client::IntoClientRequest;
use url::Url;

use super::error::CableTunnelError;
use super::known_devices::CableKnownDeviceId;
use super::protocol::CableTunnelConnectionType;
use crate::proto::ctap2::cbor;
use crate::transport::cable::error::CableError;

const MAX_TUNNEL_REDIRECTS: usize = 5;

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

/// Builds the tunnel request, re-attaching the fido.cable and client-payload headers.
pub(crate) fn build_tunnel_request(
    url: &str,
    connection_type: &CableTunnelConnectionType,
) -> Result<Request, CableError> {
    let mut request = url.into_client_request().map_err(CableError::from)?;
    let headers = request.headers_mut();
    headers.insert("Sec-WebSocket-Protocol", "fido.cable".parse()?);

    if let CableTunnelConnectionType::KnownDevice { client_payload, .. } = connection_type {
        let client_payload = cbor::to_vec(client_payload)?;
        headers.insert(
            "X-caBLE-Client-Payload",
            hex::encode(client_payload).parse()?,
        );
    }
    Ok(request)
}

/// Resolves a redirect Location, which may be relative, against the current URL.
fn resolve_redirect_target(base: &str, location: &str) -> Result<String, CableError> {
    let base = Url::parse(base)?;
    let target = base.join(location)?;
    Ok(target.to_string())
}

/// Maps a non-101 tunnel handshake status to a transport error, distinguishing 410 Gone.
fn tunnel_status_error(status: StatusCode) -> CableError {
    if status == StatusCode::GONE {
        CableTunnelError::Gone.into()
    } else {
        CableTunnelError::UnexpectedStatus(status.as_u16()).into()
    }
}

/// The known-device id to forget on a 410 Gone, for a known-device connection.
pub(crate) fn known_device_id_to_forget(
    error: &CableError,
    connection_type: &CableTunnelConnectionType,
) -> Option<CableKnownDeviceId> {
    match (error, connection_type) {
        (
            CableError::CableTunnel(CableTunnelError::Gone),
            CableTunnelConnectionType::KnownDevice {
                authenticator_public_key,
                ..
            },
        ) => Some(hex::encode(authenticator_public_key)),
        _ => None,
    }
}

pub(crate) async fn connect(
    tunnel_domain: &str,
    connection_type: &CableTunnelConnectionType,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, CableError> {
    ensure_rustls_crypto_provider();

    let mut connect_url = match connection_type {
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

    for _ in 0..=MAX_TUNNEL_REDIRECTS {
        debug!(?connect_url, "Connecting to tunnel server");
        let request = build_tunnel_request(&connect_url, connection_type)?;
        trace!(?request);

        let error = match connect_async(request).await {
            Ok((ws_stream, response)) => {
                debug!(?response, "Connected to tunnel server");
                if response.status() != StatusCode::SWITCHING_PROTOCOLS {
                    error!(?response, "Failed to switch to websocket protocol");
                    return Err(CableError::ConnectionFailed);
                }
                debug!("Tunnel server returned success");
                return Ok(ws_stream);
            }
            Err(error) => error,
        };

        let response = match error {
            TungsteniteError::Http(response) => response,
            error => {
                error!(?error, "Failed to connect to tunnel server");
                return Err(CableError::from(error));
            }
        };

        let status = response.status();
        if status.is_redirection() {
            let Some(location) = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
            else {
                error!(?status, "Tunnel redirect missing a usable Location header");
                return Err(CableError::ConnectionFailed);
            };
            connect_url = resolve_redirect_target(&connect_url, location)?;
            debug!(?connect_url, "Following tunnel redirect");
            continue;
        }

        error!(?status, "Tunnel server rejected the connection");
        return Err(tunnel_status_error(status));
    }

    error!("Exceeded the maximum number of tunnel redirects");
    Err(CableTunnelError::TooManyRedirects.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::cable::known_devices::{ClientPayload, ClientPayloadHint};
    use p256::NonZeroScalar;
    use rand::rngs::OsRng;
    use serde_bytes::ByteBuf;

    fn known_device_connection_type(public_key: Vec<u8>) -> CableTunnelConnectionType {
        CableTunnelConnectionType::KnownDevice {
            contact_id: "contact-id".to_string(),
            authenticator_public_key: public_key,
            client_payload: ClientPayload {
                link_id: ByteBuf::from(vec![1u8; 8]),
                client_nonce: ByteBuf::from(vec![2u8; 16]),
                hint: ClientPayloadHint::GetAssertion,
            },
        }
    }

    fn qr_connection_type() -> CableTunnelConnectionType {
        CableTunnelConnectionType::QrCode {
            routing_id: "aabbcc".to_string(),
            tunnel_id: "00112233445566778899aabbccddeeff".to_string(),
            private_key: NonZeroScalar::random(&mut OsRng),
        }
    }

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

    #[test]
    fn resolve_redirect_target_relative_and_absolute() {
        let base = "wss://cable.example.com/cable/contact/abc";
        assert_eq!(
            resolve_redirect_target(base, "/cable/contact/v2/abc").unwrap(),
            "wss://cable.example.com/cable/contact/v2/abc"
        );
        assert_eq!(
            resolve_redirect_target(base, "wss://cable.example.net/cable/contact/xyz").unwrap(),
            "wss://cable.example.net/cable/contact/xyz"
        );
    }

    #[test]
    fn build_tunnel_request_reattaches_headers_for_known_device() {
        let connection_type = known_device_connection_type(vec![4u8; 65]);
        let request = build_tunnel_request(
            "wss://cable.example.com/cable/contact/abc",
            &connection_type,
        )
        .unwrap();
        assert_eq!(
            request
                .headers()
                .get("Sec-WebSocket-Protocol")
                .unwrap()
                .to_str()
                .unwrap(),
            "fido.cable"
        );
        assert!(request.headers().get("X-caBLE-Client-Payload").is_some());
    }

    #[test]
    fn build_tunnel_request_omits_payload_for_qr_code() {
        let connection_type = qr_connection_type();
        let request = build_tunnel_request(
            "wss://cable.example.com/cable/connect/aabbcc/0011",
            &connection_type,
        )
        .unwrap();
        assert_eq!(
            request
                .headers()
                .get("Sec-WebSocket-Protocol")
                .unwrap()
                .to_str()
                .unwrap(),
            "fido.cable"
        );
        assert!(request.headers().get("X-caBLE-Client-Payload").is_none());
    }

    #[test]
    fn gone_forgets_known_device() {
        let public_key = vec![7u8; 65];
        let connection_type = known_device_connection_type(public_key.clone());
        assert_eq!(
            known_device_id_to_forget(
                &CableError::CableTunnel(CableTunnelError::Gone),
                &connection_type
            ),
            Some(hex::encode(&public_key))
        );
    }

    #[test]
    fn gone_does_not_forget_qr_code() {
        let connection_type = qr_connection_type();
        assert_eq!(
            known_device_id_to_forget(
                &CableError::CableTunnel(CableTunnelError::Gone),
                &connection_type
            ),
            None
        );
    }

    #[test]
    fn non_gone_error_does_not_forget_known_device() {
        let connection_type = known_device_connection_type(vec![7u8; 65]);
        assert_eq!(
            known_device_id_to_forget(&CableError::ConnectionFailed, &connection_type),
            None
        );
    }

    #[test]
    fn gone_status_maps_to_distinct_error() {
        assert!(matches!(
            tunnel_status_error(StatusCode::GONE),
            CableError::CableTunnel(CableTunnelError::Gone)
        ));
        assert!(matches!(
            tunnel_status_error(StatusCode::BAD_GATEWAY),
            CableError::CableTunnel(CableTunnelError::UnexpectedStatus(502))
        ));
    }
}
