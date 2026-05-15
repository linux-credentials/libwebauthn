//! [`CableDataChannel`] over a direct BLE L2CAP connection-oriented channel.
use std::str::FromStr;

use async_trait::async_trait;
use btleplug::api::{AddressType, BDAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, warn};

use super::data_channel::CableDataChannel;
use crate::transport::error::TransportError;

/// End-of-Message sequence terminating every L2CAP message (CRLF).
const EOM: [u8; 2] = [0x0D, 0x0A];

/// [`CableDataChannel`] over the insecure L2CAP CoC socket the CMHD opens for CTAP 2.3 hybrid.
/// Messages are CRLF-terminated per the CTAP 2.3 hybrid draft.
pub(crate) struct L2capDataChannel {
    stream: bluer::l2cap::Stream,
    // Carries bytes read past a message boundary so `recv` stays cancel-safe.
    read_buf: Vec<u8>,
}

impl L2capDataChannel {
    /// Connects to the peer's auto-generated PSM over an insecure L2CAP CoC.
    ///
    /// The socket is left at the kernel's default `sec_level` of
    /// `BT_SECURITY_LOW`, which on an LE link does not trigger pairing or
    /// encryption. We deliberately don't call `set_security`:
    /// `BT_SECURITY_SDP` (0) is rejected by `l2cap_sock_setsockopt` with
    /// `-EINVAL` on any L2CAP CoC.
    pub(crate) async fn connect(
        addr: BDAddr,
        addr_type: Option<AddressType>,
        psm: u16,
    ) -> Result<Self, TransportError> {
        let (addr, addr_type) = bdaddr_to_bluer(addr, addr_type)?;

        let stream =
            bluer::l2cap::Stream::connect(bluer::l2cap::SocketAddr::new(addr, addr_type, psm))
                .await
                .map_err(|e| {
                    error!(?e, %addr, psm, "Failed to connect L2CAP CoC");
                    TransportError::ConnectionFailed
                })?;

        Ok(Self {
            stream,
            read_buf: Vec::new(),
        })
    }
}

#[async_trait]
impl CableDataChannel for L2capDataChannel {
    async fn send(&mut self, message: &[u8]) -> Result<(), TransportError> {
        // NOTE: CRLF-terminating binary ciphertext is ambiguous in the CTAP 2.3 hybrid draft
        // and may need revisiting against real hardware.
        self.stream.write_all(message).await.map_err(|e| {
            error!(?e, "Failed to write L2CAP message");
            TransportError::IoError(e.kind())
        })?;
        self.stream.write_all(&EOM).await.map_err(|e| {
            error!(?e, "Failed to write L2CAP EOM");
            TransportError::IoError(e.kind())
        })?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        loop {
            if let Some(message) = split_next_message(&mut self.read_buf) {
                return Ok(Some(message));
            }
            let mut chunk = [0u8; 1024];
            let n = self.stream.read(&mut chunk).await.map_err(|e| {
                error!(?e, "Failed to read L2CAP message");
                TransportError::IoError(e.kind())
            })?;
            if n == 0 {
                // Peer closed; only a clean close if nothing is half-buffered.
                if self.read_buf.is_empty() {
                    return Ok(None);
                }
                error!(buffered = self.read_buf.len(), "L2CAP closed mid-message");
                return Err(TransportError::ConnectionLost);
            }
            self.read_buf
                .extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        }
    }
}

/// Drains the first CRLF-terminated message from `buf`, returning it without the
/// CRLF. Returns `None` (leaving `buf` untouched) until a full message is buffered.
fn split_next_message(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let eom = buf.windows(EOM.len()).position(|w| w == EOM)?;
    let message: Vec<u8> = buf.get(..eom).unwrap_or(&[]).to_vec();
    buf.drain(..eom + EOM.len());
    Some(message)
}

/// Converts a btleplug address to a bluer one. Uses a `Display`/`FromStr` round
/// trip (both render `AA:BB:CC:DD:EE:FF`) to sidestep byte-order pitfalls.
fn bdaddr_to_bluer(
    addr: BDAddr,
    addr_type: Option<AddressType>,
) -> Result<(bluer::Address, bluer::AddressType), TransportError> {
    let addr = bluer::Address::from_str(&addr.to_string()).map_err(|e| {
        error!(?e, "Failed to parse Bluetooth address");
        TransportError::InvalidEndpoint
    })?;
    let addr_type = match addr_type {
        Some(AddressType::Public) => bluer::AddressType::LePublic,
        Some(AddressType::Random) => bluer::AddressType::LeRandom,
        None => {
            warn!("Peer address type unknown; defaulting to LE public");
            bluer::AddressType::LePublic
        }
    };
    Ok((addr, addr_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_message_across_reads() {
        let mut buf = b"hel".to_vec();
        assert_eq!(split_next_message(&mut buf), None);
        assert_eq!(buf, b"hel");
        buf.extend_from_slice(b"lo\r\n");
        assert_eq!(split_next_message(&mut buf), Some(b"hello".to_vec()));
        assert!(buf.is_empty());
    }

    #[test]
    fn split_multiple_buffered_messages() {
        let mut buf = b"one\r\ntwo\r\nthr".to_vec();
        assert_eq!(split_next_message(&mut buf), Some(b"one".to_vec()));
        assert_eq!(split_next_message(&mut buf), Some(b"two".to_vec()));
        assert_eq!(split_next_message(&mut buf), None);
        assert_eq!(buf, b"thr");
    }

    #[test]
    fn split_nothing_buffered() {
        let mut buf = Vec::new();
        assert_eq!(split_next_message(&mut buf), None);
        assert!(buf.is_empty());
    }

    #[test]
    fn split_empty_message() {
        let mut buf = b"\r\nrest".to_vec();
        assert_eq!(split_next_message(&mut buf), Some(Vec::new()));
        assert_eq!(buf, b"rest");
    }

    #[test]
    fn split_handles_binary_payload() {
        let mut buf = vec![0x00, 0xFF, 0x0D, 0x0A];
        assert_eq!(split_next_message(&mut buf), Some(vec![0x00, 0xFF]));
        assert!(buf.is_empty());
    }

    #[test]
    fn eom_is_crlf() {
        assert_eq!(EOM, [0x0D, 0x0A]);
    }

    #[test]
    fn address_round_trip_public() {
        let bd = BDAddr::from([0x1F, 0x2A, 0x00, 0xCC, 0x22, 0xF1]);
        let (addr, addr_type) = bdaddr_to_bluer(bd, Some(AddressType::Public)).unwrap();
        assert_eq!(
            addr,
            bluer::Address::new([0x1F, 0x2A, 0x00, 0xCC, 0x22, 0xF1])
        );
        assert_eq!(addr_type, bluer::AddressType::LePublic);
    }

    #[test]
    fn address_round_trip_random() {
        let bd = BDAddr::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let (addr, addr_type) = bdaddr_to_bluer(bd, Some(AddressType::Random)).unwrap();
        assert_eq!(
            addr,
            bluer::Address::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        );
        assert_eq!(addr_type, bluer::AddressType::LeRandom);
    }

    #[test]
    fn address_type_defaults_to_public() {
        let bd = BDAddr::from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let (_, addr_type) = bdaddr_to_bluer(bd, None).unwrap();
        assert_eq!(addr_type, bluer::AddressType::LePublic);
    }
}
