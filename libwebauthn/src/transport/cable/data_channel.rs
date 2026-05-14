//! Transport-agnostic message channel for the hybrid transport.
// Unused until the protocol refactor wires it in.
#![allow(dead_code)]

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::error;

use crate::transport::error::TransportError;

/// A bidirectional channel carrying discrete protocol messages: the Noise
/// handshake messages, then the encrypted CTAP frames. caBLE rides this over a
/// WebSocket tunnel; CTAP 2.3 hybrid can also ride it over a BLE L2CAP connection.
#[async_trait]
pub(crate) trait CableDataChannel: Send {
    /// Sends one message as a discrete unit.
    async fn send(&mut self, message: &[u8]) -> Result<(), TransportError>;

    /// Receives the next message. `Ok(None)` signals a clean close by the peer.
    /// Must be cancel-safe so it can be used as a `tokio::select!` branch.
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, TransportError>;
}

/// [`CableDataChannel`] over the caBLE WebSocket tunnel. Each protocol message is
/// a single binary WebSocket frame.
pub(crate) struct WebSocketDataChannel {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl WebSocketDataChannel {
    pub(crate) fn new(stream: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self { stream }
    }
}

#[async_trait]
impl CableDataChannel for WebSocketDataChannel {
    async fn send(&mut self, message: &[u8]) -> Result<(), TransportError> {
        self.stream
            .send(Message::Binary(message.to_vec().into()))
            .await
            .map_err(|e| {
                error!(?e, "Failed to send WebSocket message");
                TransportError::ConnectionFailed
            })
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        loop {
            match self.stream.next().await {
                Some(Ok(Message::Binary(data))) => return Ok(Some(data.into())),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Ok(other)) => {
                    error!(?other, "Unexpected WebSocket message type");
                    return Err(TransportError::ConnectionFailed);
                }
                Some(Err(e)) => {
                    error!(?e, "Failed to read WebSocket message");
                    return Err(TransportError::ConnectionFailed);
                }
            }
        }
    }
}
