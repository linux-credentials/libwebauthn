//! Transport-agnostic message channel for the hybrid transport.
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{Error, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::error;

use crate::transport::cable::error::CableError;

/// A bidirectional channel carrying discrete protocol messages: the Noise
/// handshake messages, then the encrypted CTAP frames. caBLE rides this over a
/// WebSocket tunnel; CTAP 2.3 hybrid can also ride it over a BLE L2CAP connection.
#[async_trait]
pub(crate) trait CableDataChannel: Send {
    /// Sends one message as a discrete unit.
    async fn send(&mut self, message: &[u8]) -> Result<(), CableError>;

    /// Receives the next message. `Ok(None)` signals a clean close by the peer.
    /// Must be cancel-safe so it can be used as a `tokio::select!` branch.
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, CableError>;
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
    async fn send(&mut self, message: &[u8]) -> Result<(), CableError> {
        self.stream
            .send(Message::Binary(message.to_vec().into()))
            .await
            .map_err(|e| {
                error!(?e, "Failed to send WebSocket message");
                match e {
                    Error::Io(io) => CableError::from(io),
                    _ => CableError::ConnectionFailed,
                }
            })
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, CableError> {
        loop {
            match self.stream.next().await {
                Some(Ok(Message::Binary(data))) => return Ok(Some(data.into())),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_))) | None | Some(Err(Error::ConnectionClosed)) => {
                    return Ok(None)
                }
                Some(Ok(other)) => {
                    error!(?other, "Unexpected WebSocket message type");
                    return Err(CableError::ConnectionFailed);
                }
                Some(Err(Error::Io(e))) => {
                    error!(?e, "Failed to read WebSocket message");
                    return Err(CableError::from(e));
                }
                Some(Err(e)) => {
                    error!(?e, "Failed to read WebSocket message");
                    return Err(CableError::ConnectionFailed);
                }
            }
        }
    }
}
