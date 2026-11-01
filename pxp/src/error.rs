//! Errors specific to the caBLE / hybrid transport.

use std::sync::Arc;

use tokio_tungstenite::tungstenite::http::header::InvalidHeaderValue;
use tokio_tungstenite::tungstenite::Error as TungsteniteError;

/// caBLE transport error. `Clone` because it rides the [`PxpUpdate`](crate::PxpUpdate) UX
/// broadcast stream, which requires `Clone`; non-`Clone` native causes
/// (`snow`, `io`, `tungstenite`, `serde_cbor`, `http`) are kept behind an
/// `Arc` rather than flattened.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum PxpError {
    #[error("noise protocol error: {0}")]
    Noise(Arc<snow::Error>),
    #[error("input/output error: {0}")]
    Io(Arc<std::io::Error>),
    #[error("websocket error: {0}")]
    WebSocket(Arc<TungsteniteError>),
    #[error("cbor error: {0}")]
    Cbor(Arc<serde_cbor_2::Error>),
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("uuid parse error: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("invalid http header: {0}")]
    HttpHeader(Arc<InvalidHeaderValue>),
    #[error(transparent)]
    PxpTunnel(#[from] PxpTunnelError),
    #[error("connection failed")]
    ConnectionFailed,
    #[error("connection lost")]
    ConnectionLost,
    #[error("invalid endpoint")]
    InvalidEndpoint,
    #[error("invalid framing")]
    InvalidFraming,
    #[error("transport unavailable")]
    TransportUnavailable,
    #[error("timeout")]
    Timeout,
    #[error("invalid key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("encryption failed")]
    EncryptionFailed,
}

impl From<snow::Error> for PxpError {
    fn from(error: snow::Error) -> Self {
        PxpError::Noise(Arc::new(error))
    }
}

impl From<std::io::Error> for PxpError {
    fn from(error: std::io::Error) -> Self {
        PxpError::Io(Arc::new(error))
    }
}

impl From<TungsteniteError> for PxpError {
    fn from(error: TungsteniteError) -> Self {
        PxpError::WebSocket(Arc::new(error))
    }
}

impl From<InvalidHeaderValue> for PxpError {
    fn from(error: InvalidHeaderValue) -> Self {
        PxpError::HttpHeader(Arc::new(error))
    }
}

impl From<serde_cbor_2::Error> for PxpError {
    fn from(error: serde_cbor_2::Error) -> Self {
        PxpError::Cbor(Arc::new(error))
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Clone)]
pub enum PxpTunnelError {
    /// The tunnel server returned HTTP 410 Gone for the contacted resource.
    #[error("tunnel server reported the resource is gone (HTTP 410)")]
    Gone,
    /// The tunnel server returned an unexpected, non-success HTTP status.
    #[error("tunnel server returned unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
    /// The tunnel server kept redirecting past the allowed limit.
    #[error("tunnel server exceeded the maximum number of redirects")]
    TooManyRedirects,
}
