//! Errors specific to the caBLE / hybrid transport.

use std::sync::Arc;

use tokio_tungstenite::tungstenite::http::header::InvalidHeaderValue;
use tokio_tungstenite::tungstenite::Error as TungsteniteError;

use crate::proto::ctap2::cbor::CborError;

/// caBLE transport error. `Clone` because it rides the [`CableUpdate`] UX
/// broadcast stream, which requires `Clone`; non-`Clone` native causes
/// (`snow`, `io`, `tungstenite`, `serde_cbor`, `http`) are kept behind an
/// `Arc` rather than flattened.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum CableError {
    #[error("noise protocol error: {0}")]
    Noise(Arc<snow::Error>),
    #[error("input/output error: {0}")]
    Io(Arc<std::io::Error>),
    #[error("websocket error: {0}")]
    WebSocket(Arc<TungsteniteError>),
    #[error("cbor error: {0}")]
    Cbor(Arc<CborError>),
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("uuid parse error: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("invalid http header: {0}")]
    HttpHeader(Arc<InvalidHeaderValue>),
    #[error(transparent)]
    CableTunnel(#[from] CableTunnelError),
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

impl From<snow::Error> for CableError {
    fn from(error: snow::Error) -> Self {
        CableError::Noise(Arc::new(error))
    }
}

impl From<std::io::Error> for CableError {
    fn from(error: std::io::Error) -> Self {
        CableError::Io(Arc::new(error))
    }
}

impl From<TungsteniteError> for CableError {
    fn from(error: TungsteniteError) -> Self {
        CableError::WebSocket(Arc::new(error))
    }
}

impl From<InvalidHeaderValue> for CableError {
    fn from(error: InvalidHeaderValue) -> Self {
        CableError::HttpHeader(Arc::new(error))
    }
}

impl From<CborError> for CableError {
    fn from(error: CborError) -> Self {
        CableError::Cbor(Arc::new(error))
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Clone)]
pub enum CableTunnelError {
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
