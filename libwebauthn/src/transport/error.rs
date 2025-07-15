#[derive(thiserror::Error, Debug, PartialEq)]
pub enum TransportError {
    #[error("connection failed")]
    ConnectionFailed,
    #[error("connection lost")]
    ConnectionLost,
    #[error("invalid endpoint")]
    InvalidEndpoint,
    #[error("invalid framing")]
    InvalidFraming,
    #[error("negotiation failed")]
    NegotiationFailed,
    #[error("transport unavailable")]
    TransportUnavailable,
    #[error("timeout")]
    Timeout,
    #[error("device not found")]
    UnknownDevice,
    #[error("invalid key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("input/output error: {0}")]
    IoError(std::io::ErrorKind),
}
