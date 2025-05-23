pub use crate::proto::CtapError;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum PlatformError {
    #[error("pin too short")]
    PinTooShort,
    #[error("pin too long")]
    PinTooLong,
    #[error("pin not supported")]
    PinNotSupported,
    #[error("no user verification mechanism available")]
    NoUvAvailable,
    #[error("invalid device response")]
    InvalidDeviceResponse,
    #[error("operation not supported")]
    NotSupported,
    #[error("syntax error")]
    SyntaxError,
}

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
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("Ctap error: {0}")]
    Ctap(#[from] CtapError),
    #[error("Platform error: {0}")]
    Platform(#[from] PlatformError),
}

impl From<snow::Error> for Error {
    fn from(_error: snow::Error) -> Self {
        Error::Transport(TransportError::NegotiationFailed)
    }
}
