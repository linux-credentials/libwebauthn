pub use crate::proto::CtapError;
use crate::{proto::ctap2::cbor::CborError, webauthn::TransportError};

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

impl From<CborError> for Error {
    fn from(error: CborError) -> Self {
        Error::Platform(PlatformError::CborError(error))
    }
}

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
    #[error("cbor serialization error: {0}")]
    CborError(#[from] CborError),
    #[error("cancelled by user")]
    Cancelled,
}
