use crate::proto::ctap2::cbor::CborError;
pub use crate::proto::CtapError;

/// Ceremony-level error, generic over the channel's concrete transport error.
///
/// `E` is bound exactly once, by the channel that runs the operation
/// ([`Channel::TransportError`](crate::transport::Channel::TransportError)).
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error<E> {
    #[error("ctap error: {0}")]
    Ctap(#[source] CtapError),
    #[error("transport error: {0}")]
    Transport(#[source] E),
    #[error("platform error: {0}")]
    Platform(#[source] PlatformError),
}

/// Former name of the ceremony [`Error`], retained to avoid call-site churn.
pub use self::Error as WebAuthnError;

impl<E> From<CtapError> for Error<E> {
    fn from(error: CtapError) -> Self {
        Error::Ctap(error)
    }
}

impl<E> From<PlatformError> for Error<E> {
    fn from(error: PlatformError) -> Self {
        Error::Platform(error)
    }
}

impl<E> From<CborError> for Error<E> {
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
    #[error("request exceeds authenticator limits")]
    RequestTooLarge,
    #[error("operation not supported")]
    NotSupported,
    #[error("syntax error")]
    SyntaxError,
    #[error("cbor serialization error: {0}")]
    CborError(#[from] CborError),
    #[error("crypto error: {0}")]
    CryptoError(String),
    #[error("cancelled by user")]
    Cancelled,
}
