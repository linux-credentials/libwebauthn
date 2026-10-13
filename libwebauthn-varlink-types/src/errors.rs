use libwebauthn::proto::CtapError;
use libwebauthn::transport::cable::error::CableError;
use libwebauthn::webauthn::error::PlatformError;
use serde::{Deserialize, Serialize};
use zlink::introspect;

use crate::VarlinkOperation;

#[derive(Debug, Clone, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "com.github.linux-credentials.webauthn")]
pub enum VarlinkError {
    /// The channel closed before it connected.
    PrematureConnectionClose,
    /// This connection has no channel: `FutureDeviceConnection` was never
    /// called on it, or the channel was used up or closed.
    NoActiveConnection,
    /// This connection's channel was opened for a different operation than
    /// the one requested. The channel stays open.
    OperationMismatch {
        expected: VarlinkOperation,
        actual: VarlinkOperation,
    },
    /// The token passed to `ProvidePin` belongs to no pending PIN request: it
    /// is unknown, expired, or already answered.
    UnknownPinRequest,
    InvalidRequest {
        message: String,
    },
    CeremonyFailed {
        message: String,
    },
    /// The caBLE/hybrid transport failed. See `TransportErrorDetails` for the
    /// specific cause.
    TransportError {
        error: VarlinkTransportError,
    },
    CeremonyError {
        error: VarlinkCeremonyError,
    },
    MakeCredentialPrepareError {
        error: VarlinkCredentialPrepareError,
    },
    /// Serializing the ceremony's response into WebAuthn IDL JSON failed.
    ResponseSerializationError {
        message: String,
    },
}

impl std::fmt::Display for VarlinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrematureConnectionClose => write!(f, "the channel closed before it connected"),
            Self::NoActiveConnection => write!(f, "this connection has no channel"),
            Self::OperationMismatch { expected, actual } => {
                write!(f, "the channel was opened for {actual:?}, not {expected:?}")
            }
            Self::UnknownPinRequest => write!(f, "no pending PIN request has this token"),
            Self::InvalidRequest { message } => write!(f, "invalid request: {message}"),
            Self::CeremonyFailed { message } => write!(f, "ceremony failed: {message}"),
            Self::TransportError { error } => write!(f, "transport error: {}", error.message),
            Self::CeremonyError { error } => write!(f, "ceremony error: {}", error.message),
            Self::MakeCredentialPrepareError { error } => {
                write!(f, "invalid registration request: {}", error.message)
            }
            Self::ResponseSerializationError { message } => {
                write!(f, "failed to serialize the response: {message}")
            }
        }
    }
}

// zlink's `ReplyError` derive copies the enum's attributes, so `thiserror`
// cannot be used here.
impl std::error::Error for VarlinkError {}

impl From<CableError> for VarlinkError {
    fn from(err: CableError) -> Self {
        VarlinkError::TransportError { error: err.into() }
    }
}

impl From<libwebauthn::ops::webauthn::MakeCredentialPrepareError> for VarlinkError {
    fn from(err: libwebauthn::ops::webauthn::MakeCredentialPrepareError) -> Self {
        VarlinkError::MakeCredentialPrepareError { error: err.into() }
    }
}

impl From<libwebauthn::ops::webauthn::ResponseSerializationError> for VarlinkError {
    fn from(err: libwebauthn::ops::webauthn::ResponseSerializationError) -> Self {
        VarlinkError::ResponseSerializationError {
            message: err.to_string(),
        }
    }
}

impl From<libwebauthn::webauthn::error::Error<CableError>> for VarlinkError {
    fn from(err: libwebauthn::webauthn::error::Error<CableError>) -> Self {
        match err {
            libwebauthn::webauthn::error::Error::Ctap(err) => {
                Self::CeremonyError { error: err.into() }
            }
            libwebauthn::webauthn::error::Error::Platform(err) => {
                Self::CeremonyError { error: err.into() }
            }
            libwebauthn::webauthn::error::Error::Transport(err) => {
                Self::CeremonyError { error: err.into() }
            }
            // `Error` is `#[non_exhaustive]`, so a variant added upstream
            // ends up here. It still reaches the client, as a generic
            // ceremony failure with its message.
            other => Self::CeremonyFailed {
                message: other.to_string(),
            },
        }
    }
}

/// Mirrors `libwebauthn::transport::cable::error::CableError` 1:1 for
/// Varlink clients, so they can react to specific caBLE/hybrid transport
/// failures (e.g. distinguishing a `Timeout` from a `ConnectionLost`).
///
/// Modeled as a struct rather than a data-carrying enum: `introspect::Type`'s
/// enum derive only supports unit variants (Varlink IDL enums are plain
/// string sets), so the discriminant lives in `kind` and the human-readable
/// cause in `message`.
#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "TransportErrorDetails")]
pub struct VarlinkTransportError {
    pub kind: VarlinkTransportErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "TransportErrorKind")]
pub enum VarlinkTransportErrorKind {
    Noise,
    Io,
    WebSocket,
    Cbor,
    UrlParse,
    UuidParse,
    InvalidHttpHeader,
    CableTunnel,
    ConnectionFailed,
    ConnectionLost,
    InvalidEndpoint,
    InvalidFraming,
    TransportUnavailable,
    Timeout,
    InvalidKey,
    InvalidSignature,
    EncryptionFailed,
    /// Fallback for `CableError` variants added upstream that aren't
    /// explicitly mapped yet (`CableError` is `#[non_exhaustive]`).
    Other,
}

impl From<CableError> for VarlinkTransportError {
    fn from(err: CableError) -> Self {
        let message = err.to_string();
        let kind = match err {
            CableError::Noise(_) => VarlinkTransportErrorKind::Noise,
            CableError::Io(_) => VarlinkTransportErrorKind::Io,
            CableError::WebSocket(_) => VarlinkTransportErrorKind::WebSocket,
            CableError::Cbor(_) => VarlinkTransportErrorKind::Cbor,
            CableError::Url(_) => VarlinkTransportErrorKind::UrlParse,
            CableError::Uuid(_) => VarlinkTransportErrorKind::UuidParse,
            CableError::HttpHeader(_) => VarlinkTransportErrorKind::InvalidHttpHeader,
            CableError::CableTunnel(_) => VarlinkTransportErrorKind::CableTunnel,
            CableError::ConnectionFailed => VarlinkTransportErrorKind::ConnectionFailed,
            CableError::ConnectionLost => VarlinkTransportErrorKind::ConnectionLost,
            CableError::InvalidEndpoint => VarlinkTransportErrorKind::InvalidEndpoint,
            CableError::InvalidFraming => VarlinkTransportErrorKind::InvalidFraming,
            CableError::TransportUnavailable => VarlinkTransportErrorKind::TransportUnavailable,
            CableError::Timeout => VarlinkTransportErrorKind::Timeout,
            CableError::InvalidKey => VarlinkTransportErrorKind::InvalidKey,
            CableError::InvalidSignature => VarlinkTransportErrorKind::InvalidSignature,
            CableError::EncryptionFailed => VarlinkTransportErrorKind::EncryptionFailed,
            _ => VarlinkTransportErrorKind::Other,
        };
        VarlinkTransportError { kind, message }
    }
}

/// Mirrors `libwebauthn::webauthn::error::Error` for Varlink clients: a
/// ceremony can fail due to a CTAP-level error, a platform-level error, or
/// the underlying transport.
///
/// Like [`VarlinkTransportError`], this is modeled as a struct (not a
/// data-carrying enum) because `introspect::Type`'s enum derive only
/// supports unit variants. The discriminant lives in `kind`, with
/// `transport` populated only when `kind` is `Transport`.
#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "CeremonyErrorDetails")]
pub struct VarlinkCeremonyError {
    pub kind: VarlinkCeremonyErrorKind,
    pub message: String,
    /// Populated when `kind` is `Transport`; carries the detailed
    /// transport-specific error.
    pub transport: Option<VarlinkTransportError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "CeremonyErrorKind")]
pub enum VarlinkCeremonyErrorKind {
    Ctap,
    Platform,
    Transport,
}

impl From<CtapError> for VarlinkCeremonyError {
    fn from(err: CtapError) -> Self {
        VarlinkCeremonyError {
            kind: VarlinkCeremonyErrorKind::Ctap,
            message: err.to_string(),
            transport: None,
        }
    }
}

impl From<PlatformError> for VarlinkCeremonyError {
    fn from(err: PlatformError) -> Self {
        VarlinkCeremonyError {
            kind: VarlinkCeremonyErrorKind::Platform,
            message: err.to_string(),
            transport: None,
        }
    }
}

impl From<CableError> for VarlinkCeremonyError {
    fn from(err: CableError) -> Self {
        let transport: VarlinkTransportError = err.into();
        VarlinkCeremonyError {
            message: transport.message.clone(),
            kind: VarlinkCeremonyErrorKind::Transport,
            transport: Some(transport),
        }
    }
}

/// Mirrors `libwebauthn::ops::webauthn::MakeCredentialPrepareError` for
/// Varlink clients: a `MakeCredentialRequest::prepare` call can fail because
/// the request JSON was malformed, or because the relying party/AppID didn't
/// validate against the calling origin.
///
/// Like [`VarlinkTransportError`], this is modeled as a struct (not a
/// data-carrying enum) because `introspect::Type`'s enum derive only
/// supports unit variants. The discriminant lives in `kind`, with the
/// human-readable cause (including any relying party/AppID details) in
/// `message`.
#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "PrepareErrorDetails")]
pub struct VarlinkCredentialPrepareError {
    pub kind: VarlinkCredentialPrepareErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "PrepareErrorKind")]
pub enum VarlinkCredentialPrepareErrorKind {
    /// The client must throw an "EncodingError" DOMException.
    EncodingError,
    InvalidRelyingPartyId,
    MismatchingRelyingPartyId,
    /// The client must throw a "SecurityError" DOMException.
    InvalidAppId,
}

impl From<libwebauthn::ops::webauthn::MakeCredentialPrepareError>
    for VarlinkCredentialPrepareError
{
    fn from(err: libwebauthn::ops::webauthn::MakeCredentialPrepareError) -> Self {
        use libwebauthn::ops::webauthn::MakeCredentialPrepareError as E;
        let kind = match &err {
            E::EncodingError(_) => VarlinkCredentialPrepareErrorKind::EncodingError,
            E::InvalidRelyingPartyId(_) => VarlinkCredentialPrepareErrorKind::InvalidRelyingPartyId,
            E::MismatchingRelyingPartyId(_, _) => {
                VarlinkCredentialPrepareErrorKind::MismatchingRelyingPartyId
            }
            E::InvalidAppId(_) => VarlinkCredentialPrepareErrorKind::InvalidAppId,
        };
        VarlinkCredentialPrepareError {
            message: err.to_string(),
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use libwebauthn::ops::webauthn::MakeCredentialPrepareError;
    use libwebauthn::webauthn::error::Error;

    use super::*;

    #[test]
    fn errors_display_their_cause() {
        assert_eq!(
            VarlinkError::NoActiveConnection.to_string(),
            "this connection has no channel"
        );
        assert_eq!(
            VarlinkError::OperationMismatch {
                expected: VarlinkOperation::MakeCredential,
                actual: VarlinkOperation::GetAssertion,
            }
            .to_string(),
            "the channel was opened for GetAssertion, not MakeCredential"
        );
        assert_eq!(
            VarlinkError::from(CableError::Timeout).to_string(),
            format!("transport error: {}", CableError::Timeout)
        );
    }

    #[test]
    fn cable_errors_keep_their_kind_and_message() {
        let error = VarlinkTransportError::from(CableError::ConnectionLost);
        assert!(matches!(
            error.kind,
            VarlinkTransportErrorKind::ConnectionLost
        ));
        assert_eq!(error.message, CableError::ConnectionLost.to_string());

        let error = VarlinkTransportError::from(CableError::Timeout);
        assert!(matches!(error.kind, VarlinkTransportErrorKind::Timeout));

        let io = std::io::Error::other("socket closed");
        let error = VarlinkTransportError::from(CableError::Io(io.into()));
        assert!(matches!(error.kind, VarlinkTransportErrorKind::Io));
        assert!(error.message.contains("socket closed"), "{}", error.message);
    }

    #[test]
    fn cable_error_becomes_transport_error() {
        assert!(matches!(
            VarlinkError::from(CableError::InvalidFraming),
            VarlinkError::TransportError {
                error: VarlinkTransportError {
                    kind: VarlinkTransportErrorKind::InvalidFraming,
                    ..
                }
            }
        ));
    }

    #[test]
    fn ceremony_errors_keep_their_source() {
        let error = VarlinkError::from(Error::<CableError>::Ctap(CtapError::PINInvalid));
        let VarlinkError::CeremonyError { error } = error else {
            panic!("expected a ceremony error, got {error:?}");
        };
        assert!(matches!(error.kind, VarlinkCeremonyErrorKind::Ctap));
        assert!(error.transport.is_none());

        let error = VarlinkError::from(Error::<CableError>::Platform(PlatformError::PinTooShort));
        let VarlinkError::CeremonyError { error } = error else {
            panic!("expected a ceremony error, got {error:?}");
        };
        assert!(matches!(error.kind, VarlinkCeremonyErrorKind::Platform));
        assert!(error.transport.is_none());

        let error = VarlinkError::from(Error::<CableError>::Transport(CableError::Timeout));
        let VarlinkError::CeremonyError { error } = error else {
            panic!("expected a ceremony error, got {error:?}");
        };
        assert!(matches!(error.kind, VarlinkCeremonyErrorKind::Transport));
        assert!(matches!(
            error.transport,
            Some(VarlinkTransportError {
                kind: VarlinkTransportErrorKind::Timeout,
                ..
            })
        ));
    }

    #[test]
    fn prepare_errors_keep_their_kind() {
        let kind = |error| VarlinkCredentialPrepareError::from(error).kind;
        assert!(matches!(
            kind(MakeCredentialPrepareError::InvalidRelyingPartyId(
                "x".into()
            )),
            VarlinkCredentialPrepareErrorKind::InvalidRelyingPartyId
        ));
        assert!(matches!(
            kind(MakeCredentialPrepareError::MismatchingRelyingPartyId(
                "a.org".into(),
                "b.org".into()
            )),
            VarlinkCredentialPrepareErrorKind::MismatchingRelyingPartyId
        ));
        assert!(matches!(
            kind(MakeCredentialPrepareError::InvalidAppId("x".into())),
            VarlinkCredentialPrepareErrorKind::InvalidAppId
        ));
    }
}
