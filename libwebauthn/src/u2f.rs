//! High-level FIDO U2F (CTAP1) client API for registering and authenticating
//! against an authenticator device. The [`U2F`] trait is blanket-implemented for
//! any [`Channel`] and offers three async operations: protocol negotiation,
//! registration, and signing.
//!
//! [`RegisterRequest`] and [`SignRequest`] describe the inputs, while the
//! corresponding response types carry the results back to the caller. The trait
//! handles the full lifecycle of a U2F exchange, from negotiating the device
//! protocol through running the request with error handling.

use async_trait::async_trait;
use tracing::{instrument, warn};

use crate::fido::FidoProtocol;
use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::u2f::{RegisterResponse, SignResponse};
use crate::proto::ctap1::Ctap1;
use crate::transport::Channel;
use crate::webauthn::error::{PlatformError, WebAuthnError};

#[async_trait]
pub trait U2F: Channel {
    async fn u2f_negotiate_protocol(
        &mut self,
    ) -> Result<FidoProtocol, WebAuthnError<Self::TransportError>>;
    async fn u2f_register(
        &mut self,
        op: &RegisterRequest,
    ) -> Result<RegisterResponse, WebAuthnError<Self::TransportError>>;
    async fn u2f_sign(
        &mut self,
        op: &SignRequest,
    ) -> Result<SignResponse, WebAuthnError<Self::TransportError>>;
}

#[async_trait]
impl<C> U2F for C
where
    C: Channel,
{
    #[instrument(skip_all)]
    async fn u2f_negotiate_protocol(
        &mut self,
    ) -> Result<FidoProtocol, WebAuthnError<Self::TransportError>> {
        let supported = self.supported_protocols().await?;
        if !supported.u2f && !supported.fido2 {
            warn!("Negotiation failed: channel doesn't support U2F nor FIDO2");
            return Err(WebAuthnError::Platform(PlatformError::NotSupported));
        }
        // Ensure CTAP1 version is reported correctly.
        self.ctap1_version().await?;
        let selected = FidoProtocol::U2F;
        Ok(selected)
    }

    #[instrument(skip_all, fields(dev = %self))]
    async fn u2f_register(
        &mut self,
        op: &RegisterRequest,
    ) -> Result<RegisterResponse, WebAuthnError<Self::TransportError>> {
        let protocol = self.u2f_negotiate_protocol().await?;
        match protocol {
            FidoProtocol::U2F => self.ctap1_register(op).await,
            _ => Err(WebAuthnError::Platform(PlatformError::NotSupported)),
        }
    }

    #[instrument(skip_all, fields(dev = %self))]
    async fn u2f_sign(
        &mut self,
        op: &SignRequest,
    ) -> Result<SignResponse, WebAuthnError<Self::TransportError>> {
        let protocol = self.u2f_negotiate_protocol().await?;
        match protocol {
            FidoProtocol::U2F => self.ctap1_sign(op).await,
            _ => Err(WebAuthnError::Platform(PlatformError::NotSupported)),
        }
    }
}
