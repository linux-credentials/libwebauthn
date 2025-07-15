use async_trait::async_trait;
use tracing::{instrument, warn};

use crate::fido::FidoProtocol;
use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::ops::u2f::{RegisterResponse, SignResponse};
use crate::proto::ctap1::Ctap1;
use crate::transport::{error::TransportError, Channel};
use crate::webauthn::error::Error;

#[async_trait]
pub trait U2F {
    async fn u2f_negotiate_protocol(&mut self) -> Result<FidoProtocol, Error>;
    async fn u2f_register(&mut self, op: &RegisterRequest) -> Result<RegisterResponse, Error>;
    async fn u2f_sign(&mut self, op: &SignRequest) -> Result<SignResponse, Error>;
}

#[async_trait]
impl<C> U2F for C
where
    C: Channel,
{
    #[instrument(skip_all)]
    async fn u2f_negotiate_protocol(&mut self) -> Result<FidoProtocol, Error> {
        let supported = self.supported_protocols().await?;
        if !supported.u2f && !supported.fido2 {
            warn!("Negotiation failed: channel doesn't support U2F nor FIDO2");
            return Err(Error::Transport(TransportError::NegotiationFailed));
        }
        // Ensure CTAP1 version is reported correctly.
        self.ctap1_version().await?;
        let selected = FidoProtocol::U2F;
        Ok(selected)
    }

    #[instrument(skip_all, fields(dev = %self))]
    async fn u2f_register(&mut self, op: &RegisterRequest) -> Result<RegisterResponse, Error> {
        let protocol = self.u2f_negotiate_protocol().await?;
        match protocol {
            FidoProtocol::U2F => self.ctap1_register(op).await,
            _ => Err(Error::Transport(TransportError::NegotiationFailed)),
        }
    }

    #[instrument(skip_all, fields(dev = %self))]
    async fn u2f_sign(&mut self, op: &SignRequest) -> Result<SignResponse, Error> {
        let protocol = self.u2f_negotiate_protocol().await?;
        match protocol {
            FidoProtocol::U2F => self.ctap1_sign(op).await,
            _ => Err(Error::Transport(TransportError::NegotiationFailed)),
        }
    }
}
