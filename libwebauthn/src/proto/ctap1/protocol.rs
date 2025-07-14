use std::convert::TryInto;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::{sleep, timeout as tokio_timeout};
use tracing::{debug, error, info, instrument, span, trace, warn, Level};

use super::apdu::{ApduRequest, ApduResponse, ApduResponseStatus};
use super::{
    Ctap1RegisterRequest, Ctap1RegisterResponse, Ctap1SignRequest, Ctap1SignResponse,
    Ctap1VersionRequest, Ctap1VersionResponse,
};
use crate::proto::ctap1::model::Preflight;
use crate::proto::CtapError;
use crate::transport::{error::TransportError, Channel};
use crate::webauthn::error::Error;

const UP_SLEEP: Duration = Duration::from_millis(150);
const VERSION_TIMEOUT: Duration = Duration::from_millis(500);

#[async_trait]
pub trait Ctap1 {
    async fn ctap1_version(&mut self) -> Result<Ctap1VersionResponse, Error>;
    async fn ctap1_register(
        &mut self,
        op: &Ctap1RegisterRequest,
    ) -> Result<Ctap1RegisterResponse, Error>;
    async fn ctap1_sign(&mut self, op: &Ctap1SignRequest) -> Result<Ctap1SignResponse, Error>;
}

#[async_trait]
impl<C> Ctap1 for C
where
    C: Channel,
{
    #[instrument(skip_all)]
    async fn ctap1_version(&mut self) -> Result<Ctap1VersionResponse, Error> {
        let request = &Ctap1VersionRequest::new();
        let apdu_request: ApduRequest = request.into();
        self.apdu_send(&apdu_request, VERSION_TIMEOUT).await?;
        let apdu_response = self.apdu_recv(VERSION_TIMEOUT).await?;
        let response: Ctap1VersionResponse = apdu_response.try_into().or(Err(CtapError::Other))?;
        debug!({ ?response.version }, "CTAP1 version response");
        Ok(response)
    }

    #[instrument(skip_all)]
    async fn ctap1_register(
        &mut self,
        request: &Ctap1RegisterRequest,
    ) -> Result<Ctap1RegisterResponse, Error> {
        debug!({ %request.require_user_presence }, "CTAP1 register request");
        trace!(?request);

        let (request, preflight_requests) = request.preflight()?;
        debug!({ count = preflight_requests.len() }, "Preflight requests");
        for preflight in preflight_requests.iter() {
            let span = span!(Level::DEBUG, "preflight");
            let _enter = span.enter();
            match self.ctap1_sign(preflight).await {
                Ok(_) => {
                    info!("Already-registered credential found during preflight request.");
                    return Err(Error::Ctap(CtapError::CredentialExcluded));
                }
                Err(Error::Ctap(CtapError::NoCredentials)) => {
                    debug!("Credential doesn't already exist, continuing.");
                }
                Err(err) => {
                    warn!(?err, "Preflight request failed with unexpected error.");
                }
            };
        }

        let apdu_request: ApduRequest = (&request).into();
        let apdu_response = send_apdu_request_wait_uv(self, &apdu_request, request.timeout).await?;
        let status = apdu_response.status().or(Err(CtapError::Other))?;
        if status != ApduResponseStatus::NoError {
            error!(?status, "APDU response has error code");
            return Err(Error::Ctap(CtapError::from(status)));
        }

        let response: Ctap1RegisterResponse = apdu_response.try_into().unwrap();
        debug!("CTAP1 register response");
        trace!(?response);
        Ok(response)
    }

    #[instrument(skip_all, fields(preflight = !request.require_user_presence))]
    async fn ctap1_sign(&mut self, request: &Ctap1SignRequest) -> Result<Ctap1SignResponse, Error> {
        debug!({ %request.require_user_presence }, "CTAP1 sign request");
        trace!(?request);

        let apdu_request: ApduRequest = request.into();
        let apdu_response = send_apdu_request_wait_uv(self, &apdu_request, request.timeout).await?;
        let status = apdu_response.status().or(Err(CtapError::Other))?;
        if status != ApduResponseStatus::NoError {
            error!(?status, "APDU response has error code");
            return Err(Error::Ctap(CtapError::from(status)));
        }

        let response: Ctap1SignResponse = apdu_response.try_into().unwrap();
        debug!({ ?response.user_presence_verified }, "CTAP1 sign response received");
        trace!(?response);
        Ok(response)
    }
}

async fn send_apdu_request_wait_uv<'c, C: Channel>(
    channel: &'c mut C,
    request: &ApduRequest,
    timeout: Duration,
) -> Result<ApduResponse, Error> {
    tokio_timeout(timeout, async {
        loop {
            channel.apdu_send(request, timeout).await?;
            let apdu_response = channel.apdu_recv(timeout).await?;
            let apdu_status = apdu_response
                .status()
                .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
            let ctap_error: CtapError = apdu_status.into();
            match ctap_error {
                CtapError::Ok => return Ok(apdu_response),
                CtapError::UserPresenceRequired => (), // Sleep some more.
                _ => return Err(Error::Ctap(ctap_error)),
            };
            debug!("UP required. Sleeping for {:?}.", UP_SLEEP);
            sleep(UP_SLEEP).await;
        }
    })
    .await
    .or(Err(Error::Ctap(CtapError::UserActionTimeout)))?
}
