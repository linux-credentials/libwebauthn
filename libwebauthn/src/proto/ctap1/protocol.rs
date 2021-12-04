use std::{convert::TryInto, marker::PhantomData, time::Duration};

use async_trait::async_trait;
use tokio::time::{sleep, timeout as tokio_timeout};
use tracing::{debug, instrument, trace};

use super::apdu::{ApduRequest, ApduResponse, ApduResponseStatus};
use super::{
    Ctap1RegisterRequest, Ctap1RegisterResponse, Ctap1SignRequest, Ctap1SignResponse,
    Ctap1VersionRequest, Ctap1VersionResponse,
};
use crate::proto::CtapError;
use crate::transport::device::FidoDevice;
use crate::transport::error::{Error, TransportError};

const UP_SLEEP: Duration = Duration::from_millis(150);
const VERSION_TIMEOUT: Duration = Duration::from_millis(500);

#[async_trait]
pub trait Ctap1<T> {
    async fn version(device: &mut T) -> Result<Ctap1VersionResponse, Error>;

    async fn register(
        device: &mut T,
        op: &Ctap1RegisterRequest,
    ) -> Result<Ctap1RegisterResponse, Error>;

    async fn sign(device: &mut T, op: &Ctap1SignRequest) -> Result<Ctap1SignResponse, Error>;
}

pub struct Ctap1Protocol<T: FidoDevice + ?Sized> {
    device_type: PhantomData<T>,
}

#[async_trait]
impl<T> Ctap1<T> for Ctap1Protocol<T>
where
    T: FidoDevice + Send,
{
    #[instrument(skip_all)]
    async fn register(
        device: &mut T,
        request: &Ctap1RegisterRequest,
    ) -> Result<Ctap1RegisterResponse, Error> {
        debug!({ %request.app_id, %request.require_user_presence, %request.check_only }, "CTAP1 register request");
        trace!(?request);
        // TODO iterate over exclude list

        let apdu_request: ApduRequest = request.into();
        let apdu_response =
            Ctap1Protocol::send_apdu_request_wait_uv(device, &apdu_request, request.timeout)
                .await?;
        let status = apdu_response.status().or(Err(CtapError::Other))?;
        if status != ApduResponseStatus::NoError {
            return Err(Error::Ctap(CtapError::from(status)));
        }

        let response: Ctap1RegisterResponse = apdu_response.try_into().unwrap();
        debug!("CTAP1 register response");
        trace!(?response);
        Ok(response)
    }

    #[instrument(skip_all)]
    async fn sign(device: &mut T, request: &Ctap1SignRequest) -> Result<Ctap1SignResponse, Error> {
        debug!({ %request.app_id, %request.require_user_presence }, "CTAP1 sign request");
        trace!(?request);

        let apdu_request: ApduRequest = request.into();
        let apdu_response =
            Ctap1Protocol::send_apdu_request_wait_uv(device, &apdu_request, request.timeout)
                .await?;
        let status = apdu_response.status().or(Err(CtapError::Other))?;
        if status != ApduResponseStatus::NoError {
            return Err(Error::Ctap(CtapError::from(status)));
        }

        let response: Ctap1SignResponse = apdu_response.try_into().unwrap();
        debug!({ ?response.user_presence_verified }, "CTAP1 sign response received");
        trace!(?response);
        Ok(response)
    }

    #[instrument(skip_all)]
    async fn version(device: &mut T) -> Result<Ctap1VersionResponse, Error> {
        let request = &Ctap1VersionRequest::new();
        let apdu_request: ApduRequest = request.into();
        let apdu_response = device
            .send_apdu_request(&apdu_request, VERSION_TIMEOUT)
            .await?;
        let response: Ctap1VersionResponse = apdu_response.try_into().or(Err(CtapError::Other))?;
        debug!({ ?response.version }, "CTAP1 version response");
        Ok(response)
    }
}

impl<T> Ctap1Protocol<T>
where
    T: FidoDevice,
{
    async fn send_apdu_request_wait_uv(
        device: &mut T,
        request: &ApduRequest,
        timeout: Duration,
    ) -> Result<ApduResponse, Error> {
        tokio_timeout(timeout, async {
            loop {
                let apdu_response = device.send_apdu_request(request, timeout).await?;
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
}
