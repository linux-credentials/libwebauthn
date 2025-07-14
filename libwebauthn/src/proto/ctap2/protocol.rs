use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, instrument, trace, warn};

use crate::proto::ctap2::cbor::{self, CborRequest};
use crate::proto::ctap2::{Ctap2BioEnrollmentResponse, Ctap2CommandCode};
use crate::transport::Channel;
use crate::unwrap_field;
use crate::webauthn::error::{CtapError, Error, PlatformError};

use super::model::Ctap2ClientPinResponse;
use super::{
    Ctap2AuthenticatorConfigRequest, Ctap2BioEnrollmentRequest, Ctap2ClientPinRequest,
    Ctap2CredentialManagementRequest, Ctap2CredentialManagementResponse, Ctap2GetAssertionRequest,
    Ctap2GetAssertionResponse, Ctap2GetInfoResponse, Ctap2MakeCredentialRequest,
    Ctap2MakeCredentialResponse,
};

const TIMEOUT_GET_INFO: Duration = Duration::from_millis(250);

macro_rules! parse_cbor {
    ($type:ty, $data:expr) => {{
        match cbor::from_slice::<$type>($data) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(
                    "Failed to parse {} from CBOR-data provided by the device. Parsing error: {:?}",
                    stringify!($type),
                    e
                );
                return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
            }
        }
    }};
}

#[async_trait]
pub trait Ctap2 {
    async fn ctap2_get_info(&mut self) -> Result<Ctap2GetInfoResponse, Error>;
    async fn ctap2_make_credential(
        &mut self,
        request: &Ctap2MakeCredentialRequest,
        timeout: Duration,
    ) -> Result<Ctap2MakeCredentialResponse, Error>;
    async fn ctap2_client_pin(
        &mut self,
        request: &Ctap2ClientPinRequest,
        timeout: Duration,
    ) -> Result<Ctap2ClientPinResponse, Error>;
    async fn ctap2_get_assertion(
        &mut self,
        request: &Ctap2GetAssertionRequest,
        timeout: Duration,
    ) -> Result<Ctap2GetAssertionResponse, Error>;
    async fn ctap2_get_next_assertion(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2GetAssertionResponse, Error>;
    async fn ctap2_selection(&mut self, timeout: Duration) -> Result<(), Error>;
    async fn ctap2_authenticator_config(
        &mut self,
        request: &Ctap2AuthenticatorConfigRequest,
        timeout: Duration,
    ) -> Result<(), Error>;
    async fn ctap2_bio_enrollment(
        &mut self,
        request: &Ctap2BioEnrollmentRequest,
        timeout: Duration,
    ) -> Result<Ctap2BioEnrollmentResponse, Error>;
    async fn ctap2_credential_management(
        &mut self,
        request: &Ctap2CredentialManagementRequest,
        timeout: Duration,
    ) -> Result<Ctap2CredentialManagementResponse, Error>;
}

#[async_trait]
impl<C> Ctap2 for C
where
    C: Channel,
{
    #[instrument(skip_all)]
    async fn ctap2_get_info(&mut self) -> Result<Ctap2GetInfoResponse, Error> {
        let cbor_request = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
        self.cbor_send(&cbor_request, TIMEOUT_GET_INFO).await?;
        let cbor_response = self.cbor_recv(TIMEOUT_GET_INFO).await?;
        match cbor_response.status_code {
            CtapError::Ok => (),
            error => return Err(Error::Ctap(error)),
        };
        let data = unwrap_field!(cbor_response.data);
        let ctap_response = parse_cbor!(Ctap2GetInfoResponse, &data);
        debug!("CTAP2 GetInfo successful");
        trace!(?ctap_response);
        Ok(ctap_response)
    }

    #[instrument(skip_all)]
    async fn ctap2_make_credential(
        &mut self,
        request: &Ctap2MakeCredentialRequest,
        timeout: Duration,
    ) -> Result<Ctap2MakeCredentialResponse, Error> {
        trace!(?request);
        self.cbor_send(&request.into(), timeout).await?;
        let cbor_response = self.cbor_recv(timeout).await?;
        match cbor_response.status_code {
            CtapError::Ok => (),
            error => return Err(Error::Ctap(error)),
        };
        let data = unwrap_field!(cbor_response.data);
        trace!("MakeCredential: {:?}", data);
        let ctap_response = parse_cbor!(Ctap2MakeCredentialResponse, &data);
        debug!("CTAP2 MakeCredential successful");
        trace!(?ctap_response);
        Ok(ctap_response)
    }

    #[instrument(skip_all)]
    async fn ctap2_get_assertion(
        &mut self,
        request: &Ctap2GetAssertionRequest,
        timeout: Duration,
    ) -> Result<Ctap2GetAssertionResponse, Error> {
        trace!(?request);
        self.cbor_send(&request.into(), timeout).await?;
        let cbor_response = self.cbor_recv(timeout).await?;
        match cbor_response.status_code {
            CtapError::Ok => (),
            error => return Err(Error::Ctap(error)),
        };
        let data = unwrap_field!(cbor_response.data);
        trace!("GetAssertion: {:?}", data);
        let ctap_response = parse_cbor!(Ctap2GetAssertionResponse, &data);
        debug!("CTAP2 GetAssertion successful");
        trace!(?ctap_response);
        Ok(ctap_response)
    }

    #[instrument(skip_all)]
    async fn ctap2_get_next_assertion(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2GetAssertionResponse, Error> {
        debug!("CTAP2 GetNextAssertion request");
        let cbor_request = CborRequest::new(Ctap2CommandCode::AuthenticatorGetNextAssertion);
        self.cbor_send(&cbor_request, timeout).await?;
        let cbor_response = self.cbor_recv(timeout).await?;
        let data = unwrap_field!(cbor_response.data);
        let ctap_response = parse_cbor!(Ctap2GetAssertionResponse, &data);
        debug!("CTAP2 GetNextAssertion successful");
        trace!(?ctap_response);
        Ok(ctap_response)
    }

    #[instrument(skip_all)]
    async fn ctap2_selection(&mut self, timeout: Duration) -> Result<(), Error> {
        debug!("CTAP2 Authenticator Selection request");
        let cbor_request = CborRequest::new(Ctap2CommandCode::AuthenticatorSelection);

        self.cbor_send(&cbor_request, timeout).await?;
        let cbor_response = self.cbor_recv(timeout).await?;
        match cbor_response.status_code {
            CtapError::Ok => {
                return Ok(());
            }
            error => {
                warn!(?error, "Selection request failed with status code");
                return Err(Error::Ctap(error));
            }
        }
    }

    #[instrument(skip_all)]
    async fn ctap2_client_pin(
        &mut self,
        request: &Ctap2ClientPinRequest,
        timeout: Duration,
    ) -> Result<Ctap2ClientPinResponse, Error> {
        trace!(?request);
        self.cbor_send(&request.into(), timeout).await?;
        let cbor_response = self.cbor_recv(timeout).await?;
        match cbor_response.status_code {
            CtapError::Ok => (),
            error => return Err(Error::Ctap(error)),
        };
        if let Some(data) = cbor_response.data {
            let ctap_response = parse_cbor!(Ctap2ClientPinResponse, &data);
            debug!("CTAP2 ClientPin successful");
            trace!(?ctap_response);
            Ok(ctap_response)
        } else {
            // Seems like a bug in serde_indexed: https://github.com/trussed-dev/serde-indexed/issues/10
            // Can't deserialize an empty vec[], even though everything is optional and marked as default.
            // So we work around it here by creating our own default value.
            Ok(Ctap2ClientPinResponse::default())
        }
    }

    #[instrument(skip_all)]
    async fn ctap2_authenticator_config(
        &mut self,
        request: &Ctap2AuthenticatorConfigRequest,
        timeout: Duration,
    ) -> Result<(), Error> {
        trace!(?request);
        self.cbor_send(&request.into(), timeout).await?;
        let cbor_response = self.cbor_recv(timeout).await?;
        match cbor_response.status_code {
            CtapError::Ok => {
                return Ok(());
            }
            error => {
                warn!(
                    ?error,
                    "Authenticator config request failed with status code"
                );
                return Err(Error::Ctap(error));
            }
        }
    }

    #[instrument(skip_all)]
    async fn ctap2_bio_enrollment(
        &mut self,
        request: &Ctap2BioEnrollmentRequest,
        timeout: Duration,
    ) -> Result<Ctap2BioEnrollmentResponse, Error> {
        trace!(?request);
        self.cbor_send(&request.into(), timeout).await?;
        let cbor_response = self.cbor_recv(timeout).await?;
        match cbor_response.status_code {
            CtapError::Ok => (),
            error => return Err(Error::Ctap(error)),
        };
        if let Some(data) = cbor_response.data {
            let ctap_response = parse_cbor!(Ctap2BioEnrollmentResponse, &data);
            debug!("CTAP2 BioEnrollment successful");
            trace!(?ctap_response);
            Ok(ctap_response)
        } else {
            // Seems like a bug in serde_indexed: https://github.com/trussed-dev/serde-indexed/issues/10
            // Can't deserialize an empty vec[], even though everything is optional and marked as default.
            // So we work around it here by creating our own default value.
            Ok(Ctap2BioEnrollmentResponse::default())
        }
    }

    #[instrument(skip_all)]
    async fn ctap2_credential_management(
        &mut self,
        request: &Ctap2CredentialManagementRequest,
        timeout: Duration,
    ) -> Result<Ctap2CredentialManagementResponse, Error> {
        trace!(?request);
        self.cbor_send(&request.into(), timeout).await?;
        let cbor_response = self.cbor_recv(timeout).await?;
        match cbor_response.status_code {
            CtapError::Ok => (),
            error => return Err(Error::Ctap(error)),
        };
        if let Some(data) = cbor_response.data {
            let ctap_response = parse_cbor!(Ctap2CredentialManagementResponse, &data);
            debug!("CTAP2 CredentialManagement successful");
            trace!(?ctap_response);
            Ok(ctap_response)
        } else {
            // Seems like a bug in serde_indexed: https://github.com/trussed-dev/serde-indexed/issues/10
            // Can't deserialize an empty vec[], even though everything is optional and marked as default.
            // So we work around it here by creating our own default value.
            Ok(Ctap2CredentialManagementResponse::default())
        }
    }
}
