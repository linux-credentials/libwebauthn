use std::io::Error as IOError;

use crate::proto::ctap2::cbor;
use crate::proto::ctap2::model::Ctap2ClientPinRequest;
use crate::proto::ctap2::model::Ctap2CommandCode;
use crate::proto::ctap2::model::Ctap2GetAssertionRequest;
use crate::proto::ctap2::model::Ctap2MakeCredentialRequest;
use crate::proto::ctap2::Ctap2AuthenticatorConfigRequest;
use crate::proto::ctap2::Ctap2BioEnrollmentRequest;
use crate::proto::ctap2::Ctap2CredentialManagementRequest;
use crate::proto::ctap2::Ctap2LargeBlobsRequest;
use crate::webauthn::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct CborRequest {
    pub command: Ctap2CommandCode,
    pub encoded_data: Vec<u8>,
}

impl CborRequest {
    pub fn new(command: Ctap2CommandCode) -> Self {
        Self {
            command,
            encoded_data: vec![],
        }
    }

    pub fn ctap_hid_data(&self) -> Vec<u8> {
        let mut data = vec![self.command as u8];
        data.extend(&self.encoded_data);
        data
    }

    pub fn raw_long(&self) -> Result<Vec<u8>, IOError> {
        let mut data = vec![self.command as u8];
        data.extend(self.encoded_data.iter().copied());
        Ok(data)
    }
}

impl TryFrom<&Ctap2MakeCredentialRequest> for CborRequest {
    type Error = Error;
    fn try_from(request: &Ctap2MakeCredentialRequest) -> Result<CborRequest, Error> {
        Ok(CborRequest {
            command: Ctap2CommandCode::AuthenticatorMakeCredential,
            encoded_data: cbor::to_vec(&request)?,
        })
    }
}

impl TryFrom<&Ctap2GetAssertionRequest> for CborRequest {
    type Error = Error;
    fn try_from(request: &Ctap2GetAssertionRequest) -> Result<CborRequest, Error> {
        Ok(CborRequest {
            command: Ctap2CommandCode::AuthenticatorGetAssertion,
            encoded_data: cbor::to_vec(&request)?,
        })
    }
}

impl TryFrom<&Ctap2ClientPinRequest> for CborRequest {
    type Error = Error;
    fn try_from(request: &Ctap2ClientPinRequest) -> Result<CborRequest, Error> {
        Ok(CborRequest {
            command: Ctap2CommandCode::AuthenticatorClientPin,
            encoded_data: cbor::to_vec(&request)?,
        })
    }
}

impl TryFrom<&Ctap2AuthenticatorConfigRequest> for CborRequest {
    type Error = Error;
    fn try_from(request: &Ctap2AuthenticatorConfigRequest) -> Result<CborRequest, Error> {
        Ok(CborRequest {
            command: Ctap2CommandCode::AuthenticatorConfig,
            encoded_data: cbor::to_vec(&request)?,
        })
    }
}

impl TryFrom<&Ctap2BioEnrollmentRequest> for CborRequest {
    type Error = Error;
    fn try_from(request: &Ctap2BioEnrollmentRequest) -> Result<CborRequest, Error> {
        let command = if request.use_legacy_preview {
            Ctap2CommandCode::AuthenticatorBioEnrollmentPreview
        } else {
            Ctap2CommandCode::AuthenticatorBioEnrollment
        };
        Ok(CborRequest {
            command,
            encoded_data: cbor::to_vec(&request)?,
        })
    }
}

impl TryFrom<&Ctap2CredentialManagementRequest> for CborRequest {
    type Error = Error;
    fn try_from(request: &Ctap2CredentialManagementRequest) -> Result<CborRequest, Error> {
        let command = if request.use_legacy_preview {
            Ctap2CommandCode::AuthenticatorCredentialManagementPreview
        } else {
            Ctap2CommandCode::AuthenticatorCredentialManagement
        };
        Ok(CborRequest {
            command,
            encoded_data: cbor::to_vec(&request)?,
        })
    }
}

impl TryFrom<&Ctap2LargeBlobsRequest> for CborRequest {
    type Error = Error;
    fn try_from(request: &Ctap2LargeBlobsRequest) -> Result<CborRequest, Error> {
        Ok(CborRequest {
            command: Ctap2CommandCode::AuthenticatorLargeBlobs,
            encoded_data: cbor::to_vec(&request)?,
        })
    }
}
