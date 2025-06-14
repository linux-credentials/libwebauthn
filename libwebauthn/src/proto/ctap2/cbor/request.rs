use std::io::Error as IOError;

use crate::proto::ctap2::cbor;
use crate::proto::ctap2::model::Ctap2ClientPinRequest;
use crate::proto::ctap2::model::Ctap2CommandCode;
use crate::proto::ctap2::model::Ctap2GetAssertionRequest;
use crate::proto::ctap2::model::Ctap2MakeCredentialRequest;
use crate::proto::ctap2::Ctap2AuthenticatorConfigRequest;
use crate::proto::ctap2::Ctap2BioEnrollmentRequest;
use crate::proto::ctap2::Ctap2CredentialManagementRequest;

#[derive(Debug, Clone)]
pub struct CborRequest {
    pub command: Ctap2CommandCode,
    pub encoded_data: Vec<u8>,
}

impl CborRequest {
    pub fn new(command: Ctap2CommandCode) -> Self {
        Self {
            command: command,
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

impl From<&Ctap2MakeCredentialRequest> for CborRequest {
    fn from(request: &Ctap2MakeCredentialRequest) -> CborRequest {
        CborRequest {
            command: Ctap2CommandCode::AuthenticatorMakeCredential,
            encoded_data: cbor::to_vec(&request).unwrap(),
        }
    }
}

impl From<&Ctap2GetAssertionRequest> for CborRequest {
    fn from(request: &Ctap2GetAssertionRequest) -> CborRequest {
        CborRequest {
            command: Ctap2CommandCode::AuthenticatorGetAssertion,
            encoded_data: cbor::to_vec(&request).unwrap(),
        }
    }
}

impl From<&Ctap2ClientPinRequest> for CborRequest {
    fn from(request: &Ctap2ClientPinRequest) -> CborRequest {
        CborRequest {
            command: Ctap2CommandCode::AuthenticatorClientPin,
            encoded_data: cbor::to_vec(&request).unwrap(),
        }
    }
}

impl From<&Ctap2AuthenticatorConfigRequest> for CborRequest {
    fn from(request: &Ctap2AuthenticatorConfigRequest) -> CborRequest {
        CborRequest {
            command: Ctap2CommandCode::AuthenticatorConfig,
            encoded_data: cbor::to_vec(&request).unwrap(),
        }
    }
}

impl From<&Ctap2BioEnrollmentRequest> for CborRequest {
    fn from(request: &Ctap2BioEnrollmentRequest) -> CborRequest {
        let command = if request.use_legacy_preview {
            Ctap2CommandCode::AuthenticatorBioEnrollmentPreview
        } else {
            Ctap2CommandCode::AuthenticatorBioEnrollment
        };
        CborRequest {
            command,
            encoded_data: cbor::to_vec(&request).unwrap(),
        }
    }
}

impl From<&Ctap2CredentialManagementRequest> for CborRequest {
    fn from(request: &Ctap2CredentialManagementRequest) -> CborRequest {
        let command = if request.use_legacy_preview {
            Ctap2CommandCode::AuthenticatorCredentialManagementPreview
        } else {
            Ctap2CommandCode::AuthenticatorCredentialManagement
        };
        CborRequest {
            command,
            encoded_data: cbor::to_vec(&request).unwrap(),
        }
    }
}
