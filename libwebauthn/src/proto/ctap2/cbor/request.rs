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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ctap2::model::{
        Ctap2CredentialType, Ctap2GetAssertionOptions, Ctap2MakeCredentialOptions,
        Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
        Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity,
    };
    use serde_bytes::ByteBuf;

    // Deterministic, hand-pickable inputs: fixed byte fills and example.com.
    fn fixed_make_credential_request() -> Ctap2MakeCredentialRequest {
        Ctap2MakeCredentialRequest {
            hash: ByteBuf::from([0x01u8; 32].to_vec()),
            relying_party: Ctap2PublicKeyCredentialRpEntity {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
            },
            user: Ctap2PublicKeyCredentialUserEntity {
                id: ByteBuf::from([0x02u8; 16].to_vec()),
                name: Some("alice".to_string()),
                display_name: Some("Alice".to_string()),
            },
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: Some(vec![Ctap2PublicKeyCredentialDescriptor {
                id: ByteBuf::from([0x03u8; 16].to_vec()),
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                transports: None,
            }]),
            extensions: None,
            options: Some(Ctap2MakeCredentialOptions {
                require_resident_key: Some(true),
                deprecated_require_user_verification: None,
            }),
            pin_auth_param: None,
            pin_auth_proto: None,
            enterprise_attestation: None,
        }
    }

    fn fixed_get_assertion_request() -> Ctap2GetAssertionRequest {
        Ctap2GetAssertionRequest {
            relying_party_id: "example.com".to_string(),
            client_data_hash: ByteBuf::from([0x04u8; 32].to_vec()),
            allow: vec![Ctap2PublicKeyCredentialDescriptor {
                id: ByteBuf::from([0x05u8; 16].to_vec()),
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                transports: None,
            }],
            extensions: None,
            options: Some(Ctap2GetAssertionOptions {
                require_user_presence: true,
                require_user_verification: false,
            }),
            pin_auth_param: None,
            pin_auth_proto: None,
        }
    }

    #[test]
    fn make_credential_request_golden_cbor() {
        let cbor = CborRequest::try_from(&fixed_make_credential_request()).unwrap();
        assert_eq!(cbor.command, Ctap2CommandCode::AuthenticatorMakeCredential);
        // Canonical indexed map, keys 0x01,0x02,0x03,0x04,0x05,0x07 in order.
        assert_eq!(hex::encode(&cbor.encoded_data), "a6015820010101010101010101010101010101010101010101010101010101010101010102a26269646b6578616d706c652e636f6d646e616d65674578616d706c6503a36269645002020202020202020202020202020202646e616d6565616c6963656b646973706c61794e616d6565416c6963650481a263616c672664747970656a7075626c69632d6b65790581a2626964500303030303030303030303030303030364747970656a7075626c69632d6b657907a162726bf5");
    }

    #[test]
    fn get_assertion_request_golden_cbor() {
        let cbor = CborRequest::try_from(&fixed_get_assertion_request()).unwrap();
        assert_eq!(cbor.command, Ctap2CommandCode::AuthenticatorGetAssertion);
        // Canonical indexed map with keys 0x01,0x02,0x03,0x05 in order, uv omitted.
        assert_eq!(hex::encode(&cbor.encoded_data), "a4016b6578616d706c652e636f6d02582004040404040404040404040404040404040404040404040404040404040404040381a2626964500505050505050505050505050505050564747970656a7075626c69632d6b657905a1627570f5");
    }
}
