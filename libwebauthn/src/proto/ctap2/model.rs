use crate::pin::PinUvAuthProtocol;
use crate::proto::ctap1::Ctap1Transport;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde_bytes::ByteBuf;
use serde_derive::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

mod get_info;
pub use get_info::Ctap2GetInfoResponse;
mod bio_enrollment;
pub use bio_enrollment::{
    Ctap2BioEnrollmentFingerprintKind, Ctap2BioEnrollmentModality, Ctap2BioEnrollmentRequest,
    Ctap2BioEnrollmentResponse, Ctap2BioEnrollmentTemplateId, Ctap2LastEnrollmentSampleStatus,
};
mod authenticator_config;
pub use authenticator_config::{
    Ctap2AuthenticatorConfigCommand, Ctap2AuthenticatorConfigParams,
    Ctap2AuthenticatorConfigRequest,
};
mod client_pin;
pub use client_pin::{
    Ctap2AuthTokenPermissionRole, Ctap2ClientPinRequest, Ctap2ClientPinResponse,
    Ctap2PinUvAuthProtocol,
};
mod make_credential;
pub use make_credential::{
    Ctap2MakeCredentialOptions, Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse,
    Ctap2MakeCredentialsResponseExtensions,
};
mod get_assertion;
pub use get_assertion::{
    Ctap2AttestationStatement, Ctap2GetAssertionOptions, Ctap2GetAssertionRequest,
    Ctap2GetAssertionResponse, Ctap2GetAssertionResponseExtensions, FidoU2fAttestationStmt,
};
mod credential_management;
pub use credential_management::{
    Ctap2CredentialData, Ctap2CredentialManagementMetadata, Ctap2CredentialManagementRequest,
    Ctap2CredentialManagementResponse, Ctap2RPData,
};

#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum Ctap2CommandCode {
    AuthenticatorMakeCredential = 0x01,
    AuthenticatorGetAssertion = 0x02,
    AuthenticatorGetInfo = 0x04,
    AuthenticatorClientPin = 0x06,
    AuthenticatorGetNextAssertion = 0x08,
    AuthenticatorBioEnrollment = 0x09,
    AuthenticatorBioEnrollmentPreview = 0x40,
    AuthenticatorCredentialManagement = 0x0A,
    AuthenticatorCredentialManagementPreview = 0x41,
    AuthenticatorSelection = 0x0B,
    AuthenticatorConfig = 0x0D,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ctap2PublicKeyCredentialRpEntity {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Ctap2PublicKeyCredentialRpEntity {
    pub fn dummy() -> Self {
        Self {
            id: String::from(".dummy"),
            name: Some(String::from(".dummy")),
        }
    }
}

impl Ctap2PublicKeyCredentialRpEntity {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: String::from(id),
            name: Some(String::from(name)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ctap2PublicKeyCredentialUserEntity {
    pub id: ByteBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    // TODO(afresta): Validation as per https://www.w3.org/TR/webauthn/#sctn-user-credential-params
    #[serde(rename = "displayName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl Ctap2PublicKeyCredentialUserEntity {
    pub fn dummy() -> Self {
        Self {
            id: ByteBuf::from([1]),
            name: Some(String::from("dummy")),
            display_name: None,
        }
    }
}

impl Ctap2PublicKeyCredentialUserEntity {
    pub fn new(id: &[u8], name: &str, display_name: &str) -> Self {
        Self {
            id: ByteBuf::from(id),
            name: Some(String::from(name)),
            display_name: Some(String::from(display_name)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Ctap2PublicKeyCredentialType {
    #[serde(rename = "public-key")]
    PublicKey,

    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ctap2Transport {
    Ble,
    Nfc,
    Usb,
    Internal,
    Hybrid,
}

impl From<&Ctap1Transport> for Ctap2Transport {
    fn from(ctap1: &Ctap1Transport) -> Ctap2Transport {
        match ctap1 {
            Ctap1Transport::Bt => Ctap2Transport::Ble,
            Ctap1Transport::Ble => Ctap2Transport::Ble,
            Ctap1Transport::Usb => Ctap2Transport::Usb,
            Ctap1Transport::Nfc => Ctap2Transport::Nfc,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ctap2PublicKeyCredentialDescriptor {
    pub id: ByteBuf,
    pub r#type: Ctap2PublicKeyCredentialType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<Ctap2Transport>>,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2COSEAlgorithmIdentifier {
    ES256 = -7,
    EDDSA = -8,
    TOPT = -9,
    #[serde(other)]
    Unknown = -999,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Ctap2CredentialType {
    #[serde(rename = "alg")]
    pub algorithm: Ctap2COSEAlgorithmIdentifier,

    #[serde(rename = "type")]
    pub public_key_type: Ctap2PublicKeyCredentialType,
}

impl Default for Ctap2CredentialType {
    fn default() -> Self {
        Self {
            public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
            algorithm: Ctap2COSEAlgorithmIdentifier::ES256,
        }
    }
}

impl Ctap2CredentialType {
    pub fn new(
        public_key_type: Ctap2PublicKeyCredentialType,
        algorithm: Ctap2COSEAlgorithmIdentifier,
    ) -> Self {
        Self {
            public_key_type,
            algorithm,
        }
    }

    pub fn is_known(&self) -> bool {
        self.algorithm != Ctap2COSEAlgorithmIdentifier::Unknown
            && self.public_key_type != Ctap2PublicKeyCredentialType::Unknown
    }
}

pub trait Ctap2UserVerifiableRequest {
    fn ensure_uv_set(&mut self);
    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &Box<dyn PinUvAuthProtocol>,
        uv_auth_token: &[u8],
    );
    fn client_data_hash(&self) -> &[u8];
    fn permissions(&self) -> Ctap2AuthTokenPermissionRole;
    fn permissions_rpid(&self) -> Option<&str>;
    fn can_use_uv(&self, info: &Ctap2GetInfoResponse) -> bool;
    fn handle_legacy_preview(&mut self, info: &Ctap2GetInfoResponse);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ctap2UserVerificationOperation {
    GetPinUvAuthTokenUsingUvWithPermissions,
    GetPinUvAuthTokenUsingPinWithPermissions,
    GetPinToken,
    None,
}

#[cfg(test)]
mod tests {
    use crate::proto::ctap2::Ctap2PublicKeyCredentialDescriptor;

    use super::{Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialType};
    use hex;
    use serde_bytes::ByteBuf;
    use serde_cbor;

    #[test]
    /// Verify CBOR serialization conforms to CTAP canonical standard, including ordering (see #95)
    pub fn credential_type_field_serialization() {
        let credential_type = Ctap2CredentialType {
            algorithm: Ctap2COSEAlgorithmIdentifier::ES256,
            public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
        };
        let serialized = serde_cbor::to_vec(&credential_type).unwrap();
        // Known good, verified by hand with cbor.me playground
        let expected = hex::decode("a263616c672664747970656a7075626c69632d6b6579").unwrap();
        assert_eq!(serialized, expected);
    }

    #[test]
    /// Verify CBOR serialization conforms to CTAP canonical standard, including ordering (see #95)
    pub fn credential_descriptor_serialization() {
        let credential_descriptor = Ctap2PublicKeyCredentialDescriptor {
            id: ByteBuf::from(vec![0x42]),
            r#type: Ctap2PublicKeyCredentialType::PublicKey,
            transports: None,
        };
        let serialized = serde_cbor::to_vec(&credential_descriptor).unwrap();
        // Known good, verified by hand with cbor.me playground
        let expected = hex::decode("a2626964414264747970656a7075626c69632d6b6579").unwrap();
        assert_eq!(serialized, expected);
    }

    #[test]
    pub fn deserialize_known_credential_type() {
        // python $ cbor2.dumps({"alg":-7,"type":"public-key"}).hex()
        let serialized: Vec<u8> =
            hex::decode("a263616c672664747970656a7075626c69632d6b6579").unwrap();
        let credential_type: Ctap2CredentialType = serde_cbor::from_slice(&serialized).unwrap();
        assert_eq!(
            credential_type,
            Ctap2CredentialType {
                algorithm: Ctap2COSEAlgorithmIdentifier::ES256,
                public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
            }
        );
        assert!(credential_type.is_known());
    }

    #[test]
    pub fn deserialize_unknown_credential_type_algorithm() {
        // python $ cbor2.dumps({"alg":-42,"type":"public-key"}).hex()
        let serialized: Vec<u8> =
            hex::decode("a263616c67382964747970656a7075626c69632d6b6579").unwrap();
        let credential_type: Ctap2CredentialType = serde_cbor::from_slice(&serialized).unwrap();
        assert_eq!(
            credential_type,
            Ctap2CredentialType {
                algorithm: Ctap2COSEAlgorithmIdentifier::Unknown,
                public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
            }
        );
        assert!(!credential_type.is_known());
    }

    #[test]
    pub fn deerialize_unknown_credential_type() {
        // python $ cbor2.dumps({"alg":-7,"type":"unknown"}).hex()
        let serialized: Vec<u8> = hex::decode("a263616c6726647479706567756e6b6e6f776e").unwrap();
        let credential_type: Ctap2CredentialType = serde_cbor::from_slice(&serialized).unwrap();
        assert!(!credential_type.is_known());
    }
}
