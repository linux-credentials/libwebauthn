use crate::proto::ctap1::Ctap1Transport;
use crate::Transport;
use crate::{
    ops::webauthn::idl::create::PublicKeyCredentialUserEntity, pin::PinUvAuthProtocol,
    webauthn::Error,
};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde_bytes::ByteBuf;
use serde_derive::{Deserialize, Serialize};
use serde_repr::Serialize_repr;

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
#[cfg(test)]
pub use client_pin::Ctap2PinUvAuthProtocolCommand;
pub use client_pin::{
    Ctap2AuthTokenPermissionRole, Ctap2ClientPinRequest, Ctap2ClientPinResponse,
    Ctap2PinUvAuthProtocol,
};

mod make_credential;
pub use make_credential::{
    Ctap2MakeCredentialOptions, Ctap2MakeCredentialRequest, Ctap2MakeCredentialResponse,
    Ctap2MakeCredentialsResponseExtensions, Ctap2PrfMakeCredentialInput,
};
mod get_assertion;
pub(crate) use get_assertion::{parse_unsigned_prf, UnsignedPrfOutput};
pub use get_assertion::{
    Ctap2AttestationStatement, Ctap2GetAssertionOptions, Ctap2GetAssertionRequest,
    Ctap2GetAssertionResponse, Ctap2GetAssertionResponseExtensions, Ctap2PrfGetAssertionInput,
    Ctap2PrfSalts, FidoU2fAttestationStmt,
};
mod credential_management;
pub use credential_management::{
    Ctap2CredentialData, Ctap2CredentialManagementMetadata, Ctap2CredentialManagementRequest,
    Ctap2CredentialManagementResponse, Ctap2RPData,
};
mod large_blobs;
pub use large_blobs::{Ctap2LargeBlobsRequest, Ctap2LargeBlobsResponse};

/// CTAP2 command codes; `#[non_exhaustive]` so consumers handle unknown variants.
///
/// ```compile_fail
/// use libwebauthn::proto::ctap2::Ctap2CommandCode;
/// let code = Ctap2CommandCode::AuthenticatorGetInfo;
/// let _value: u8 = match code {
///     Ctap2CommandCode::AuthenticatorMakeCredential => 0x01,
///     Ctap2CommandCode::AuthenticatorGetAssertion => 0x02,
///     Ctap2CommandCode::AuthenticatorGetInfo => 0x04,
///     Ctap2CommandCode::AuthenticatorClientPin => 0x06,
///     Ctap2CommandCode::AuthenticatorGetNextAssertion => 0x08,
///     Ctap2CommandCode::AuthenticatorBioEnrollment => 0x09,
///     Ctap2CommandCode::AuthenticatorBioEnrollmentPreview => 0x40,
///     Ctap2CommandCode::AuthenticatorCredentialManagement => 0x0A,
///     Ctap2CommandCode::AuthenticatorCredentialManagementPreview => 0x41,
///     Ctap2CommandCode::AuthenticatorSelection => 0x0B,
///     Ctap2CommandCode::AuthenticatorLargeBlobs => 0x0C,
///     Ctap2CommandCode::AuthenticatorConfig => 0x0D,
/// };
/// ```
#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone, PartialEq, Serialize_repr)]
#[repr(u8)]
#[non_exhaustive]
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
    AuthenticatorLargeBlobs = 0x0C,
    AuthenticatorConfig = 0x0D,
    // TODO: authenticatorReset (0x07) is not implemented. When it is added, a successful
    // reset must evict this device's persistent pcmr record from the persistent token
    // store, since reset regenerates the device identifier and invalidates the token.
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ctap2PublicKeyCredentialRpEntity {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Ctap2PublicKeyCredentialRpEntity {
    pub(crate) fn dummy() -> Self {
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
    pub(crate) fn dummy() -> Self {
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

impl From<PublicKeyCredentialUserEntity> for Ctap2PublicKeyCredentialUserEntity {
    fn from(user: PublicKeyCredentialUserEntity) -> Self {
        Self {
            id: ByteBuf::from(user.id),
            name: Some(user.name),
            display_name: Some(user.display_name),
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

/// AuthenticatorTransport from a credential descriptor. Unknown values are kept in `Other` so they pass through unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
#[non_exhaustive]
pub enum Ctap2Transport {
    Ble,
    Nfc,
    Usb,
    Internal,
    Hybrid,
    SmartCard,
    Other(String),
}

impl Ctap2Transport {
    fn as_str(&self) -> &str {
        match self {
            Self::Ble => "ble",
            Self::Nfc => "nfc",
            Self::Usb => "usb",
            Self::Internal => "internal",
            Self::Hybrid => "hybrid",
            Self::SmartCard => "smart-card",
            Self::Other(value) => value,
        }
    }
}

impl From<String> for Ctap2Transport {
    fn from(value: String) -> Self {
        match value.as_str() {
            "ble" => Self::Ble,
            "nfc" => Self::Nfc,
            "usb" => Self::Usb,
            "internal" => Self::Internal,
            "hybrid" => Self::Hybrid,
            "smart-card" => Self::SmartCard,
            _ => Self::Other(value),
        }
    }
}

impl From<Ctap2Transport> for String {
    fn from(transport: Ctap2Transport) -> Self {
        match transport {
            Ctap2Transport::Other(value) => value,
            known => known.as_str().to_owned(),
        }
    }
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

impl From<Transport> for Ctap2Transport {
    fn from(transport: Transport) -> Ctap2Transport {
        match transport {
            Transport::Usb => Ctap2Transport::Usb,
            Transport::Ble => Ctap2Transport::Ble,
            Transport::Nfc => Ctap2Transport::Nfc,
            Transport::Hybrid => Ctap2Transport::Hybrid,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ctap2PublicKeyCredentialDescriptor {
    pub id: ByteBuf,
    pub r#type: Ctap2PublicKeyCredentialType,

    // CTAP2 PublicKeyCredentialDescriptor only carries `id` and `type` on the wire.
    // Strict authenticators reject extra fields with CTAP2_ERR_INVALID_CBOR (0x12).
    // We keep `transports` in memory for U2F downgrade and accept it on deserialize
    // (some authenticators include it in responses), but never serialize it.
    #[serde(skip_serializing, default)]
    pub transports: Option<Vec<Ctap2Transport>>,
}

/// COSE algorithm identifier from the IANA COSE Algorithms registry.
///
/// Stored as a transparent `i32` so registered and unregistered values both
/// flow through unchanged. Use the associated constants for known values and
/// [`is_known`](Self::is_known) to test recognition.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ctap2COSEAlgorithmIdentifier(pub i32);

impl Ctap2COSEAlgorithmIdentifier {
    pub const ES256: Self = Self(-7);
    pub const EDDSA: Self = Self(-8);
    /// ESP256 (RFC 9864), equivalent to ES256 with explicit hash binding.
    pub const ESP256: Self = Self(-9);
    pub const ES384: Self = Self(-35);
    pub const ES512: Self = Self(-36);
    pub const PS256: Self = Self(-37);
    pub const PS384: Self = Self(-38);
    pub const PS512: Self = Self(-39);
    pub const ES256K: Self = Self(-47);
    pub const RS256: Self = Self(-257);
    pub const RS384: Self = Self(-258);
    pub const RS512: Self = Self(-259);
    pub const RS1: Self = Self(-65535);

    pub fn is_known(self) -> bool {
        matches!(
            self,
            Self::ES256
                | Self::EDDSA
                | Self::ESP256
                | Self::ES384
                | Self::ES512
                | Self::PS256
                | Self::PS384
                | Self::PS512
                | Self::ES256K
                | Self::RS256
                | Self::RS384
                | Self::RS512
                | Self::RS1
        )
    }
}

impl From<i32> for Ctap2COSEAlgorithmIdentifier {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl From<Ctap2COSEAlgorithmIdentifier> for i32 {
    fn from(value: Ctap2COSEAlgorithmIdentifier) -> Self {
        value.0
    }
}

impl From<Ctap2COSEAlgorithmIdentifier> for i64 {
    fn from(value: Ctap2COSEAlgorithmIdentifier) -> Self {
        i64::from(value.0)
    }
}

impl std::fmt::Debug for Ctap2COSEAlgorithmIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match *self {
            Self::ES256 => Some("ES256"),
            Self::EDDSA => Some("EDDSA"),
            Self::ESP256 => Some("ESP256"),
            Self::ES384 => Some("ES384"),
            Self::ES512 => Some("ES512"),
            Self::PS256 => Some("PS256"),
            Self::PS384 => Some("PS384"),
            Self::PS512 => Some("PS512"),
            Self::ES256K => Some("ES256K"),
            Self::RS256 => Some("RS256"),
            Self::RS384 => Some("RS384"),
            Self::RS512 => Some("RS512"),
            Self::RS1 => Some("RS1"),
            _ => None,
        };
        match name {
            Some(n) => write!(f, "Ctap2COSEAlgorithmIdentifier::{}({})", n, self.0),
            None => write!(f, "Ctap2COSEAlgorithmIdentifier({})", self.0),
        }
    }
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
        self.algorithm.is_known() && self.public_key_type != Ctap2PublicKeyCredentialType::Unknown
    }
}

pub trait Ctap2UserVerifiableRequest {
    fn ensure_uv_set(&mut self);
    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &dyn PinUvAuthProtocol,
        uv_auth_token: &[u8],
    ) -> Result<(), Error>;
    fn client_data_hash(&self) -> Option<&[u8]> {
        None
    }
    fn permissions(&self) -> Ctap2AuthTokenPermissionRole;
    fn permissions_rpid(&self) -> Option<&str>;
    fn can_use_uv(&self, info: &Ctap2GetInfoResponse) -> bool;
    fn handle_legacy_preview(&mut self, info: &Ctap2GetInfoResponse);
    /// We need to establish a shared secret, even if no PIN or UV is set on the device
    fn needs_shared_secret(&self, info: &Ctap2GetInfoResponse) -> bool;
    /// Decide, and cache on the request, whether to acquire a persistent (pcmr) token.
    /// Called once from the UV flow with whether a persistent token store is available.
    /// Default: never request one.
    fn set_persistent_token_use(&mut self, _info: &Ctap2GetInfoResponse, _store_available: bool) {}
    /// Whether this request will reuse or mint a persistent (pcmr) token, per the cached
    /// decision from [`Self::set_persistent_token_use`]. Default false.
    fn wants_persistent_token(&self) -> bool {
        false
    }
    /// Record that a reused persistent (pcmr) token was rejected by the authenticator, so
    /// the retry stops reusing it and mints a fresh one instead. Default: no-op.
    fn note_persistent_token_rejected(&mut self) {}
    /// Whether a reused persistent token was already rejected during this ceremony, per
    /// [`Self::note_persistent_token_rejected`]. Default false.
    fn persistent_token_rejected(&self) -> bool {
        false
    }
    /// True if the request requires a full pinUvAuthToken (not just a shared secret). Drives
    /// `user_verification` to skip the `OnlyForSharedSecret` downgrade on UV=Discouraged.
    /// Default false: HMAC/PRF-style requests are satisfied by shared-secret-only.
    fn needs_pin_uv_auth_token(&self, _info: &Ctap2GetInfoResponse) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ctap2UserVerificationOperation {
    GetPinUvAuthTokenUsingUvWithPermissions,
    GetPinUvAuthTokenUsingPinWithPermissions,
    GetPinToken,
    OnlyForSharedSecret,
    LegacyUv,
}

#[cfg(test)]
mod tests {
    use crate::proto::ctap2::cbor;
    use crate::proto::ctap2::Ctap2PublicKeyCredentialDescriptor;

    use super::{
        Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialType,
        Ctap2Transport,
    };
    use hex;
    use serde_bytes::ByteBuf;
    use serde_cbor_2 as serde_cbor;

    #[test]
    /// Verify CBOR serialization conforms to CTAP canonical standard, including ordering (see #95)
    pub fn credential_type_field_serialization() {
        let credential_type = Ctap2CredentialType {
            algorithm: Ctap2COSEAlgorithmIdentifier::ES256,
            public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
        };
        let serialized = cbor::to_vec(&credential_type).unwrap();
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
        let serialized = cbor::to_vec(&credential_descriptor).unwrap();
        // Known good, verified by hand with cbor.me playground
        let expected = hex::decode("a2626964414264747970656a7075626c69632d6b6579").unwrap();
        assert_eq!(serialized, expected);
    }

    #[test]
    /// CTAP2 PublicKeyCredentialDescriptor is `{id, type}` only; `transports` is a
    /// WebAuthn-level field that strict authenticators reject as InvalidCbor (#191).
    pub fn credential_descriptor_serialization_strips_transports() {
        let credential_descriptor = Ctap2PublicKeyCredentialDescriptor {
            id: ByteBuf::from(vec![0x42]),
            r#type: Ctap2PublicKeyCredentialType::PublicKey,
            transports: Some(vec![Ctap2Transport::Usb]),
        };
        let serialized = cbor::to_vec(&credential_descriptor).unwrap();
        let expected = hex::decode("a2626964414264747970656a7075626c69632d6b6579").unwrap();
        assert_eq!(serialized, expected);
    }

    #[test]
    /// Some authenticators include `transports` in CTAP2 responses even though the spec
    /// doesn't list it; we must remain tolerant when deserializing.
    pub fn credential_descriptor_deserialization_accepts_transports() {
        // python $ cbor2.dumps({"id": bytes([0x42]), "type": "public-key", "transports": ["usb"]}).hex()
        let serialized = hex::decode(
            "a3626964414264747970656a7075626c69632d6b65796a7472616e73706f7274738163757362",
        )
        .unwrap();
        let descriptor: Ctap2PublicKeyCredentialDescriptor =
            serde_cbor::from_slice(&serialized).unwrap();
        assert_eq!(descriptor.id, ByteBuf::from(vec![0x42]));
        assert_eq!(descriptor.r#type, Ctap2PublicKeyCredentialType::PublicKey);
        assert_eq!(descriptor.transports, Some(vec![Ctap2Transport::Usb]));
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
    pub fn deserialize_preserves_unrecognised_algorithm() {
        // python $ cbor2.dumps({"alg":-42,"type":"public-key"}).hex()
        let serialized: Vec<u8> =
            hex::decode("a263616c67382964747970656a7075626c69632d6b6579").unwrap();
        let credential_type: Ctap2CredentialType = serde_cbor::from_slice(&serialized).unwrap();
        assert_eq!(
            credential_type,
            Ctap2CredentialType {
                algorithm: Ctap2COSEAlgorithmIdentifier(-42),
                public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
            }
        );
        assert!(!credential_type.is_known());
    }

    #[test]
    pub fn deserialize_unknown_credential_type() {
        // python $ cbor2.dumps({"alg":-7,"type":"unknown"}).hex()
        let serialized: Vec<u8> = hex::decode("a263616c6726647479706567756e6b6e6f776e").unwrap();
        let credential_type: Ctap2CredentialType = serde_cbor::from_slice(&serialized).unwrap();
        assert!(!credential_type.is_known());
    }

    #[test]
    pub fn unrecognised_algorithm_roundtrips_through_cbor() {
        // -12345 has no IANA assignment; the wire value must survive
        // CBOR encode/decode without being rewritten to a sentinel.
        let credential_type = Ctap2CredentialType {
            algorithm: Ctap2COSEAlgorithmIdentifier(-12345),
            public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
        };
        let serialized = cbor::to_vec(&credential_type).unwrap();
        let back: Ctap2CredentialType = serde_cbor::from_slice(&serialized).unwrap();
        assert_eq!(back.algorithm, Ctap2COSEAlgorithmIdentifier(-12345));
        assert!(!back.algorithm.is_known());
    }

    #[test]
    pub fn rs256_constant_matches_iana_value() {
        assert_eq!(
            Ctap2COSEAlgorithmIdentifier::RS256,
            Ctap2COSEAlgorithmIdentifier(-257)
        );
        assert!(Ctap2COSEAlgorithmIdentifier::RS256.is_known());
    }

    #[test]
    pub fn esp256_is_recognised() {
        // -9 is ESP256 per RFC 9864; libwebauthn previously mis-named this
        // codepoint TOPT.
        assert_eq!(
            Ctap2COSEAlgorithmIdentifier::ESP256,
            Ctap2COSEAlgorithmIdentifier(-9)
        );
        assert!(Ctap2COSEAlgorithmIdentifier::ESP256.is_known());
    }

    #[test]
    fn unrecognised_transport_roundtrips_through_cbor() {
        let value = Ctap2Transport::Other("future-transport".to_string());
        let encoded = serde_cbor::to_vec(&value).unwrap();
        let decoded: Ctap2Transport = serde_cbor::from_slice(&encoded).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn smart_card_transport_roundtrips_through_cbor() {
        let encoded = serde_cbor::to_vec(&Ctap2Transport::SmartCard).unwrap();
        let decoded: Ctap2Transport = serde_cbor::from_slice(&encoded).unwrap();
        assert_eq!(decoded, Ctap2Transport::SmartCard);
    }
}
