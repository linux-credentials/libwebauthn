use std::time::Duration;

use ctap_types::ctap2::credential_management::CredentialProtectionPolicy as Ctap2CredentialProtectionPolicy;
use serde::{Deserialize, Serialize};
use serde_json::{self, Value as JsonValue};
use sha2::{Digest, Sha256};
use tracing::{debug, instrument, trace};

use crate::{
    fido::AuthenticatorData,
    ops::webauthn::{
        client_data::ClientData,
        idl::{
            create::PublicKeyCredentialCreationOptionsJSON,
            response::{
                AuthenticationExtensionsClientOutputsJSON, AuthenticatorAttestationResponseJSON,
                CredentialPropertiesOutputJSON, LargeBlobOutputJSON, PRFOutputJSON,
                RegistrationResponseJSON, ResponseSerializationError, WebAuthnIDLResponse,
            },
            Base64UrlString, FromInnerModel, JsonError, WebAuthnIDL,
        },
        Operation, RelyingPartyId,
    },
    proto::{
        ctap1::{Ctap1RegisteredKey, Ctap1Version},
        ctap2::{
            cbor, Ctap2AttestationStatement, Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType,
            Ctap2GetInfoResponse, Ctap2MakeCredentialsResponseExtensions,
            Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
            Ctap2PublicKeyCredentialUserEntity,
        },
    },
};

use super::timeout::DEFAULT_TIMEOUT;
use super::{DowngradableRequest, RegisterRequest, UserVerificationRequirement};

#[derive(Debug, Clone)]
pub struct MakeCredentialResponse {
    pub format: String,
    pub authenticator_data: AuthenticatorData<MakeCredentialsResponseExtensions>,
    pub attestation_statement: Ctap2AttestationStatement,
    pub enterprise_attestation: Option<bool>,
    pub large_blob_key: Option<Vec<u8>>,
    pub unsigned_extensions_output: MakeCredentialsResponseUnsignedExtensions,
}

/// Serializable attestation object for CBOR encoding.
#[derive(Debug, Clone, Serialize)]
struct AttestationObject<'a> {
    #[serde(rename = "fmt")]
    format: &'a str,
    #[serde(rename = "authData", with = "serde_bytes")]
    auth_data: &'a [u8],
    #[serde(rename = "attStmt")]
    attestation_statement: &'a Ctap2AttestationStatement,
}

impl WebAuthnIDLResponse for MakeCredentialResponse {
    type InnerModel = RegistrationResponseJSON;
    type Context = MakeCredentialRequest;

    fn to_inner_model(
        &self,
        request: &Self::Context,
    ) -> Result<Self::InnerModel, ResponseSerializationError> {
        // Get credential ID from attested credential data
        let credential_id_bytes = self
            .authenticator_data
            .attested_credential
            .as_ref()
            .map(|cred| cred.credential_id.clone())
            .unwrap_or_default();

        let id = base64_url::encode(&credential_id_bytes);
        let raw_id = Base64UrlString::from(credential_id_bytes);

        // Serialize authenticator data
        let authenticator_data_bytes = self
            .authenticator_data
            .to_response_bytes()
            .map_err(|e| ResponseSerializationError::AuthenticatorDataError(e.to_string()))?;

        // Get public key algorithm from attested credential data
        let public_key_algorithm = self
            .authenticator_data
            .attested_credential
            .as_ref()
            .map(|cred| Self::get_public_key_algorithm(&cred.credential_public_key))
            .unwrap_or(Ctap2COSEAlgorithmIdentifier::ES256 as i64);

        // Serialize public key to COSE key format
        let public_key = self
            .authenticator_data
            .attested_credential
            .as_ref()
            .map(|cred| {
                cbor::to_vec(&cred.credential_public_key)
                    .map(Base64UrlString::from)
                    .map_err(|e| ResponseSerializationError::PublicKeyError(e.to_string()))
            })
            .transpose()?;

        // Build attestation object (CBOR map with authData, fmt, attStmt)
        let attestation_object_bytes = self.build_attestation_object(&authenticator_data_bytes)?;

        // Get transports (we don't have direct access, so return empty for now)
        let transports = Vec::new();

        // Build client extension results
        let client_extension_results = self.build_client_extension_results();

        Ok(RegistrationResponseJSON {
            id,
            raw_id,
            response: AuthenticatorAttestationResponseJSON {
                client_data_json: Base64UrlString::from(request.client_data_json()),
                authenticator_data: Base64UrlString::from(authenticator_data_bytes),
                transports,
                public_key,
                public_key_algorithm,
                attestation_object: Base64UrlString::from(attestation_object_bytes),
            },
            authenticator_attachment: None,
            client_extension_results,
            r#type: "public-key".to_string(),
        })
    }
}

impl MakeCredentialResponse {
    /// Get the COSE algorithm identifier from the public key variant
    fn get_public_key_algorithm(key: &cosey::PublicKey) -> i64 {
        match key {
            cosey::PublicKey::P256Key(_) => Ctap2COSEAlgorithmIdentifier::ES256 as i64,
            cosey::PublicKey::EcdhEsHkdf256Key(_) => -25, // ECDH-ES + HKDF-256
            cosey::PublicKey::Ed25519Key(_) => Ctap2COSEAlgorithmIdentifier::EDDSA as i64,
            cosey::PublicKey::TotpKey(_) => 0, // No standard algorithm for TOTP
        }
    }

    fn build_attestation_object(
        &self,
        authenticator_data_bytes: &[u8],
    ) -> Result<Vec<u8>, ResponseSerializationError> {
        let attestation_object = AttestationObject {
            format: &self.format,
            auth_data: authenticator_data_bytes,
            attestation_statement: &self.attestation_statement,
        };

        cbor::to_vec(&attestation_object)
            .map_err(|e| ResponseSerializationError::AttestationObjectError(e.to_string()))
    }

    fn build_client_extension_results(&self) -> AuthenticationExtensionsClientOutputsJSON {
        let mut results = AuthenticationExtensionsClientOutputsJSON::default();
        let unsigned_ext = &self.unsigned_extensions_output;

        // Credential properties extension
        if let Some(cred_props) = &unsigned_ext.cred_props {
            results.cred_props = Some(CredentialPropertiesOutputJSON { rk: cred_props.rk });
        }

        // HMAC-secret extension (hmacCreateSecret)
        results.hmac_create_secret = unsigned_ext.hmac_create_secret;

        // Large blob extension
        if let Some(large_blob) = &unsigned_ext.large_blob {
            results.large_blob = Some(LargeBlobOutputJSON {
                supported: large_blob.supported,
                blob: None,
                written: None,
            });
        }

        // PRF extension
        if let Some(prf) = &unsigned_ext.prf {
            results.prf = Some(PRFOutputJSON {
                enabled: prf.enabled,
                results: None,
            });
        }

        results
    }
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MakeCredentialsResponseUnsignedExtensions {
    // pub app_id: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredentialPropsExtension>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub cred_blob: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_create_secret: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<MakeCredentialLargeBlobExtensionOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<MakeCredentialPrfOutput>,
}

impl MakeCredentialsResponseUnsignedExtensions {
    pub fn has_some(&self) -> bool {
        self.cred_props.is_some()
            || self.hmac_create_secret.is_some()
            || self.large_blob.is_some()
            || self.prf.is_some()
    }

    pub fn from_signed_extensions(
        signed_extensions: &Option<Ctap2MakeCredentialsResponseExtensions>,
        request: &MakeCredentialRequest,
        info: Option<&Ctap2GetInfoResponse>,
    ) -> MakeCredentialsResponseUnsignedExtensions {
        let mut hmac_create_secret = None;
        let mut prf = None;
        if let Some(signed_extensions) = signed_extensions {
            if let Some(incoming_ext) = &request.extensions {
                // hmacCreateSecret and prf can both be requested and returned independently.
                // Both map to the same underlying CTAP2 hmac-secret extension.
                if incoming_ext.hmac_create_secret.is_some() {
                    hmac_create_secret = signed_extensions.hmac_secret;
                }
                if incoming_ext.prf.is_some() {
                    prf = Some(MakeCredentialPrfOutput {
                        enabled: signed_extensions.hmac_secret,
                    });
                }
            }
        }

        // credProps extension
        // https://w3c.github.io/webauthn/#sctn-authenticator-credential-properties-extension
        let cred_props = match &request
            .extensions
            .as_ref()
            .and_then(|x| x.cred_props.as_ref())
        {
            None | Some(false) => None, // Not requested, so we don't give an answer
            Some(true) => {
                // https://w3c.github.io/webauthn/#dom-credentialpropertiesoutput-rk
                // Some authenticators create discoverable credentials even when not
                // requested by the client platform. Because of this, client platforms may be
                // forced to omit the rk property because they lack the assurance to be able
                // to set it to false.
                if info.map(|x| x.supports_fido_2_1()) == Some(true) {
                    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#op-makecred-step-rk
                    // if the "rk" option is false: the authenticator MUST create a non-discoverable credential.
                    // Note: This step is a change from CTAP2.0 where if the "rk" option is false the authenticator could optionally create a discoverable credential.
                    match request.resident_key {
                        Some(ResidentKeyRequirement::Discouraged) | None => {
                            Some(CredentialPropsExtension { rk: Some(false) })
                        }
                        Some(ResidentKeyRequirement::Preferred) => {
                            if info.map(|i| i.option_enabled("rk")).unwrap_or_default() {
                                Some(CredentialPropsExtension { rk: Some(true) })
                            } else {
                                // Default value in case "rk" is missing (which it is in this constellation) is "false"
                                // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#makecred-rk
                                Some(CredentialPropsExtension { rk: Some(false) })
                            }
                        }
                        Some(ResidentKeyRequirement::Required) => {
                            Some(CredentialPropsExtension { rk: Some(true) })
                        }
                    }
                } else {
                    Some(CredentialPropsExtension {
                        // For CTAP 2.0, we can't say if "rk" is true or not.
                        rk: None,
                    })
                }
            }
        };

        // largeBlob extension
        // https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension
        let large_blob = match &request
            .extensions
            .as_ref()
            .and_then(|x| x.large_blob.as_ref())
            .map(|x| x.support)
        {
            None | Some(MakeCredentialLargeBlobExtension::None) => None, // Not requested, so we don't give an answer
            Some(MakeCredentialLargeBlobExtension::Preferred)
            | Some(MakeCredentialLargeBlobExtension::Required) => {
                if info.map(|x| x.option_enabled("largeBlobs")) == Some(true) {
                    Some(MakeCredentialLargeBlobExtensionOutput {
                        supported: Some(true),
                    })
                } else {
                    None
                }
            }
        };

        MakeCredentialsResponseUnsignedExtensions {
            cred_props,
            hmac_create_secret,
            large_blob,
            prf,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ResidentKeyRequirement {
    Required,
    Preferred,
    #[serde(other)]
    Discouraged,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MakeCredentialRequest {
    /// The challenge from the relying party.
    pub challenge: Vec<u8>,
    /// The origin of the request.
    pub origin: String,
    /// Whether the request is cross-origin (optional per WebAuthn spec).
    pub cross_origin: Option<bool>,
    /// rpEntity
    pub relying_party: Ctap2PublicKeyCredentialRpEntity,
    /// userEntity
    pub user: Ctap2PublicKeyCredentialUserEntity,
    pub resident_key: Option<ResidentKeyRequirement>,
    pub user_verification: UserVerificationRequirement,
    /// credTypesAndPubKeyAlgs
    pub algorithms: Vec<Ctap2CredentialType>,
    /// excludeCredentialDescriptorList
    pub exclude: Option<Vec<Ctap2PublicKeyCredentialDescriptor>>,
    /// extensions
    pub extensions: Option<MakeCredentialsRequestExtensions>,
    pub timeout: Duration,
}

impl MakeCredentialRequest {
    /// Builds the ClientData for this request.
    fn client_data(&self) -> ClientData {
        ClientData {
            operation: Operation::MakeCredential,
            challenge: self.challenge.clone(),
            origin: self.origin.clone(),
            cross_origin: self.cross_origin,
            top_origin: None,
        }
    }

    /// Computes the client data hash (SHA-256 of the client data JSON).
    pub fn client_data_hash(&self) -> Vec<u8> {
        self.client_data().hash()
    }

    /// Returns the client data JSON bytes for response serialization.
    pub fn client_data_json(&self) -> Vec<u8> {
        self.client_data().to_json_bytes()
    }
}

impl FromInnerModel<PublicKeyCredentialCreationOptionsJSON, MakeCredentialRequestParsingError>
    for MakeCredentialRequest
{
    fn from_inner_model(
        rpid: &RelyingPartyId,
        inner: PublicKeyCredentialCreationOptionsJSON,
    ) -> Result<Self, MakeCredentialRequestParsingError> {
        let rp_id = RelyingPartyId::try_from(inner.rp.id.as_str()).map_err(|err| {
            MakeCredentialRequestParsingError::InvalidRelyingPartyId(err.to_string())
        })?;
        // TODO(#160): Add support for related origin per WebAuthn Level 3.
        if rp_id.0 != rpid.0 {
            return Err(
                MakeCredentialRequestParsingError::MismatchingRelyingPartyId(
                    rp_id.0,
                    rpid.0.to_string(),
                ),
            );
        }
        let mut relying_party = inner.rp;
        relying_party.id = rp_id.0;
        let resident_key = if inner
            .authenticator_selection
            .as_ref()
            .map(|s| s.require_resident_key)
            == Some(true)
        {
            Some(ResidentKeyRequirement::Required)
        } else {
            inner
                .authenticator_selection
                .as_ref()
                .and_then(|s| s.resident_key)
        };

        let user_verification = inner
            .authenticator_selection
            .as_ref()
            .map_or(UserVerificationRequirement::Preferred, |s| {
                s.user_verification
            });

        let timeout: Duration = inner
            .timeout
            .map(|s| Duration::from_millis(s.into()))
            .unwrap_or(DEFAULT_TIMEOUT);

        Ok(Self {
            challenge: inner.challenge.to_vec(),
            origin: rpid.to_owned().into(),
            cross_origin: None,
            relying_party,
            user: inner.user.into(),
            resident_key,
            user_verification,
            algorithms: inner.params,
            exclude: if inner.exclude_credentials.is_empty() {
                None
            } else {
                Some(inner.exclude_credentials)
            },
            extensions: inner.extensions,
            timeout,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MakeCredentialRequestParsingError {
    /// The client must throw an "EncodingError" DOMException.
    #[error("Invalid JSON format: {0}")]
    EncodingError(#[from] JsonError),
    #[error("Invalid relying party ID: {0}")]
    InvalidRelyingPartyId(String),
    #[error("Mismatching relying party ID: {0} != {1}")]
    MismatchingRelyingPartyId(String, String),
}

impl WebAuthnIDL<MakeCredentialRequestParsingError> for MakeCredentialRequest {
    type Error = MakeCredentialRequestParsingError;
    type InnerModel = PublicKeyCredentialCreationOptionsJSON;
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct MakeCredentialPrfInput {
    /// The `eval` field is parsed but not used during credential creation.
    /// PRF evaluation only occurs during assertion (getAssertion), not registration.
    /// We parse it here to accept valid WebAuthn JSON input without errors.
    #[serde(rename = "eval")]
    pub _eval: Option<JsonValue>,
}

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct MakeCredentialPrfOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProtectionExtension {
    pub policy: CredentialProtectionPolicy,
    pub enforce_policy: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CredentialProtectionPolicy {
    UserVerificationOptional = 1,
    #[serde(rename = "userVerificationOptionalWithCredentialIDList")]
    UserVerificationOptionalWithCredentialIDList = 2,
    UserVerificationRequired = 3,
}

impl From<CredentialProtectionPolicy> for Ctap2CredentialProtectionPolicy {
    fn from(value: CredentialProtectionPolicy) -> Self {
        match value {
            CredentialProtectionPolicy::UserVerificationOptional => {
                Ctap2CredentialProtectionPolicy::Optional
            }
            CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList => {
                Ctap2CredentialProtectionPolicy::OptionalWithCredentialIdList
            }
            CredentialProtectionPolicy::UserVerificationRequired => {
                Ctap2CredentialProtectionPolicy::Required
            }
        }
    }
}

impl From<Ctap2CredentialProtectionPolicy> for CredentialProtectionPolicy {
    fn from(value: Ctap2CredentialProtectionPolicy) -> Self {
        match value {
            Ctap2CredentialProtectionPolicy::Optional => {
                CredentialProtectionPolicy::UserVerificationOptional
            }
            Ctap2CredentialProtectionPolicy::OptionalWithCredentialIdList => {
                CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList
            }
            Ctap2CredentialProtectionPolicy::Required => {
                CredentialProtectionPolicy::UserVerificationRequired
            }
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPropsExtension {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq)]
pub struct MakeCredentialLargeBlobExtensionInput {
    pub support: MakeCredentialLargeBlobExtension,
}

#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MakeCredentialLargeBlobExtension {
    Preferred,
    Required,
    #[default]
    #[serde(other)]
    None,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct MakeCredentialLargeBlobExtensionOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MakeCredentialsRequestExtensions {
    pub cred_props: Option<bool>,
    pub cred_protect: Option<CredentialProtectionExtension>,
    pub cred_blob: Option<Base64UrlString>,
    pub large_blob: Option<MakeCredentialLargeBlobExtensionInput>,
    pub min_pin_length: Option<bool>,
    pub hmac_create_secret: Option<bool>,
    pub prf: Option<MakeCredentialPrfInput>,
}

pub type MakeCredentialsResponseExtensions = Ctap2MakeCredentialsResponseExtensions;

impl MakeCredentialRequest {
    pub fn dummy() -> Self {
        Self {
            challenge: Vec::new(),
            origin: "example.org".to_owned(),
            cross_origin: Some(false),
            relying_party: Ctap2PublicKeyCredentialRpEntity::dummy(),
            user: Ctap2PublicKeyCredentialUserEntity::dummy(),
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: None,
            resident_key: None,
            user_verification: UserVerificationRequirement::Discouraged,
            timeout: Duration::from_secs(10),
        }
    }
}

impl DowngradableRequest<RegisterRequest> for MakeCredentialRequest {
    #[instrument(skip_all)]
    fn is_downgradable(&self) -> bool {
        // All of the below conditions must be true for the platform to proceed to next step.
        // If any of the below conditions is not true, platform errors out with CTAP2_ERR_UNSUPPORTED_OPTION

        // pubKeyCredParams must use the ES256 algorithm (-7).
        if !self
            .algorithms
            .iter()
            .any(|a| a.algorithm == Ctap2COSEAlgorithmIdentifier::ES256)
        {
            debug!("Not downgradable: request doesn't support ES256 algorithm");
            return false;
        }

        // Options must not include "rk" set to true.
        if matches!(self.resident_key, Some(ResidentKeyRequirement::Required)) {
            debug!("Not downgradable: request requires resident key");
            return false;
        }

        // Options must not include "uv" set to true.
        if let UserVerificationRequirement::Required = self.user_verification {
            debug!("Not downgradable: relying party (RP) requires user verification");
            return false;
        }

        true
    }

    fn try_downgrade(&self) -> Result<RegisterRequest, crate::webauthn::CtapError> {
        trace!(?self);
        let mut hasher = Sha256::default();
        hasher.update(self.relying_party.id.as_bytes());
        let rp_id_hash = hasher.finalize().to_vec();

        let downgraded = RegisterRequest {
            version: Ctap1Version::U2fV2,
            app_id_hash: rp_id_hash,
            challenge: self.client_data_hash(),
            registered_keys: self
                .exclude
                .as_ref()
                .unwrap_or(&vec![])
                .into_iter()
                .map(|exclude| Ctap1RegisteredKey {
                    version: Ctap1Version::U2fV2,
                    key_handle: exclude.id.to_vec(),
                    transports: {
                        match &exclude.transports {
                            None => None,
                            Some(ctap2_transports) => {
                                let transports: Result<Vec<_>, _> =
                                    ctap2_transports.into_iter().map(|t| t.try_into()).collect();
                                transports.ok()
                            }
                        }
                    },
                    app_id: Some(self.relying_party.id.clone()),
                })
                .collect(),
            require_user_presence: true,
            timeout: self.timeout,
        };
        trace!(?downgraded);
        Ok(downgraded)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::ops::webauthn::MakeCredentialRequest;
    use crate::ops::webauthn::RelyingPartyId;
    use crate::proto::ctap2::Ctap2PublicKeyCredentialType;

    use super::*;

    pub const REQUEST_BASE_JSON: &str = r#"
    {
        "rp": {
            "id": "example.org",
            "name": "example.org"
        },
        "user": {
            "id": "dXNlcmlk",
            "name": "mario.rossi",
            "displayName": "Mario Rossi"
        },
        "challenge": "Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu",
        "pubKeyCredParams": [
            {
                "type": "public-key",
                "alg": -7
            }
        ],
        "timeout": 30000,
        "excludeCredentials": [],
        "authenticatorSelection": {
            "residentKey": "discouraged",
            "userVerification": "preferred"
        },
        "attestation": "none",
        "attestationFormats": ["packed", "fido-u2f"]
    }
    "#;

    fn request_base() -> MakeCredentialRequest {
        MakeCredentialRequest {
            challenge: base64_url::decode("Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu").unwrap(),
            origin: "example.org".to_string(),
            cross_origin: None,
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(b"userid", "mario.rossi", "Mario Rossi"),
            resident_key: Some(ResidentKeyRequirement::Discouraged),
            user_verification: UserVerificationRequirement::Preferred,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: None,
            timeout: Duration::from_secs(30),
        }
    }

    fn json_field_add(str: &str, field: &str, value: &str) -> String {
        let mut v: serde_json::Value = serde_json::from_str(str).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert(field.to_owned(), serde_json::from_str(value).unwrap());
        serde_json::to_string(&v).unwrap()
    }

    fn json_field_rm(str: &str, field: &str) -> String {
        let mut v: serde_json::Value = serde_json::from_str(str).unwrap();
        v.as_object_mut().unwrap().remove(field);
        serde_json::to_string(&v).unwrap()
    }

    fn test_request_from_json_required_field(field: &str) {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_rm(REQUEST_BASE_JSON, field);

        let result = MakeCredentialRequest::from_json(&rpid, &req_json);
        assert!(matches!(
            result,
            Err(MakeCredentialRequestParsingError::EncodingError(_))
        ));
    }

    #[test]
    fn test_request_from_json_base() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req: MakeCredentialRequest =
            MakeCredentialRequest::from_json(&rpid, REQUEST_BASE_JSON).unwrap();
        assert_eq!(req, request_base());
    }

    #[test]
    fn test_request_from_json_require_rp() {
        test_request_from_json_required_field("rp");
    }

    #[test]
    fn test_request_from_json_require_user() {
        test_request_from_json_required_field("user");
    }

    #[test]
    fn test_request_from_json_require_pub_key_cred_params() {
        test_request_from_json_required_field("pubKeyCredParams");
    }

    #[test]
    fn test_request_from_json_require_challenge() {
        test_request_from_json_required_field("challenge");
    }

    #[test]
    #[ignore] // FIXME(#134): Add validation for challenges
    fn test_request_from_json_challenge_empty() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json: String = json_field_rm(REQUEST_BASE_JSON, "challenge");
        let req_json = json_field_add(&req_json, "challenge", r#""""#);

        let result = MakeCredentialRequest::from_json(&rpid, &req_json);
        assert!(matches!(
            result,
            Err(MakeCredentialRequestParsingError::EncodingError(_))
        ));
    }

    #[test]
    fn test_request_from_json_prf_extension() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "extensions",
            r#"{"prf": {"eval": {"first": "second"}}}"#,
        );

        let req: MakeCredentialRequest =
            MakeCredentialRequest::from_json(&rpid, &req_json).unwrap();
        assert!(matches!(
            req.extensions,
            Some(MakeCredentialsRequestExtensions { prf: Some(_), .. })
        ));
    }

    #[test]
    fn test_request_from_json_unknown_pub_key_cred_params() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "pubKeyCredParams",
            r#"[{"type": "something", "alg": -12345}]"#,
        );
        let req: MakeCredentialRequest =
            MakeCredentialRequest::from_json(&rpid, &req_json).unwrap();
        assert_eq!(
            req.algorithms,
            vec![Ctap2CredentialType {
                algorithm: Ctap2COSEAlgorithmIdentifier::Unknown, // FIXME(#148): Passhtrough unknown algorithms
                public_key_type: Ctap2PublicKeyCredentialType::Unknown,
            }]
        );
    }

    #[test]
    fn test_request_from_json_default_timeout() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_rm(REQUEST_BASE_JSON, "timeout");

        let req: MakeCredentialRequest =
            MakeCredentialRequest::from_json(&rpid, &req_json).unwrap();
        assert_eq!(req.timeout, DEFAULT_TIMEOUT);
    }

    /// Per spec, when authenticatorSelection is missing, userVerification should default to "preferred".
    /// https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-userverification
    #[test]
    fn test_request_from_json_default_user_verification_preferred() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_rm(REQUEST_BASE_JSON, "authenticatorSelection");

        let req: MakeCredentialRequest =
            MakeCredentialRequest::from_json(&rpid, &req_json).unwrap();
        assert_eq!(
            req.user_verification,
            UserVerificationRequirement::Preferred
        );
    }

    /// Per spec, when userVerification is missing inside authenticatorSelection,
    /// it should default to "preferred".
    #[test]
    fn test_request_from_json_missing_user_verification_in_authenticator_selection() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        // Replace authenticatorSelection with one that has no userVerification field
        let mut req_json = json_field_rm(REQUEST_BASE_JSON, "authenticatorSelection");
        req_json = json_field_add(
            &req_json,
            "authenticatorSelection",
            r#"{"residentKey": "discouraged"}"#,
        );

        let req: MakeCredentialRequest =
            MakeCredentialRequest::from_json(&rpid, &req_json).unwrap();
        assert_eq!(
            req.user_verification,
            UserVerificationRequirement::Preferred
        );
    }

    #[test]
    fn test_request_from_json_invalid_rp_id() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "example.org.", "name": "example.org"}"#,
        );

        let result = MakeCredentialRequest::from_json(&rpid, &req_json);
        assert!(matches!(
            result,
            Err(MakeCredentialRequestParsingError::InvalidRelyingPartyId(_))
        ));
    }

    #[test]
    fn test_request_from_json_mismatching_rp_id() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "other.example.org", "name": "example.org"}"#,
        );

        let result = MakeCredentialRequest::from_json(&rpid, &req_json);
        assert!(matches!(
            result,
            Err(MakeCredentialRequestParsingError::MismatchingRelyingPartyId(_, _))
        ));
    }

    // Tests for response JSON serialization

    fn create_test_response() -> MakeCredentialResponse {
        use crate::fido::{AttestedCredentialData, AuthenticatorData, AuthenticatorDataFlags};
        use cosey::Bytes;
        use std::collections::BTreeMap;

        // Create a simple attested credential with a P256 key
        let credential_id = vec![0x01, 0x02, 0x03, 0x04];
        let aaguid = [0u8; 16];

        // Create a P256 public key for testing
        let public_key = cosey::PublicKey::P256Key(cosey::P256PublicKey {
            x: Bytes::from_slice(&[0u8; 32]).unwrap(),
            y: Bytes::from_slice(&[0u8; 32]).unwrap(),
        });

        let attested_credential = AttestedCredentialData {
            aaguid,
            credential_id,
            credential_public_key: public_key,
        };

        let authenticator_data = AuthenticatorData {
            rp_id_hash: [0u8; 32],
            flags: AuthenticatorDataFlags::USER_PRESENT,
            signature_count: 0,
            attested_credential: Some(attested_credential),
            extensions: None,
        };

        MakeCredentialResponse {
            format: "none".to_string(),
            authenticator_data,
            attestation_statement: Ctap2AttestationStatement::None(BTreeMap::new()),
            enterprise_attestation: None,
            large_blob_key: None,
            unsigned_extensions_output: MakeCredentialsResponseUnsignedExtensions::default(),
        }
    }

    fn create_test_request() -> MakeCredentialRequest {
        MakeCredentialRequest {
            challenge: b"DEADCODE_challenge".to_vec(),
            origin: "example.org".to_string(),
            cross_origin: None,
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(b"userid", "mario.rossi", "Mario Rossi"),
            resident_key: Some(ResidentKeyRequirement::Discouraged),
            user_verification: UserVerificationRequirement::Preferred,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: None,
            timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn test_response_to_json() {
        use crate::ops::webauthn::idl::response::JsonFormat;

        let response = create_test_response();
        let request = create_test_request();
        let json = response.to_json(&request, JsonFormat::default());
        assert!(json.is_ok());

        let json_str = json.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Verify required fields
        assert!(parsed.get("id").is_some());
        assert!(parsed.get("rawId").is_some());
        assert!(parsed.get("type").is_some());
        assert_eq!(parsed.get("type").unwrap(), "public-key");

        // Verify response object
        let response_obj = parsed.get("response").unwrap();
        assert!(response_obj.get("clientDataJSON").is_some());
        assert!(response_obj.get("authenticatorData").is_some());
        assert!(response_obj.get("attestationObject").is_some());
        assert!(response_obj.get("publicKeyAlgorithm").is_some());

        // Verify algorithm is ES256 (-7) for P256 key
        assert_eq!(
            response_obj.get("publicKeyAlgorithm").unwrap(),
            Ctap2COSEAlgorithmIdentifier::ES256 as i64
        );
    }

    #[test]
    fn test_response_to_inner_model() {
        let response = create_test_response();
        let request = create_test_request();
        let model = response.to_inner_model(&request).unwrap();

        // Verify the credential ID
        assert_eq!(model.raw_id.0, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(model.r#type, "public-key");

        // Verify attestation response
        assert_eq!(
            model.response.public_key_algorithm,
            Ctap2COSEAlgorithmIdentifier::ES256 as i64
        );
        assert!(model.response.transports.is_empty());
    }

    #[test]
    fn test_response_attestation_object_format() {
        let response = create_test_response();
        let request = create_test_request();
        let model = response.to_inner_model(&request).unwrap();

        // Decode the attestation object
        let attestation_bytes = model.response.attestation_object.0;
        let attestation: cbor::Value = cbor::from_slice(&attestation_bytes).unwrap();

        // Verify it's a map with the expected keys
        if let cbor::Value::Map(map) = attestation {
            let has_fmt = map
                .keys()
                .any(|k| matches!(k, cbor::Value::Text(s) if s == "fmt"));
            let has_auth_data = map
                .keys()
                .any(|k| matches!(k, cbor::Value::Text(s) if s == "authData"));
            let has_att_stmt = map
                .keys()
                .any(|k| matches!(k, cbor::Value::Text(s) if s == "attStmt"));

            assert!(has_fmt, "attestation object should have 'fmt' key");
            assert!(
                has_auth_data,
                "attestation object should have 'authData' key"
            );
            assert!(has_att_stmt, "attestation object should have 'attStmt' key");
        } else {
            panic!("attestation object should be a CBOR map");
        }
    }

    #[test]
    fn test_response_with_extensions() {
        let mut response = create_test_response();

        // Add some extension outputs
        response.unsigned_extensions_output = MakeCredentialsResponseUnsignedExtensions {
            cred_props: Some(CredentialPropsExtension { rk: Some(true) }),
            hmac_create_secret: Some(true),
            large_blob: None,
            prf: Some(MakeCredentialPrfOutput {
                enabled: Some(true),
            }),
        };

        let request = create_test_request();
        let model = response.to_inner_model(&request).unwrap();

        // Verify extension outputs
        assert!(model.client_extension_results.cred_props.is_some());
        assert_eq!(
            model
                .client_extension_results
                .cred_props
                .as_ref()
                .unwrap()
                .rk,
            Some(true)
        );
        assert_eq!(
            model.client_extension_results.hmac_create_secret,
            Some(true)
        );
        assert!(model.client_extension_results.prf.is_some());
        assert_eq!(
            model.client_extension_results.prf.as_ref().unwrap().enabled,
            Some(true)
        );
    }
}
