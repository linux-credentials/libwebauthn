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
            create::PublicKeyCredentialCreationOptionsJSON, Base64UrlString, FromInnerModel,
            JsonError, WebAuthnIDL,
        },
        Operation, RelyingPartyId,
    },
    proto::{
        ctap1::{Ctap1RegisteredKey, Ctap1Version},
        ctap2::{
            Ctap2AttestationStatement, Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType,
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
    pub hash: Vec<u8>,
    pub origin: String,
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

        let client_data_json = ClientData {
            operation: Operation::MakeCredential,
            challenge: inner.challenge.to_vec(),
            origin: rpid.to_string(),
            cross_origin: None,
            top_origin: None,
        };

        Ok(Self {
            hash: client_data_json.hash(),
            origin: rpid.to_owned().into(),
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
            timeout: timeout,
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
            hash: vec![0; 32],
            relying_party: Ctap2PublicKeyCredentialRpEntity::dummy(),
            user: Ctap2PublicKeyCredentialUserEntity::dummy(),
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: None,
            origin: "example.org".to_owned(),
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
            challenge: self.hash.clone(),
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
            origin: "example.org".to_string(),
            hash: ClientData {
                operation: Operation::MakeCredential,
                challenge: base64_url::decode("Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu")
                    .unwrap(),
                origin: "example.org".to_string(),
                cross_origin: None,
                top_origin: None,
            }
            .hash(),
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
}
