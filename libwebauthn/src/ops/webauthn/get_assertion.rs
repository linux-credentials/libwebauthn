use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error, trace};

use crate::{
    fido::AuthenticatorData,
    ops::webauthn::{
        client_data::ClientData,
        idl::{
            get::{
                HmacGetSecretInputJson, LargeBlobInputJson, PrfInputJson,
                PublicKeyCredentialRequestOptionsJSON,
            },
            response::{
                AuthenticationExtensionsClientOutputsJSON, AuthenticationResponseJSON,
                AuthenticatorAssertionResponseJSON, HMACGetSecretOutputJSON, LargeBlobOutputJSON,
                PRFOutputJSON, PRFValuesJSON, ResponseSerializationError, WebAuthnIDLResponse,
            },
            Base64UrlString, FromInnerModel, JsonError,
        },
        Operation, WebAuthnIDL,
    },
    pin::PinUvAuthProtocol,
    proto::ctap2::{
        Ctap2AttestationStatement, Ctap2GetAssertionResponseExtensions,
        Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialUserEntity,
    },
    webauthn::CtapError,
};

use super::timeout::DEFAULT_TIMEOUT;
use super::{DowngradableRequest, RelyingPartyId, SignRequest, UserVerificationRequirement};

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct PRFValue {
    #[serde(with = "serde_bytes")]
    pub first: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub second: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetAssertionRequest {
    pub relying_party_id: String,
    pub challenge: Vec<u8>,
    pub origin: String,
    pub cross_origin: Option<bool>,
    pub allow: Vec<Ctap2PublicKeyCredentialDescriptor>,
    pub extensions: Option<GetAssertionRequestExtensions>,
    pub user_verification: UserVerificationRequirement,
    pub timeout: Duration,
}

impl GetAssertionRequest {
    fn client_data(&self) -> ClientData {
        ClientData {
            operation: Operation::GetAssertion,
            challenge: self.challenge.clone(),
            origin: self.origin.clone(),
            cross_origin: self.cross_origin,
            top_origin: None,
        }
    }

    pub fn client_data_hash(&self) -> Vec<u8> {
        self.client_data().hash()
    }

    /// Returns the canonical JSON representation of the client data.
    pub fn client_data_json(&self) -> String {
        self.client_data().to_json()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum GetAssertionRequestParsingError {
    /// The client must throw an "EncodingError" DOMException.
    #[error("Invalid JSON format: {0}")]
    EncodingError(#[from] JsonError),

    #[error("Unexpected length for {0}: {1}")]
    UnexpectedLengthError(String, usize),

    #[error("Not supported: {0}")]
    NotSupported(String),

    #[error("Invalid relying party ID: {0}")]
    InvalidRelyingPartyId(String),

    #[error("Mismatching relying party ID: {0} != {1}")]
    MismatchingRelyingPartyId(String, String),
}

impl WebAuthnIDL<GetAssertionRequestParsingError> for GetAssertionRequest {
    type Error = GetAssertionRequestParsingError;
    type InnerModel = PublicKeyCredentialRequestOptionsJSON;
}

/** dictionary PublicKeyCredentialRequestOptionsJSON {
    required Base64URLString                                challenge;
    unsigned long                                           timeout;
    DOMString                                               rpId;
    sequence<PublicKeyCredentialDescriptorJSON>             allowCredentials = [];
    DOMString                                               userVerification = "preferred";
    sequence<DOMString>                                     hints = [];
    AuthenticationExtensionsClientInputsJSON                extensions;
}; */

impl FromInnerModel<PublicKeyCredentialRequestOptionsJSON, GetAssertionRequestParsingError>
    for GetAssertionRequest
{
    fn from_inner_model(
        rpid: &RelyingPartyId,
        inner: PublicKeyCredentialRequestOptionsJSON,
    ) -> Result<Self, GetAssertionRequestParsingError> {
        if let Some(relying_party_id) = inner.relying_party_id.as_deref() {
            let parsed = RelyingPartyId::try_from(relying_party_id).map_err(|err| {
                GetAssertionRequestParsingError::InvalidRelyingPartyId(err.to_string())
            })?;
            // TODO(#160): Add support for related origin per WebAuthn Level 3.
            if parsed.0 != rpid.0 {
                return Err(GetAssertionRequestParsingError::MismatchingRelyingPartyId(
                    parsed.0,
                    rpid.0.to_string(),
                ));
            }
        }

        let prf = match inner.extensions.as_ref() {
            Some(ext) => match &ext.prf {
                Some(prf_json) => Some(PrfInput::try_from(prf_json.clone())?),
                None => None,
            },
            None => None,
        };

        let extensions =
            inner
                .extensions
                .as_ref()
                .map(|extensions_opt| GetAssertionRequestExtensions {
                    cred_blob: extensions_opt.cred_blob.unwrap_or(false),
                    large_blob: extensions_opt
                        .large_blob
                        .clone()
                        .and_then(|lb| GetAssertionLargeBlobExtension::try_from(lb).ok()),
                    prf: prf.clone(),
                });

        let timeout: Duration = inner
            .timeout
            .map(|s| Duration::from_millis(s.into()))
            .unwrap_or(DEFAULT_TIMEOUT);

        Ok(GetAssertionRequest {
            relying_party_id: rpid.to_string(),
            challenge: inner.challenge.to_vec(),
            origin: rpid.to_string(),
            cross_origin: None,
            allow: inner
                .allow_credentials
                .into_iter()
                .map(|c| c.into())
                .collect(),
            extensions,
            user_verification: inner.user_verification,
            timeout,
        })
    }
}

/// Internal enum for CTAP-level HMAC/PRF handling.
/// At WebAuthn level, only PRF is exposed. This enum is used internally
/// to support both PRF (WebAuthn) and raw HMAC (CTAP testing).
#[derive(Debug, Clone, PartialEq)]
pub enum GetAssertionHmacOrPrfInput {
    HmacGetSecret(HMACGetSecretInput),
    Prf(PrfInput),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PrfInput {
    pub eval: Option<PRFValue>,
    pub eval_by_credential: HashMap<String, PRFValue>,
}

impl TryFrom<PrfInputJson> for PrfInput {
    type Error = GetAssertionRequestParsingError;

    fn try_from(value: PrfInputJson) -> Result<Self, Self::Error> {
        let eval = match value.eval {
            Some(value) => Some(PRFValue {
                first: value.first.as_slice().try_into().map_err(|_| {
                    GetAssertionRequestParsingError::UnexpectedLengthError(
                        "extensions.prf.eval.first".to_string(),
                        value.first.as_slice().len(),
                    )
                })?,
                second: match value.second {
                    Some(s) => Some(s.as_slice().try_into().map_err(|_| {
                        GetAssertionRequestParsingError::UnexpectedLengthError(
                            "extensions.prf.eval.second".to_string(),
                            s.as_slice().len(),
                        )
                    })?),
                    None => None,
                },
            }),
            None => None,
        };
        let eval_by_credential = match value.eval_by_credential {
            Some(map) => map
                .into_iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        PRFValue {
                            first: v.first.as_slice().try_into().map_err(|_| {
                                GetAssertionRequestParsingError::UnexpectedLengthError(
                                    "extensions.prf.eval_by_credential[i].first".to_string(),
                                    v.first.as_slice().len(),
                                )
                            })?,
                            second: match v.second {
                                Some(s) => Some(s.as_slice().try_into().map_err(|_| {
                                    GetAssertionRequestParsingError::UnexpectedLengthError(
                                        "extensions.prf.eval_by_credential[i].second".to_string(),
                                        s.as_slice().len(),
                                    )
                                })?),
                                None => None,
                            },
                        },
                    ))
                })
                .collect::<Result<HashMap<String, PRFValue>, GetAssertionRequestParsingError>>()?,
            None => HashMap::new(),
        };

        Ok(PrfInput {
            eval,
            eval_by_credential,
        })
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct GetAssertionPrfOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<PRFValue>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HMACGetSecretInput {
    pub salt1: [u8; 32],
    pub salt2: Option<[u8; 32]>,
}

impl TryFrom<HmacGetSecretInputJson> for HMACGetSecretInput {
    type Error = GetAssertionRequestParsingError;

    fn try_from(value: HmacGetSecretInputJson) -> Result<Self, Self::Error> {
        let salt1 = value.salt1.as_slice().try_into().map_err(|_| {
            GetAssertionRequestParsingError::UnexpectedLengthError(
                "extensions.hmacCreateSecret.salt1".to_string(),
                value.salt1.as_slice().len(),
            )
        })?;
        let salt2 = match value.salt2 {
            Some(s) => Some(s.as_slice().try_into().map_err(|_| {
                GetAssertionRequestParsingError::UnexpectedLengthError(
                    "extensions.hmacCreateSecret.salt2".to_string(),
                    s.as_slice().len(),
                )
            })?),
            None => None,
        };
        Ok(HMACGetSecretInput { salt1, salt2 })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetAssertionLargeBlobExtension {
    Read,
    // Not yet supported
    // Write(Vec<u8>),
}

impl TryFrom<LargeBlobInputJson> for GetAssertionLargeBlobExtension {
    type Error = GetAssertionRequestParsingError;

    fn try_from(value: LargeBlobInputJson) -> Result<Self, Self::Error> {
        match value.read {
            Some(true) => Ok(GetAssertionLargeBlobExtension::Read),
            Some(false) => Err(GetAssertionRequestParsingError::NotSupported(
                "largeBlob writes not supported".to_string(),
            )),
            None => Err(GetAssertionRequestParsingError::NotSupported(
                "largeBlob read not requested".to_string(),
            )),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct GetAssertionLargeBlobExtensionOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<Vec<u8>>,
    // Not yet supported
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub written: Option<bool>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct GetAssertionRequestExtensions {
    pub cred_blob: bool,
    /// PRF extension input. At the CTAP level, this is converted to HMAC secret.
    pub prf: Option<PrfInput>,
    pub large_blob: Option<GetAssertionLargeBlobExtension>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HMACGetSecretOutput {
    pub output1: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output2: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ctap2HMACGetSecretOutput {
    // We get this from the device, but have to decrypt it, and
    // potentially split it into 2 arrays
    #[serde(with = "serde_bytes")]
    pub(crate) encrypted_output: Vec<u8>,
}

impl Ctap2HMACGetSecretOutput {
    pub(crate) fn decrypt_output(
        &self,
        shared_secret: &[u8],
        uv_proto: &Box<dyn PinUvAuthProtocol>,
    ) -> Option<HMACGetSecretOutput> {
        let output = match uv_proto.decrypt(shared_secret, &self.encrypted_output) {
            Ok(o) => o,
            Err(e) => {
                error!("Failed to decrypt HMAC Secret output with the shared secret: {e:?}. Skipping HMAC extension");
                return None;
            }
        };
        let mut res = HMACGetSecretOutput::default();
        if output.len() == 32 {
            res.output1.copy_from_slice(&output);
        } else if output.len() == 64 {
            let (o1, o2) = output.split_at(32);
            res.output1.copy_from_slice(o1);
            res.output2 = Some(o2.try_into().unwrap());
        } else {
            error!("Failed to split HMAC Secret outputs. Unexpected output length: {}. Skipping HMAC extension", output.len());
            return None;
        }

        Some(res)
    }
}

pub type GetAssertionResponseExtensions = Ctap2GetAssertionResponseExtensions;

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAssertionResponseUnsignedExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_get_secret: Option<HMACGetSecretOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<GetAssertionLargeBlobExtensionOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<GetAssertionPrfOutput>,
}

/// Context required for serializing a GetAssertion response to JSON.
#[derive(Debug, Clone)]
pub struct GetAssertionResponse {
    pub assertions: Vec<Assertion>,
}

#[derive(Debug, Clone)]
pub struct Assertion {
    pub credential_id: Option<Ctap2PublicKeyCredentialDescriptor>,
    pub authenticator_data: AuthenticatorData<GetAssertionResponseExtensions>,
    pub signature: Vec<u8>,
    pub user: Option<Ctap2PublicKeyCredentialUserEntity>,
    pub credentials_count: Option<u32>,
    pub user_selected: Option<bool>,
    pub large_blob_key: Option<Vec<u8>>,
    pub unsigned_extensions_output: Option<GetAssertionResponseUnsignedExtensions>,
    pub enterprise_attestation: Option<bool>,
    pub attestation_statement: Option<Ctap2AttestationStatement>,
}

impl WebAuthnIDLResponse for Assertion {
    type InnerModel = AuthenticationResponseJSON;
    type Context = GetAssertionRequest;

    fn to_inner_model(
        &self,
        request: &Self::Context,
    ) -> Result<Self::InnerModel, ResponseSerializationError> {
        // Get credential ID - either from credential_id field or from authenticator_data
        let credential_id_bytes = self
            .credential_id
            .as_ref()
            .map(|cred| cred.id.to_vec())
            .unwrap_or_default();

        let id = base64_url::encode(&credential_id_bytes);
        let raw_id = Base64UrlString::from(credential_id_bytes);

        // Serialize authenticator data
        let authenticator_data_bytes = self
            .authenticator_data
            .to_response_bytes()
            .map_err(|e| ResponseSerializationError::AuthenticatorDataError(e.to_string()))?;

        // Get user handle if available
        let user_handle = self
            .user
            .as_ref()
            .map(|user| Base64UrlString::from(user.id.as_ref()));

        // Build client extension results
        let client_extension_results = self.build_client_extension_results();

        Ok(AuthenticationResponseJSON {
            id,
            raw_id,
            response: AuthenticatorAssertionResponseJSON {
                client_data_json: Base64UrlString::from(request.client_data_json().into_bytes()),
                authenticator_data: Base64UrlString::from(authenticator_data_bytes),
                signature: Base64UrlString::from(self.signature.clone()),
                user_handle,
            },
            authenticator_attachment: None,
            client_extension_results,
            r#type: "public-key".to_string(),
        })
    }
}

impl Assertion {
    fn build_client_extension_results(&self) -> AuthenticationExtensionsClientOutputsJSON {
        let mut results = AuthenticationExtensionsClientOutputsJSON::default();

        if let Some(unsigned_ext) = &self.unsigned_extensions_output {
            // HMAC-secret extension output
            if let Some(hmac_output) = &unsigned_ext.hmac_get_secret {
                results.hmac_get_secret = Some(HMACGetSecretOutputJSON {
                    output1: Base64UrlString::from(hmac_output.output1.as_slice()),
                    output2: hmac_output
                        .output2
                        .as_ref()
                        .map(|o| Base64UrlString::from(o.as_slice())),
                });
            }

            // Large blob extension output
            if let Some(large_blob) = &unsigned_ext.large_blob {
                results.large_blob = Some(LargeBlobOutputJSON {
                    supported: None,
                    blob: large_blob
                        .blob
                        .as_ref()
                        .map(|b| Base64UrlString::from(b.as_slice())),
                    written: None, // Write not yet supported
                });
            }

            // PRF extension output
            if let Some(prf_output) = &unsigned_ext.prf {
                results.prf = Some(PRFOutputJSON {
                    enabled: None,
                    results: prf_output.results.as_ref().map(|prf_value| PRFValuesJSON {
                        first: Base64UrlString::from(prf_value.first.as_slice()),
                        second: prf_value
                            .second
                            .as_ref()
                            .map(|s| Base64UrlString::from(s.as_slice())),
                    }),
                });
            }
        }

        results
    }
}

impl From<&[Assertion]> for GetAssertionResponse {
    fn from(assertions: &[Assertion]) -> Self {
        Self {
            assertions: assertions.to_owned(),
        }
    }
}

impl From<Assertion> for GetAssertionResponse {
    fn from(assertion: Assertion) -> Self {
        Self {
            assertions: vec![assertion],
        }
    }
}

impl DowngradableRequest<Vec<SignRequest>> for GetAssertionRequest {
    fn is_downgradable(&self) -> bool {
        // Options must not include "uv" set to true.
        if let UserVerificationRequirement::Required = self.user_verification {
            debug!("Not downgradable: relying party (RP) requires user verification");
            return false;
        }

        // allowList must have at least one credential.
        if self.allow.is_empty() {
            debug!("Not downgradable: allowList is empty.");
            return false;
        }

        true
    }

    fn try_downgrade(&self) -> Result<Vec<SignRequest>, CtapError> {
        trace!(?self);
        let downgraded_requests: Vec<SignRequest> = self
            .allow
            .iter()
            .map(|credential| {
                // Let controlByte be a byte initialized as follows:
                // * If "up" is set to false, set it to 0x08 (dont-enforce-user-presence-and-sign).
                // * For USB, set it to 0x07 (check-only). This should prevent call getting blocked on waiting for user
                //   input. If response returns success, then call again setting the enforce-user-presence-and-sign.
                // * For NFC, set it to 0x03 (enforce-user-presence-and-sign). The tap has already provided the presence
                //   and won’t block.
                // --> This is already set to 0x08 in trait: From<&Ctap1RegisterRequest> for ApduRequest

                // Use clientDataHash parameter of CTAP2 request as CTAP1/U2F challenge parameter (32 bytes).
                let challenge = self.client_data_hash();

                // Let rpIdHash be a byte string of size 32 initialized with SHA-256 hash of rp.id parameter as
                // CTAP1/U2F application parameter (32 bytes).
                let mut hasher = Sha256::default();
                hasher.update(self.relying_party_id.as_bytes());
                let rp_id_hash = hasher.finalize().to_vec();

                // Let credentialId is the byte string initialized with the id for this PublicKeyCredentialDescriptor.
                let credential_id = &credential.id;

                // Let u2fAuthenticateRequest be a byte string with the following structure: [...]
                SignRequest::new_upgraded(&rp_id_hash, &challenge, credential_id, self.timeout)
            })
            .collect();
        trace!(?downgraded_requests);
        Ok(downgraded_requests)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_bytes::ByteBuf;

    use crate::ops::webauthn::GetAssertionRequest;
    use crate::ops::webauthn::RelyingPartyId;
    use crate::proto::ctap2::Ctap2PublicKeyCredentialType;

    use super::*;

    pub const REQUEST_BASE_JSON: &str = r#"
    {
        "challenge": "Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu",
        "timeout": 30000,
        "rpId": "example.org",
        "allowCredentials": [
            {
                "type": "public-key",
                "id": "bXktY3JlZGVudGlhbC1pZA"
            }
        ],
        "userVerification": "preferred"
    }
    "#;

    fn request_base() -> GetAssertionRequest {
        GetAssertionRequest {
            relying_party_id: "example.org".to_owned(),
            challenge: base64_url::decode("Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu").unwrap(),
            origin: "example.org".to_string(),
            cross_origin: None,
            allow: vec![Ctap2PublicKeyCredentialDescriptor {
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                id: ByteBuf::from(base64_url::decode("bXktY3JlZGVudGlhbC1pZA").unwrap()),
                transports: None,
            }],
            extensions: None, // No extensions key in the base JSON
            user_verification: UserVerificationRequirement::Preferred,
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

    #[test]
    fn test_request_from_json_base() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req: GetAssertionRequest =
            GetAssertionRequest::from_json(&rpid, REQUEST_BASE_JSON).unwrap();
        assert_eq!(req, request_base());
    }

    #[test]
    fn test_request_from_json_ignore_missing_rp_id() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_rm(REQUEST_BASE_JSON, "rpId");

        let req: GetAssertionRequest = GetAssertionRequest::from_json(&rpid, &req_json).unwrap();
        assert_eq!(req, request_base());
    }

    #[test]
    fn test_request_from_json_invalid_rp_id() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_add(&REQUEST_BASE_JSON, "rpId", r#""example.org.""#);

        let result = GetAssertionRequest::from_json(&rpid, &req_json);
        assert!(matches!(
            result,
            Err(GetAssertionRequestParsingError::InvalidRelyingPartyId(_))
        ));
    }

    #[test]
    fn test_request_from_json_mismatching_rp_id() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_add(&REQUEST_BASE_JSON, "rpId", r#""other.example.org""#);

        let result = GetAssertionRequest::from_json(&rpid, &req_json);
        assert!(matches!(
            result,
            Err(GetAssertionRequestParsingError::MismatchingRelyingPartyId(
                _,
                _
            ))
        ));
    }

    #[test]
    fn test_request_from_json_ignore_missing_allow_credentials() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_rm(REQUEST_BASE_JSON, "allowCredentials");

        let req: GetAssertionRequest = GetAssertionRequest::from_json(&rpid, &req_json).unwrap();
        assert_eq!(
            req,
            GetAssertionRequest {
                allow: vec![],
                ..request_base()
            }
        );
    }

    #[test]
    fn test_request_from_json_default_timeout() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_rm(REQUEST_BASE_JSON, "timeout");

        let req: GetAssertionRequest = GetAssertionRequest::from_json(&rpid, &req_json).unwrap();
        assert_eq!(req.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn test_request_from_json_empty_extensions() {
        // Test that "extensions": {} results in Some(default) not None
        // This is important for strict portals that distinguish between
        // no extensions key vs empty extensions object
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_add(REQUEST_BASE_JSON, "extensions", r#"{}"#);

        let req: GetAssertionRequest = GetAssertionRequest::from_json(&rpid, &req_json).unwrap();
        assert_eq!(
            req.extensions,
            Some(GetAssertionRequestExtensions::default())
        );
    }

    #[test]
    #[ignore] // FIXME(#134) allow arbitrary size input
    fn test_request_from_json_prf_extension() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "extensions",
            r#"{"prf":{"eval":{"first": "second"}}}"#,
        );

        let req: GetAssertionRequest = GetAssertionRequest::from_json(&rpid, &req_json).unwrap();
        if let Some(GetAssertionRequestExtensions {
            prf:
                Some(PrfInput {
                    eval: Some(ref prf_value),
                    ..
                }),
            ..
        }) = &req.extensions
        {
            assert_eq!(&prf_value.first[..], b"first");
            assert_eq!(
                prf_value.second.as_ref().map(|s| &s[..]),
                Some(&b"second"[..])
            );
        } else {
            panic!("Expected PRF extension with correct values");
        }
    }

    // Tests for response JSON serialization

    fn create_test_assertion() -> Assertion {
        use crate::fido::{AuthenticatorData, AuthenticatorDataFlags};

        let authenticator_data = AuthenticatorData {
            rp_id_hash: [0u8; 32],
            flags: AuthenticatorDataFlags::USER_PRESENT,
            signature_count: 1,
            attested_credential: None,
            extensions: None,
        };

        Assertion {
            credential_id: Some(Ctap2PublicKeyCredentialDescriptor {
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                id: ByteBuf::from(vec![0x01, 0x02, 0x03, 0x04]),
                transports: None,
            }),
            authenticator_data,
            signature: vec![0xDE, 0xAD, 0xC0, 0xDE],
            user: None,
            credentials_count: None,
            user_selected: None,
            large_blob_key: None,
            unsigned_extensions_output: None,
            enterprise_attestation: None,
            attestation_statement: None,
        }
    }

    fn create_test_request() -> GetAssertionRequest {
        GetAssertionRequest {
            relying_party_id: "example.org".to_owned(),
            challenge: b"DEADCODE_challenge".to_vec(),
            origin: "example.org".to_string(),
            cross_origin: None,
            allow: vec![],
            extensions: None,
            user_verification: UserVerificationRequirement::Preferred,
            timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn test_assertion_to_json() {
        use crate::ops::webauthn::idl::response::JsonFormat;

        let assertion = create_test_assertion();
        let request = create_test_request();
        let json = assertion.to_json_string(&request, JsonFormat::default());
        assert!(json.is_ok());

        let json_str = json.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Verify credential ID fields match test data
        let expected_credential_id = base64_url::encode(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(parsed.get("id").unwrap(), &expected_credential_id);
        assert_eq!(parsed.get("rawId").unwrap(), &expected_credential_id);
        assert_eq!(parsed.get("type").unwrap(), "public-key");

        // Verify response object
        let response_obj = parsed.get("response").unwrap();
        assert!(response_obj.get("clientDataJSON").is_some());
        assert!(response_obj.get("authenticatorData").is_some());

        // Verify signature matches test data
        let expected_signature = base64_url::encode(&[0xDE, 0xAD, 0xC0, 0xDE]);
        assert_eq!(response_obj.get("signature").unwrap(), &expected_signature);
    }

    #[test]
    fn test_assertion_to_inner_model() {
        let assertion = create_test_assertion();
        let request = create_test_request();
        let model = assertion.to_inner_model(&request).unwrap();

        // Verify the credential ID
        assert_eq!(model.raw_id.0, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(model.r#type, "public-key");

        // Verify signature
        assert_eq!(model.response.signature.0, vec![0xDE, 0xAD, 0xC0, 0xDE]);
    }

    #[test]
    fn test_assertion_with_user_handle() {
        use crate::proto::ctap2::Ctap2PublicKeyCredentialUserEntity;

        let mut assertion = create_test_assertion();
        assertion.user = Some(Ctap2PublicKeyCredentialUserEntity::new(
            b"test-user-id",
            "testuser",
            "Test User",
        ));

        let request = create_test_request();
        let model = assertion.to_inner_model(&request).unwrap();

        // Verify user handle is present
        assert!(model.response.user_handle.is_some());
        assert_eq!(
            model.response.user_handle.as_ref().unwrap().0,
            b"test-user-id".to_vec()
        );
    }

    #[test]
    fn test_assertion_with_extensions() {
        let mut assertion = create_test_assertion();
        assertion.unsigned_extensions_output = Some(GetAssertionResponseUnsignedExtensions {
            hmac_get_secret: None,
            large_blob: None,
            prf: Some(GetAssertionPrfOutput {
                results: Some(PRFValue {
                    first: [0x01u8; 32],
                    second: None,
                }),
            }),
        });

        let request = create_test_request();
        let model = assertion.to_inner_model(&request).unwrap();

        // Verify extension outputs - PRF should be set with correct values
        let prf = model.client_extension_results.prf.as_ref().unwrap();
        assert!(prf.enabled.is_none()); // enabled is only set on registration
        let results = prf.results.as_ref().unwrap();
        assert_eq!(results.first.0, vec![0x01u8; 32]);
        assert!(results.second.is_none());
    }
}
