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
            FromInnerModel, JsonError,
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

use super::{DowngradableRequest, RelyingPartyId, SignRequest, UserVerificationRequirement};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

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
    pub hash: Vec<u8>,
    pub allow: Vec<Ctap2PublicKeyCredentialDescriptor>,
    pub extensions: GetAssertionRequestExtensions,
    pub user_verification: UserVerificationRequirement,
    pub timeout: Duration,
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
        let hmac_or_prf = match inner.extensions.clone() {
            Some(ext) => {
                if let Some(prf) = ext.prf {
                    let prf_input = PrfInput::try_from(prf)?;
                    Some(GetAssertionHmacOrPrfInput::Prf(prf_input))
                } else if let Some(hmac) = ext.hamc_get_secret {
                    let hmac_input = HMACGetSecretInput::try_from(hmac)?;
                    Some(GetAssertionHmacOrPrfInput::HmacGetSecret(hmac_input))
                } else {
                    None
                }
            }
            None => None,
        };

        let extensions_opt = inner.extensions.clone();
        let extensions = GetAssertionRequestExtensions {
            cred_blob: extensions_opt
                .as_ref()
                .and_then(|ext| ext.cred_blob)
                .unwrap_or(false),
            large_blob: extensions_opt
                .as_ref()
                .and_then(|ext| ext.large_blob.clone())
                .map(Option::<GetAssertionLargeBlobExtension>::try_from)
                .transpose()?
                .flatten(),
            hmac_or_prf,
        };

        let timeout: Duration = inner
            .timeout
            .map(|s| Duration::from_millis(s.into()))
            .unwrap_or(DEFAULT_TIMEOUT);

        let client_data_json = ClientData {
            operation: Operation::GetAssertion,
            challenge: inner.challenge.to_vec(),
            origin: rpid.to_string(),
            cross_origin: None,
        };

        Ok(GetAssertionRequest {
            relying_party_id: rpid.to_string(),
            hash: client_data_json.hash(),
            allow: inner
                .allow_credentials
                .into_iter()
                .map(|c| c.into())
                .collect(),
            extensions,
            user_verification: inner.uv_requirement,
            timeout,
        })
    }
}

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

impl TryFrom<LargeBlobInputJson> for Option<GetAssertionLargeBlobExtension> {
    type Error = GetAssertionRequestParsingError;

    fn try_from(value: LargeBlobInputJson) -> Result<Self, Self::Error> {
        match value.read {
            Some(true) => Ok(Some(GetAssertionLargeBlobExtension::Read)),
            Some(false) => Err(GetAssertionRequestParsingError::NotSupported(
                "largeBlob writes not supported".to_string(),
            )),
            None => Ok(None),
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
    pub hmac_or_prf: Option<GetAssertionHmacOrPrfInput>,
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
                let challenge = &self.hash;

                // Let rpIdHash be a byte string of size 32 initialized with SHA-256 hash of rp.id parameter as
                // CTAP1/U2F application parameter (32 bytes).
                let mut hasher = Sha256::default();
                hasher.update(self.relying_party_id.as_bytes());
                let rp_id_hash = hasher.finalize().to_vec();

                // Let credentialId is the byte string initialized with the id for this PublicKeyCredentialDescriptor.
                let credential_id = &credential.id;

                // Let u2fAuthenticateRequest be a byte string with the following structure: [...]
                SignRequest::new_upgraded(&rp_id_hash, challenge, credential_id, self.timeout)
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
        let client_data_json = ClientData {
            operation: Operation::GetAssertion,
            challenge: base64_url::decode("Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu").unwrap(),
            origin: "example.org".to_string(),
            cross_origin: None,
        };
        GetAssertionRequest {
            relying_party_id: "example.org".to_owned(),
            hash: client_data_json.hash(),
            allow: vec![Ctap2PublicKeyCredentialDescriptor {
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                id: ByteBuf::from(base64_url::decode("bXktY3JlZGVudGlhbC1pZA").unwrap()),
                transports: None,
            }],
            extensions: GetAssertionRequestExtensions::default(),
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
    fn test_request_from_json_ignore_request_rp_id() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_rm(REQUEST_BASE_JSON, "rpId");
        let req_json = json_field_add(&req_json, "rpId", r#""another-example.org""#);

        let req: GetAssertionRequest = GetAssertionRequest::from_json(&rpid, &req_json).unwrap();
        assert_eq!(req, request_base());
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
    #[ignore] // FIXME(#134) allow arbitrary size input
    fn test_request_from_json_prf_extension() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "extensions",
            r#"{"prf":{"eval":{"first": "second"}}}"#,
        );

        let req: GetAssertionRequest = GetAssertionRequest::from_json(&rpid, &req_json).unwrap();
        if let GetAssertionRequestExtensions {
            hmac_or_prf:
                Some(GetAssertionHmacOrPrfInput::Prf(PrfInput {
                    eval: Some(ref prf_value),
                    ..
                })),
            ..
        } = &req.extensions
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
}
