use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use ctap_types::ctap2::credential_management::CredentialProtectionPolicy as Ctap2CredentialProtectionPolicy;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, instrument, trace};

use crate::{
    fido::AuthenticatorData,
    ops::webauthn::{
        client_data::ClientData,
        idl::{
            create::PublicKeyCredentialCreationOptionsJSON,
            get::PrfValuesJson,
            response::{
                AuthenticationExtensionsClientOutputsJSON, AuthenticatorAttestationResponseJSON,
                CredentialPropertiesOutputJSON, LargeBlobOutputJSON, PRFOutputJSON, PRFValuesJSON,
                RegistrationResponseJSON, ResponseSerializationError, WebAuthnIDLResponse,
            },
            rp_id_authorised, Base64UrlString, FromIdlModel, JsonError, RequestSettings,
        },
        Operation, PrfInputValue, PrfOutputValue, RelyingPartyId, RequestOrigin,
    },
    proto::{
        ctap1::{Ctap1RegisteredKey, Ctap1Version},
        ctap2::{
            cbor, cbor::Value, cose, parse_unsigned_prf, Ctap2AttestationStatement,
            Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2GetInfoResponse,
            Ctap2MakeCredentialsResponseExtensions, Ctap2PublicKeyCredentialDescriptor,
            Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialUserEntity, Ctap2Transport,
            UnsignedPrfOutput,
        },
    },
    transport::AuthTokenData,
    Transport,
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
    /// Transport the credential was created over, stamped by the channel.
    pub transport: Option<Transport>,
    /// Transports the authenticator advertised in getInfo (0x09), if any.
    pub authenticator_transports: Option<Vec<String>>,
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

/// Maps the active transport to AuthenticatorTransport tokens for the registration
/// `transports` member. The list is deduplicated and lexicographically sorted per
/// WebAuthn L3 §5.2.1.1, and is empty when the transport is unknown.
fn registration_transports(transport: Option<Transport>) -> Vec<String> {
    let mut tokens: Vec<String> = transport
        .into_iter()
        .map(Ctap2Transport::from)
        .filter_map(|t| serde_json::to_value(t).ok())
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    tokens.sort();
    tokens.dedup();
    tokens
}

fn scrub_aaguid(authenticator_data: &mut [u8]) -> Result<(), ResponseSerializationError> {
    const AAGUID_OFFSET: usize = 37;
    const AAGUID_LEN: usize = 16;
    authenticator_data
        .get_mut(AAGUID_OFFSET..AAGUID_OFFSET + AAGUID_LEN)
        .ok_or_else(|| {
            ResponseSerializationError::AuthenticatorDataError(
                "authenticator data too short to scrub AAGUID".into(),
            )
        })?
        .fill(0);
    Ok(())
}

fn build_attestation_object(
    format: &str,
    attestation_statement: &Ctap2AttestationStatement,
    authenticator_data_bytes: &[u8],
) -> Result<Vec<u8>, ResponseSerializationError> {
    let attestation_object = AttestationObject {
        format,
        auth_data: authenticator_data_bytes,
        attestation_statement,
    };

    cbor::to_vec(&attestation_object)
        .map_err(|e| ResponseSerializationError::AttestationObjectError(e.to_string()))
}

impl WebAuthnIDLResponse for MakeCredentialResponse {
    type IdlModel = RegistrationResponseJSON;
    type Context = MakeCredentialRequest;

    fn to_idl_model(
        &self,
        request: &Self::Context,
    ) -> Result<Self::IdlModel, ResponseSerializationError> {
        // The AT flag MUST be set on makeCredential responses per CTAP 2.2 §6.1.
        let attested = self
            .authenticator_data
            .attested_credential
            .as_ref()
            .ok_or_else(|| {
                ResponseSerializationError::AuthenticatorDataError(
                    "missing attested credential data".into(),
                )
            })?;

        let id = base64_url::encode(&attested.credential_id);
        let raw_id = Base64UrlString::from(attested.credential_id.clone());

        let mut authenticator_data_bytes = self
            .authenticator_data
            .to_response_bytes()
            .map_err(|e| ResponseSerializationError::AuthenticatorDataError(e.to_string()))?;

        let scrub_attestation = request.attestation.as_deref() == Some("none");
        if scrub_attestation {
            scrub_aaguid(&mut authenticator_data_bytes)?;
        }

        let public_key_algorithm = i64::from(
            cose::read_alg(&attested.credential_public_key)
                .map_err(|e| ResponseSerializationError::PublicKeyError(e.to_string()))?,
        );

        // SubjectPublicKeyInfo per WebAuthn L3 §5.2.1.1. `to_spki` returns
        // `Ok(None)` for algorithms libwebauthn does not implement, which
        // surfaces as `getPublicKey() === null` to the relying party.
        let public_key = cose::to_spki(&attested.credential_public_key)
            .map_err(|e| ResponseSerializationError::PublicKeyError(e.to_string()))?
            .map(Base64UrlString::from);

        // Build attestation object (CBOR map with authData, fmt, attStmt)
        let none_statement = Ctap2AttestationStatement::None(BTreeMap::new());
        let (format, attestation_statement) = if scrub_attestation {
            ("none", &none_statement)
        } else {
            (self.format.as_str(), &self.attestation_statement)
        };
        let attestation_object_bytes =
            build_attestation_object(format, attestation_statement, &authenticator_data_bytes)?;

        // WebAuthn getTransports(): the authenticator's getInfo 0x09 transports
        // folded with the ceremony transport, unique tokens lexicographically sorted.
        let mut transports = self.authenticator_transports.clone().unwrap_or_default();
        transports.extend(registration_transports(self.transport));
        transports.sort();
        transports.dedup();

        // Build client extension results
        let client_extension_results = self.build_client_extension_results();

        Ok(RegistrationResponseJSON {
            id,
            raw_id,
            response: AuthenticatorAttestationResponseJSON {
                client_data_json: Base64UrlString::from(request.client_data_json().into_bytes()),
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

        if let Some(prf) = &unsigned_ext.prf {
            results.prf = Some(PRFOutputJSON {
                enabled: prf.enabled,
                results: prf.results.as_ref().map(|v| PRFValuesJSON {
                    first: Base64UrlString::from(v.first.as_slice()),
                    second: v
                        .second
                        .as_ref()
                        .map(|s| Base64UrlString::from(s.as_slice())),
                }),
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
        unsigned_outputs: Option<&BTreeMap<Value, Value>>,
        request: &MakeCredentialRequest,
        info: Option<&Ctap2GetInfoResponse>,
        auth_data: Option<&AuthTokenData>,
    ) -> MakeCredentialsResponseUnsignedExtensions {
        let mut hmac_create_secret = None;
        let mut prf = None;
        // Native `prf` outputs arrive in unsignedExtensionOutputs, not authData.
        let unsigned_prf = unsigned_outputs.and_then(parse_unsigned_prf);
        if let Some(incoming_ext) = &request.extensions {
            if incoming_ext.hmac_create_secret.is_some() {
                hmac_create_secret = signed_extensions.as_ref().and_then(|s| s.hmac_secret);
            }
            if incoming_ext.prf.is_some() && (signed_extensions.is_some() || unsigned_prf.is_some())
            {
                let decrypted_results = signed_extensions
                    .as_ref()
                    .and_then(|s| s.hmac_secret_mc.as_ref())
                    .zip(auth_data)
                    .and_then(|(out, auth)| {
                        let uv_proto = auth.protocol_version.create_protocol_object();
                        out.decrypt_output(&auth.shared_secret, uv_proto.as_ref())
                    })
                    .map(|decrypted| PrfOutputValue {
                        first: decrypted.output1,
                        second: decrypted.output2,
                    });
                let UnsignedPrfOutput {
                    enabled: unsigned_enabled,
                    results: unsigned_results,
                } = unsigned_prf.unwrap_or_default();
                prf = Some(MakeCredentialPrfOutput {
                    enabled: signed_extensions
                        .as_ref()
                        .and_then(|s| s.hmac_secret)
                        .or(unsigned_enabled),
                    results: decrypted_results.or(unsigned_results),
                });
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
    /// The top-level origin if the request was made from a cross-origin
    /// nested browsing context. None for same-origin requests.
    pub top_origin: Option<String>,
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
    /// Attestation conveyance preference. `Some("none")` scrubs attestation.
    pub attestation: Option<String>,
    pub timeout: Duration,
}

impl MakeCredentialRequest {
    /// Builds the ClientData for this request.
    fn client_data(&self) -> ClientData {
        ClientData {
            operation: Operation::MakeCredential,
            challenge: self.challenge.clone(),
            origin: self.origin.clone(),
            top_origin: self.top_origin.clone(),
        }
    }

    /// Computes the client data hash (SHA-256 of the client data JSON).
    pub fn client_data_hash(&self) -> Vec<u8> {
        self.client_data().hash()
    }

    /// Returns the canonical JSON representation of the client data.
    pub fn client_data_json(&self) -> String {
        self.client_data().to_json()
    }
}

#[async_trait]
impl FromIdlModel<PublicKeyCredentialCreationOptionsJSON> for MakeCredentialRequest {
    type Error = MakeCredentialPrepareError;

    async fn from_idl_model(
        request_origin: &RequestOrigin,
        settings: &RequestSettings<'_>,
        inner: PublicKeyCredentialCreationOptionsJSON,
    ) -> Result<Self, MakeCredentialPrepareError> {
        let effective_rp_id = request_origin.origin.host.as_str();
        let rp_id = RelyingPartyId::try_from(inner.rp.id.as_deref().unwrap_or(effective_rp_id))
            .map_err(|err| MakeCredentialPrepareError::InvalidRelyingPartyId(err.to_string()))?;
        if !rp_id_authorised(request_origin, &rp_id, settings).await {
            return Err(MakeCredentialPrepareError::MismatchingRelyingPartyId(
                rp_id.0,
                effective_rp_id.to_string(),
            ));
        }
        let relying_party = Ctap2PublicKeyCredentialRpEntity {
            id: rp_id.0,
            name: inner.rp.name,
        };
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
            origin: request_origin.origin.to_string(),
            top_origin: request_origin.top_origin.as_ref().map(|o| o.to_string()),
            relying_party,
            user: inner.user.into(),
            resident_key,
            user_verification,
            algorithms: inner.params,
            exclude: if inner.exclude_credentials.is_empty() {
                None
            } else {
                Some(
                    inner
                        .exclude_credentials
                        .into_iter()
                        .map(|c| c.into())
                        .collect(),
                )
            },
            extensions: inner.extensions,
            // WebAuthn IDL defaults attestation conveyance to "none".
            attestation: inner.attestation.or_else(|| Some("none".to_string())),
            timeout,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MakeCredentialPrepareError {
    /// The client must throw an "EncodingError" DOMException.
    #[error("Invalid JSON format: {0}")]
    EncodingError(#[from] JsonError),
    #[error("Invalid relying party ID: {0}")]
    InvalidRelyingPartyId(String),
    #[error("Mismatching relying party ID: {0} != {1}")]
    MismatchingRelyingPartyId(String, String),
}

impl MakeCredentialRequest {
    /// Builds a [`MakeCredentialRequest`] from its WebAuthn IDL JSON, validating
    /// the caller origin against rp.id per `settings`.
    pub async fn prepare(
        request_origin: &RequestOrigin,
        json: &str,
        settings: &RequestSettings<'_>,
    ) -> Result<Self, MakeCredentialPrepareError> {
        let model: PublicKeyCredentialCreationOptionsJSON = serde_json::from_str(json)?;
        Self::from_idl_model(request_origin, settings, model).await
    }
}

#[derive(Debug, Default, Clone, Deserialize, PartialEq)]
pub struct MakeCredentialPrfInput {
    #[serde(default, deserialize_with = "deserialize_prf_eval")]
    pub eval: Option<PrfInputValue>,
}

fn deserialize_prf_eval<'de, D>(deserializer: D) -> Result<Option<PrfInputValue>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(json) = Option::<PrfValuesJson>::deserialize(deserializer)? else {
        return Ok(None);
    };
    // WebAuthn L3 §10.1.4: PRF salt inputs are BufferSources of any length.
    Ok(Some(PrfInputValue {
        first: json.first.as_slice().to_vec(),
        second: json.second.map(|s| s.as_slice().to_vec()),
    }))
}

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct MakeCredentialPrfOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<PrfOutputValue>,
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
    /// FIDO AppID Exclusion extension (WebAuthn L3 §10.1.2). When set, the
    /// excludeList is preflighted against both `SHA-256(rp.id)` and
    /// `SHA-256(appidExclude)` so that legacy U2F-keyed credentials are
    /// detected and registration is prevented.
    pub appid_exclude: Option<String>,
}

pub type MakeCredentialsResponseExtensions = Ctap2MakeCredentialsResponseExtensions;

impl MakeCredentialRequest {
    #[cfg(test)]
    pub(crate) fn dummy() -> Self {
        Self {
            challenge: Vec::new(),
            origin: "example.org".to_owned(),
            top_origin: None,
            relying_party: Ctap2PublicKeyCredentialRpEntity::dummy(),
            user: Ctap2PublicKeyCredentialUserEntity::dummy(),
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: None,
            attestation: None,
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

        // Enforced credProtect with a non-default policy cannot be honoured by U2F.
        if let Some(cred_protect) = self
            .extensions
            .as_ref()
            .and_then(|e| e.cred_protect.as_ref())
        {
            if cred_protect.enforce_policy
                && cred_protect.policy != CredentialProtectionPolicy::UserVerificationOptional
            {
                debug!("Not downgradable: request enforces a non-default credProtect policy");
                return false;
            }
        }

        // U2F has no large-blob storage.
        if matches!(
            self.extensions
                .as_ref()
                .and_then(|e| e.large_blob.as_ref())
                .map(|lb| lb.support),
            Some(MakeCredentialLargeBlobExtension::Required)
        ) {
            debug!("Not downgradable: request requires the largeBlob extension");
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
                .iter()
                .map(|exclude| Ctap1RegisteredKey {
                    version: Ctap1Version::U2fV2,
                    key_handle: exclude.id.to_vec(),
                    transports: {
                        match &exclude.transports {
                            None => None,
                            Some(ctap2_transports) => {
                                let transports: Result<Vec<_>, _> =
                                    ctap2_transports.iter().map(|t| t.try_into()).collect();
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

    use async_trait::async_trait;

    use crate::ops::webauthn::psl::{MockPublicSuffixList, PublicSuffixList};
    use crate::ops::webauthn::related_origins::{
        HttpClientError, MaxRegistrableLabels, RelatedOrigins, RelatedOriginsError,
        RelatedOriginsSource,
    };
    use crate::ops::webauthn::{MakeCredentialRequest, OriginValidation, RequestOrigin};
    use crate::proto::ctap2::Ctap2PublicKeyCredentialType;

    use super::*;

    // Fixed-result source; `panicking` proves the suffix-check short-circuit by
    // failing if consulted.
    struct MockSource {
        result: Option<Result<Vec<String>, RelatedOriginsError>>,
    }

    impl MockSource {
        fn origins(items: &[&str]) -> Self {
            Self {
                result: Some(Ok(items.iter().map(|s| s.to_string()).collect())),
            }
        }

        fn err(e: RelatedOriginsError) -> Self {
            Self {
                result: Some(Err(e)),
            }
        }

        fn panicking() -> Self {
            Self { result: None }
        }
    }

    #[async_trait]
    impl RelatedOriginsSource for MockSource {
        async fn allowed_origins(
            &self,
            _: &RelyingPartyId,
        ) -> Result<Vec<String>, RelatedOriginsError> {
            match &self.result {
                Some(r) => r.clone(),
                None => panic!("allowed_origins should not be called"),
            }
        }
    }

    async fn from_json(
        origin: &RequestOrigin,
        psl: &dyn PublicSuffixList,
        related_origins: RelatedOrigins<'_>,
        json: &str,
    ) -> Result<MakeCredentialRequest, MakeCredentialPrepareError> {
        MakeCredentialRequest::prepare(
            origin,
            json,
            &RequestSettings {
                origin: OriginValidation::Validate {
                    public_suffix_list: psl,
                    related_origins,
                },
            },
        )
        .await
    }

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
            origin: "https://example.org".to_string(),
            top_origin: None,
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(b"userid", "mario.rossi", "Mario Rossi"),
            resident_key: Some(ResidentKeyRequirement::Discouraged),
            user_verification: UserVerificationRequirement::Preferred,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: None,
            attestation: Some("none".to_string()),
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

    async fn test_request_from_json_required_field(field: &str) {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req_json = json_field_rm(REQUEST_BASE_JSON, field);

        let result = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await;
        assert!(matches!(
            result,
            Err(MakeCredentialPrepareError::EncodingError(_))
        ));
    }

    #[tokio::test]
    async fn test_request_from_json_base() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req: MakeCredentialRequest = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            REQUEST_BASE_JSON,
        )
        .await
        .unwrap();
        assert_eq!(req, request_base());
    }

    #[tokio::test]
    async fn test_request_from_json_require_rp() {
        test_request_from_json_required_field("rp").await;
    }

    #[tokio::test]
    async fn test_request_from_json_require_user() {
        test_request_from_json_required_field("user").await;
    }

    #[tokio::test]
    async fn test_request_from_json_require_pub_key_cred_params() {
        test_request_from_json_required_field("pubKeyCredParams").await;
    }

    #[tokio::test]
    async fn test_request_from_json_require_challenge() {
        test_request_from_json_required_field("challenge").await;
    }

    #[tokio::test]
    #[ignore] // FIXME(#134): Add validation for challenges
    async fn test_request_from_json_challenge_empty() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req_json: String = json_field_rm(REQUEST_BASE_JSON, "challenge");
        let req_json = json_field_add(&req_json, "challenge", r#""""#);

        let result = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await;
        assert!(matches!(
            result,
            Err(MakeCredentialPrepareError::EncodingError(_))
        ));
    }

    #[tokio::test]
    async fn test_request_from_json_prf_extension() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let first = base64_url::encode(&[1u8; 32]);
        let second = base64_url::encode(&[2u8; 32]);
        let ext = format!(r#"{{"prf": {{"eval": {{"first": "{first}", "second": "{second}"}}}}}}"#);
        let req_json = json_field_add(REQUEST_BASE_JSON, "extensions", &ext);

        let req: MakeCredentialRequest = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        let prf = req
            .extensions
            .as_ref()
            .and_then(|e| e.prf.as_ref())
            .and_then(|p| p.eval.as_ref())
            .expect("prf.eval parsed");
        assert_eq!(prf.first, vec![1u8; 32]);
        assert_eq!(prf.second, Some(vec![2u8; 32]));
    }

    #[tokio::test]
    async fn test_request_from_json_prf_extension_empty() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req_json = json_field_add(REQUEST_BASE_JSON, "extensions", r#"{"prf": {}}"#);

        let req: MakeCredentialRequest = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        let prf = req.extensions.unwrap().prf.unwrap();
        assert!(prf.eval.is_none());
    }

    #[tokio::test]
    async fn test_request_from_json_prf_extension_short_input() {
        // WebAuthn L3 §10.1.4: PRF salt inputs are BufferSources of any length.
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let short = base64_url::encode(&[0u8; 16]);
        let ext = format!(r#"{{"prf": {{"eval": {{"first": "{short}"}}}}}}"#);
        let req_json = json_field_add(REQUEST_BASE_JSON, "extensions", &ext);

        let req: MakeCredentialRequest = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        let prf = req
            .extensions
            .as_ref()
            .and_then(|e| e.prf.as_ref())
            .and_then(|p| p.eval.as_ref())
            .expect("prf.eval parsed");
        assert_eq!(prf.first, vec![0u8; 16]);
        assert!(prf.second.is_none());
    }

    #[tokio::test]
    async fn test_request_from_json_appid_exclude_extension() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "extensions",
            r#"{"appidExclude": "https://www.example.org/u2f/origins.json"}"#,
        );

        let req: MakeCredentialRequest = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        let ext = req.extensions.expect("extensions should be present");
        assert_eq!(
            ext.appid_exclude.as_deref(),
            Some("https://www.example.org/u2f/origins.json")
        );
    }

    #[tokio::test]
    async fn test_request_from_json_unknown_pub_key_cred_params() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "pubKeyCredParams",
            r#"[{"type": "something", "alg": -12345}]"#,
        );
        let req: MakeCredentialRequest = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        assert_eq!(
            req.algorithms,
            vec![Ctap2CredentialType {
                algorithm: Ctap2COSEAlgorithmIdentifier(-12345),
                public_key_type: Ctap2PublicKeyCredentialType::Unknown,
            }]
        );
    }

    #[tokio::test]
    async fn test_request_from_json_default_timeout() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req_json = json_field_rm(REQUEST_BASE_JSON, "timeout");

        let req: MakeCredentialRequest = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        assert_eq!(req.timeout, DEFAULT_TIMEOUT);
    }

    /// Per spec, when authenticatorSelection is missing, userVerification should default to "preferred".
    /// https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-userverification
    #[tokio::test]
    async fn test_request_from_json_default_user_verification_preferred() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req_json = json_field_rm(REQUEST_BASE_JSON, "authenticatorSelection");

        let req: MakeCredentialRequest = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        assert_eq!(
            req.user_verification,
            UserVerificationRequirement::Preferred
        );
    }

    /// Per spec, when userVerification is missing inside authenticatorSelection,
    /// it should default to "preferred".
    #[tokio::test]
    async fn test_request_from_json_missing_user_verification_in_authenticator_selection() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        // Replace authenticatorSelection with one that has no userVerification field
        let mut req_json = json_field_rm(REQUEST_BASE_JSON, "authenticatorSelection");
        req_json = json_field_add(
            &req_json,
            "authenticatorSelection",
            r#"{"residentKey": "discouraged"}"#,
        );

        let req: MakeCredentialRequest = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        assert_eq!(
            req.user_verification,
            UserVerificationRequirement::Preferred
        );
    }

    #[tokio::test]
    async fn test_request_from_json_invalid_rp_id() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "example.org.", "name": "example.org"}"#,
        );

        let result = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await;
        assert!(matches!(
            result,
            Err(MakeCredentialPrepareError::InvalidRelyingPartyId(_))
        ));
    }

    #[tokio::test]
    async fn test_request_from_json_rp_id_defaults_to_effective_domain() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req_json = json_field_add(REQUEST_BASE_JSON, "rp", r#"{"name": "example.org"}"#);

        let req = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        assert_eq!(req.relying_party.id, "example.org");
    }

    #[tokio::test]
    async fn test_request_from_json_rejects_ipv4_effective_domain() {
        let request_origin: RequestOrigin = "https://127.0.0.1:8443".parse().unwrap();
        let req_json = json_field_add(REQUEST_BASE_JSON, "rp", r#"{"name": "example.org"}"#);

        let result = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await;
        assert!(matches!(
            result,
            Err(MakeCredentialPrepareError::InvalidRelyingPartyId(_))
        ));
    }

    #[tokio::test]
    async fn test_request_from_json_rejects_ipv6_effective_domain() {
        let request_origin: RequestOrigin = "https://[::1]:8443".parse().unwrap();
        let req_json = json_field_add(REQUEST_BASE_JSON, "rp", r#"{"name": "example.org"}"#);

        let result = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await;
        assert!(matches!(
            result,
            Err(MakeCredentialPrepareError::InvalidRelyingPartyId(_))
        ));
    }

    #[tokio::test]
    async fn origin_trust_accepts_mismatching_rp_id() {
        let request_origin: RequestOrigin = "https://app.example.org".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "example.com", "name": "example.com"}"#,
        );
        let req = MakeCredentialRequest::prepare(
            &request_origin,
            &req_json,
            &RequestSettings {
                origin: OriginValidation::Trust,
            },
        )
        .await
        .unwrap();
        assert_eq!(req.relying_party.id, "example.com");
    }

    #[tokio::test]
    async fn origin_trust_still_rejects_invalid_rp_id() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "example.org.", "name": "example.org"}"#,
        );
        let result = MakeCredentialRequest::prepare(
            &request_origin,
            &req_json,
            &RequestSettings {
                origin: OriginValidation::Trust,
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(MakeCredentialPrepareError::InvalidRelyingPartyId(_))
        ));
    }

    #[tokio::test]
    async fn test_request_from_json_mismatching_rp_id() {
        let request_origin: RequestOrigin = "https://example.org".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "other.example.org", "name": "example.org"}"#,
        );

        let result = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await;
        assert!(matches!(
            result,
            Err(MakeCredentialPrepareError::MismatchingRelyingPartyId(_, _))
        ));
    }

    #[tokio::test]
    async fn test_request_from_json_rp_id_is_parent_registrable_suffix() {
        let request_origin: RequestOrigin = "https://login.example.org".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "example.org", "name": "example.org"}"#,
        );

        let req = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        assert_eq!(req.relying_party.id, "example.org");
        assert_eq!(req.origin, "https://login.example.org");
    }

    #[tokio::test]
    async fn test_request_from_json_rp_id_is_etld_rejected() {
        let request_origin: RequestOrigin = "https://example.co.uk".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "co.uk", "name": "co.uk"}"#,
        );

        let result = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await;
        assert!(matches!(
            result,
            Err(MakeCredentialPrepareError::MismatchingRelyingPartyId(_, _))
        ));
    }

    #[tokio::test]
    async fn test_request_from_json_http_localhost_accepted() {
        let request_origin: RequestOrigin = "http://localhost".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "localhost", "name": "localhost"}"#,
        );

        let req = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        assert_eq!(req.relying_party.id, "localhost");
        assert_eq!(req.origin, "http://localhost");
    }

    #[tokio::test]
    async fn test_request_from_json_http_localhost_with_port_accepted() {
        let request_origin: RequestOrigin = "http://localhost:3000".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "localhost", "name": "localhost"}"#,
        );

        let req = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Disabled,
            &req_json,
        )
        .await
        .unwrap();
        assert_eq!(req.relying_party.id, "localhost");
        assert_eq!(req.origin, "http://localhost:3000");
    }

    // `.de` substituted with `.org` (MockPublicSuffixList lacks `.de`); pattern
    // (different eTLD between caller origin and rp.id) is identical.

    #[tokio::test]
    async fn related_origins_match_resolves_mismatch() {
        let request_origin: RequestOrigin = "https://app.example.org".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "example.com", "name": "example.com"}"#,
        );
        let source = MockSource::origins(&["https://app.example.org"]);

        let req = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Enabled {
                source: &source,
                max_labels: MaxRegistrableLabels::default(),
            },
            &req_json,
        )
        .await
        .unwrap();
        assert_eq!(req.relying_party.id, "example.com");
    }

    #[tokio::test]
    async fn related_origins_no_match_keeps_mismatch_error() {
        let request_origin: RequestOrigin = "https://app.example.org".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "example.com", "name": "example.com"}"#,
        );
        let source = MockSource::origins(&["https://other.org"]);

        let result = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Enabled {
                source: &source,
                max_labels: MaxRegistrableLabels::default(),
            },
            &req_json,
        )
        .await;
        assert!(matches!(
            result,
            Err(MakeCredentialPrepareError::MismatchingRelyingPartyId(_, _))
        ));
    }

    #[tokio::test]
    async fn related_origins_fetch_error_keeps_mismatch_error() {
        let request_origin: RequestOrigin = "https://app.example.org".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "example.com", "name": "example.com"}"#,
        );
        let source = MockSource::err(RelatedOriginsError::Http(HttpClientError::Transport(
            "simulated".into(),
        )));

        let result = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Enabled {
                source: &source,
                max_labels: MaxRegistrableLabels::default(),
            },
            &req_json,
        )
        .await;
        assert!(matches!(
            result,
            Err(MakeCredentialPrepareError::MismatchingRelyingPartyId(_, _))
        ));
    }

    #[tokio::test]
    async fn related_origins_not_consulted_when_suffix_matches() {
        let request_origin: RequestOrigin = "https://login.example.com".parse().unwrap();
        let req_json = json_field_add(
            REQUEST_BASE_JSON,
            "rp",
            r#"{"id": "example.com", "name": "example.com"}"#,
        );
        let source = MockSource::panicking();

        let req = from_json(
            &request_origin,
            &MockPublicSuffixList,
            RelatedOrigins::Enabled {
                source: &source,
                max_labels: MaxRegistrableLabels::default(),
            },
            &req_json,
        )
        .await
        .unwrap();
        assert_eq!(req.relying_party.id, "example.com");
    }

    // Tests for response JSON serialization

    fn create_test_response() -> MakeCredentialResponse {
        use crate::fido::{AttestedCredentialData, AuthenticatorData, AuthenticatorDataFlags};
        use cosey::Bytes;
        use std::collections::BTreeMap;

        // Create a simple attested credential with a P256 key
        let credential_id = vec![0x01, 0x02, 0x03, 0x04];
        let aaguid = [0u8; 16];

        // Minimal COSE_Key for a P-256 ES256 credential, used as opaque
        // bytes by the test harness.
        let cose_public_key = cosey::PublicKey::P256Key(cosey::P256PublicKey {
            x: Bytes::from_slice(&[0u8; 32]).unwrap(),
            y: Bytes::from_slice(&[0u8; 32]).unwrap(),
        });
        let credential_public_key = cbor::to_vec(&cose_public_key).unwrap();

        let attested_credential = AttestedCredentialData {
            aaguid,
            credential_id,
            credential_public_key,
        };

        let authenticator_data = AuthenticatorData {
            rp_id_hash: [0u8; 32],
            flags: AuthenticatorDataFlags::USER_PRESENT,
            signature_count: 0,
            attested_credential: Some(attested_credential),
            extensions: None,
            raw: None,
        };

        MakeCredentialResponse {
            format: "none".to_string(),
            authenticator_data,
            attestation_statement: Ctap2AttestationStatement::None(BTreeMap::new()),
            enterprise_attestation: None,
            large_blob_key: None,
            unsigned_extensions_output: MakeCredentialsResponseUnsignedExtensions::default(),
            transport: None,
            authenticator_transports: None,
        }
    }

    fn create_test_request() -> MakeCredentialRequest {
        MakeCredentialRequest {
            challenge: b"DEADCODE_challenge".to_vec(),
            origin: "example.org".to_string(),
            top_origin: None,
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(b"userid", "mario.rossi", "Mario Rossi"),
            resident_key: Some(ResidentKeyRequirement::Discouraged),
            user_verification: UserVerificationRequirement::Preferred,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: None,
            attestation: None,
            timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn test_response_to_json() {
        use crate::ops::webauthn::idl::response::JsonFormat;

        let response = create_test_response();
        let request = create_test_request();
        let json = response.to_json_string(&request, JsonFormat::default());
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
        assert!(response_obj.get("attestationObject").is_some());

        // Verify algorithm is ES256 (-7) for P256 key
        assert_eq!(
            response_obj.get("publicKeyAlgorithm").unwrap(),
            i64::from(Ctap2COSEAlgorithmIdentifier::ES256)
        );
    }

    #[test]
    fn prf_output_serialized_into_client_extension_results() {
        let mut response = create_test_response();
        response.unsigned_extensions_output = MakeCredentialsResponseUnsignedExtensions {
            prf: Some(MakeCredentialPrfOutput {
                enabled: Some(true),
                results: Some(PrfOutputValue {
                    first: [0xAB; 32],
                    second: Some([0xCD; 32]),
                }),
            }),
            ..Default::default()
        };

        let results = serde_json::to_value(response.build_client_extension_results()).unwrap();
        assert_eq!(results["prf"]["enabled"], serde_json::json!(true));
        assert_eq!(
            results["prf"]["results"]["first"],
            serde_json::json!(base64_url::encode(&[0xAB; 32]))
        );
        assert_eq!(
            results["prf"]["results"]["second"],
            serde_json::json!(base64_url::encode(&[0xCD; 32]))
        );
    }

    #[test]
    fn test_response_to_idl_model() {
        let response = create_test_response();
        let request = create_test_request();
        let model = response.to_idl_model(&request).unwrap();

        // Verify the credential ID
        assert_eq!(model.raw_id.0, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(model.r#type, "public-key");

        // Verify attestation response
        assert_eq!(
            model.response.public_key_algorithm,
            i64::from(Ctap2COSEAlgorithmIdentifier::ES256)
        );
        assert!(model.response.transports.is_empty());
    }

    #[test]
    fn test_response_to_idl_model_populates_transports() {
        // WebAuthn L3 §5.2.1.1: the registration `transports` member reports the
        // transport the credential was created over, as AuthenticatorTransport tokens.
        // Both the FIDO2 and U2F-downgrade paths converge on this serialization.
        let mut response = create_test_response();
        let request = create_test_request();

        for (transport, token) in [
            (Transport::Usb, "usb"),
            (Transport::Ble, "ble"),
            (Transport::Nfc, "nfc"),
            (Transport::Hybrid, "hybrid"),
        ] {
            response.transport = Some(transport);
            let model = response.to_idl_model(&request).unwrap();
            assert_eq!(model.response.transports, vec![token.to_string()]);
        }

        // The token reaches the JSON wire format too.
        response.transport = Some(Transport::Nfc);
        let json = response
            .to_json_string(
                &request,
                crate::ops::webauthn::idl::response::JsonFormat::default(),
            )
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let transports = parsed["response"]["transports"].as_array().unwrap();
        assert_eq!(transports, &vec![serde_json::Value::from("nfc")]);

        // An unknown transport leaves the list empty.
        response.transport = None;
        let model = response.to_idl_model(&request).unwrap();
        assert!(model.response.transports.is_empty());
    }

    #[test]
    fn test_response_to_idl_model_transports_from_get_info() {
        // The authenticator's getInfo (0x09) transports are folded with the
        // ceremony transport, as unique tokens in lexicographical order.
        let mut response = create_test_response();
        let request = create_test_request();

        // Reported out of order with a duplicate; the ceremony transport (ble) folds in.
        response.transport = Some(Transport::Ble);
        response.authenticator_transports = Some(vec![
            "usb".to_string(),
            "nfc".to_string(),
            "usb".to_string(),
        ]);
        let model = response.to_idl_model(&request).unwrap();
        assert_eq!(
            model.response.transports,
            vec!["ble".to_string(), "nfc".to_string(), "usb".to_string()]
        );

        // A ceremony transport already in the reported list is not duplicated.
        response.transport = Some(Transport::Usb);
        response.authenticator_transports = Some(vec!["usb".to_string(), "nfc".to_string()]);
        let model = response.to_idl_model(&request).unwrap();
        assert_eq!(
            model.response.transports,
            vec!["nfc".to_string(), "usb".to_string()]
        );

        // No reported transports leaves just the ceremony transport.
        response.authenticator_transports = None;
        let model = response.to_idl_model(&request).unwrap();
        assert_eq!(model.response.transports, vec!["usb".to_string()]);

        // Unknown tokens pass through, folded with the ceremony transport.
        response.transport = Some(Transport::Ble);
        response.authenticator_transports =
            Some(vec!["smart-card".to_string(), "custom".to_string()]);
        let model = response.to_idl_model(&request).unwrap();
        assert_eq!(
            model.response.transports,
            vec![
                "ble".to_string(),
                "custom".to_string(),
                "smart-card".to_string()
            ]
        );
    }

    #[test]
    fn test_response_emits_spki_for_es256() {
        // The test fixture builds an ES256 P-256 credential, so getPublicKey()
        // must return DER-encoded SubjectPublicKeyInfo per WebAuthn L3 §5.2.1.1.
        // The SPKI for ES256 starts with the SEQUENCE / SEQUENCE / OID prefix
        // 30 59 30 13 06 07 2A 86 48 CE 3D 02 01 (id-ecPublicKey), followed
        // by the secp256r1 OID and the uncompressed point.
        let response = create_test_response();
        let request = create_test_request();
        let model = response.to_idl_model(&request).unwrap();

        let public_key_bytes = model
            .response
            .public_key
            .expect("ES256 must produce SPKI")
            .0;
        assert_eq!(public_key_bytes.len(), 91, "ES256 SPKI is 91 bytes");
        // SEQUENCE tag + length, then nested SEQUENCE for AlgorithmIdentifier.
        assert_eq!(&public_key_bytes[..2], &[0x30, 0x59]);
        // id-ecPublicKey OID: 1.2.840.10045.2.1
        let id_ec_public_key = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        assert!(
            public_key_bytes
                .windows(id_ec_public_key.len())
                .any(|w| w == id_ec_public_key),
            "SPKI must contain id-ecPublicKey OID"
        );
    }

    #[test]
    fn test_response_attestation_object_format() {
        let response = create_test_response();
        let request = create_test_request();
        let model = response.to_idl_model(&request).unwrap();

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

    fn create_attested_response(aaguid: [u8; 16]) -> MakeCredentialResponse {
        use crate::fido::{AttestedCredentialData, AuthenticatorData, AuthenticatorDataFlags};
        use crate::proto::ctap2::FidoU2fAttestationStmt;
        use cosey::Bytes;
        use serde_bytes::ByteBuf;

        let cose_public_key = cosey::PublicKey::P256Key(cosey::P256PublicKey {
            x: Bytes::from_slice(&[0u8; 32]).unwrap(),
            y: Bytes::from_slice(&[0u8; 32]).unwrap(),
        });
        let credential_public_key = cbor::to_vec(&cose_public_key).unwrap();

        let authenticator_data = AuthenticatorData {
            rp_id_hash: [0u8; 32],
            flags: AuthenticatorDataFlags::USER_PRESENT
                | AuthenticatorDataFlags::ATTESTED_CREDENTIALS,
            signature_count: 0,
            attested_credential: Some(AttestedCredentialData {
                aaguid,
                credential_id: vec![0x01, 0x02, 0x03, 0x04],
                credential_public_key,
            }),
            extensions: None,
            raw: None,
        };

        MakeCredentialResponse {
            format: "fido-u2f".to_string(),
            authenticator_data,
            attestation_statement: Ctap2AttestationStatement::FidoU2F(FidoU2fAttestationStmt {
                signature: ByteBuf::from(vec![0xAA; 16]),
                certificates: vec![ByteBuf::from(vec![0xBB; 8])],
            }),
            enterprise_attestation: None,
            large_blob_key: None,
            unsigned_extensions_output: MakeCredentialsResponseUnsignedExtensions::default(),
            transport: None,
            authenticator_transports: None,
        }
    }

    #[test]
    fn attestation_none_conveyance_scrubs_fmt_attstmt_and_aaguid() {
        let response = create_attested_response([0x11u8; 16]);
        let mut request = create_test_request();
        request.attestation = Some("none".to_string());

        let model = response.to_idl_model(&request).unwrap();

        let auth_data = &model.response.authenticator_data.0;
        assert_eq!(&auth_data[37..53], &[0u8; 16], "top-level authData AAGUID");

        let attestation: cbor::Value =
            cbor::from_slice(&model.response.attestation_object.0).unwrap();
        let cbor::Value::Map(map) = attestation else {
            panic!("attestation object should be a CBOR map");
        };
        let value_for = |key: &str| {
            map.iter()
                .find(|(k, _)| matches!(k, cbor::Value::Text(s) if s == key))
                .map(|(_, v)| v)
        };
        assert!(
            matches!(value_for("fmt"), Some(cbor::Value::Text(s)) if s == "none"),
            "fmt must be scrubbed to none"
        );
        match value_for("attStmt") {
            Some(cbor::Value::Map(stmt)) => assert!(stmt.is_empty(), "attStmt must be empty"),
            other => panic!("attStmt must be an empty map, got {other:?}"),
        }
        match value_for("authData") {
            Some(cbor::Value::Bytes(embedded)) => {
                assert_eq!(&embedded[37..53], &[0u8; 16], "embedded authData AAGUID");
            }
            other => panic!("authData must be CBOR bytes, got {other:?}"),
        }
    }

    #[test]
    fn attestation_direct_preserves_attestation() {
        let response = create_attested_response([0x11u8; 16]);
        let mut request = create_test_request();
        request.attestation = Some("direct".to_string());

        let model = response.to_idl_model(&request).unwrap();

        let auth_data = &model.response.authenticator_data.0;
        assert_eq!(
            &auth_data[37..53],
            &[0x11u8; 16],
            "AAGUID must be preserved"
        );

        let attestation: cbor::Value =
            cbor::from_slice(&model.response.attestation_object.0).unwrap();
        let cbor::Value::Map(map) = attestation else {
            panic!("attestation object should be a CBOR map");
        };
        let fmt = map
            .iter()
            .find(|(k, _)| matches!(k, cbor::Value::Text(s) if s == "fmt"))
            .map(|(_, v)| v);
        assert!(
            matches!(fmt, Some(cbor::Value::Text(s)) if s == "fido-u2f"),
            "fmt must be preserved"
        );
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
                results: None,
            }),
        };

        let request = create_test_request();
        let model = response.to_idl_model(&request).unwrap();

        // Verify cred_props extension
        let cred_props = model.client_extension_results.cred_props.as_ref().unwrap();
        assert_eq!(cred_props.rk, Some(true));

        // Verify hmac_create_secret extension
        assert_eq!(
            model.client_extension_results.hmac_create_secret,
            Some(true)
        );

        // Verify PRF extension - on registration, only 'enabled' is set, not 'results'
        let prf = model.client_extension_results.prf.as_ref().unwrap();
        assert_eq!(prf.enabled, Some(true));
        assert!(prf.results.is_none()); // results only returned on authentication
    }
}
