use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

use ctap_types::ctap2::credential_management::CredentialProtectionPolicy as Ctap2CredentialProtectionPolicy;
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use sha2::{Digest, Sha256};
use tracing::{debug, error, instrument, trace};

use crate::{
    fido::AuthenticatorData,
    pin::PinUvAuthProtocol,
    proto::{
        ctap1::{Ctap1RegisteredKey, Ctap1Version},
        ctap2::{
            Ctap2AttestationStatement, Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType,
            Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
            Ctap2PublicKeyCredentialUserEntity,
        },
    },
    webauthn::CtapError,
};

use super::u2f::{RegisterRequest, SignRequest};

#[derive(Debug, Clone, Copy)]
pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

impl UserVerificationRequirement {
    /// Check if user verification is preferred or required for this request
    pub fn is_preferred(&self) -> bool {
        match self {
            Self::Required | Self::Preferred => true,
            Self::Discouraged => false,
        }
    }

    /// Check if user verification is strictly required for this request
    pub fn is_required(&self) -> bool {
        match self {
            Self::Required => true,
            Self::Preferred | Self::Discouraged => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MakeCredentialResponse {
    pub format: String,
    pub authenticator_data: AuthenticatorData<MakeCredentialsResponseExtensions>,
    pub attestation_statement: Ctap2AttestationStatement,
    pub enterprise_attestation: Option<bool>,
    pub large_blob_key: Option<Vec<u8>>,
    pub unsigned_extension_output: Option<BTreeMap<Value, Value>>,
}

#[derive(Debug, Clone)]
pub struct MakeCredentialRequest {
    pub hash: Vec<u8>,
    pub origin: String,
    /// rpEntity
    pub relying_party: Ctap2PublicKeyCredentialRpEntity,
    /// userEntity
    pub user: Ctap2PublicKeyCredentialUserEntity,
    pub require_resident_key: bool,
    pub user_verification: UserVerificationRequirement,
    /// credTypesAndPubKeyAlgs
    pub algorithms: Vec<Ctap2CredentialType>,
    /// excludeCredentialDescriptorList
    pub exclude: Option<Vec<Ctap2PublicKeyCredentialDescriptor>>,
    /// extensions
    pub extensions: Option<MakeCredentialsRequestExtensions>,
    pub timeout: Duration,
}

#[derive(Debug, Default, Clone)]
pub struct PRFValue {
    pub first: [u8; 32],
    pub second: Option<[u8; 32]>,
}

#[derive(Debug, Default, Clone)]
pub enum MakeCredentialHmacOrPrfInput {
    #[default]
    None,
    HmacGetSecret,
    Prf,
    // The spec tells us that in theory, we could hand in
    // an `eval` here, IF the CTAP2 would get an additional
    // extension to handle that. There is no such CTAP-extension
    // right now, so we don't expose it for now, as it would just
    // be ignored anyways.
    // https://w3c.github.io/webauthn/#prf
    // "If eval is present and a future extension to [FIDO-CTAP] permits evaluation of the PRF at creation time, configure hmac-secret inputs accordingly: .."
    // Prf {
    //     eval: Option<PRFValue>,
    // },
}

#[derive(Debug, Default, Clone)]
pub enum MakeCredentialHmacOrPrfOutput {
    #[default]
    None,
    HmacGetSecret(bool),
    Prf {
        enabled: bool,
    },
}

#[derive(Debug, Clone)]
pub struct CredentialProtectionExtension {
    pub policy: CredentialProtectionPolicy,
    pub enforce_policy: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CredentialProtectionPolicy {
    UserVerificationOptional = 1,
    UserVerificationOptionalWithCredentialIdList = 2,
    UserVerificationRequired = 3,
}

impl From<CredentialProtectionPolicy> for Ctap2CredentialProtectionPolicy {
    fn from(value: CredentialProtectionPolicy) -> Self {
        match value {
            CredentialProtectionPolicy::UserVerificationOptional => {
                Ctap2CredentialProtectionPolicy::Optional
            }
            CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList => {
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
                CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList
            }
            Ctap2CredentialProtectionPolicy::Required => {
                CredentialProtectionPolicy::UserVerificationRequired
            }
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MakeCredentialLargeBlobExtension {
    #[default]
    None,
    Preferred,
    Required,
}

#[derive(Debug, Default, Clone)]
pub struct MakeCredentialsRequestExtensions {
    pub cred_props: Option<bool>,
    pub cred_protect: Option<CredentialProtectionExtension>,
    pub cred_blob: Option<Vec<u8>>,
    pub large_blob: MakeCredentialLargeBlobExtension,
    pub min_pin_length: Option<bool>,
    pub hmac_or_prf: MakeCredentialHmacOrPrfInput,
}

#[derive(Debug, Default, Clone)]
pub struct MakeCredentialsResponseExtensions {
    pub cred_protect: Option<CredentialProtectionPolicy>,
    /// If storing credBlob was successful
    pub cred_blob: Option<bool>,
    /// Current min PIN lenght
    pub min_pin_length: Option<u32>,
    pub hmac_or_prf: MakeCredentialHmacOrPrfOutput,
    // Currently, credProps only returns one value: rk = bool
    // If these get more in the future, we can use a struct here.
    pub cred_props_rk: Option<bool>,
}

impl MakeCredentialRequest {
    #[cfg(test)]
    pub fn dummy() -> Self {
        Self {
            hash: vec![0; 32],
            relying_party: Ctap2PublicKeyCredentialRpEntity::dummy(),
            user: Ctap2PublicKeyCredentialUserEntity::dummy(),
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: None,
            origin: "example.org".to_owned(),
            require_resident_key: false,
            user_verification: UserVerificationRequirement::Preferred,
            timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GetAssertionRequest {
    pub relying_party_id: String,
    pub hash: Vec<u8>,
    pub allow: Vec<Ctap2PublicKeyCredentialDescriptor>,
    pub extensions: Option<GetAssertionRequestExtensions>,
    pub user_verification: UserVerificationRequirement,
    pub timeout: Duration,
}

#[derive(Debug, Default, Clone)]
pub enum GetAssertionHmacOrPrfInput {
    #[default]
    None,
    HmacGetSecret(HMACGetSecretInput),
    Prf {
        eval: Option<PRFValue>,
        eval_by_credential: HashMap<String, PRFValue>,
    },
}

#[derive(Debug, Default, Clone)]
pub enum GetAssertionHmacOrPrfOutput {
    #[default]
    None,
    HmacGetSecret(HMACGetSecretOutput),
    Prf {
        enabled: bool,
        // The spec tells us this should be a Vec<PRFValue>, but doesn't
        // explain how it could hold more than 1 value
        result: PRFValue,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HMACGetSecretInput {
    pub salt1: [u8; 32],
    pub salt2: Option<[u8; 32]>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum GetAssertionLargeBlobExtension {
    #[default]
    None,
    Read,
    // Not yet supported
    // Write(Vec<u8>),
}

#[derive(Debug, Default, Clone)]
pub struct GetAssertionRequestExtensions {
    pub cred_blob: Option<bool>,
    pub hmac_or_prf: GetAssertionHmacOrPrfInput,
    pub large_blob: GetAssertionLargeBlobExtension,
}

#[derive(Clone, Debug, Default)]
pub struct HMACGetSecretOutput {
    pub output1: [u8; 32],
    pub output2: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(transparent)]
pub struct Ctap2HMACGetSecretOutput {
    // We get this from the device, but have to decrypt it, and
    // potentially split it into 2 arrays
    #[serde(with = "serde_bytes")]
    pub(crate) encrypted_output: Vec<u8>,
}

impl Ctap2HMACGetSecretOutput {
    pub(crate) fn decrypt_output(
        self,
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
            res.output1.copy_from_slice(&o1);
            res.output2 = Some(o2.try_into().unwrap());
        } else {
            error!("Failed to split HMAC Secret outputs. Unexpected output length: {}. Skipping HMAC extension", output.len());
            return None;
        }

        Some(res)
    }
}

#[derive(Debug, Default, Clone)]
pub struct GetAssertionResponseExtensions {
    // Stored credBlob
    pub cred_blob: Option<Vec<u8>>,
    pub hmac_or_prf: GetAssertionHmacOrPrfOutput,
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
    pub unsigned_extension_outputs: Option<BTreeMap<Value, Value>>,
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

pub trait DowngradableRequest<T> {
    fn is_downgradable(&self) -> bool;
    fn try_downgrade(&self) -> Result<T, CtapError>;
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
        if self.require_resident_key {
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
    use crate::ops::webauthn::{
        DowngradableRequest, MakeCredentialRequest, UserVerificationRequirement,
    };
    use crate::proto::ctap2::{
        Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialType,
    };

    #[test]
    fn ctap2_make_credential_downgradable() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::default()];
        request.require_resident_key = false;
        assert!(request.is_downgradable());
    }

    #[test]
    fn ctap2_make_credential_downgradable_unsupported_rk() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::default()];
        request.require_resident_key = true;
        assert!(!request.is_downgradable());
    }

    #[test]
    fn ctap2_make_credential_downgradable_unsupported_uv() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::default()];
        request.user_verification = UserVerificationRequirement::Required;
        assert!(!request.is_downgradable());
    }

    #[test]
    fn ctap2_make_credential_downgradable_unsupported_algorithm() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::new(
            Ctap2PublicKeyCredentialType::PublicKey,
            Ctap2COSEAlgorithmIdentifier::EDDSA,
        )];
        assert!(!request.is_downgradable());
    }
}
