use std::time::Duration;

use ctap_types::ctap2::credential_management::CredentialProtectionPolicy as Ctap2CredentialProtectionPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, instrument, trace};

use crate::{
    fido::AuthenticatorData,
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
            (hmac_create_secret, prf) = if let Some(incoming_ext) = &request.extensions {
                match &incoming_ext.hmac_or_prf {
                    MakeCredentialHmacOrPrfInput::None => (None, None),
                    MakeCredentialHmacOrPrfInput::HmacGetSecret => {
                        (signed_extensions.hmac_secret, None)
                    }
                    MakeCredentialHmacOrPrfInput::Prf => (
                        None,
                        Some(MakeCredentialPrfOutput {
                            enabled: signed_extensions.hmac_secret,
                        }),
                    ),
                }
            } else {
                (None, None)
            };
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
                    Some(CredentialPropsExtension {
                        rk: Some(request.require_resident_key),
                    })
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
        let large_blob = match &request.extensions.as_ref().map(|x| &x.large_blob) {
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

#[derive(Debug, Default, Clone, Serialize)]
pub struct MakeCredentialPrfOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CredentialProtectionExtension {
    pub policy: CredentialProtectionPolicy,
    pub enforce_policy: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum CredentialProtectionPolicy {
    #[serde(rename = "userVerificationOptional")]
    UserVerificationOptional = 1,
    #[serde(rename = "userVerificationOptionalWithCredentialIDList")]
    UserVerificationOptionalWithCredentialIDList = 2,
    #[serde(rename = "userVerificationRequired")]
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

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MakeCredentialLargeBlobExtension {
    #[default]
    None,
    Preferred,
    Required,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct MakeCredentialLargeBlobExtensionOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
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
            require_resident_key: false,
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
