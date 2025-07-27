use super::idl::WebAuthnIDL;

use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error, trace};

use crate::{
    fido::AuthenticatorData,
    ops::webauthn::{
        create::PublicKeyCredentialCreationOptionsJSON,
        idl::{FromInnerModel, JsonError},
        rpid::RelyingPartyId,
    },
    pin::PinUvAuthProtocol,
    proto::ctap2::{
        Ctap2AttestationStatement, Ctap2GetAssertionResponseExtensions,
        Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialUserEntity,
    },
    webauthn::CtapError,
};

use super::{DowngradableRequest, SignRequest, UserVerificationRequirement};

#[derive(Debug, Default, Clone, Serialize)]
pub struct PRFValue {
    #[serde(with = "serde_bytes")]
    pub first: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub second: Option<[u8; 32]>,
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum GetAssertionLargeBlobExtension {
    #[default]
    None,
    Read,
    // Not yet supported
    // Write(Vec<u8>),
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct GetAssertionLargeBlobExtensionOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<Vec<u8>>,
    // Not yet supported
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub written: Option<bool>,
}

#[derive(Debug, Default, Clone)]
pub struct GetAssertionRequestExtensions {
    pub cred_blob: Option<bool>,
    pub hmac_or_prf: GetAssertionHmacOrPrfInput,
    pub large_blob: GetAssertionLargeBlobExtension,
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
