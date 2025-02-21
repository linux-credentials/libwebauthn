use crate::{
    fido::AuthenticatorData,
    ops::webauthn::{
        Assertion, Ctap2HMACGetSecretOutput, GetAssertionRequest, GetAssertionRequestExtensions,
        GetAssertionResponseExtensions, HMACGetSecretInput,
    },
    pin::PinUvAuthProtocol,
    transport::AuthTokenData,
};

use super::{
    Ctap2AuthTokenPermissionRole, Ctap2COSEAlgorithmIdentifier, Ctap2GetInfoResponse,
    Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialUserEntity,
    Ctap2UserVerifiableRequest,
};
use cosey::PublicKey;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_cbor::Value;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use std::collections::BTreeMap;
use tracing::error;

#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct Ctap2GetAssertionOptions {
    #[serde(rename = "up")]
    /// True for all requests; False for pre-flight only.
    pub require_user_presence: bool,

    #[serde(rename = "uv")]
    #[serde(skip_serializing_if = "Self::skip_serializing_uv")]
    pub require_user_verification: bool,
}

impl Ctap2GetAssertionOptions {
    fn skip_serializing_uv(uv: &bool) -> bool {
        !uv
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackedAttestationStmt {
    #[serde(rename = "alg")]
    pub algorithm: Ctap2COSEAlgorithmIdentifier,

    #[serde(rename = "sig")]
    pub signature: ByteBuf,

    #[serde(rename = "x5c")]
    pub certificates: Vec<ByteBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FidoU2fAttestationStmt {
    #[serde(rename = "alg")]
    pub algorithm: Ctap2COSEAlgorithmIdentifier,

    #[serde(rename = "sig")]
    pub signature: ByteBuf,

    #[serde(rename = "x5c")]
    pub certificates: Vec<ByteBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpmAttestationStmt {
    #[serde(rename = "ver")]
    pub version: String,

    #[serde(rename = "alg")]
    pub algorithm: Ctap2COSEAlgorithmIdentifier,

    #[serde(rename = "sig")]
    pub signature: ByteBuf,

    #[serde(rename = "x5c")]
    pub certificates: Vec<ByteBuf>,

    #[serde(rename = "certInfo")]
    pub certificate_info: ByteBuf,

    #[serde(rename = "pubArea")]
    pub public_area: ByteBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppleAnonymousAttestationStmt {
    #[serde(rename = "x5c")]
    pub certificates: Vec<ByteBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Ctap2AttestationStatement {
    PackedOrAndroid(PackedAttestationStmt),
    Tpm(TpmAttestationStmt),
    FidoU2F(FidoU2fAttestationStmt),
    AppleAnonymous(AppleAnonymousAttestationStmt),
    None(BTreeMap<Value, Value>),
}

// https://www.w3.org/TR/webauthn/#op-get-assertion
#[derive(Debug, Clone, SerializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2GetAssertionRequest {
    /// rpId (0x01)
    pub relying_party_id: String,

    /// clientDataHash (0x02)
    pub client_data_hash: ByteBuf,

    /// allowList (0x03)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Ctap2PublicKeyCredentialDescriptor>,

    /// extensions (0x04)
    #[serde(skip_serializing_if = "Self::skip_serializing_extensions")]
    pub extensions: Option<Ctap2GetAssertionRequestExtensions>,

    /// options (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Ctap2GetAssertionOptions>,

    /// pinUvAuthParam (0x06)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_param: Option<ByteBuf>,

    /// pinUvAuthProtocol (0x07)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_proto: Option<u32>,
}

impl Ctap2GetAssertionRequest {
    pub fn skip_serializing_extensions(
        extensions: &Option<Ctap2GetAssertionRequestExtensions>,
    ) -> bool {
        extensions
            .as_ref()
            .map_or(true, |extensions| extensions.skip_serializing())
    }
}

impl From<&GetAssertionRequest> for Ctap2GetAssertionRequest {
    fn from(op: &GetAssertionRequest) -> Self {
        Self {
            relying_party_id: op.relying_party_id.clone(),
            client_data_hash: ByteBuf::from(op.hash.clone()),
            allow: op.allow.clone(),
            extensions: op.extensions.as_ref().map(|x| x.clone().into()),
            options: Some(Ctap2GetAssertionOptions {
                require_user_presence: true,
                require_user_verification: op.user_verification.is_required(),
            }),
            pin_auth_param: None,
            pin_auth_proto: None,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ctap2GetAssertionRequestExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<bool>,
    // Thanks, FIDO-spec for this consistent naming scheme...
    #[serde(rename = "hmac-secret", skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<CalculatedHMACGetSecretInput>,
    // From which we calculate hmac_secret
    #[serde(skip)]
    pub hmac_salts: Option<HMACGetSecretInput>,
}

impl From<GetAssertionRequestExtensions> for Ctap2GetAssertionRequestExtensions {
    fn from(other: GetAssertionRequestExtensions) -> Self {
        Ctap2GetAssertionRequestExtensions {
            cred_blob: other.cred_blob,
            hmac_secret: None, // Get's calculated later
            hmac_salts: other.hmac_secret,
        }
    }
}

impl Ctap2GetAssertionRequestExtensions {
    pub fn skip_serializing(&self) -> bool {
        self.cred_blob.is_none() && self.hmac_secret.is_none()
    }

    pub fn calculate_hmac(&mut self, auth_data: &AuthTokenData) {
        let input = if let Some(hmac_input) = &self.hmac_salts {
            hmac_input
        } else {
            return;
        };
        let uv_proto = auth_data.protocol_version.create_protocol_object();

        let public_key = auth_data.key_agreement.clone();
        // saltEnc(0x02): Encryption of the one or two salts (called salt1 (32 bytes) and salt2 (32 bytes)) using the shared secret as follows:
        //     One salt case: encrypt(shared secret, salt1)
        //     Two salt case: encrypt(shared secret, salt1 || salt2)
        let mut salts = input.salt1.to_vec();
        if let Some(salt2) = input.salt2 {
            salts.extend(salt2);
        }
        let salt_enc = if let Ok(res) = uv_proto.encrypt(&auth_data.shared_secret, &salts) {
            ByteBuf::from(res)
        } else {
            error!("Failed to encrypt HMAC salts with shared secret! Skipping HMAC");
            return;
        };

        let salt_auth = ByteBuf::from(uv_proto.authenticate(&auth_data.shared_secret, &salt_enc));

        self.hmac_secret = Some(CalculatedHMACGetSecretInput {
            public_key,
            salt_enc,
            salt_auth,
            pin_auth_proto: Some(auth_data.protocol_version as u32),
        })
    }
}

#[derive(Debug, Clone, SerializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct CalculatedHMACGetSecretInput {
    // keyAgreement(0x01): public key of platform key-agreement key.
    pub public_key: PublicKey,
    // saltEnc(0x02): Encryption of the one or two salts
    pub salt_enc: ByteBuf,
    // saltAuth(0x03): authenticate(shared secret, saltEnc)
    pub salt_auth: ByteBuf,
    // pinUvAuthProtocol(0x04): (optional) as selected when getting the shared secret. CTAP2.1 platforms MUST include this parameter if the value of pinUvAuthProtocol is not 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_proto: Option<u32>,
}

#[derive(Debug, Clone, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2GetAssertionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<Ctap2PublicKeyCredentialDescriptor>,

    pub authenticator_data: AuthenticatorData<Ctap2GetAssertionResponseExtensions>,

    pub signature: ByteBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<Ctap2PublicKeyCredentialUserEntity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials_count: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_selected: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<ByteBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_extension_outputs: Option<BTreeMap<Value, Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_attestation: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_statement: Option<Ctap2AttestationStatement>,
}

impl Ctap2UserVerifiableRequest for Ctap2GetAssertionRequest {
    fn ensure_uv_set(&mut self) {
        self.options = Some(Ctap2GetAssertionOptions {
            require_user_verification: true,
            ..self.options.unwrap_or(Ctap2GetAssertionOptions::default())
        });
    }

    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &Box<dyn PinUvAuthProtocol>,
        uv_auth_token: &[u8],
    ) {
        let uv_auth_param = uv_proto.authenticate(uv_auth_token, self.client_data_hash());
        self.pin_auth_proto = Some(uv_proto.version() as u32);
        self.pin_auth_param = Some(ByteBuf::from(uv_auth_param));
    }

    fn client_data_hash(&self) -> &[u8] {
        self.client_data_hash.as_slice()
    }

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        return Ctap2AuthTokenPermissionRole::GET_ASSERTION;
    }

    fn permissions_rpid(&self) -> Option<&str> {
        Some(&self.relying_party_id)
    }

    fn can_use_uv(&self, _info: &Ctap2GetInfoResponse) -> bool {
        true
    }

    fn handle_legacy_preview(&mut self, _info: &Ctap2GetInfoResponse) {
        // No-op
    }
}

impl Ctap2GetAssertionResponse {
    pub fn into_assertion_output(self, auth_data: Option<&AuthTokenData>) -> Assertion {
        let authenticator_data = AuthenticatorData::<GetAssertionResponseExtensions> {
            rp_id_hash: self.authenticator_data.rp_id_hash,
            flags: self.authenticator_data.flags,
            signature_count: self.authenticator_data.signature_count,
            attested_credential: self.authenticator_data.attested_credential,
            extensions: self
                .authenticator_data
                .extensions
                .map(|x| x.into_output(auth_data)),
        };
        Assertion {
            credential_id: self.credential_id,
            authenticator_data,
            signature: self.signature.into_vec(),
            user: self.user,
            credentials_count: self.credentials_count,
            user_selected: self.user_selected,
            large_blob_key: self.large_blob_key.map(ByteBuf::into_vec),
            unsigned_extension_outputs: self.unsigned_extension_outputs,
            enterprise_attestation: self.enterprise_attestation,
            attestation_statement: self.attestation_statement,
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ctap2GetAssertionResponseExtensions {
    // Stored credBlob
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub cred_blob: Option<Vec<u8>>,

    // Thanks, FIDO-spec for this consistent naming scheme...
    #[serde(
        rename = "hmac-secret",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret: Option<Ctap2HMACGetSecretOutput>,
}

impl Ctap2GetAssertionResponseExtensions {
    pub(crate) fn into_output(
        self,
        auth_data: Option<&AuthTokenData>,
    ) -> GetAssertionResponseExtensions {
        GetAssertionResponseExtensions {
            cred_blob: self.cred_blob,
            hmac_secret: self.hmac_secret.and_then(|x| {
                if let Some(auth_data) = auth_data {
                    let uv_proto = auth_data.protocol_version.create_protocol_object();
                    x.decrypt_output(&auth_data.shared_secret, &uv_proto)
                } else {
                    None
                }
            }),
        }
    }
}
