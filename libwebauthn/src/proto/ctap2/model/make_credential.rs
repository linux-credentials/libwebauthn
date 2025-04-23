use super::{
    Ctap2AttestationStatement, Ctap2AuthTokenPermissionRole, Ctap2CredentialType,
    Ctap2GetInfoResponse, Ctap2PinUvAuthProtocol, Ctap2PublicKeyCredentialDescriptor,
    Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialUserEntity,
    Ctap2UserVerifiableRequest,
};
use crate::{
    fido::AuthenticatorData,
    ops::webauthn::{
        CredentialProtectionPolicy, MakeCredentialHmacOrPrfInput, MakeCredentialHmacOrPrfOutput,
        MakeCredentialRequest, MakeCredentialResponse, MakeCredentialsRequestExtensions,
        MakeCredentialsResponseExtensions,
    },
    pin::PinUvAuthProtocol,
    proto::CtapError,
    transport::AuthTokenData,
    webauthn::Error,
};
use ctap_types::ctap2::credential_management::CredentialProtectionPolicy as Ctap2CredentialProtectionPolicy;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_cbor::Value;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Ctap2MakeCredentialOptions {
    #[serde(rename = "rk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,

    #[serde(rename = "uv")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated_require_user_verification: Option<bool>,
}

impl Ctap2MakeCredentialOptions {
    pub fn skip_serializing(&self) -> bool {
        self.require_resident_key.is_none() && self.deprecated_require_user_verification.is_none()
    }
}

// https://www.w3.org/TR/webauthn/#authenticatormakecredential
#[derive(Debug, Clone, SerializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2MakeCredentialRequest {
    /// clientDataHash (0x01)
    pub hash: ByteBuf,

    /// rp (0x02)
    pub relying_party: Ctap2PublicKeyCredentialRpEntity,

    /// user (0x03)
    pub user: Ctap2PublicKeyCredentialUserEntity,

    /// pubKeyCredParams (0x04)
    pub algorithms: Vec<Ctap2CredentialType>,

    /// excludeList (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<Ctap2PublicKeyCredentialDescriptor>>,

    /// extensions (0x06)
    #[serde(skip_serializing_if = "Self::skip_serializing_extensions")]
    pub extensions: Option<Ctap2MakeCredentialsRequestExtensions>,

    /// options (0x07)
    #[serde(skip_serializing_if = "Self::skip_serializing_options")]
    pub options: Option<Ctap2MakeCredentialOptions>,

    /// pinUvAuthParam (0x08)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_param: Option<ByteBuf>,

    /// pinUvAuthProtocol (0x09)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth_proto: Option<u32>,

    /// enterpriseAttestation (0x0A)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_attestation: Option<u32>,
}

impl Ctap2MakeCredentialRequest {
    /// Function that forces a touch
    /// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-makeCred-authnr-alg
    /// 1. If authenticator supports either pinUvAuthToken or clientPin features and the platform sends a zero length pinUvAuthParam:
    ///  1. Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    pub(crate) fn dummy() -> Self {
        Self {
            hash: ByteBuf::from(vec![0; 32]),
            relying_party: Ctap2PublicKeyCredentialRpEntity::dummy(),
            user: Ctap2PublicKeyCredentialUserEntity::dummy(),
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: None,
            options: None,
            pin_auth_param: Some(ByteBuf::from(Vec::new())),
            pin_auth_proto: Some(Ctap2PinUvAuthProtocol::One as u32),
            enterprise_attestation: None,
        }
    }

    pub fn skip_serializing_options(options: &Option<Ctap2MakeCredentialOptions>) -> bool {
        options.map_or(true, |options| options.skip_serializing())
    }

    pub fn skip_serializing_extensions(
        extensions: &Option<Ctap2MakeCredentialsRequestExtensions>,
    ) -> bool {
        extensions
            .as_ref()
            .map_or(true, |extensions| extensions.skip_serializing())
    }

    pub(crate) fn from_webauthn_request(
        req: &MakeCredentialRequest,
        info: &Ctap2GetInfoResponse,
    ) -> Result<Self, Error> {
        // Checking if extensions can be fulfilled
        //
        // CredProtection
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#credProtectFeatureDetection
        // When enforceCredentialProtectionPolicy is true, and credentialProtectionPolicy's value
        // is either userVerificationOptionalWithCredentialIDList or userVerificationRequired,
        // the platform SHOULD NOT create the credential in a way that does not implement the
        // requested protection policy. (For example, by creating it on an authenticator that
        // does not support this extension.)
        if let Some(cred_protection) = req
            .extensions
            .as_ref()
            .and_then(|x| x.cred_protect.as_ref())
        {
            if cred_protection.enforce_policy
                && cred_protection.policy != CredentialProtectionPolicy::UserVerificationOptional
                && !info.is_uv_protected()
            {
                return Err(Error::Ctap(CtapError::UnsupportedExtension));
            }
        }
        Ok(req.into())
    }
}

impl From<&MakeCredentialRequest> for Ctap2MakeCredentialRequest {
    fn from(op: &MakeCredentialRequest) -> Ctap2MakeCredentialRequest {
        Ctap2MakeCredentialRequest {
            hash: ByteBuf::from(op.hash.clone()),
            relying_party: op.relying_party.clone(),
            user: op.user.clone(),
            algorithms: op.algorithms.clone(),
            exclude: op.exclude.clone(),
            extensions: op.extensions.as_ref().map(|x| x.clone().into()),
            options: Some(Ctap2MakeCredentialOptions {
                require_resident_key: if op.require_resident_key {
                    Some(true)
                } else {
                    None
                },
                deprecated_require_user_verification: None,
            }),
            pin_auth_param: None,
            pin_auth_proto: None,
            enterprise_attestation: None,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ctap2MakeCredentialsRequestExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<Ctap2CredentialProtectionPolicy>,
    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub cred_blob: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,
    // Thanks, FIDO-spec for this consistent naming scheme...
    #[serde(rename = "hmac-secret", skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<bool>,
}

impl Ctap2MakeCredentialsRequestExtensions {
    pub fn skip_serializing(&self) -> bool {
        self.cred_protect.is_none()
            && self.cred_blob.is_none()
            && self.large_blob_key.is_none()
            && self.min_pin_length.is_none()
            && self.hmac_secret.is_none()
    }
}

impl From<MakeCredentialsRequestExtensions> for Ctap2MakeCredentialsRequestExtensions {
    fn from(other: MakeCredentialsRequestExtensions) -> Self {
        let hmac_secret = match other.hmac_or_prf {
            MakeCredentialHmacOrPrfInput::None => None,
            MakeCredentialHmacOrPrfInput::HmacGetSecret | MakeCredentialHmacOrPrfInput::Prf => {
                Some(true)
            }
        };
        Ctap2MakeCredentialsRequestExtensions {
            cred_blob: other.cred_blob,
            hmac_secret,
            cred_protect: other.cred_protect.map(|x| x.policy.into()),
            large_blob_key: other.large_blob_key,
            min_pin_length: other.min_pin_length,
        }
    }
}

#[derive(Debug, Clone, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2MakeCredentialResponse {
    pub format: String,
    pub authenticator_data: AuthenticatorData<Ctap2MakeCredentialsResponseExtensions>,
    pub attestation_statement: Ctap2AttestationStatement,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_attestation: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<ByteBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_extension_output: Option<BTreeMap<Value, Value>>,
}

impl Ctap2MakeCredentialResponse {
    pub fn into_make_credential_output(
        self,
        request: &MakeCredentialRequest,
        auth_data: Option<&AuthTokenData>,
    ) -> MakeCredentialResponse {
        let authenticator_data = AuthenticatorData::<MakeCredentialsResponseExtensions> {
            rp_id_hash: self.authenticator_data.rp_id_hash,
            flags: self.authenticator_data.flags,
            signature_count: self.authenticator_data.signature_count,
            attested_credential: self.authenticator_data.attested_credential,
            extensions: self
                .authenticator_data
                .extensions
                .map(|x| x.into_output(request, auth_data)),
        };
        MakeCredentialResponse {
            format: self.format,
            authenticator_data,
            attestation_statement: self.attestation_statement,
            enterprise_attestation: self.enterprise_attestation,
            large_blob_key: self.large_blob_key.map(|x| x.into_vec()),
            unsigned_extension_output: self.unsigned_extension_output,
        }
    }
}

impl Ctap2UserVerifiableRequest for Ctap2MakeCredentialRequest {
    fn ensure_uv_set(&mut self) {
        self.options = Some(Ctap2MakeCredentialOptions {
            deprecated_require_user_verification: Some(true),
            ..self.options.unwrap_or_default()
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
        self.hash.as_slice()
    }

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        // GET_ASSERTION needed for pre-flight requests
        Ctap2AuthTokenPermissionRole::MAKE_CREDENTIAL | Ctap2AuthTokenPermissionRole::GET_ASSERTION
    }

    fn permissions_rpid(&self) -> Option<&str> {
        Some(&self.relying_party.id)
    }

    fn can_use_uv(&self, _info: &Ctap2GetInfoResponse) -> bool {
        true
    }

    fn handle_legacy_preview(&mut self, _info: &Ctap2GetInfoResponse) {
        // No-op
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ctap2MakeCredentialsResponseExtensions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<Ctap2CredentialProtectionPolicy>,
    // If storing credBlob was successful
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<bool>,
    // No output provided for largeBlobKey in MakeCredential requests
    // pub large_blob_key: Option<bool>,

    // Current min PIN lenght
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,

    // Thanks, FIDO-spec for this consistent naming scheme...
    #[serde(
        rename = "hmac-secret",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret: Option<bool>,
}

impl Ctap2MakeCredentialsResponseExtensions {
    pub fn into_output(
        self,
        request: &MakeCredentialRequest,
        _auth_data: Option<&AuthTokenData>,
    ) -> MakeCredentialsResponseExtensions {
        let hmac_or_prf = if let Some(incoming_ext) = &request.extensions {
            match &incoming_ext.hmac_or_prf {
                MakeCredentialHmacOrPrfInput::None => MakeCredentialHmacOrPrfOutput::None,
                MakeCredentialHmacOrPrfInput::HmacGetSecret => {
                    MakeCredentialHmacOrPrfOutput::HmacGetSecret(
                        self.hmac_secret.unwrap_or_default(),
                    )
                }
                MakeCredentialHmacOrPrfInput::Prf => MakeCredentialHmacOrPrfOutput::Prf {
                    enabled: self.hmac_secret.unwrap_or_default(),
                },
            }
        } else {
            MakeCredentialHmacOrPrfOutput::None
        };
        MakeCredentialsResponseExtensions {
            cred_protect: self.cred_protect.map(|x| x.into()),
            cred_blob: self.cred_blob,
            min_pin_length: self.min_pin_length,
            hmac_or_prf,
        }
    }
}
