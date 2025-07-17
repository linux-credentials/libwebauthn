use super::{
    Ctap2AttestationStatement, Ctap2AuthTokenPermissionRole, Ctap2CredentialType,
    Ctap2GetInfoResponse, Ctap2PinUvAuthProtocol, Ctap2PublicKeyCredentialDescriptor,
    Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialUserEntity,
    Ctap2UserVerifiableRequest,
};
use crate::{
    fido::AuthenticatorData,
    ops::webauthn::{
        CredentialProtectionPolicy, DiscoverableCredentialRequirement,
        MakeCredentialHmacOrPrfInput, MakeCredentialLargeBlobExtension, MakeCredentialRequest,
        MakeCredentialResponse, MakeCredentialsRequestExtensions,
        MakeCredentialsResponseUnsignedExtensions,
    },
    pin::PinUvAuthProtocol,
    proto::CtapError,
    webauthn::Error,
};
use ctap_types::ctap2::credential_management::CredentialProtectionPolicy as Ctap2CredentialProtectionPolicy;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use tracing::warn;

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
pub struct Ctap2MakeCredentialRequest {
    /// clientDataHash (0x01)
    #[serde(index = 0x01)]
    pub hash: ByteBuf,

    /// rp (0x02)
    #[serde(index = 0x02)]
    pub relying_party: Ctap2PublicKeyCredentialRpEntity,

    /// user (0x03)
    #[serde(index = 0x03)]
    pub user: Ctap2PublicKeyCredentialUserEntity,

    /// pubKeyCredParams (0x04)
    #[serde(index = 0x04)]
    pub algorithms: Vec<Ctap2CredentialType>,

    /// excludeList (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05)]
    pub exclude: Option<Vec<Ctap2PublicKeyCredentialDescriptor>>,

    /// extensions (0x06)
    #[serde(skip_serializing_if = "Self::skip_serializing_extensions")]
    #[serde(index = 0x06)]
    pub extensions: Option<Ctap2MakeCredentialsRequestExtensions>,

    /// options (0x07)
    #[serde(skip_serializing_if = "Self::skip_serializing_options")]
    #[serde(index = 0x07)]
    pub options: Option<Ctap2MakeCredentialOptions>,

    /// pinUvAuthParam (0x08)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x08)]
    pub pin_auth_param: Option<ByteBuf>,

    /// pinUvAuthProtocol (0x09)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x09)]
    pub pin_auth_proto: Option<u32>,

    /// enterpriseAttestation (0x0A)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x0A)]
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
        let extensions = match &req.extensions {
            Some(ext) => {
                Some(Ctap2MakeCredentialsRequestExtensions::from_webauthn_request(ext, info)?)
            }
            None => None,
        };

        // Discoverable credential / resident key requirements
        let require_resident_key = match req.discoverable_credential {
            Some(DiscoverableCredentialRequirement::Discouraged) => Some(false),
            Some(DiscoverableCredentialRequirement::Preferred) => {
                if info.option_enabled("rk") {
                    Some(true)
                } else {
                    // The device does not support rk, so we try to not even mention it in the
                    // final request, to avoid the possibility of weird devices failing.
                    // If they don't support it, the default will not be to create a discoverable
                    // credential.
                    None
                }
            }
            Some(DiscoverableCredentialRequirement::Required) => {
                if !info.option_enabled("rk") {
                    warn!("This request will potentially fail. Discoverable credential required, but device does not support it.");
                }
                // We still send the request to the device and let it sort it out.
                // We only add a warning for easier debugging.
                Some(true)
            }
            None => None,
        };

        Ok(Ctap2MakeCredentialRequest {
            hash: ByteBuf::from(req.hash.clone()),
            relying_party: req.relying_party.clone(),
            user: req.user.clone(),
            algorithms: req.algorithms.clone(),
            exclude: req.exclude.clone(),
            extensions,
            options: Some(Ctap2MakeCredentialOptions {
                require_resident_key,
                deprecated_require_user_verification: None,
            }),
            pin_auth_param: None,
            pin_auth_proto: None,
            enterprise_attestation: None,
        })
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

impl Ctap2MakeCredentialsRequestExtensions {
    fn from_webauthn_request(
        requested_extensions: &MakeCredentialsRequestExtensions,
        info: &Ctap2GetInfoResponse,
    ) -> Result<Self, Error> {
        // CredProtection
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#credProtectFeatureDetection
        // When enforceCredentialProtectionPolicy is true, and credentialProtectionPolicy's value
        // is either userVerificationOptionalWithCredentialIDList or userVerificationRequired,
        // the platform SHOULD NOT create the credential in a way that does not implement the
        // requested protection policy. (For example, by creating it on an authenticator that
        // does not support this extension.)
        if let Some(cred_protection) = requested_extensions.cred_protect.as_ref() {
            if cred_protection.enforce_policy
                && cred_protection.policy != CredentialProtectionPolicy::UserVerificationOptional
                && !info.is_uv_protected()
            {
                return Err(Error::Ctap(CtapError::UnsupportedExtension));
            }
        }

        // LargeBlob (NOTE: Not to be confused with LargeBlobKey. LargeBlob has "Preferred" as well)
        // https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions#largeblob
        //
        let large_blob_key = match requested_extensions.large_blob {
            MakeCredentialLargeBlobExtension::Required => {
                // "required": The credential will be created with an authenticator to store blobs. The create() call will fail if this is impossible.
                if !info.option_enabled("largeBlobs") {
                    warn!("This request will potentially fail. Large blob extension required, but device does not support it.");
                }
                // We still send the request to the device and let it sort it out.
                // We only add a warning for easier debugging.
                Some(true)
            }
            MakeCredentialLargeBlobExtension::Preferred => {
                if info.option_enabled("largeBlobs") {
                    Some(true)
                } else {
                    // The device does not support large blobs, so we try to not even mention it in the
                    // final request, to avoid the possibility of weird devices failing.
                    None
                }
            }
            MakeCredentialLargeBlobExtension::None => None,
        };

        // HMAC Secret
        let hmac_secret = match requested_extensions.hmac_or_prf {
            MakeCredentialHmacOrPrfInput::None => None,
            MakeCredentialHmacOrPrfInput::HmacGetSecret | MakeCredentialHmacOrPrfInput::Prf => {
                Some(true)
            }
        };

        Ok(Ctap2MakeCredentialsRequestExtensions {
            cred_blob: requested_extensions.cred_blob.clone(),
            hmac_secret,
            cred_protect: requested_extensions
                .cred_protect
                .as_ref()
                .map(|x| x.policy.clone().into()),
            large_blob_key,
            min_pin_length: requested_extensions.min_pin_length,
        })
    }
}

#[derive(Debug, Clone, DeserializeIndexed)]
pub struct Ctap2MakeCredentialResponse {
    #[serde(index = 0x01)]
    pub format: String,

    #[serde(index = 0x02)]
    pub authenticator_data: AuthenticatorData<Ctap2MakeCredentialsResponseExtensions>,

    #[serde(index = 0x03)]
    pub attestation_statement: Ctap2AttestationStatement,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub enterprise_attestation: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05)]
    pub large_blob_key: Option<ByteBuf>,
}

impl Ctap2MakeCredentialResponse {
    pub fn into_make_credential_output(
        self,
        request: &MakeCredentialRequest,
        info: Option<&Ctap2GetInfoResponse>,
    ) -> MakeCredentialResponse {
        let unsigned_extensions_output =
            MakeCredentialsResponseUnsignedExtensions::from_signed_extensions(
                &self.authenticator_data.extensions,
                request,
                info,
            );
        MakeCredentialResponse {
            format: self.format,
            authenticator_data: self.authenticator_data,
            attestation_statement: self.attestation_statement,
            enterprise_attestation: self.enterprise_attestation,
            large_blob_key: self.large_blob_key.map(|x| x.into_vec()),
            unsigned_extensions_output,
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
    // If storing credBlob was successful
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<Ctap2CredentialProtectionPolicy>,
    // Thanks, FIDO-spec for this consistent naming scheme...
    #[serde(
        rename = "hmac-secret",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret: Option<bool>,
    // Current min PIN lenght
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,
}
