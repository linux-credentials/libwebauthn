use super::{
    get_assertion::CalculatedHMACGetSecretInput, Ctap2AttestationStatement,
    Ctap2AuthTokenPermissionRole, Ctap2CredentialType, Ctap2GetInfoResponse,
    Ctap2PinUvAuthProtocol, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity, Ctap2UserVerifiableRequest,
};
use crate::{
    fido::AuthenticatorData,
    ops::webauthn::{
        CredentialProtectionPolicy, Ctap2HMACGetSecretOutput, MakeCredentialLargeBlobExtension,
        MakeCredentialRequest, MakeCredentialResponse, MakeCredentialsRequestExtensions,
        MakeCredentialsResponseUnsignedExtensions, PrfInputValue, ResidentKeyRequirement,
    },
    pin::PinUvAuthProtocol,
    proto::CtapError,
    transport::AuthTokenData,
    webauthn::{Error, PlatformError},
};
use ctap_types::ctap2::credential_management::CredentialProtectionPolicy as Ctap2CredentialProtectionPolicy;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use tracing::{error, warn};

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
        options.is_none_or(|options| options.skip_serializing())
    }

    pub fn skip_serializing_extensions(
        extensions: &Option<Ctap2MakeCredentialsRequestExtensions>,
    ) -> bool {
        extensions
            .as_ref()
            .is_none_or(|extensions| extensions.skip_serializing())
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
        let require_resident_key = match req.resident_key {
            Some(ResidentKeyRequirement::Discouraged) => Some(false),
            Some(ResidentKeyRequirement::Preferred) => {
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
            Some(ResidentKeyRequirement::Required) => {
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
            hash: ByteBuf::from(req.client_data_hash()),
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
    // CTAP 2.2 § 12.8
    #[serde(rename = "hmac-secret-mc", skip_serializing_if = "Option::is_none")]
    pub hmac_secret_mc: Option<CalculatedHMACGetSecretInput>,
    #[serde(skip)]
    pub(crate) prf_input: Option<PrfInputValue>,
}

impl Ctap2MakeCredentialsRequestExtensions {
    pub fn skip_serializing(&self) -> bool {
        self.cred_protect.is_none()
            && self.cred_blob.is_none()
            && self.large_blob_key.is_none()
            && self.min_pin_length.is_none()
            && self.hmac_secret.is_none()
            && self.hmac_secret_mc.is_none()
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
        let large_blob_key = match requested_extensions
            .large_blob
            .as_ref()
            .map(|info| info.support)
        {
            Some(MakeCredentialLargeBlobExtension::Required) => {
                // Required + unsupported must fail rather than silently degrade.
                if !info.option_enabled("largeBlobs") {
                    return Err(Error::Ctap(CtapError::UnsupportedExtension));
                }
                Some(true)
            }
            Some(MakeCredentialLargeBlobExtension::Preferred) => {
                if info.option_enabled("largeBlobs") {
                    Some(true)
                } else {
                    // The device does not support large blobs, so we try to not even mention it in the
                    // final request, to avoid the possibility of weird devices failing.
                    None
                }
            }
            _ => None,
        };

        let hmac_secret = if requested_extensions.hmac_create_secret == Some(true)
            || requested_extensions.prf.is_some()
        {
            Some(true)
        } else {
            None
        };

        let prf_input = requested_extensions
            .prf
            .as_ref()
            .and_then(|prf| prf.eval.clone())
            .filter(|_| {
                info.supports_extension("hmac-secret-mc") && info.supports_extension("hmac-secret")
            });

        Ok(Ctap2MakeCredentialsRequestExtensions {
            cred_blob: requested_extensions
                .cred_blob
                .as_ref()
                .map(|inner| inner.0.clone()),
            hmac_secret,
            hmac_secret_mc: None,
            prf_input,
            cred_protect: requested_extensions
                .cred_protect
                .as_ref()
                .map(|x| x.policy.clone().into()),
            large_blob_key,
            min_pin_length: requested_extensions.min_pin_length,
        })
    }

    /// Encrypts the buffered PRF input with the channel's shared secret; CTAP 2.2 § 12.8.
    pub fn calculate_hmac_secret_mc(&mut self, auth_data: &AuthTokenData) -> Result<(), Error> {
        let Some(prf_input) = self.prf_input.take() else {
            return Ok(());
        };
        debug_assert_eq!(self.hmac_secret, Some(true));
        let hmac_input = prf_input.to_hmac_secret_input();

        let uv_proto = auth_data.protocol_version.create_protocol_object();
        let mut salts = hmac_input.salt1.to_vec();
        if let Some(salt2) = hmac_input.salt2 {
            salts.extend(salt2);
        }
        let salt_enc = match uv_proto.encrypt(&auth_data.shared_secret, &salts) {
            Ok(bytes) => ByteBuf::from(bytes),
            Err(err) => {
                error!(
                    ?err,
                    "Failed to encrypt hmac-secret-mc salts; dropping extension"
                );
                return Ok(());
            }
        };
        let salt_auth = ByteBuf::from(uv_proto.authenticate(&auth_data.shared_secret, &salt_enc)?);

        self.hmac_secret_mc = Some(CalculatedHMACGetSecretInput {
            public_key: auth_data.key_agreement.clone(),
            salt_enc,
            salt_auth,
            pin_auth_proto: Some(auth_data.protocol_version as u32),
        });
        Ok(())
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
        auth_data: Option<&AuthTokenData>,
    ) -> MakeCredentialResponse {
        let unsigned_extensions_output =
            MakeCredentialsResponseUnsignedExtensions::from_signed_extensions(
                &self.authenticator_data.extensions,
                request,
                info,
                auth_data,
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
        uv_proto: &dyn PinUvAuthProtocol,
        uv_auth_token: &[u8],
    ) -> Result<(), Error> {
        let hash = self
            .client_data_hash()
            .ok_or(Error::Platform(PlatformError::InvalidDeviceResponse))?;
        let uv_auth_param = uv_proto.authenticate(uv_auth_token, hash)?;
        self.pin_auth_proto = Some(uv_proto.version() as u32);
        self.pin_auth_param = Some(ByteBuf::from(uv_auth_param));
        Ok(())
    }

    fn client_data_hash(&self) -> Option<&[u8]> {
        Some(self.hash.as_slice())
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

    fn needs_shared_secret(&self, get_info_response: &Ctap2GetInfoResponse) -> bool {
        let mc_supported = get_info_response.supports_extension("hmac-secret-mc")
            && get_info_response.supports_extension("hmac-secret");
        let mc_requested = self
            .extensions
            .as_ref()
            .is_some_and(|e| e.prf_input.is_some());
        mc_supported && mc_requested
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
    // CTAP 2.2 § 12.8
    #[serde(
        rename = "hmac-secret-mc",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret_mc: Option<Ctap2HMACGetSecretOutput>,
    // Current min PIN lenght
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::webauthn::MakeCredentialLargeBlobExtensionInput;
    use crate::ops::webauthn::{MakeCredentialPrfInput, MakeCredentialRequest};
    use std::collections::HashMap;
    use std::time::Duration;

    fn info_with_options(options: &[(&str, bool)]) -> Ctap2GetInfoResponse {
        let mut info = Ctap2GetInfoResponse::default();
        let mut map = HashMap::new();
        for (k, v) in options {
            map.insert((*k).to_string(), *v);
        }
        info.options = Some(map);
        info
    }

    #[test]
    fn ctap2_extensions_large_blob_required_unsupported_returns_unsupported_extension() {
        let info = info_with_options(&[("largeBlobs", false)]);
        let requested = MakeCredentialsRequestExtensions {
            large_blob: Some(MakeCredentialLargeBlobExtensionInput {
                support: MakeCredentialLargeBlobExtension::Required,
            }),
            ..MakeCredentialsRequestExtensions::default()
        };

        let result =
            Ctap2MakeCredentialsRequestExtensions::from_webauthn_request(&requested, &info);
        assert!(matches!(
            result,
            Err(Error::Ctap(CtapError::UnsupportedExtension))
        ));
    }

    #[test]
    fn ctap2_extensions_large_blob_required_option_absent_returns_unsupported_extension() {
        // No options at all (largeBlobs neither present nor enabled).
        let info = Ctap2GetInfoResponse::default();
        let requested = MakeCredentialsRequestExtensions {
            large_blob: Some(MakeCredentialLargeBlobExtensionInput {
                support: MakeCredentialLargeBlobExtension::Required,
            }),
            ..MakeCredentialsRequestExtensions::default()
        };

        let result =
            Ctap2MakeCredentialsRequestExtensions::from_webauthn_request(&requested, &info);
        assert!(matches!(
            result,
            Err(Error::Ctap(CtapError::UnsupportedExtension))
        ));
    }

    #[test]
    fn ctap2_extensions_large_blob_required_supported_returns_some_true() {
        let info = info_with_options(&[("largeBlobs", true)]);
        let requested = MakeCredentialsRequestExtensions {
            large_blob: Some(MakeCredentialLargeBlobExtensionInput {
                support: MakeCredentialLargeBlobExtension::Required,
            }),
            ..MakeCredentialsRequestExtensions::default()
        };

        let extensions =
            Ctap2MakeCredentialsRequestExtensions::from_webauthn_request(&requested, &info)
                .unwrap();
        assert_eq!(extensions.large_blob_key, Some(true));
    }

    #[test]
    fn ctap2_extensions_large_blob_preferred_unsupported_omits_request() {
        let info = info_with_options(&[("largeBlobs", false)]);
        let requested = MakeCredentialsRequestExtensions {
            large_blob: Some(MakeCredentialLargeBlobExtensionInput {
                support: MakeCredentialLargeBlobExtension::Preferred,
            }),
            ..MakeCredentialsRequestExtensions::default()
        };

        let extensions =
            Ctap2MakeCredentialsRequestExtensions::from_webauthn_request(&requested, &info)
                .unwrap();
        assert_eq!(extensions.large_blob_key, None);
    }

    fn info_with_extensions(exts: &[&str]) -> Ctap2GetInfoResponse {
        Ctap2GetInfoResponse {
            extensions: Some(exts.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        }
    }

    fn mc_request_with_prf(eval: Option<PrfInputValue>) -> MakeCredentialRequest {
        MakeCredentialRequest {
            challenge: vec![0u8; 32],
            origin: "https://example.org".into(),
            top_origin: None,
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(b"u", "u", "U"),
            resident_key: None,
            user_verification: Default::default(),
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: Some(MakeCredentialsRequestExtensions {
                prf: Some(MakeCredentialPrfInput { eval }),
                ..Default::default()
            }),
            timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn prf_with_mc_supported_buffers_prf_input_and_sets_hmac_secret() {
        let info = info_with_extensions(&["hmac-secret", "hmac-secret-mc"]);
        let req = mc_request_with_prf(Some(PrfInputValue {
            first: vec![3u8; 32],
            second: None,
        }));
        let ctap = Ctap2MakeCredentialRequest::from_webauthn_request(&req, &info).unwrap();
        let ext = ctap.extensions.unwrap();
        assert_eq!(ext.hmac_secret, Some(true));
        assert!(ext.prf_input.is_some());
        assert!(ext.hmac_secret_mc.is_none()); // not yet encrypted
    }

    #[test]
    fn prf_without_mc_support_only_sets_hmac_secret() {
        let info = info_with_extensions(&["hmac-secret"]);
        let req = mc_request_with_prf(Some(PrfInputValue {
            first: vec![3u8; 32],
            second: None,
        }));
        let ctap = Ctap2MakeCredentialRequest::from_webauthn_request(&req, &info).unwrap();
        let ext = ctap.extensions.unwrap();
        assert_eq!(ext.hmac_secret, Some(true));
        assert!(ext.prf_input.is_none());
        assert!(ext.hmac_secret_mc.is_none());
    }

    #[test]
    fn prf_without_eval_does_not_buffer_prf_input() {
        let info = info_with_extensions(&["hmac-secret", "hmac-secret-mc"]);
        let req = mc_request_with_prf(None);
        let ctap = Ctap2MakeCredentialRequest::from_webauthn_request(&req, &info).unwrap();
        let ext = ctap.extensions.unwrap();
        assert_eq!(ext.hmac_secret, Some(true));
        assert!(ext.prf_input.is_none());
    }

    #[test]
    fn needs_shared_secret_true_only_when_mc_advertised_and_buffered() {
        let info_mc = info_with_extensions(&["hmac-secret", "hmac-secret-mc"]);
        let info_no_mc = info_with_extensions(&["hmac-secret"]);

        let with = Ctap2MakeCredentialRequest::from_webauthn_request(
            &mc_request_with_prf(Some(PrfInputValue::default())),
            &info_mc,
        )
        .unwrap();
        assert!(with.needs_shared_secret(&info_mc));
        assert!(!with.needs_shared_secret(&info_no_mc));

        let without =
            Ctap2MakeCredentialRequest::from_webauthn_request(&mc_request_with_prf(None), &info_mc)
                .unwrap();
        assert!(!without.needs_shared_secret(&info_mc));
    }

    #[test]
    fn calculate_hmac_secret_mc_populates_wire_field_and_clears_buffer() {
        use crate::proto::ctap2::Ctap2UserVerificationOperation;
        use cosey::{Bytes, PublicKey};

        let info = info_with_extensions(&["hmac-secret", "hmac-secret-mc"]);
        let req = mc_request_with_prf(Some(PrfInputValue {
            first: vec![9u8; 32],
            second: None,
        }));
        let mut ctap = Ctap2MakeCredentialRequest::from_webauthn_request(&req, &info).unwrap();

        let pin_proto = Ctap2PinUvAuthProtocol::One;
        let auth = AuthTokenData::new(
            vec![0u8; 32],
            pin_proto,
            PublicKey::EcdhEsHkdf256Key(cosey::EcdhEsHkdf256PublicKey {
                x: Bytes::from_slice(&[1u8; 32]).unwrap(),
                y: Bytes::from_slice(&[2u8; 32]).unwrap(),
            }),
            Ctap2UserVerificationOperation::OnlyForSharedSecret,
        );

        let ext = ctap.extensions.as_mut().unwrap();
        ext.calculate_hmac_secret_mc(&auth).unwrap();
        assert!(ext.prf_input.is_none());
        let mc_in = ext.hmac_secret_mc.as_ref().expect("hmac_secret_mc set");
        assert_eq!(mc_in.pin_auth_proto, Some(pin_proto as u32));
        assert!(!mc_in.salt_enc.is_empty());
        assert!(!mc_in.salt_auth.is_empty());

        // Wire round-trip: both keys must appear in the extensions CBOR map.
        let bytes = crate::proto::ctap2::cbor::to_vec(&ext).unwrap();
        let parsed: std::collections::BTreeMap<String, serde_cbor_2::Value> =
            crate::proto::ctap2::cbor::from_slice(&bytes).unwrap();
        assert_eq!(
            parsed.get("hmac-secret"),
            Some(&serde_cbor_2::Value::Bool(true))
        );
        assert!(parsed.contains_key("hmac-secret-mc"));
    }

    #[test]
    fn calculate_hmac_secret_mc_pin_protocol_two() {
        use crate::proto::ctap2::Ctap2UserVerificationOperation;
        use cosey::{Bytes, PublicKey};

        let info = info_with_extensions(&["hmac-secret", "hmac-secret-mc"]);
        let mut ctap = Ctap2MakeCredentialRequest::from_webauthn_request(
            &mc_request_with_prf(Some(PrfInputValue {
                first: vec![0xAB; 32],
                second: Some(vec![0xCD; 32]),
            })),
            &info,
        )
        .unwrap();
        // Protocol 2 shared secret is 64 bytes: HMAC key || AES key.
        let auth = AuthTokenData::new(
            vec![0u8; 64],
            Ctap2PinUvAuthProtocol::Two,
            PublicKey::EcdhEsHkdf256Key(cosey::EcdhEsHkdf256PublicKey {
                x: Bytes::from_slice(&[1u8; 32]).unwrap(),
                y: Bytes::from_slice(&[2u8; 32]).unwrap(),
            }),
            Ctap2UserVerificationOperation::OnlyForSharedSecret,
        );
        let ext = ctap.extensions.as_mut().unwrap();
        ext.calculate_hmac_secret_mc(&auth).unwrap();
        let mc_in = ext.hmac_secret_mc.as_ref().unwrap();
        assert_eq!(
            mc_in.pin_auth_proto,
            Some(Ctap2PinUvAuthProtocol::Two as u32)
        );
        // 16-byte IV || AES-256-CBC(64 bytes of salts).
        assert_eq!(mc_in.salt_enc.len(), 16 + 64);
    }

    #[test]
    fn from_signed_extensions_decrypts_results_with_auth_data() {
        use crate::proto::ctap2::Ctap2UserVerificationOperation;
        use cosey::{Bytes, PublicKey};

        // Round-trip a known PRF input through encrypt(client) → decrypt(client),
        // simulating the authenticator returning encrypt(shared_secret, hmac_outputs).
        let prf_value = PrfInputValue {
            first: vec![1u8; 32],
            second: Some(vec![2u8; 32]),
        };
        let pin_proto = Ctap2PinUvAuthProtocol::One;
        let uv_proto = pin_proto.create_protocol_object();
        let shared_secret = vec![3u8; 32];
        let auth_data = AuthTokenData::new(
            shared_secret.clone(),
            pin_proto,
            PublicKey::EcdhEsHkdf256Key(cosey::EcdhEsHkdf256PublicKey {
                x: Bytes::from_slice(&[1u8; 32]).unwrap(),
                y: Bytes::from_slice(&[2u8; 32]).unwrap(),
            }),
            Ctap2UserVerificationOperation::OnlyForSharedSecret,
        );

        // Fake authenticator output: any 64 bytes encrypted with the shared secret.
        let fake_outputs = vec![0x42u8; 64];
        let encrypted = uv_proto.encrypt(&shared_secret, &fake_outputs).unwrap();
        let signed = Ctap2MakeCredentialsResponseExtensions {
            hmac_secret: Some(true),
            hmac_secret_mc: Some(Ctap2HMACGetSecretOutput {
                encrypted_output: encrypted,
            }),
            ..Default::default()
        };
        let req = mc_request_with_prf(Some(prf_value));

        let out = MakeCredentialsResponseUnsignedExtensions::from_signed_extensions(
            &Some(signed),
            &req,
            None,
            Some(&auth_data),
        );
        let prf = out.prf.expect("prf present");
        assert_eq!(prf.enabled, Some(true));
        let results = prf.results.expect("results populated");
        assert_eq!(results.first, [0x42; 32]);
        assert_eq!(results.second, Some([0x42; 32]));
    }

    #[test]
    fn response_extensions_decode_hmac_secret_mc_key() {
        use std::collections::BTreeMap;
        let mut map: BTreeMap<&str, serde_cbor_2::Value> = BTreeMap::new();
        map.insert("hmac-secret", serde_cbor_2::Value::Bool(true));
        map.insert("hmac-secret-mc", serde_cbor_2::Value::Bytes(vec![0xAA; 32]));
        let bytes = crate::proto::ctap2::cbor::to_vec(&map).unwrap();
        let parsed: Ctap2MakeCredentialsResponseExtensions =
            crate::proto::ctap2::cbor::from_slice(&bytes).unwrap();
        assert_eq!(parsed.hmac_secret, Some(true));
        assert!(parsed.hmac_secret_mc.is_some());
    }
}
