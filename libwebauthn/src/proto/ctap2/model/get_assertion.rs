use crate::{
    fido::AuthenticatorData,
    ops::webauthn::{
        Assertion, Ctap2HMACGetSecretOutput, GetAssertionHmacOrPrfInput,
        GetAssertionLargeBlobExtension, GetAssertionLargeBlobExtensionOutput,
        GetAssertionPrfOutput, GetAssertionRequest, GetAssertionRequestExtensions,
        GetAssertionResponseUnsignedExtensions, HMACGetSecretInput, PRFValue,
    },
    pin::PinUvAuthProtocol,
    proto::ctap2::cbor::Value,
    transport::AuthTokenData,
    webauthn::{Error, PlatformError},
};

use super::{
    Ctap2AuthTokenPermissionRole, Ctap2COSEAlgorithmIdentifier, Ctap2GetInfoResponse,
    Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialUserEntity,
    Ctap2UserVerifiableRequest,
};
use cosey::PublicKey;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackedAttestationStmt {
    #[serde(rename = "alg")]
    pub algorithm: Ctap2COSEAlgorithmIdentifier,

    #[serde(rename = "sig")]
    pub signature: ByteBuf,

    #[serde(rename = "x5c", skip_serializing_if = "Vec::is_empty", default)]
    pub certificates: Vec<ByteBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FidoU2fAttestationStmt {
    #[serde(rename = "sig")]
    pub signature: ByteBuf,

    /// Certificate chain as an array (spec requires array even for single cert).
    #[serde(rename = "x5c")]
    pub certificates: Vec<ByteBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TpmAttestationStmt {
    #[serde(rename = "ver")]
    pub version: String,

    #[serde(rename = "alg")]
    pub algorithm: Ctap2COSEAlgorithmIdentifier,

    #[serde(rename = "sig")]
    pub signature: ByteBuf,

    #[serde(rename = "x5c", skip_serializing_if = "Vec::is_empty", default)]
    pub certificates: Vec<ByteBuf>,

    #[serde(rename = "certInfo")]
    pub certificate_info: ByteBuf,

    #[serde(rename = "pubArea")]
    pub public_area: ByteBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppleAnonymousAttestationStmt {
    #[serde(rename = "x5c", skip_serializing_if = "Vec::is_empty", default)]
    pub certificates: Vec<ByteBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
pub struct Ctap2GetAssertionRequest {
    /// rpId (0x01)
    #[serde(index = 0x01)]
    pub relying_party_id: String,

    /// clientDataHash (0x02)
    #[serde(index = 0x02)]
    pub client_data_hash: ByteBuf,

    /// allowList (0x03)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(index = 0x03)]
    pub allow: Vec<Ctap2PublicKeyCredentialDescriptor>,

    /// extensions (0x04)
    #[serde(skip_serializing_if = "Self::skip_serializing_extensions")]
    #[serde(index = 0x04)]
    pub extensions: Option<Ctap2GetAssertionRequestExtensions>,

    /// options (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05)]
    pub options: Option<Ctap2GetAssertionOptions>,

    /// pinUvAuthParam (0x06)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x06)]
    pub pin_auth_param: Option<ByteBuf>,

    /// pinUvAuthProtocol (0x07)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x07)]
    pub pin_auth_proto: Option<u32>,
}

impl Ctap2GetAssertionRequest {
    pub fn skip_serializing_extensions(
        extensions: &Option<Ctap2GetAssertionRequestExtensions>,
    ) -> bool {
        extensions
            .as_ref()
            .is_none_or(|extensions| extensions.skip_serializing())
    }

    pub(crate) fn from_webauthn_request(
        req: &GetAssertionRequest,
        info: &Ctap2GetInfoResponse,
    ) -> Result<Self, Error> {
        // Cloning it, so we can modify it
        let mut req = req.clone();
        // LargeBlob (NOTE: Not to be confused with LargeBlobKey)
        // https://w3c.github.io/webauthn/#sctn-large-blob-extension
        // If read is present and has the value true:
        // [..]
        // 3. If successful, set blob to the result.
        //
        // So we silently drop the extension if the device does not support it.
        if !info.option_enabled("largeBlobs") {
            if let Some(ref mut ext) = req.extensions {
                ext.large_blob = None;
            }
        }

        Ok(Ctap2GetAssertionRequest::from(req))
    }
}

impl From<GetAssertionRequest> for Ctap2GetAssertionRequest {
    fn from(op: GetAssertionRequest) -> Self {
        let client_data_hash = ByteBuf::from(op.client_data_hash());
        Self {
            relying_party_id: op.relying_party_id,
            client_data_hash,
            allow: op.allow,
            extensions: op.extensions.map(|ext| ext.into()),
            options: Some(Ctap2GetAssertionOptions {
                require_user_presence: true,
                require_user_verification: op.user_verification.is_required(),
            }),
            pin_auth_param: None,
            pin_auth_proto: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ctap2GetAssertionRequestExtensions {
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub cred_blob: bool,
    // Thanks, FIDO-spec for this consistent naming scheme...
    #[serde(rename = "hmac-secret", skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<CalculatedHMACGetSecretInput>,
    // From which we calculate hmac_secret
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<bool>,
    #[serde(skip)]
    pub(crate) hmac_or_prf: Option<GetAssertionHmacOrPrfInput>,
}

impl From<GetAssertionRequestExtensions> for Ctap2GetAssertionRequestExtensions {
    fn from(other: GetAssertionRequestExtensions) -> Self {
        Ctap2GetAssertionRequestExtensions {
            cred_blob: other.cred_blob,
            hmac_secret: None, // Gets calculated later
            hmac_or_prf: other.prf.map(GetAssertionHmacOrPrfInput::Prf),
            large_blob_key: if other.large_blob == Some(GetAssertionLargeBlobExtension::Read) {
                Some(true)
            } else {
                None
            },
        }
    }
}

impl Ctap2GetAssertionRequestExtensions {
    pub fn skip_serializing(&self) -> bool {
        !self.cred_blob
            && self.hmac_secret.is_none()
            && self.large_blob_key.is_none()
            && self.hmac_or_prf.is_none()
    }

    pub fn calculate_hmac(
        &mut self,
        allow_list: &[Ctap2PublicKeyCredentialDescriptor],
        auth_data: &AuthTokenData,
    ) -> Result<(), Error> {
        let input = match &self.hmac_or_prf {
            None => None,
            Some(GetAssertionHmacOrPrfInput::HmacGetSecret(hmac_get_secret_input)) => {
                Some(hmac_get_secret_input.clone())
            }
            Some(GetAssertionHmacOrPrfInput::Prf(prf_input)) => {
                Self::prf_to_hmac_input(&prf_input.eval, &prf_input.eval_by_credential, allow_list)?
            }
        };

        let input = match input {
            None => {
                // We haven't been provided with any usable HMAC input
                return Ok(());
            }
            Some(i) => i,
        };

        // CTAP2 HMAC extension calculation
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
            // TODO: This is a bit of a weird one. Normally, we would just skip HMACs that
            //       fail for whatever reason, so a Result<> was not necessary.
            //       But with the PRF-extension, the spec tells us explicitly to return
            //       certain DOMErrors, which are handled above by `return Err(..)`.
            //       In this stage, I think it's still ok to soft-error out. The result will
            //       lack the HMAC-results, and the repackaging from CTAP2 to webauthn can then
            //       error out accordingly.
            return Ok(());
        };

        let salt_auth = ByteBuf::from(uv_proto.authenticate(&auth_data.shared_secret, &salt_enc)?);

        self.hmac_secret = Some(CalculatedHMACGetSecretInput {
            public_key,
            salt_enc,
            salt_auth,
            pin_auth_proto: Some(auth_data.protocol_version as u32),
        });
        Ok(())
    }

    fn prf_to_hmac_input(
        eval: &Option<PRFValue>,
        eval_by_credential: &HashMap<String, PRFValue>,
        allow_list: &[Ctap2PublicKeyCredentialDescriptor],
    ) -> Result<Option<HMACGetSecretInput>, Error> {
        // https://w3c.github.io/webauthn/#prf
        //
        // 1. If evalByCredential is not empty but allowCredentials is empty, return a DOMException whose name is “NotSupportedError”.
        if !eval_by_credential.is_empty() && allow_list.is_empty() {
            return Err(Error::Platform(PlatformError::NotSupported));
        }

        // 4.0 Let ev be null, and try to find any applicable PRF input(s):
        let mut ev = None;
        for (enc_cred_id, prf_value) in eval_by_credential {
            // 2. If any key in evalByCredential is the empty string, or is not a valid base64url encoding, or does not equal the id of some element of allowCredentials after performing base64url decoding, then return a DOMException whose name is “SyntaxError”.
            if enc_cred_id.is_empty() {
                return Err(Error::Platform(PlatformError::SyntaxError));
            }
            let cred_id = base64_url::decode(enc_cred_id)
                .map_err(|_| Error::Platform(PlatformError::SyntaxError))?;

            // 4.1 If evalByCredential is present and contains an entry whose key is the base64url encoding of the credential ID that will be returned, let ev be the value of that entry.
            let found_cred_id = allow_list.iter().find(|x| x.id == cred_id);
            if found_cred_id.is_some() {
                ev = Some(prf_value);
                break;
            }
        }

        //  4.2 If ev is null and eval is present, then let ev be the value of eval.
        if ev.is_none() {
            ev = eval.as_ref();
        }

        // 5. If ev is not null:
        if let Some(ev) = ev {
            // SHA-256(UTF8Encode("WebAuthn PRF") || 0x00 || ev.first).
            let mut prefix = String::from("WebAuthn PRF").into_bytes();
            prefix.push(0x00);

            let mut input = HMACGetSecretInput::default();
            // 5.1 Let salt1 be the value of SHA-256(UTF8Encode("WebAuthn PRF") || 0x00 || ev.first).
            let mut salt1_input = prefix.clone();
            salt1_input.extend(ev.first);

            let mut hasher = Sha256::default();
            hasher.update(salt1_input);
            let salt1_hash = hasher.finalize().to_vec();
            input.salt1.copy_from_slice(&salt1_hash[..32]);

            // 5.2 If ev.second is present, let salt2 be the value of SHA-256(UTF8Encode("WebAuthn PRF") || 0x00 || ev.second).
            if let Some(second) = ev.second {
                let mut salt2_input = prefix.clone();
                salt2_input.extend(second);
                let mut hasher = Sha256::default();
                hasher.update(salt2_input);
                let salt2_hash = hasher.finalize().to_vec();
                let mut salt2 = [0u8; 32];
                salt2.copy_from_slice(&salt2_hash[..32]);
                input.salt2 = Some(salt2);
            };

            Ok(Some(input))
        } else {
            // We don't have a usable PRF, so we don't do any HMAC
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, SerializeIndexed)]
pub struct CalculatedHMACGetSecretInput {
    // keyAgreement(0x01): public key of platform key-agreement key.
    #[serde(index = 0x01)]
    pub public_key: PublicKey,
    // saltEnc(0x02): Encryption of the one or two salts
    #[serde(index = 0x02)]
    pub salt_enc: ByteBuf,
    // saltAuth(0x03): authenticate(shared secret, saltEnc)
    #[serde(index = 0x03)]
    pub salt_auth: ByteBuf,
    // pinUvAuthProtocol(0x04): (optional) as selected when getting the shared secret. CTAP2.1 platforms MUST include this parameter if the value of pinUvAuthProtocol is not 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub pin_auth_proto: Option<u32>,
}

#[derive(Debug, Clone, DeserializeIndexed)]
pub struct Ctap2GetAssertionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub credential_id: Option<Ctap2PublicKeyCredentialDescriptor>,

    #[serde(index = 0x02)]
    pub authenticator_data: AuthenticatorData<Ctap2GetAssertionResponseExtensions>,

    #[serde(index = 0x03)]
    pub signature: ByteBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub user: Option<Ctap2PublicKeyCredentialUserEntity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05)]
    pub credentials_count: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x06)]
    pub user_selected: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x07)]
    pub large_blob_key: Option<ByteBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x08)]
    pub enterprise_attestation: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x09)]
    pub attestation_statement: Option<Ctap2AttestationStatement>,
}

impl Ctap2UserVerifiableRequest for Ctap2GetAssertionRequest {
    fn ensure_uv_set(&mut self) {
        self.options = Some(Ctap2GetAssertionOptions {
            require_user_verification: true,
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
        Some(self.client_data_hash.as_slice())
    }

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        Ctap2AuthTokenPermissionRole::GET_ASSERTION
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

    fn needs_shared_secret(&self, get_info_response: &Ctap2GetInfoResponse) -> bool {
        let hmac_supported = get_info_response
            .extensions
            .as_ref()
            .map(|e| e.contains(&String::from("hmac-secret")))
            .unwrap_or_default();
        let hmac_requested = self
            .extensions
            .as_ref()
            .map(|e| e.hmac_or_prf.is_some())
            .unwrap_or_default();
        hmac_requested && hmac_supported
    }
}

impl Ctap2GetAssertionResponse {
    pub fn into_assertion_output(
        self,
        request: &GetAssertionRequest,
        auth_data: Option<&AuthTokenData>,
    ) -> Assertion {
        let unsigned_extensions_output = self
            .authenticator_data
            .extensions
            .as_ref()
            .map(|x| x.to_unsigned_extensions(request, &self, auth_data));
        // CTAP2 6.2.2: authenticators may omit credential ID when the allow list has one entry.
        // We always return it, for convenience.
        let credential_id = self.credential_id.or_else(|| {
            if request.allow.len() == 1 {
                Some(request.allow[0].clone())
            } else {
                None
            }
        });
        Assertion {
            credential_id,
            authenticator_data: self.authenticator_data,
            signature: self.signature.into_vec(),
            user: self.user,
            credentials_count: self.credentials_count,
            user_selected: self.user_selected,
            large_blob_key: self.large_blob_key.map(ByteBuf::into_vec),
            unsigned_extensions_output,
            enterprise_attestation: self.enterprise_attestation,
            attestation_statement: self.attestation_statement,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
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
    pub(crate) fn to_unsigned_extensions(
        &self,
        request: &GetAssertionRequest,
        _response: &Ctap2GetAssertionResponse,
        auth_data: Option<&AuthTokenData>,
    ) -> GetAssertionResponseUnsignedExtensions {
        let decrypted_hmac = self.hmac_secret.as_ref().and_then(|x| {
            if let Some(auth_data) = auth_data {
                let uv_proto = auth_data.protocol_version.create_protocol_object();
                x.decrypt_output(&auth_data.shared_secret, uv_proto.as_ref())
            } else {
                None
            }
        });

        let prf = decrypted_hmac.and_then(|decrypted| {
            // At WebAuthn level, we only support PRF (not raw HMAC).
            // The PRF input was converted to HMAC internally.
            request
                .extensions
                .as_ref()
                .and_then(|ext| ext.prf.as_ref())
                .map(|_| GetAssertionPrfOutput {
                    results: Some(PRFValue {
                        first: decrypted.output1,
                        second: decrypted.output2,
                    }),
                })
        });

        // `blob` stays `None` until `authenticatorLargeBlobs` is wired up; returning
        // the raw `largeBlobKey` here would disclose the per-credential AES key to
        // the RP instead of the decrypted blob payload.
        let large_blob = request
            .extensions
            .as_ref()
            .and_then(|ext| ext.large_blob.as_ref())
            .map(|_| GetAssertionLargeBlobExtensionOutput { blob: None });

        GetAssertionResponseUnsignedExtensions {
            hmac_get_secret: None,
            large_blob,
            prf,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fido::AuthenticatorDataFlags;
    use crate::proto::ctap2::Ctap2PublicKeyCredentialType;
    use std::time::Duration;

    fn make_credential(id: &[u8]) -> Ctap2PublicKeyCredentialDescriptor {
        Ctap2PublicKeyCredentialDescriptor {
            id: ByteBuf::from(id.to_vec()),
            r#type: Ctap2PublicKeyCredentialType::PublicKey,
            transports: None,
        }
    }

    fn make_response(
        credential_id: Option<Ctap2PublicKeyCredentialDescriptor>,
    ) -> Ctap2GetAssertionResponse {
        Ctap2GetAssertionResponse {
            credential_id,
            authenticator_data: AuthenticatorData {
                rp_id_hash: [0u8; 32],
                flags: AuthenticatorDataFlags::USER_PRESENT,
                signature_count: 0,
                attested_credential: None,
                extensions: None,
            },
            signature: ByteBuf::from(vec![0u8; 32]),
            user: None,
            credentials_count: None,
            user_selected: None,
            large_blob_key: None,
            enterprise_attestation: None,
            attestation_statement: None,
        }
    }

    fn make_request(allow: Vec<Ctap2PublicKeyCredentialDescriptor>) -> GetAssertionRequest {
        GetAssertionRequest {
            relying_party_id: "example.com".to_string(),
            challenge: vec![0u8; 32],
            origin: "https://example.com".to_string(),
            top_origin: None,
            allow,
            extensions: None,
            user_verification: Default::default(),
            timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn populates_credential_id_from_single_entry_allow_list() {
        let cred = make_credential(b"cred-1");
        let response = make_response(None);
        let request = make_request(vec![cred.clone()]);

        let assertion = response.into_assertion_output(&request, None);
        assert_eq!(assertion.credential_id, Some(cred));
    }

    #[test]
    fn preserves_existing_credential_id() {
        let existing = make_credential(b"existing");
        let allow_entry = make_credential(b"allow-entry");
        let response = make_response(Some(existing.clone()));
        let request = make_request(vec![allow_entry]);

        let assertion = response.into_assertion_output(&request, None);
        assert_eq!(assertion.credential_id, Some(existing));
    }

    #[test]
    fn none_with_multi_entry_allow_list() {
        let response = make_response(None);
        let request = make_request(vec![make_credential(b"a"), make_credential(b"b")]);

        let assertion = response.into_assertion_output(&request, None);
        assert_eq!(assertion.credential_id, None);
    }

    #[test]
    fn none_with_empty_allow_list() {
        let response = make_response(None);
        let request = make_request(vec![]);

        let assertion = response.into_assertion_output(&request, None);
        assert_eq!(assertion.credential_id, None);
    }

    #[test]
    fn large_blob_read_does_not_leak_key_into_webauthn_response() {
        let cred = make_credential(b"cred-1");
        let device_returned_key = vec![0xAAu8; 32];
        let mut response = make_response(Some(cred.clone()));
        response.large_blob_key = Some(ByteBuf::from(device_returned_key.clone()));
        response.authenticator_data.extensions = Some(Ctap2GetAssertionResponseExtensions {
            cred_blob: None,
            hmac_secret: None,
        });

        let mut request = make_request(vec![cred]);
        request.extensions = Some(GetAssertionRequestExtensions {
            cred_blob: false,
            prf: None,
            large_blob: Some(GetAssertionLargeBlobExtension::Read),
        });

        let assertion = response.into_assertion_output(&request, None);
        let large_blob = assertion
            .unsigned_extensions_output
            .expect("unsigned extensions present")
            .large_blob
            .expect("largeBlob extension output present");

        assert!(large_blob.blob.is_none());
        assert_eq!(
            assertion.large_blob_key.as_deref(),
            Some(&device_returned_key[..])
        );
    }
}
