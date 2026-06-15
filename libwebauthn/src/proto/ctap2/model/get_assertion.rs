use crate::{
    fido::AuthenticatorData,
    ops::webauthn::{
        Assertion, Ctap2HMACGetSecretOutput, GetAssertionHmacOrPrfInput,
        GetAssertionLargeBlobExtension, GetAssertionLargeBlobExtensionOutput,
        GetAssertionPrfOutput, GetAssertionRequest, GetAssertionRequestExtensions,
        GetAssertionResponseUnsignedExtensions, HMACGetSecretInput, PrfInputValue, PrfOutputValue,
    },
    pin::PinUvAuthProtocol,
    proto::ctap2::cbor::{map_to_json_object, Value},
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

        let mut ctap2_request = Ctap2GetAssertionRequest::from(req);
        if info.supports_extension("prf") {
            let Ctap2GetAssertionRequest {
                allow, extensions, ..
            } = &mut ctap2_request;
            if let Some(ext) = extensions.as_mut() {
                ext.convert_prf_to_native(allow)?;
            }
        }
        Ok(ctap2_request)
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
    // Field order is CTAP2 canonical CBOR map order: shortest key first, then bytewise.
    /// Native `prf` extension, used by phone/platform authenticators that advertise
    /// `prf` in getInfo instead of `hmac-secret` (e.g. over hybrid).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<Ctap2PrfGetAssertionInput>,
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
    /// Set when the WebAuthn `largeBlob` extension is `Write`/`Delete`. Drives the
    /// `lbw` bit in `permissions()` so the negotiated pinUvAuthToken can authorize
    /// `authenticatorLargeBlobs(set)` (CTAP 2.2 §6.10.2/§6.5.5.7.1).
    #[serde(skip)]
    pub(crate) large_blob_write: bool,
}

impl From<GetAssertionRequestExtensions> for Ctap2GetAssertionRequestExtensions {
    fn from(other: GetAssertionRequestExtensions) -> Self {
        let needs_key = matches!(
            other.large_blob,
            Some(GetAssertionLargeBlobExtension::Read)
                | Some(GetAssertionLargeBlobExtension::Write(_))
                | Some(GetAssertionLargeBlobExtension::Delete)
        );
        let is_write = matches!(
            other.large_blob,
            Some(GetAssertionLargeBlobExtension::Write(_))
                | Some(GetAssertionLargeBlobExtension::Delete)
        );
        Ctap2GetAssertionRequestExtensions {
            prf: None, // Set by convert_prf_to_native when the device advertises `prf`
            cred_blob: other.cred_blob,
            hmac_secret: None, // Gets calculated later
            hmac_or_prf: other.prf.map(GetAssertionHmacOrPrfInput::Prf),
            large_blob_key: if needs_key { Some(true) } else { None },
            large_blob_write: is_write,
        }
    }
}

impl Ctap2GetAssertionRequestExtensions {
    pub fn skip_serializing(&self) -> bool {
        self.prf.is_none()
            && !self.cred_blob
            && self.hmac_secret.is_none()
            && self.large_blob_key.is_none()
            && self.hmac_or_prf.is_none()
    }

    /// Rewrites the buffered PRF input as a native `prf` extension, bypassing the
    /// hmac-secret shared-secret envelope (the transport tunnel provides confidentiality).
    fn convert_prf_to_native(
        &mut self,
        allow_list: &[Ctap2PublicKeyCredentialDescriptor],
    ) -> Result<(), Error> {
        let Some(GetAssertionHmacOrPrfInput::Prf(prf_input)) = &self.hmac_or_prf else {
            return Ok(());
        };

        // Same WebAuthn L3 §10.1.4 client checks as prf_to_hmac_input below.
        if !prf_input.eval_by_credential.is_empty() && allow_list.is_empty() {
            return Err(Error::Platform(PlatformError::NotSupported));
        }

        let mut eval_by_credential = BTreeMap::new();
        for (enc_cred_id, value) in &prf_input.eval_by_credential {
            if enc_cred_id.is_empty() {
                return Err(Error::Platform(PlatformError::SyntaxError));
            }
            let cred_id = base64_url::decode(enc_cred_id)
                .map_err(|_| Error::Platform(PlatformError::SyntaxError))?;
            // Entries not matching the allow list are skipped, mirroring prf_to_hmac_input.
            if allow_list.iter().any(|cred| cred.id == cred_id) {
                eval_by_credential.insert(ByteBuf::from(cred_id), Ctap2PrfSalts::from(value));
            }
        }

        let eval = prf_input.eval.as_ref().map(Ctap2PrfSalts::from);
        // No usable input: send nothing, like the hmac path (L3 §10.1.4 step 5).
        if eval.is_some() || !eval_by_credential.is_empty() {
            self.prf = Some(Ctap2PrfGetAssertionInput {
                eval,
                eval_by_credential: if eval_by_credential.is_empty() {
                    None
                } else {
                    Some(eval_by_credential)
                },
            });
        }
        self.hmac_or_prf = None;
        Ok(())
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
            error!("Failed to encrypt HMAC salts");
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
        eval: &Option<PrfInputValue>,
        eval_by_credential: &HashMap<String, PrfInputValue>,
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

        // 5. If ev is not null, derive salt1/salt2 per WebAuthn L3.
        Ok(ev.map(PrfInputValue::to_hmac_secret_input))
    }
}

/// Hashed PRF salts (WebAuthn L3 §10.1.4) sent in the clear within the native
/// `prf` extension; no hmac-secret encryption envelope is applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ctap2PrfSalts {
    #[serde(with = "serde_bytes")]
    pub first: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub second: Option<[u8; 32]>,
}

impl From<&PrfInputValue> for Ctap2PrfSalts {
    fn from(value: &PrfInputValue) -> Self {
        let hashed = value.to_hmac_secret_input();
        Self {
            first: hashed.salt1,
            second: hashed.salt2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ctap2PrfGetAssertionInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eval: Option<Ctap2PrfSalts>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_canonical_byte_map"
    )]
    pub eval_by_credential: Option<BTreeMap<ByteBuf, Ctap2PrfSalts>>,
}

/// CTAP2 canonical CBOR map order for byte-string keys: shorter keys first,
/// then bytewise. `BTreeMap<ByteBuf, _>` alone gives plain lexicographic order.
fn serialize_canonical_byte_map<S>(
    map: &Option<BTreeMap<ByteBuf, Ctap2PrfSalts>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    let Some(map) = map else {
        // Unreachable behind skip_serializing_if, but stay total.
        return serializer.serialize_none();
    };
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
    let mut ser = serializer.serialize_map(Some(entries.len()))?;
    for (key, value) in entries {
        ser.serialize_entry(key, value)?;
    }
    ser.end()
}

/// `prf` entry of a response's unsignedExtensionOutputs map.
#[derive(Debug, Default)]
pub(crate) struct UnsignedPrfOutput {
    pub enabled: Option<bool>,
    pub results: Option<PrfOutputValue>,
}

pub(crate) fn parse_unsigned_prf(outputs: &BTreeMap<Value, Value>) -> Option<UnsignedPrfOutput> {
    let bytes32 = |value: Option<&Value>| -> Option<[u8; 32]> {
        match value {
            Some(Value::Bytes(bytes)) => bytes.as_slice().try_into().ok(),
            _ => None,
        }
    };
    let Some(Value::Map(prf)) = outputs.get(&Value::Text("prf".to_string())) else {
        return None;
    };
    let enabled = match prf.get(&Value::Text("enabled".to_string())) {
        Some(Value::Bool(enabled)) => Some(*enabled),
        _ => None,
    };
    let results = match prf.get(&Value::Text("results".to_string())) {
        Some(Value::Map(results)) => {
            let first = bytes32(results.get(&Value::Text("first".to_string())));
            let second = results.get(&Value::Text("second".to_string()));
            // Any malformed entry invalidates the whole results map.
            match (first, second) {
                (Some(first), None) => Some(PrfOutputValue {
                    first,
                    second: None,
                }),
                (Some(first), Some(second)) => bytes32(Some(second)).map(|second| PrfOutputValue {
                    first,
                    second: Some(second),
                }),
                (None, _) => None,
            }
        }
        _ => None,
    };
    Some(UnsignedPrfOutput { enabled, results })
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
    pub unsigned_extension_outputs: Option<BTreeMap<Value, Value>>,
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
        if let Some(ref mut options) = self.options {
            options.require_user_verification = false;
        }
        Ok(())
    }

    fn client_data_hash(&self) -> Option<&[u8]> {
        Some(self.client_data_hash.as_slice())
    }

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        let mut perms = Ctap2AuthTokenPermissionRole::GET_ASSERTION;
        if self.extensions.as_ref().is_some_and(|e| e.large_blob_write) {
            // CTAP 2.2 §6.10.2 requires the lbw bit on the token used for
            // authenticatorLargeBlobs(set). Negotiating it alongside ga avoids a
            // second PIN/UV ceremony for the chunked upload that follows.
            perms |= Ctap2AuthTokenPermissionRole::LARGE_BLOB_WRITE;
        }
        perms
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
        (hmac_requested && hmac_supported) || self.needs_pin_uv_auth_token(get_info_response)
    }

    fn needs_pin_uv_auth_token(&self, info: &Ctap2GetInfoResponse) -> bool {
        // largeBlob.write/delete needs a full token with the `lbw` permission
        // (CTAP 2.2 §6.10.2 line 113). Only require it when the device is
        // UV-protected; an unprotected authenticator accepts writes without
        // auth per spec line 137.
        self.extensions.as_ref().is_some_and(|e| e.large_blob_write)
            && info.option_enabled("largeBlobs")
            && info.is_uv_protected()
    }
}

impl Ctap2GetAssertionResponse {
    pub fn into_assertion_output(
        self,
        request: &GetAssertionRequest,
        auth_data: Option<&AuthTokenData>,
    ) -> Assertion {
        let mut unsigned_extensions_output = self
            .authenticator_data
            .extensions
            .as_ref()
            .map(|x| x.to_unsigned_extensions(request, auth_data));

        // unsignedExtensionOutputs (response 0x08) are independent of the signed
        // authenticator-data extensions, so surface them even when no signed
        // extensions are present. CTAP 2.2: an empty map equals an omitted field.
        if let Some(map) = &self.unsigned_extension_outputs {
            let mut object = map_to_json_object(map);
            // The typed prf field below is the canonical surface for this entry.
            object.remove("prf");
            if !object.is_empty() {
                unsigned_extensions_output
                    .get_or_insert_with(Default::default)
                    .unsigned_extension_outputs = object;
            }

            // Native `prf` path: results arrive here in plaintext, not inside the
            // signed extensions under an hmac-secret envelope.
            let prf_requested = request
                .extensions
                .as_ref()
                .is_some_and(|ext| ext.prf.is_some());
            if prf_requested {
                if let Some(results) = parse_unsigned_prf(map).and_then(|prf| prf.results) {
                    let unsigned = unsigned_extensions_output.get_or_insert_with(Default::default);
                    if unsigned.prf.is_none() {
                        unsigned.prf = Some(GetAssertionPrfOutput {
                            results: Some(results),
                        });
                    }
                }
            }
        }

        // CTAP2 6.2.2: authenticators may omit credential ID when the allow list has one entry.
        // We always return it, for convenience.
        let credential_id = self.credential_id.or_else(|| {
            if request.allow.len() == 1 {
                request.allow.first().cloned()
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
            unsigned_extensions_output,
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
                    results: Some(PrfOutputValue {
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
            .map(|_| GetAssertionLargeBlobExtensionOutput {
                blob: None,
                written: None,
            });

        // FIDO AppID extension: on the FIDO2 path the application parameter
        // is always derived from rp.id, so if the caller requested `appid`
        // we signal "not used" (Some(false)). When the extension was not
        // requested, we leave it None so it doesn't appear in the JSON output.
        let appid = request
            .extensions
            .as_ref()
            .and_then(|ext| ext.appid.as_ref())
            .map(|_| false);

        GetAssertionResponseUnsignedExtensions {
            hmac_get_secret: None,
            large_blob,
            prf,
            appid,
            unsigned_extension_outputs: Default::default(),
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
                raw: None,
            },
            signature: ByteBuf::from(vec![0u8; 32]),
            user: None,
            credentials_count: None,
            user_selected: None,
            large_blob_key: None,
            unsigned_extension_outputs: None,
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
            appid: None,
        });

        let assertion = response.into_assertion_output(&request, None);
        let large_blob = assertion
            .unsigned_extensions_output
            .expect("unsigned extensions present")
            .large_blob
            .expect("largeBlob extension output present");

        assert!(large_blob.blob.is_none());
    }

    fn info_with_extensions(exts: &[&str]) -> Ctap2GetInfoResponse {
        Ctap2GetInfoResponse {
            extensions: Some(exts.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        }
    }

    fn hashed_salt(input: &[u8]) -> [u8; 32] {
        PrfInputValue {
            first: input.to_vec(),
            second: None,
        }
        .to_hmac_secret_input()
        .salt1
    }

    fn prf_request(
        allow: Vec<Ctap2PublicKeyCredentialDescriptor>,
        eval: Option<PrfInputValue>,
        eval_by_credential: HashMap<String, PrfInputValue>,
    ) -> GetAssertionRequest {
        let mut request = make_request(allow);
        request.extensions = Some(GetAssertionRequestExtensions {
            cred_blob: false,
            prf: Some(crate::ops::webauthn::PrfInput {
                eval,
                eval_by_credential,
            }),
            large_blob: None,
            appid: None,
        });
        request
    }

    #[test]
    fn native_prf_used_when_getinfo_advertises_prf() {
        let cred = make_credential(b"cred-1");
        let mut by_cred = HashMap::new();
        by_cred.insert(
            base64_url::encode(b"cred-1"),
            PrfInputValue {
                first: b"by-cred-first".to_vec(),
                second: None,
            },
        );
        let request = prf_request(
            vec![cred],
            Some(PrfInputValue {
                first: b"eval-first".to_vec(),
                second: Some(b"eval-second".to_vec()),
            }),
            by_cred,
        );
        let info = info_with_extensions(&["prf"]);

        let ctap2 = Ctap2GetAssertionRequest::from_webauthn_request(&request, &info).unwrap();
        let ext = ctap2.extensions.as_ref().unwrap();
        assert!(ext.hmac_or_prf.is_none(), "buffered input must be consumed");
        assert!(!ctap2.needs_shared_secret(&info));
        let ext = ctap2.extensions.as_ref().unwrap();
        assert!(!ext.skip_serializing());
        let prf = ext.prf.as_ref().expect("native prf set");
        let eval = prf.eval.as_ref().expect("eval present");
        assert_eq!(eval.first, hashed_salt(b"eval-first"));
        assert_eq!(eval.second, Some(hashed_salt(b"eval-second")));
        let by_cred = prf.eval_by_credential.as_ref().expect("evalByCredential");
        let entry = by_cred
            .get(&ByteBuf::from(b"cred-1".to_vec()))
            .expect("keyed by raw credential id bytes");
        assert_eq!(entry.first, hashed_salt(b"by-cred-first"));
        assert_eq!(entry.second, None);

        // Wire format: {"prf": {"eval": {...}, "evalByCredential": {bytes: {...}}}}
        let bytes = crate::proto::ctap2::cbor::to_vec(&ext).unwrap();
        let parsed: Value = crate::proto::ctap2::cbor::from_slice(&bytes).unwrap();
        let Value::Map(map) = parsed else {
            panic!("extensions must serialize to a map")
        };
        assert_eq!(map.len(), 1, "only the prf entry must be serialized");
        let Some(Value::Map(prf_map)) = map.get(&Value::Text("prf".to_string())) else {
            panic!("prf entry missing")
        };
        let Some(Value::Map(eval_map)) = prf_map.get(&Value::Text("eval".to_string())) else {
            panic!("eval entry missing")
        };
        // Salts must encode as 32-byte CBOR byte strings.
        for key in ["first", "second"] {
            match eval_map.get(&Value::Text(key.to_string())) {
                Some(Value::Bytes(bytes)) => assert_eq!(bytes.len(), 32, "{key}"),
                other => panic!("{key} must be a byte string, got {other:?}"),
            }
        }
        let Some(Value::Map(by_cred_map)) =
            prf_map.get(&Value::Text("evalByCredential".to_string()))
        else {
            panic!("evalByCredential entry missing")
        };
        assert!(by_cred_map.contains_key(&Value::Bytes(b"cred-1".to_vec())));
    }

    #[test]
    fn native_prf_preferred_over_hmac_secret_when_both_advertised() {
        let request = prf_request(
            vec![],
            Some(PrfInputValue {
                first: b"x".to_vec(),
                second: None,
            }),
            HashMap::new(),
        );
        let info = info_with_extensions(&["hmac-secret", "prf"]);

        let ctap2 = Ctap2GetAssertionRequest::from_webauthn_request(&request, &info).unwrap();
        let ext = ctap2.extensions.as_ref().unwrap();
        assert!(ext.prf.is_some());
        assert!(ext.hmac_or_prf.is_none());
        assert!(!ctap2.needs_shared_secret(&info));
    }

    #[test]
    fn native_prf_not_used_without_getinfo_support() {
        let request = prf_request(
            vec![],
            Some(PrfInputValue {
                first: b"eval-first".to_vec(),
                second: None,
            }),
            HashMap::new(),
        );
        let info = info_with_extensions(&["hmac-secret"]);

        let ctap2 = Ctap2GetAssertionRequest::from_webauthn_request(&request, &info).unwrap();
        let ext = ctap2.extensions.as_ref().unwrap();
        assert!(ext.prf.is_none());
        assert!(
            ext.hmac_or_prf.is_some(),
            "hmac-secret path keeps the input"
        );
    }

    #[test]
    fn native_prf_skips_entries_not_in_allow_list() {
        let cred = make_credential(b"cred-1");
        let mut by_cred = HashMap::new();
        by_cred.insert(
            base64_url::encode(b"unknown-cred"),
            PrfInputValue {
                first: b"x".to_vec(),
                second: None,
            },
        );
        let request = prf_request(vec![cred], None, by_cred);
        let info = info_with_extensions(&["prf"]);

        let ctap2 = Ctap2GetAssertionRequest::from_webauthn_request(&request, &info).unwrap();
        let ext = ctap2.extensions.as_ref().unwrap();
        // No usable input: nothing is sent, like the hmac path.
        assert!(ext.prf.is_none());
        assert!(ext.hmac_or_prf.is_none());
        assert!(ext.skip_serializing());
    }

    #[test]
    fn native_prf_request_serializes_extensions_at_0x04() {
        // Regression guard for the original bug: the prf input used to vanish
        // from the serialized request entirely.
        let request = prf_request(
            vec![],
            Some(PrfInputValue {
                first: b"input".to_vec(),
                second: None,
            }),
            HashMap::new(),
        );
        let info = info_with_extensions(&["prf"]);
        let ctap2 = Ctap2GetAssertionRequest::from_webauthn_request(&request, &info).unwrap();

        let bytes = crate::proto::ctap2::cbor::to_vec(&ctap2).unwrap();
        let parsed: BTreeMap<u64, Value> = crate::proto::ctap2::cbor::from_slice(&bytes).unwrap();
        let Some(Value::Map(extensions)) = parsed.get(&0x04) else {
            panic!("extensions (0x04) missing from the wire")
        };
        assert!(extensions.contains_key(&Value::Text("prf".to_string())));
    }

    #[test]
    fn native_prf_composes_with_large_blob_write() {
        let mut request = prf_request(
            vec![make_credential(b"cred-1")],
            Some(PrfInputValue {
                first: b"input".to_vec(),
                second: None,
            }),
            HashMap::new(),
        );
        request.extensions.as_mut().unwrap().large_blob =
            Some(GetAssertionLargeBlobExtension::Write(b"blob".to_vec()));
        let info = Ctap2GetInfoResponse {
            extensions: Some(vec!["prf".to_string()]),
            options: Some(
                [("largeBlobs".to_string(), true), ("uv".to_string(), true)]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        };

        let ctap2 = Ctap2GetAssertionRequest::from_webauthn_request(&request, &info).unwrap();
        let ext = ctap2.extensions.as_ref().unwrap();
        assert!(ext.prf.is_some());
        assert!(ext.hmac_or_prf.is_none());
        assert_eq!(ext.large_blob_key, Some(true));
        // The pinUvAuthToken is still negotiated for the lbw permission.
        assert!(ctap2.needs_pin_uv_auth_token(&info));
        assert!(ctap2.needs_shared_secret(&info));
    }

    #[test]
    fn native_prf_forwards_all_matching_eval_by_credential_entries() {
        let mut by_cred = HashMap::new();
        for (id, salt) in [
            (&b"cred-1"[..], &b"salt-1"[..]),
            (b"cred-2", b"salt-2"),
            (b"unknown-cred", b"salt-3"),
        ] {
            by_cred.insert(
                base64_url::encode(id),
                PrfInputValue {
                    first: salt.to_vec(),
                    second: None,
                },
            );
        }
        let request = prf_request(
            vec![make_credential(b"cred-1"), make_credential(b"cred-2")],
            None,
            by_cred,
        );
        let info = info_with_extensions(&["prf"]);

        let ctap2 = Ctap2GetAssertionRequest::from_webauthn_request(&request, &info).unwrap();
        let prf = ctap2.extensions.as_ref().unwrap().prf.as_ref().unwrap();
        let by_cred = prf.eval_by_credential.as_ref().unwrap();
        assert_eq!(by_cred.len(), 2);
        assert_eq!(
            by_cred
                .get(&ByteBuf::from(b"cred-1".to_vec()))
                .unwrap()
                .first,
            hashed_salt(b"salt-1")
        );
        assert_eq!(
            by_cred
                .get(&ByteBuf::from(b"cred-2".to_vec()))
                .unwrap()
                .first,
            hashed_salt(b"salt-2")
        );
    }

    #[test]
    fn native_prf_invalid_eval_by_credential_keys_are_syntax_errors() {
        let info = info_with_extensions(&["prf"]);
        let cred = make_credential(b"cred-1");
        for bad_key in ["", "not base64url!"] {
            let mut by_cred = HashMap::new();
            by_cred.insert(
                bad_key.to_string(),
                PrfInputValue {
                    first: b"x".to_vec(),
                    second: None,
                },
            );
            let request = prf_request(vec![cred.clone()], None, by_cred);
            let result = Ctap2GetAssertionRequest::from_webauthn_request(&request, &info);
            assert!(
                matches!(result, Err(Error::Platform(PlatformError::SyntaxError))),
                "key {bad_key:?}"
            );
        }
    }

    #[test]
    fn native_prf_eval_by_credential_without_allow_list_is_not_supported() {
        let mut by_cred = HashMap::new();
        by_cred.insert(
            base64_url::encode(b"cred-1"),
            PrfInputValue {
                first: b"x".to_vec(),
                second: None,
            },
        );
        let request = prf_request(vec![], None, by_cred);
        let info = info_with_extensions(&["prf"]);

        let result = Ctap2GetAssertionRequest::from_webauthn_request(&request, &info);
        assert!(matches!(
            result,
            Err(Error::Platform(PlatformError::NotSupported))
        ));
    }

    #[test]
    fn native_prf_eval_by_credential_serializes_in_canonical_key_order() {
        // CTAP2 canonical CBOR: shorter keys first, then bytewise. Plain
        // lexicographic order would put [1, 2, 3] before [2].
        let salts = Ctap2PrfSalts {
            first: [0; 32],
            second: None,
        };
        let mut by_cred = BTreeMap::new();
        by_cred.insert(ByteBuf::from(vec![1u8, 2, 3]), salts.clone());
        by_cred.insert(ByteBuf::from(vec![2u8]), salts);
        let input = Ctap2PrfGetAssertionInput {
            eval: None,
            eval_by_credential: Some(by_cred),
        };
        let bytes = crate::proto::ctap2::cbor::to_vec(&input).unwrap();
        let pos_short = bytes
            .windows(2)
            .position(|w| w == [0x41, 0x02])
            .expect("key h'02' present");
        let pos_long = bytes
            .windows(4)
            .position(|w| w == [0x43, 0x01, 0x02, 0x03])
            .expect("key h'010203' present");
        assert!(pos_short < pos_long, "shorter key must serialize first");
    }

    fn unsigned_prf_outputs(first: &[u8], second: Option<&[u8]>) -> BTreeMap<Value, Value> {
        let mut results = BTreeMap::new();
        results.insert(
            Value::Text("first".to_string()),
            Value::Bytes(first.to_vec()),
        );
        if let Some(second) = second {
            results.insert(
                Value::Text("second".to_string()),
                Value::Bytes(second.to_vec()),
            );
        }
        let mut prf = BTreeMap::new();
        prf.insert(Value::Text("results".to_string()), Value::Map(results));
        let mut outputs = BTreeMap::new();
        outputs.insert(Value::Text("prf".to_string()), Value::Map(prf));
        outputs
    }

    #[test]
    fn assertion_output_populates_prf_from_unsigned_extension_outputs() {
        let cred = make_credential(b"cred-1");
        let mut response = make_response(Some(cred.clone()));
        // No signed extensions at all: ED flag unset, as phones respond.
        response.unsigned_extension_outputs =
            Some(unsigned_prf_outputs(&[0xAB; 32], Some(&[0xCD; 32])));

        let request = prf_request(
            vec![cred],
            Some(PrfInputValue {
                first: b"eval-first".to_vec(),
                second: None,
            }),
            HashMap::new(),
        );

        let assertion = response.into_assertion_output(&request, None);
        let unsigned = assertion
            .unsigned_extensions_output
            .expect("unsigned extensions present");
        // The raw passthrough map must not duplicate the typed prf entry.
        assert!(unsigned.unsigned_extension_outputs.is_empty());
        let prf = unsigned.prf.expect("prf output present");
        let results = prf.results.expect("results present");
        assert_eq!(results.first, [0xAB; 32]);
        assert_eq!(results.second, Some([0xCD; 32]));
    }

    #[test]
    fn assertion_output_ignores_unsigned_prf_when_not_requested() {
        let cred = make_credential(b"cred-1");
        let mut response = make_response(Some(cred.clone()));
        response.unsigned_extension_outputs = Some(unsigned_prf_outputs(&[0xAB; 32], None));

        let request = make_request(vec![cred]);
        let assertion = response.into_assertion_output(&request, None);
        // Not requested: neither a typed nor a raw prf output is surfaced.
        assert!(assertion.unsigned_extensions_output.is_none());
    }

    #[test]
    fn parse_unsigned_prf_handles_enabled_and_malformed_entries() {
        let mut prf = BTreeMap::new();
        prf.insert(Value::Text("enabled".to_string()), Value::Bool(true));
        let mut outputs = BTreeMap::new();
        outputs.insert(Value::Text("prf".to_string()), Value::Map(prf));
        let parsed = parse_unsigned_prf(&outputs).expect("prf entry");
        assert_eq!(parsed.enabled, Some(true));
        assert!(parsed.results.is_none());

        // Non-map prf entry
        let mut outputs = BTreeMap::new();
        outputs.insert(Value::Text("prf".to_string()), Value::Bool(true));
        assert!(parse_unsigned_prf(&outputs).is_none());

        // No prf entry
        assert!(parse_unsigned_prf(&BTreeMap::new()).is_none());

        // Wrong-length results are dropped
        let parsed = parse_unsigned_prf(&unsigned_prf_outputs(&[0xAB; 16], None)).unwrap();
        assert!(parsed.results.is_none());

        // A malformed second invalidates the whole results map
        let parsed =
            parse_unsigned_prf(&unsigned_prf_outputs(&[0xAB; 32], Some(&[0xCD; 16]))).unwrap();
        assert!(parsed.results.is_none());

        // Non-bool enabled is ignored
        let mut prf = BTreeMap::new();
        prf.insert(Value::Text("enabled".to_string()), Value::Integer(1));
        let mut outputs = BTreeMap::new();
        outputs.insert(Value::Text("prf".to_string()), Value::Map(prf));
        let parsed = parse_unsigned_prf(&outputs).unwrap();
        assert!(parsed.enabled.is_none());
    }

    #[test]
    fn surfaces_passthrough_prf_results_in_client_extension_results() {
        use crate::ops::webauthn::idl::response::{JsonFormat, WebAuthnIDLResponse};

        // End-to-end GPM shape: results only in unsignedExtensionOutputs (0x08),
        // no signed extensions, ED flag unset.
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = AuthenticatorDataFlags::USER_PRESENT.bits();

        let mut response: BTreeMap<u64, Value> = BTreeMap::new();
        response.insert(0x02, Value::Bytes(auth_data));
        response.insert(0x03, Value::Bytes(vec![0xAAu8; 64]));
        response.insert(
            0x08,
            Value::Map(unsigned_prf_outputs(&[0xAB; 32], Some(&[0xCD; 32]))),
        );

        let bytes = crate::proto::ctap2::cbor::to_vec(&response).unwrap();
        let parsed: Ctap2GetAssertionResponse =
            crate::proto::ctap2::cbor::from_slice(&bytes).unwrap();

        let request = prf_request(
            vec![make_credential(b"cred-1")],
            Some(PrfInputValue {
                first: b"input".to_vec(),
                second: None,
            }),
            HashMap::new(),
        );
        let assertion = parsed.into_assertion_output(&request, None);
        let json_str = assertion
            .to_json_string(&request, JsonFormat::default())
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let prf = &json["clientExtensionResults"]["prf"];
        assert_eq!(
            prf["results"]["first"],
            serde_json::json!(base64_url::encode(&[0xAB; 32]))
        );
        assert_eq!(
            prf["results"]["second"],
            serde_json::json!(base64_url::encode(&[0xCD; 32]))
        );
        // Exactly one prf member: the raw passthrough must not emit a duplicate.
        assert_eq!(json_str.matches("\"prf\"").count(), 1);
    }

    #[test]
    fn pin_uv_auth_param_clears_uv_option() {
        use crate::ops::webauthn::UserVerificationRequirement;
        use crate::pin::PinUvAuthProtocolOne;

        let mut request = make_request(vec![]);
        request.user_verification = UserVerificationRequirement::Required;
        let mut ctap2 = Ctap2GetAssertionRequest::from(request);
        assert!(ctap2.options.unwrap().require_user_verification);

        let proto = PinUvAuthProtocolOne::new();
        ctap2
            .calculate_and_set_uv_auth(&proto, &[0xAA; 32])
            .unwrap();

        assert!(ctap2.pin_auth_param.is_some());
        assert!(!ctap2.options.unwrap().require_user_verification);

        // Wire check: the options map (0x05) must not contain "uv".
        let bytes = crate::proto::ctap2::cbor::to_vec(&ctap2).unwrap();
        let parsed: BTreeMap<u64, Value> = crate::proto::ctap2::cbor::from_slice(&bytes).unwrap();
        let Some(Value::Map(options)) = parsed.get(&0x05) else {
            panic!("options map missing from serialized request");
        };
        assert!(!options.contains_key(&Value::Text("uv".to_string())));
        assert_eq!(
            options.get(&Value::Text("up".to_string())),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn decodes_unsigned_extension_outputs_at_index_0x08() {
        // 0x08 is unsignedExtensionOutputs (a CBOR map), not enterprise attestation.
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = AuthenticatorDataFlags::USER_PRESENT.bits();

        let mut ueo = BTreeMap::new();
        ueo.insert(
            Value::Text("thirdPartyPayment".to_string()),
            Value::Bool(true),
        );

        let mut response: BTreeMap<u64, Value> = BTreeMap::new();
        response.insert(0x02, Value::Bytes(auth_data));
        response.insert(0x03, Value::Bytes(vec![0xAAu8; 64]));
        response.insert(0x08, Value::Map(ueo.clone()));

        let bytes = crate::proto::ctap2::cbor::to_vec(&response).unwrap();
        let parsed: Ctap2GetAssertionResponse =
            crate::proto::ctap2::cbor::from_slice(&bytes).unwrap();

        assert_eq!(parsed.unsigned_extension_outputs, Some(ueo));
    }

    #[test]
    fn surfaces_unsigned_extension_outputs_in_client_extension_results() {
        use crate::ops::webauthn::idl::response::{JsonFormat, WebAuthnIDLResponse};

        // End-to-end: a getAssertion response carrying unsignedExtensionOutputs
        // (0x08) with a boolean (thirdPartyPayment) and a byte string is decoded
        // and surfaced into the client extension results JSON, with bytes encoded
        // as base64url.
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = AuthenticatorDataFlags::USER_PRESENT.bits();

        let mut ueo = BTreeMap::new();
        ueo.insert(
            Value::Text("thirdPartyPayment".to_string()),
            Value::Bool(true),
        );
        ueo.insert(
            Value::Text("blobby".to_string()),
            Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        );

        let mut response: BTreeMap<u64, Value> = BTreeMap::new();
        response.insert(0x02, Value::Bytes(auth_data));
        response.insert(0x03, Value::Bytes(vec![0xAAu8; 64]));
        response.insert(0x08, Value::Map(ueo));

        let bytes = crate::proto::ctap2::cbor::to_vec(&response).unwrap();
        let parsed: Ctap2GetAssertionResponse =
            crate::proto::ctap2::cbor::from_slice(&bytes).unwrap();

        let request = make_request(vec![make_credential(b"cred-1")]);
        let assertion = parsed.into_assertion_output(&request, None);
        let json_str = assertion
            .to_json_string(&request, JsonFormat::default())
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let results = &json["clientExtensionResults"];
        assert_eq!(results["thirdPartyPayment"], serde_json::json!(true));
        assert_eq!(
            results["blobby"],
            serde_json::json!(base64_url::encode(&[0xDE, 0xAD, 0xBE, 0xEF]))
        );
    }
}
