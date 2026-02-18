//! JSON response models for WebAuthn responses.
//!
//! These types follow the WebAuthn Level 3 specification for JSON serialization:
//! - `RegistrationResponseJSON` for credential creation responses (§5.1 toJSON())
//! - `AuthenticationResponseJSON` for assertion responses (§5.1 toJSON())
//!
//! See: https://www.w3.org/TR/webauthn-3/#sctn-public-key-credential-json

use serde::Serialize;

use super::Base64UrlString;

/// JSON output format options.
#[derive(Debug, Clone, Copy, Default)]
pub enum JsonFormat {
    /// Minified JSON (default).
    #[default]
    Minified,
    /// Pretty-printed JSON with indentation.
    Prettified,
}

/// Error type for WebAuthn response serialization.
#[derive(thiserror::Error, Debug)]
pub enum ResponseSerializationError {
    /// Failed to serialize authenticator data.
    #[error("Failed to serialize authenticator data: {0}")]
    AuthenticatorDataError(String),

    /// Failed to serialize attestation object.
    #[error("Failed to serialize attestation object: {0}")]
    AttestationObjectError(String),

    /// Failed to serialize public key.
    #[error("Failed to serialize public key: {0}")]
    PublicKeyError(String),

    /// Failed to serialize to JSON.
    #[error("Failed to serialize to JSON: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Failed to serialize to CBOR.
    #[error("Failed to serialize to CBOR: {0}")]
    CborError(String),
}

/// Trait for WebAuthn response types that can be serialized to JSON.
///
/// This is the inverse of `WebAuthnIDL` - it converts WebAuthn response models
/// to JSON-serializable IDL models, which can then be serialized to JSON.
pub trait WebAuthnIDLResponse: Sized {
    /// The JSON-serializable IDL model type.
    type IdlModel: Serialize;

    /// Context required for serialization (e.g., client data JSON).
    type Context;

    /// Converts this response to a JSON-serializable IDL model.
    fn to_idl_model(
        &self,
        ctx: &Self::Context,
    ) -> Result<Self::IdlModel, ResponseSerializationError>;

    /// Serializes this response to a JSON string.
    fn to_json(
        &self,
        ctx: &Self::Context,
        format: JsonFormat,
    ) -> Result<String, ResponseSerializationError> {
        let model = self.to_idl_model(ctx)?;
        match format {
            JsonFormat::Minified => Ok(serde_json::to_string(&model)?),
            JsonFormat::Prettified => Ok(serde_json::to_string_pretty(&model)?),
        }
    }
}

/// dictionary RegistrationResponseJSON {
///     required DOMString id;
///     required Base64URLString rawId;
///     required AuthenticatorAttestationResponseJSON response;
///     DOMString authenticatorAttachment;
///     required AuthenticationExtensionsClientOutputsJSON clientExtensionResults;
///     required DOMString type;
/// };
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponseJSON {
    /// The credential ID, base64url-encoded.
    pub id: String,
    /// The raw credential ID, base64url-encoded.
    pub raw_id: Base64UrlString,
    /// The authenticator's response.
    pub response: AuthenticatorAttestationResponseJSON,
    /// The authenticator attachment modality.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    /// Client extension results.
    pub client_extension_results: AuthenticationExtensionsClientOutputsJSON,
    /// The credential type (always "public-key").
    pub r#type: String,
}

/// dictionary AuthenticatorAttestationResponseJSON {
///     required Base64URLString clientDataJSON;
///     required Base64URLString authenticatorData;
///     required sequence<DOMString> transports;
///     Base64URLString publicKey;
///     required COSEAlgorithmIdentifier publicKeyAlgorithm;
///     required Base64URLString attestationObject;
/// };
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAttestationResponseJSON {
    /// The client data JSON, base64url-encoded.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Base64UrlString,
    /// The authenticator data, base64url-encoded.
    pub authenticator_data: Base64UrlString,
    /// The transports the authenticator is believed to support.
    pub transports: Vec<String>,
    /// The public key in SubjectPublicKeyInfo format, base64url-encoded.
    /// May be None if the public key algorithm is not supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Base64UrlString>,
    /// The COSE algorithm identifier.
    pub public_key_algorithm: i64,
    /// The attestation object, base64url-encoded.
    pub attestation_object: Base64UrlString,
}

/// dictionary AuthenticationResponseJSON {
///     required DOMString id;
///     required Base64URLString rawId;
///     required AuthenticatorAssertionResponseJSON response;
///     DOMString authenticatorAttachment;
///     required AuthenticationExtensionsClientOutputsJSON clientExtensionResults;
///     required DOMString type;
/// };
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationResponseJSON {
    /// The credential ID, base64url-encoded.
    pub id: String,
    /// The raw credential ID, base64url-encoded.
    pub raw_id: Base64UrlString,
    /// The authenticator's response.
    pub response: AuthenticatorAssertionResponseJSON,
    /// The authenticator attachment modality.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    /// Client extension results.
    pub client_extension_results: AuthenticationExtensionsClientOutputsJSON,
    /// The credential type (always "public-key").
    pub r#type: String,
}

/// dictionary AuthenticatorAssertionResponseJSON {
///     required Base64URLString clientDataJSON;
///     required Base64URLString authenticatorData;
///     required Base64URLString signature;
///     Base64URLString userHandle;
/// };
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAssertionResponseJSON {
    /// The client data JSON, base64url-encoded.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Base64UrlString,
    /// The authenticator data, base64url-encoded.
    pub authenticator_data: Base64UrlString,
    /// The signature, base64url-encoded.
    pub signature: Base64UrlString,
    /// The user handle, base64url-encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<Base64UrlString>,
}

/// dictionary AuthenticationExtensionsClientOutputsJSON {
/// };
///
/// Client extension outputs, with any ArrayBuffer values encoded as Base64URL.
/// Extensions are optional and may include:
/// - credBlob: bool
/// - largeBlob: { blob: Base64URLString, written: bool }
/// - prf: { results: { first: Base64URLString, second: Base64URLString } }
/// - hmacGetSecret: { output1: Base64URLString, output2: Base64URLString }
/// - credProps: { rk: bool }
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsClientOutputsJSON {
    /// The credential properties extension output (for registration).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredentialPropertiesOutputJSON>,

    /// Whether the credential was created with hmac-secret support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_create_secret: Option<bool>,

    /// HMAC-secret extension output (for authentication).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_get_secret: Option<HMACGetSecretOutputJSON>,

    /// Large blob extension output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<LargeBlobOutputJSON>,

    /// PRF extension output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<PRFOutputJSON>,
}

/// Credential properties extension output.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialPropertiesOutputJSON {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,
}

/// HMAC-secret extension output for authentication.
#[derive(Debug, Clone, Serialize)]
pub struct HMACGetSecretOutputJSON {
    pub output1: Base64UrlString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output2: Option<Base64UrlString>,
}

/// Large blob extension output.
#[derive(Debug, Clone, Serialize)]
pub struct LargeBlobOutputJSON {
    /// For registration: whether large blob storage is supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    /// For authentication (read): the blob data, base64url-encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<Base64UrlString>,
    /// For authentication (write): whether the write was successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written: Option<bool>,
}

/// PRF extension output.
#[derive(Debug, Clone, Serialize)]
pub struct PRFOutputJSON {
    /// For registration: whether PRF is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// For authentication: the PRF results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<PRFValuesJSON>,
}

/// PRF values in JSON format.
#[derive(Debug, Clone, Serialize)]
pub struct PRFValuesJSON {
    pub first: Base64UrlString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second: Option<Base64UrlString>,
}
