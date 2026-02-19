mod base64url;
pub mod create;
pub mod get;
pub mod response;
pub mod rpid;

pub use base64url::Base64UrlString;
pub use response::{
    AuthenticationExtensionsClientOutputsJSON, AuthenticationResponseJSON,
    AuthenticatorAssertionResponseJSON, AuthenticatorAttestationResponseJSON,
    CredentialPropertiesOutputJSON, HMACGetSecretOutputJSON, JsonFormat, LargeBlobOutputJSON,
    PRFOutputJSON, PRFValuesJSON, RegistrationResponseJSON, ResponseSerializationError,
    WebAuthnIDLResponse,
};

use rpid::RelyingPartyId;

use serde::de::DeserializeOwned;
use serde_json;

pub type JsonError = serde_json::Error;

pub trait WebAuthnIDL<E>: Sized
where
    E: std::error::Error, // Validation error type.
    Self: FromIdlModel<Self::IdlModel, E>,
{
    /// An error type that can be returned when deserializing from JSON, including
    /// JSON parsing errors and any additional validation errors.
    type Error: std::error::Error + From<JsonError> + From<E>;

    /// The JSON model that this IDL can deserialize from.
    type IdlModel: DeserializeOwned;

    fn from_json(rpid: &RelyingPartyId, json: &str) -> Result<Self, Self::Error> {
        let idl_model: Self::IdlModel = serde_json::from_str(json)?;
        Self::from_idl_model(rpid, idl_model).map_err(From::from)
    }
}

pub trait FromIdlModel<T, E>: Sized
where
    T: DeserializeOwned,
    E: std::error::Error,
{
    fn from_idl_model(rpid: &RelyingPartyId, model: T) -> Result<Self, E>;
}
