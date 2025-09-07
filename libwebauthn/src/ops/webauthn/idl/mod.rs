mod base64url;
pub mod create;
pub mod get;
pub mod rpid;

pub use base64url::Base64UrlString;

use rpid::RelyingPartyId;

use serde::de::DeserializeOwned;
use serde_json;

pub type JsonError = serde_json::Error;

pub trait WebAuthnIDL<E>: Sized
where
    E: std::error::Error, // Validation error type.
    Self: FromInnerModel<Self::InnerModel, E>,
{
    /// An error type that can be returned when deserializing from JSON, including
    /// JSON parsing errors and any additional validation errors.
    type Error: std::error::Error + From<JsonError> + From<E>;

    /// The JSON model that this IDL can deserialize from.
    type InnerModel: DeserializeOwned;

    fn from_json(rpid: &RelyingPartyId, json: &str) -> Result<Self, Self::Error> {
        let inner_model: Self::InnerModel = serde_json::from_str(json)?;
        Self::from_inner_model(rpid, inner_model).map_err(From::from)
    }
}

pub trait FromInnerModel<T, E>: Sized
where
    T: DeserializeOwned,
    E: std::error::Error,
{
    fn from_inner_model(rpid: &RelyingPartyId, inner: T) -> Result<Self, E>;
}
