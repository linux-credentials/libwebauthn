use std::ops::Deref;

use base64_url;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json;

use super::rpid::RelyingPartyId;

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

// TODO(afresta): Move to ctap2 module.
#[derive(Debug, Clone, PartialEq)]
pub struct Base64UrlString(pub Vec<u8>);

impl From<Vec<u8>> for Base64UrlString {
    fn from(bytes: Vec<u8>) -> Self {
        Base64UrlString(bytes)
    }
}

impl From<&[u8]> for Base64UrlString {
    fn from(bytes: &[u8]) -> Self {
        Base64UrlString(bytes.to_vec())
    }
}

impl Deref for Base64UrlString {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Base64UrlString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        base64_url::decode(&s)
            .map_err(serde::de::Error::custom)
            .map(|bytes| Base64UrlString(bytes))
    }
}

impl Serialize for Base64UrlString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = base64_url::encode(&self.0);
        serializer.serialize_str(&encoded)
    }
}

impl Into<Vec<u8>> for Base64UrlString {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl Base64UrlString {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}
