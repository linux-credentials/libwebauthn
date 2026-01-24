use std::ops::Deref;

use base64_url;
use serde::{Deserialize, Serialize};

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

impl AsRef<[u8]> for Base64UrlString {
    fn as_ref(&self) -> &[u8] {
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

impl From<Base64UrlString> for Vec<u8> {
    fn from(b64: Base64UrlString) -> Vec<u8> {
        b64.0
    }
}

impl Base64UrlString {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}
