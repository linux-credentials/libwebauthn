use serde::Deserialize;
use std::{convert::TryFrom, ops::Deref};

#[derive(Clone, Debug)]
pub struct RelyingPartyId(pub String);

impl Deref for RelyingPartyId {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<RelyingPartyId> for String {
    fn from(rpid: RelyingPartyId) -> String {
        rpid.0
    }
}

#[derive(thiserror::Error, Debug, Clone)]
// TODO(#137): Validate RelyingPartyId
pub enum Error {
    #[error("Empty Relying Party ID is not allowed")]
    EmptyRelyingPartyId,
}

impl TryFrom<&str> for RelyingPartyId {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // TODO(#137): Validate RelyingPartyId, including IDNA normalization
        // and checking for valid characters.
        match value {
            "" => Err(Error::EmptyRelyingPartyId),
            _ => Ok(RelyingPartyId(value.to_string())),
        }
    }
}

impl<'de> Deserialize<'de> for RelyingPartyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RelyingPartyId::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}
