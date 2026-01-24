use std::collections::HashMap;

use serde::Deserialize;
use serde_bytes::ByteBuf;

use crate::{
    ops::webauthn::{Base64UrlString, UserVerificationRequirement},
    proto::ctap2::{
        Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialType, Ctap2Transport,
    },
};

#[derive(Deserialize, Debug, Clone)]
pub struct PublicKeyCredentialRequestOptionsJSON {
    pub challenge: Base64UrlString,
    pub timeout: Option<u32>,
    #[serde(rename = "rpId")]
    pub relying_party_id: Option<String>,
    #[serde(rename = "allowCredentials")]
    #[serde(default)]
    pub allow_credentials: Vec<PublicKeyCredentialDescriptorJSON>,
    #[serde(rename = "userVerification")]
    pub uv_requirement: UserVerificationRequirement,
    #[serde(default)]
    pub hints: Vec<String>,
    pub extensions: Option<GetAssertionRequestExtensionsJSON>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PublicKeyCredentialDescriptorJSON {
    pub id: Base64UrlString,
    pub r#type: Ctap2PublicKeyCredentialType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<Ctap2Transport>>,
}

impl Into<Ctap2PublicKeyCredentialDescriptor> for PublicKeyCredentialDescriptorJSON {
    fn into(self) -> Ctap2PublicKeyCredentialDescriptor {
        Ctap2PublicKeyCredentialDescriptor {
            r#type: self.r#type,
            id: ByteBuf::from(self.id),
            transports: self.transports,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GetAssertionRequestExtensionsJSON {
    #[serde(rename = "getCredBlob")]
    pub cred_blob: Option<bool>,
    #[serde(rename = "largeBlobKey")]
    pub large_blob: Option<LargeBlobInputJson>,
    #[serde(rename = "hmacCreateSecret")]
    pub hmac_get_secret: Option<HmacGetSecretInputJson>,
    #[serde(rename = "prf")]
    pub prf: Option<PrfInputJson>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LargeBlobInputJson {
    pub read: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PrfInputJson {
    pub eval: Option<PrfValuesJson>,
    pub eval_by_credential: Option<HashMap<String, PrfValuesJson>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PrfValuesJson {
    pub first: Base64UrlString,
    pub second: Option<Base64UrlString>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HmacGetSecretInputJson {
    pub salt1: Base64UrlString,
    pub salt2: Option<Base64UrlString>,
}
