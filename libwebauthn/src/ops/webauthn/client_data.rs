use crate::ops::webauthn::Operation;

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientData {
    pub operation: Operation,
    pub challenge: Vec<u8>,
    pub origin: String,
    pub cross_origin: Option<bool>,
    /// The origin of the top-level document, if in an iframe.
    /// https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin
    pub top_origin: Option<String>,
}

impl ClientData {
    /// Returns the canonical JSON representation of the client data.
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let op_str = match &self.operation {
            Operation::MakeCredential => "webauthn.create",
            Operation::GetAssertion => "webauthn.get",
        };
        let challenge_str = base64_url::encode(&self.challenge);
        let origin_str = &self.origin;
        let cross_origin_str = if self.cross_origin.unwrap_or(false) {
            "true"
        } else {
            "false"
        };
        format!("{{\"type\":\"{op_str}\",\"challenge\":\"{challenge_str}\",\"origin\":\"{origin_str}\",\"crossOrigin\":{cross_origin_str}}}").into_bytes()
    }

    pub fn hash(&self) -> Vec<u8> {
        let json_bytes = self.to_json_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&json_bytes);
        hasher.finalize().to_vec()
    }
}
