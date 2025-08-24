use crate::ops::webauthn::Operation;

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ClientData {
    pub operation: Operation,
    pub challenge: Vec<u8>,
    pub origin: String,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: Option<bool>,
}

impl ClientData {
    pub fn hash(&self) -> Vec<u8> {
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
        let json =     
            format!("{{\"type\":\"{op_str}\",\"challenge\":\"{challenge_str}\",\"origin\":\"{origin_str}\",\"crossOrigin\":{cross_origin_str}}}");

        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        hasher.finalize().to_vec()
    }
}

