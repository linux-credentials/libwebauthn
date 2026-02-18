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
    pub fn to_json(&self) -> String {
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
        format!("{{\"type\":\"{op_str}\",\"challenge\":\"{challenge_str}\",\"origin\":\"{origin_str}\",\"crossOrigin\":{cross_origin_str}}}")
    }

    pub fn hash(&self) -> Vec<u8> {
        let json = self.to_json();
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client_data(cross_origin: Option<bool>) -> ClientData {
        ClientData {
            operation: Operation::GetAssertion,
            challenge: b"test-challenge".to_vec(),
            origin: "https://example.org".to_string(),
            cross_origin,
            top_origin: None,
        }
    }

    #[test]
    fn test_cross_origin_none_produces_false() {
        let client_data = make_client_data(None);
        let json = client_data.to_json();
        assert!(
            json.contains("\"crossOrigin\":false"),
            "Expected crossOrigin:false, got: {}",
            json
        );
    }

    #[test]
    fn test_cross_origin_false_produces_false() {
        let client_data = make_client_data(Some(false));
        let json = client_data.to_json();
        assert!(
            json.contains("\"crossOrigin\":false"),
            "Expected crossOrigin:false, got: {}",
            json
        );
    }

    #[test]
    fn test_cross_origin_true_produces_true() {
        let client_data = make_client_data(Some(true));
        let json = client_data.to_json();
        assert!(
            json.contains("\"crossOrigin\":true"),
            "Expected crossOrigin:true, got: {}",
            json
        );
    }

    #[test]
    fn test_to_json_format() {
        let client_data = ClientData {
            operation: Operation::MakeCredential,
            challenge: b"DEADCODE".to_vec(),
            origin: "https://example.org".to_string(),
            cross_origin: Some(true),
            top_origin: None,
        };
        let json = client_data.to_json();

        // Verify the JSON contains expected structure
        assert!(json.contains("\"type\":\"webauthn.create\""));
        assert!(json.contains("\"origin\":\"https://example.org\""));
        assert!(json.contains("\"crossOrigin\":true"));
        // Challenge should be base64url encoded
        assert!(json.contains("\"challenge\":\"REVBRENPREU\"")); // base64url of "DEADCODE"
    }
}
