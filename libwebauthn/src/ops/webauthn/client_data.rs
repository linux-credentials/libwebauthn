use crate::ops::webauthn::Operation;

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientData {
    pub operation: Operation,
    pub challenge: Vec<u8>,
    pub origin: String,
    /// The origin of the top-level document, if the request was made in a
    /// cross-origin nested browsing context (e.g. an iframe).
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
        let cross_origin_str = if self.top_origin.is_some() {
            "true"
        } else {
            "false"
        };
        match &self.top_origin {
            Some(top) => format!(
                "{{\"type\":\"{op_str}\",\"challenge\":\"{challenge_str}\",\"origin\":\"{origin_str}\",\"crossOrigin\":{cross_origin_str},\"topOrigin\":\"{top}\"}}"
            ),
            None => format!(
                "{{\"type\":\"{op_str}\",\"challenge\":\"{challenge_str}\",\"origin\":\"{origin_str}\",\"crossOrigin\":{cross_origin_str}}}"
            ),
        }
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

    fn make_client_data(top_origin: Option<String>) -> ClientData {
        ClientData {
            operation: Operation::GetAssertion,
            challenge: b"test-challenge".to_vec(),
            origin: "https://example.org".to_string(),
            top_origin,
        }
    }

    #[test]
    fn same_origin_emits_cross_origin_false() {
        let client_data = make_client_data(None);
        let json = client_data.to_json();
        assert!(
            json.contains("\"crossOrigin\":false"),
            "Expected crossOrigin:false, got: {json}"
        );
        assert!(
            !json.contains("topOrigin"),
            "Did not expect topOrigin, got: {json}"
        );
    }

    #[test]
    fn cross_origin_emits_cross_origin_true_and_top_origin() {
        let client_data = make_client_data(Some("https://top.example.org".to_string()));
        let json = client_data.to_json();
        assert!(
            json.contains("\"crossOrigin\":true"),
            "Expected crossOrigin:true, got: {json}"
        );
        assert!(
            json.contains("\"topOrigin\":\"https://top.example.org\""),
            "Expected topOrigin, got: {json}"
        );
    }

    #[test]
    fn to_json_format() {
        let client_data = ClientData {
            operation: Operation::MakeCredential,
            challenge: b"DEADCODE".to_vec(),
            origin: "https://example.org".to_string(),
            top_origin: None,
        };
        let json = client_data.to_json();

        assert!(json.contains("\"type\":\"webauthn.create\""));
        assert!(json.contains("\"origin\":\"https://example.org\""));
        assert!(json.contains("\"crossOrigin\":false"));
        assert!(json.contains("\"challenge\":\"REVBRENPREU\""));
    }
}
