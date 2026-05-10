use crate::ops::webauthn::Operation;

use serde::{Deserialize, Serialize};
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

/// Wire-format representation of the CollectedClientData dictionary, used to
/// serialize `clientDataJSON` per WebAuthn L3 §5.8.1.2.
///
/// Field order matches the algorithm in the spec: `type`, `challenge`,
/// `origin`, optional `topOrigin`, `crossOrigin`. `serde_json`'s string
/// escaping is a strict superset of CCDToString (ECMA-262 / RFC 8259 escapes
/// every code point CCDToString escapes), so routing free-form strings
/// through `serde_json::to_string` is sufficient to satisfy the spec.
#[derive(Serialize)]
struct CollectedClientDataJSON<'a> {
    #[serde(rename = "type")]
    operation: &'static str,
    challenge: &'a str,
    origin: &'a str,
    #[serde(rename = "topOrigin", skip_serializing_if = "Option::is_none")]
    top_origin: Option<&'a str>,
    #[serde(rename = "crossOrigin")]
    cross_origin: bool,
}

impl ClientData {
    /// Returns the canonical JSON representation of the client data.
    ///
    /// Strings are escaped per WebAuthn L3 §5.8.1.2 (CCDToString), via
    /// `serde_json`'s RFC 8259 string encoder. Field order matches the spec:
    /// `type`, `challenge`, `origin`, `topOrigin?`, `crossOrigin`.
    pub fn to_json(&self) -> String {
        let operation = match self.operation {
            Operation::MakeCredential => "webauthn.create",
            Operation::GetAssertion => "webauthn.get",
        };
        let challenge = base64_url::encode(&self.challenge);
        let wire = CollectedClientDataJSON {
            operation,
            challenge: &challenge,
            origin: &self.origin,
            top_origin: self.top_origin.as_deref(),
            cross_origin: self.top_origin.is_some(),
        };
        // Serializing a fixed-shape struct with `String`/`&str`/`bool` fields
        // cannot fail; preserve the infallible API by unwrapping.
        serde_json::to_string(&wire).expect("CollectedClientData serialization is infallible")
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
    use serde_json::Value;

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

    /// Per WebAuthn L3 §5.8.1.2, the serialization MUST escape strings per
    /// CCDToString (RFC 8259 string-escape rules). An origin containing a
    /// double quote must not be able to inject a fake second `origin` key.
    #[test]
    fn origin_with_double_quote_is_escaped() {
        let hostile = r#"https://example.com","origin":"https://attacker.com"#;
        let client_data = ClientData {
            operation: Operation::GetAssertion,
            challenge: b"c".to_vec(),
            origin: hostile.to_string(),
            top_origin: None,
        };
        let json = client_data.to_json();

        // The output must parse as valid JSON.
        let parsed: Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("to_json() produced invalid JSON: {e}, got: {json}"));

        // And the origin field round-trips back to the exact hostile input,
        // with no second `origin` key injected.
        assert_eq!(parsed["origin"].as_str(), Some(hostile));
        let obj = parsed.as_object().expect("top-level must be an object");
        assert_eq!(obj.keys().filter(|k| k.as_str() == "origin").count(), 1);
    }

    /// Backslashes are one of the two strict-mode CCDToString escapes.
    #[test]
    fn origin_with_backslash_is_escaped() {
        let hostile = r"https://example.com\";
        let client_data = ClientData {
            operation: Operation::GetAssertion,
            challenge: b"c".to_vec(),
            origin: hostile.to_string(),
            top_origin: None,
        };
        let json = client_data.to_json();

        let parsed: Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("to_json() produced invalid JSON: {e}, got: {json}"));
        assert_eq!(parsed["origin"].as_str(), Some(hostile));
    }

    /// U+0000..U+001F must be escaped per RFC 8259 §7.
    #[test]
    fn origin_with_control_characters_is_escaped() {
        // Include NUL, BEL, TAB, LF, CR, US (the boundary of the control range).
        let hostile = "https://example.com/\u{0000}\u{0007}\t\n\r\u{001F}";
        let client_data = ClientData {
            operation: Operation::GetAssertion,
            challenge: b"c".to_vec(),
            origin: hostile.to_string(),
            top_origin: None,
        };
        let json = client_data.to_json();

        let parsed: Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("to_json() produced invalid JSON: {e}, got: {json}"));
        assert_eq!(parsed["origin"].as_str(), Some(hostile));

        // None of the raw control bytes should appear in the wire form;
        // they must be escaped as \u00XX, \t, \n, \r.
        for &c in &[0x00u8, 0x07, 0x09, 0x0A, 0x0D, 0x1F] {
            assert!(
                !json.as_bytes().contains(&c),
                "raw control byte 0x{c:02X} leaked into JSON: {json:?}"
            );
        }
    }

    /// A hostile topOrigin must also be escaped.
    #[test]
    fn top_origin_with_double_quote_is_escaped() {
        let hostile_top = r#"https://top.example.com","crossOrigin":false,"x":"y"#;
        let client_data = ClientData {
            operation: Operation::GetAssertion,
            challenge: b"c".to_vec(),
            origin: "https://example.org".to_string(),
            top_origin: Some(hostile_top.to_string()),
        };
        let json = client_data.to_json();

        let parsed: Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("to_json() produced invalid JSON: {e}, got: {json}"));
        assert_eq!(parsed["topOrigin"].as_str(), Some(hostile_top));
        // crossOrigin must remain a boolean and not be subverted into a string
        // by the injected payload.
        assert_eq!(parsed["crossOrigin"].as_bool(), Some(true));
    }

    /// Spec field order: type, challenge, origin, topOrigin?, crossOrigin.
    #[test]
    fn field_order_matches_spec_with_top_origin() {
        let client_data = ClientData {
            operation: Operation::MakeCredential,
            challenge: b"c".to_vec(),
            origin: "https://example.org".to_string(),
            top_origin: Some("https://top.example.org".to_string()),
        };
        let json = client_data.to_json();

        let i_type = json.find("\"type\"").expect("type missing");
        let i_chal = json.find("\"challenge\"").expect("challenge missing");
        let i_orig = json.find("\"origin\"").expect("origin missing");
        let i_top = json.find("\"topOrigin\"").expect("topOrigin missing");
        let i_cross = json.find("\"crossOrigin\"").expect("crossOrigin missing");

        assert!(
            i_type < i_chal && i_chal < i_orig && i_orig < i_top && i_top < i_cross,
            "field order is wrong: {json}"
        );
    }

    /// Without topOrigin, the key MUST NOT appear at all.
    #[test]
    fn top_origin_absent_omits_key() {
        let client_data = make_client_data(None);
        let json = client_data.to_json();
        assert!(
            !json.contains("topOrigin"),
            "topOrigin key must be absent when None, got: {json}"
        );

        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("topOrigin").is_none());
    }

    /// Without topOrigin, crossOrigin still follows origin (no gap left by
    /// the omitted key).
    #[test]
    fn field_order_matches_spec_without_top_origin() {
        let client_data = make_client_data(None);
        let json = client_data.to_json();

        let i_type = json.find("\"type\"").expect("type missing");
        let i_chal = json.find("\"challenge\"").expect("challenge missing");
        let i_orig = json.find("\"origin\"").expect("origin missing");
        let i_cross = json.find("\"crossOrigin\"").expect("crossOrigin missing");

        assert!(
            i_type < i_chal && i_chal < i_orig && i_orig < i_cross,
            "field order is wrong: {json}"
        );
    }

    /// Full round-trip: every field survives the JSON encoder unchanged.
    #[test]
    fn round_trip_preserves_all_fields() {
        let client_data = ClientData {
            operation: Operation::GetAssertion,
            challenge: b"\x00\x01\x02\xff".to_vec(),
            origin: r#"https://weird".example/"#.to_string(),
            top_origin: Some(r"https://t\op.example".to_string()),
        };
        let json = client_data.to_json();

        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"].as_str(), Some("webauthn.get"));
        assert_eq!(
            parsed["challenge"].as_str(),
            Some(base64_url::encode(&client_data.challenge).as_str())
        );
        assert_eq!(parsed["origin"].as_str(), Some(client_data.origin.as_str()));
        assert_eq!(
            parsed["topOrigin"].as_str(),
            client_data.top_origin.as_deref()
        );
        assert_eq!(parsed["crossOrigin"].as_bool(), Some(true));
    }
}
