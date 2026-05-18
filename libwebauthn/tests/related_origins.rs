//! End-to-end related-origins integration tests (WebAuthn L3 §5.11).
//!
//! Drives `MakeCredentialRequest::from_json` / `GetAssertionRequest::from_json`
//! with a mock HTTP client and a tiny inline PSL impl. No network.

use async_trait::async_trait;

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, PublicSuffixList, RelatedOriginsHttpClient,
    RelyingPartyId, RequestOrigin, WebAuthnIDL, WellKnownFetchError, WellKnownResponse,
};

const KNOWN_SUFFIXES: &[&str] = &["com", "org"];

/// Minimal PSL recognising only `com` and `org`. Sufficient for these tests.
struct TestPsl;

impl PublicSuffixList for TestPsl {
    fn public_suffix(&self, host: &str) -> Option<String> {
        for suffix in KNOWN_SUFFIXES {
            if host == *suffix {
                return Some((*suffix).to_string());
            }
            let needle = format!(".{suffix}");
            if host.ends_with(&needle) {
                return Some((*suffix).to_string());
            }
        }
        None
    }
}

struct StaticHttp {
    body: &'static str,
}

#[async_trait]
impl RelatedOriginsHttpClient for StaticHttp {
    async fn fetch_well_known(
        &self,
        _: &RelyingPartyId,
    ) -> Result<WellKnownResponse, WellKnownFetchError> {
        Ok(WellKnownResponse {
            content_type: Some("application/json".into()),
            body: self.body.as_bytes().to_vec(),
        })
    }
}

const MAKE_CREDENTIAL_JSON: &str = r#"
{
    "rp": {"id": "example.org", "name": "example.org"},
    "user": {
        "id": "dXNlcmlk",
        "name": "mario.rossi",
        "displayName": "Mario Rossi"
    },
    "challenge": "Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu",
    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    "timeout": 30000,
    "excludeCredentials": [],
    "authenticatorSelection": {
        "residentKey": "discouraged",
        "userVerification": "preferred"
    },
    "attestation": "none"
}
"#;

const GET_ASSERTION_JSON: &str = r#"
{
    "challenge": "Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu",
    "timeout": 30000,
    "rpId": "example.org",
    "allowCredentials": [
        {"type": "public-key", "id": "bXktY3JlZGVudGlhbC1pZA"}
    ],
    "userVerification": "preferred"
}
"#;

// Caller and rp.id sit on different eTLDs (`example.com` vs `example.org`),
// matching the §8.3 design example so the related-origins fetch path is
// actually exercised.
const WELL_KNOWN_BODY: &str = r#"{"origins":["https://app.example.com","https://example.org"]}"#;

#[tokio::test]
async fn end_to_end_mock_match_via_make_credential() {
    let request_origin: RequestOrigin = "https://app.example.com".parse().unwrap();
    let http = StaticHttp {
        body: WELL_KNOWN_BODY,
    };

    let req =
        MakeCredentialRequest::from_json(&request_origin, &TestPsl, &http, MAKE_CREDENTIAL_JSON)
            .await
            .unwrap();

    assert_eq!(req.relying_party.id, "example.org");
    assert!(req
        .client_data_json()
        .contains(r#""origin":"https://app.example.com""#));
}

#[tokio::test]
async fn end_to_end_mock_match_via_get_assertion() {
    let request_origin: RequestOrigin = "https://app.example.com".parse().unwrap();
    let http = StaticHttp {
        body: WELL_KNOWN_BODY,
    };

    let req = GetAssertionRequest::from_json(&request_origin, &TestPsl, &http, GET_ASSERTION_JSON)
        .await
        .unwrap();

    assert_eq!(req.relying_party_id, "example.org");
    assert!(req
        .client_data_json()
        .contains(r#""origin":"https://app.example.com""#));
}
