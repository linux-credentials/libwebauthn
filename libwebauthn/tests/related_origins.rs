//! End-to-end related-origins integration tests (WebAuthn L3 §5.11). Drives
//! `prepare` with a mock HTTP client behind the well-known source and a tiny
//! inline PSL. No network.

use async_trait::async_trait;

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, HttpClient, HttpClientError, MakeCredentialRequest, MaxRegistrableLabels,
    PublicSuffixList, RelatedOrigins, RequestOrigin, RequestSettings,
    WellKnownRelatedOriginsSource,
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
impl HttpClient for StaticHttp {
    async fn get(&self, _: &url::Url) -> Result<http::Response<Vec<u8>>, HttpClientError> {
        Ok(http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(self.body.as_bytes().to_vec())
            .unwrap())
    }
}

const MAKE_CREDENTIAL_JSON: &str = r#"
{
    "rp": {"id": "example.org", "name": "example.org"},
    "user": {
        "id": "dXNlcmlk",
        "name": "alice",
        "displayName": "Alice"
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

// Caller and rp.id sit on different eTLDs (`example.com` vs `example.org`) so the
// related-origins fetch path is actually exercised.
const WELL_KNOWN_BODY: &str = r#"{"origins":["https://app.example.com","https://example.org"]}"#;

fn settings<'a>(
    psl: &'a TestPsl,
    source: &'a WellKnownRelatedOriginsSource<StaticHttp>,
) -> RequestSettings<'a> {
    RequestSettings {
        public_suffix_list: psl,
        related_origins: RelatedOrigins::Enabled {
            source,
            max_labels: MaxRegistrableLabels::default(),
        },
    }
}

#[tokio::test]
async fn end_to_end_mock_match_via_make_credential() {
    let request_origin: RequestOrigin = "https://app.example.com".parse().unwrap();
    let psl = TestPsl;
    let source = WellKnownRelatedOriginsSource::from_client(StaticHttp {
        body: WELL_KNOWN_BODY,
    });

    let req = MakeCredentialRequest::prepare(
        &request_origin,
        MAKE_CREDENTIAL_JSON,
        &settings(&psl, &source),
    )
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
    let psl = TestPsl;
    let source = WellKnownRelatedOriginsSource::from_client(StaticHttp {
        body: WELL_KNOWN_BODY,
    });

    let req = GetAssertionRequest::prepare(
        &request_origin,
        GET_ASSERTION_JSON,
        &settings(&psl, &source),
    )
    .await
    .unwrap();

    assert_eq!(req.relying_party_id, "example.org");
    assert!(req
        .client_data_json()
        .contains(r#""origin":"https://app.example.com""#));
}
