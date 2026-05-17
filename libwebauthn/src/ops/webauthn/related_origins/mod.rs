//! Related-origins validation (WebAuthn L3 §5.11).
//!
//! The HTTP fetch of the `webauthn` well-known document is abstracted behind
//! [`RelatedOriginsHttpClient`]; a reqwest-backed default lives in [`http`]
//! behind the `related-origins-client` cargo feature.

use std::collections::BTreeSet;

use async_trait::async_trait;
use serde::Deserialize;
use url::{Host, Url};

use super::idl::origin::Origin;
use super::idl::rpid::RelyingPartyId;
use super::psl::PublicSuffixList;

#[cfg(feature = "related-origins-client")]
pub mod http;

/// WebAuthn L3 §5.11 requires support for at least 5 registrable origin labels;
/// we cap at exactly 5 to bound abuse surface.
const MAX_REGISTRABLE_LABELS: usize = 5;

#[derive(Debug, Clone)]
pub struct WellKnownResponse {
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// Fetcher for `https://{rp_id}/.well-known/webauthn`, per WebAuthn L3 §5.11.1
/// step 2. Implementations MUST send no credentials, no Referer, refuse
/// non-`https://` redirects, cap the body size, and bound the request duration.
/// Implementations MUST return `Err(FetchFailed)` for any status code other
/// than 200 (after following redirects). Implementations MUST report the wire
/// `Content-Type` header value unmodified (or `None` if absent) and MUST NOT
/// synthesise an `application/json` content type for non-JSON responses.
#[async_trait]
pub trait RelatedOriginsHttpClient: Send + Sync {
    async fn fetch_well_known(
        &self,
        rp_id: &RelyingPartyId,
    ) -> Result<WellKnownResponse, RelatedOriginsError>;
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum RelatedOriginsError {
    #[error("well-known fetch failed: {0}")]
    FetchFailed(String),
    #[error("unexpected content type: {0:?}")]
    UnexpectedContentType(Option<String>),
    /// Step 2.b: body did not decode as JSON.
    #[error("malformed JSON body: {0}")]
    MalformedJson(String),
    /// Step 2.c: top-level `origins` was missing or not an array of strings.
    #[error("malformed well-known document: {0}")]
    MalformedDocument(String),
    #[error("no listed related origin matches the caller origin")]
    NoMatchingOrigin,
}

impl RelatedOriginsError {
    /// Static, log-safe variant discriminant. Use in place of the `Debug` /
    /// `Display` impls when the error may carry reqwest- or serde-supplied
    /// text (IPs, body snippets) that should not reach operator logs.
    pub fn kind(&self) -> &'static str {
        match self {
            RelatedOriginsError::FetchFailed(_) => "fetch_failed",
            RelatedOriginsError::UnexpectedContentType(_) => "unexpected_content_type",
            RelatedOriginsError::MalformedJson(_) => "malformed_json",
            RelatedOriginsError::MalformedDocument(_) => "malformed_document",
            RelatedOriginsError::NoMatchingOrigin => "no_matching_origin",
        }
    }
}

pub type RelatedOriginsResult = Result<(), RelatedOriginsError>;

#[derive(Debug, Deserialize)]
struct WellKnownDocument {
    origins: Vec<String>,
}

/// Runs the WebAuthn L3 §5.11.1 related-origins validation procedure.
/// Returns `Ok(())` when a listed origin matches `caller_origin`, otherwise
/// returns the first fetch/parse error or [`RelatedOriginsError::NoMatchingOrigin`].
pub async fn validate_related_origins(
    caller_origin: &Origin,
    rp_id: &RelyingPartyId,
    psl: &dyn PublicSuffixList,
    http: &dyn RelatedOriginsHttpClient,
) -> RelatedOriginsResult {
    let resp = http.fetch_well_known(rp_id).await?;
    let content_type_ok = resp
        .content_type
        .as_deref()
        .map(is_application_json)
        .unwrap_or(false);
    if !content_type_ok {
        return Err(RelatedOriginsError::UnexpectedContentType(
            resp.content_type,
        ));
    }

    let value: serde_json::Value = serde_json::from_slice(&resp.body)
        .map_err(|e| RelatedOriginsError::MalformedJson(e.to_string()))?;
    if !value.is_object() {
        return Err(RelatedOriginsError::MalformedJson(
            "top-level value is not a JSON object".into(),
        ));
    }
    let doc: WellKnownDocument = serde_json::from_value(value)
        .map_err(|e| RelatedOriginsError::MalformedDocument(e.to_string()))?;

    let mut labels_seen: BTreeSet<String> = BTreeSet::new();
    for origin_item in &doc.origins {
        let Ok(url) = Url::parse(origin_item) else {
            continue;
        };
        let Some(domain) = effective_domain_of(&url) else {
            continue;
        };
        let label = match registrable_origin_label(&domain, psl) {
            Some(l) if !l.is_empty() => l,
            _ => continue,
        };
        if labels_seen.len() >= MAX_REGISTRABLE_LABELS && !labels_seen.contains(&label) {
            continue;
        }
        if same_origin(caller_origin, &url) {
            return Ok(());
        }
        if labels_seen.len() < MAX_REGISTRABLE_LABELS {
            labels_seen.insert(label);
        }
    }

    Err(RelatedOriginsError::NoMatchingOrigin)
}

/// First label of `host`'s registrable domain (eTLD+1), or `None` when the host
/// has no registrable domain (e.g. bare eTLD, IP literal, unknown TLD).
pub(crate) fn registrable_origin_label(host: &str, psl: &dyn PublicSuffixList) -> Option<String> {
    let registrable = psl.registrable_domain(host)?;
    let label = registrable.split('.').next()?;
    if label.is_empty() {
        return None;
    }
    Some(label.to_string())
}

/// Effective domain of a URL per HTML §6.2: domain hosts and IP literals; opaque
/// hosts and host-less URLs return `None`.
fn effective_domain_of(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(d) => Some(d.to_string()),
        Host::Ipv4(ip) => Some(ip.to_string()),
        Host::Ipv6(ip) => Some(format!("[{ip}]")),
    }
}

/// WebAuthn L3 §5.11.1 step 4.f: typed-origin equality between the caller's
/// origin and the listed entry's tuple origin.
fn same_origin(caller: &Origin, listed: &Url) -> bool {
    let Ok(listed_str) = listed.as_str().parse::<Origin>() else {
        return false;
    };
    *caller == listed_str
}

/// Fetch §2.5 `application/json` essence check: case-insensitive, parameters
/// ignored. Used for WebAuthn L3 §5.11.1 step 2.a.
fn is_application_json(value: &str) -> bool {
    let essence = value.split(';').next().unwrap_or("").trim();
    essence.eq_ignore_ascii_case("application/json")
}

/// `RelatedOriginsHttpClient` that always refuses; preserves today's
/// "mismatching rp.id is a hard error" semantics for callers that do not opt
/// into related-origin fetches.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRelatedOriginsClient;

#[async_trait]
impl RelatedOriginsHttpClient for NoRelatedOriginsClient {
    async fn fetch_well_known(
        &self,
        _: &RelyingPartyId,
    ) -> Result<WellKnownResponse, RelatedOriginsError> {
        Err(RelatedOriginsError::FetchFailed(
            "this client does not support related origin requests".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::psl::MockPublicSuffixList;
    use super::*;

    struct MockClient {
        response: Result<WellKnownResponse, RelatedOriginsError>,
    }

    #[async_trait]
    impl RelatedOriginsHttpClient for MockClient {
        async fn fetch_well_known(
            &self,
            _: &RelyingPartyId,
        ) -> Result<WellKnownResponse, RelatedOriginsError> {
            self.response.clone()
        }
    }

    fn json_ct(body: &str) -> WellKnownResponse {
        WellKnownResponse {
            content_type: Some("application/json".into()),
            body: body.as_bytes().to_vec(),
        }
    }

    fn caller(s: &str) -> Origin {
        Origin::try_from(s).unwrap()
    }

    fn rp(s: &str) -> RelyingPartyId {
        RelyingPartyId::try_from(s).unwrap()
    }

    #[test]
    fn registrable_origin_label_basic() {
        let psl = MockPublicSuffixList;
        assert_eq!(
            registrable_origin_label("example.co.uk", &psl).as_deref(),
            Some("example"),
        );
        assert_eq!(
            registrable_origin_label("www.example.org", &psl).as_deref(),
            Some("example"),
        );
        assert_eq!(registrable_origin_label("co.uk", &psl), None);
        assert_eq!(registrable_origin_label("localhost", &psl), None);
    }

    #[test]
    fn registrable_origin_label_ipv4_is_none() {
        let psl = MockPublicSuffixList;
        assert_eq!(registrable_origin_label("127.0.0.1", &psl), None);
    }

    #[tokio::test]
    async fn same_origin_caller_listed_first() {
        let body = r#"{"origins":["https://example.com"]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Ok(())));
    }

    #[tokio::test]
    async fn same_origin_with_port_match() {
        let body = r#"{"origins":["https://example.com:8443"]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://example.com:8443"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Ok(())));
    }

    #[tokio::test]
    async fn same_origin_with_port_mismatch_rejected() {
        let body = r#"{"origins":["https://example.com:8443"]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Err(RelatedOriginsError::NoMatchingOrigin)));
    }

    #[tokio::test]
    async fn same_origin_default_port_normalised() {
        let body = r#"{"origins":["https://example.com:443"]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Ok(())));
    }

    #[tokio::test]
    async fn caller_listed_after_other_origins() {
        // Substituted `.de` with `.net` (MockPublicSuffixList lacks `.de`).
        let body = r#"{"origins":["https://other.net","https://example.com"]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Ok(())));
    }

    #[tokio::test]
    async fn label_cap_blocks_sixth_distinct_label_match() {
        // §5.11.1 step 4.e: a sixth distinct label is silently skipped, so the
        // would-be match never reaches step 4.f.
        let body = r#"{"origins":[
            "https://a.com",
            "https://b.com",
            "https://c.com",
            "https://d.com",
            "https://e.com",
            "https://example.com"
        ]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Err(RelatedOriginsError::NoMatchingOrigin)));
    }

    #[tokio::test]
    async fn label_cap_allows_repeats_of_seen_label() {
        // §5.11.1 step 4.e "contains label" exception: once `example` has been
        // recorded, further `example`-label origins still proceed to step 4.f.
        let body = r#"{"origins":[
            "https://a.example.com",
            "https://b.example.com",
            "https://c.example.com",
            "https://d.example.com",
            "https://e.example.com",
            "https://login.example.com"
        ]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://login.example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Ok(())));
    }

    #[tokio::test]
    async fn same_origin_https_vs_http_rejected() {
        // `http://example.com` is rejected by `Origin::try_from` (non-localhost),
        // so the listed entry can never be same-origin with the https caller.
        let body = r#"{"origins":["http://example.com"]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Err(RelatedOriginsError::NoMatchingOrigin)));
    }

    #[tokio::test]
    async fn unparseable_origin_item_skipped() {
        let body = r#"{"origins":["not a url","https://example.com"]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Ok(())));
    }

    #[tokio::test]
    async fn non_https_origin_item_skipped_not_rejected() {
        let body = r#"{"origins":["data:text/plain,foo","https://example.com"]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Ok(())));
    }

    #[tokio::test]
    async fn unknown_suffix_origin_skipped() {
        // `internal.localhost` has no registrable domain in MockPSL.
        let body = r#"{"origins":["https://internal.localhost","https://example.com"]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Ok(())));
    }

    #[tokio::test]
    async fn bare_etld_origin_skipped() {
        // §5.11.1 step 4.c returns None for `co.uk`.
        let body = r#"{"origins":["https://co.uk","https://example.co.uk"]}"#;
        let http = MockClient {
            response: Ok(json_ct(body)),
        };
        let res = validate_related_origins(
            &caller("https://example.co.uk"),
            &rp("example.co.uk"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Ok(())));
    }

    #[tokio::test]
    async fn wrong_content_type_rejected() {
        let http = MockClient {
            response: Ok(WellKnownResponse {
                content_type: Some("text/html".into()),
                body: b"{\"origins\":[]}".to_vec(),
            }),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(
            res,
            Err(RelatedOriginsError::UnexpectedContentType(_))
        ));
    }

    #[tokio::test]
    async fn missing_content_type_rejected() {
        let http = MockClient {
            response: Ok(WellKnownResponse {
                content_type: None,
                body: b"{\"origins\":[]}".to_vec(),
            }),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(
            res,
            Err(RelatedOriginsError::UnexpectedContentType(None))
        ));
    }

    #[tokio::test]
    async fn content_type_with_charset_accepted() {
        let http = MockClient {
            response: Ok(WellKnownResponse {
                content_type: Some("application/json; charset=utf-8".into()),
                body: br#"{"origins":["https://elsewhere.com"]}"#.to_vec(),
            }),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Err(RelatedOriginsError::NoMatchingOrigin)));
    }

    #[tokio::test]
    async fn content_type_case_insensitive() {
        let http = MockClient {
            response: Ok(WellKnownResponse {
                content_type: Some("Application/JSON".into()),
                body: br#"{"origins":["https://example.com"]}"#.to_vec(),
            }),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Ok(())));
    }

    #[tokio::test]
    async fn malformed_json_rejected() {
        let http = MockClient {
            response: Ok(json_ct("{not json}")),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Err(RelatedOriginsError::MalformedJson(_))));
    }

    #[tokio::test]
    async fn non_object_json_rejected() {
        let http = MockClient {
            response: Ok(json_ct("[1,2,3]")),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Err(RelatedOriginsError::MalformedJson(_))));
    }

    #[tokio::test]
    async fn missing_origins_key_rejected() {
        let http = MockClient {
            response: Ok(json_ct("{}")),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(
            res,
            Err(RelatedOriginsError::MalformedDocument(_))
        ));
    }

    #[tokio::test]
    async fn origins_not_array_rejected() {
        let http = MockClient {
            response: Ok(json_ct(r#"{"origins":"https://example.com"}"#)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(
            res,
            Err(RelatedOriginsError::MalformedDocument(_))
        ));
    }

    #[tokio::test]
    async fn origins_array_of_non_strings_rejected() {
        let http = MockClient {
            response: Ok(json_ct(r#"{"origins":[1,2,3]}"#)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(
            res,
            Err(RelatedOriginsError::MalformedDocument(_))
        ));
    }

    #[tokio::test]
    async fn empty_origins_array_no_match() {
        let http = MockClient {
            response: Ok(json_ct(r#"{"origins":[]}"#)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Err(RelatedOriginsError::NoMatchingOrigin)));
    }

    #[tokio::test]
    async fn fetch_error_propagates_as_fetch_failed() {
        let http = MockClient {
            response: Err(RelatedOriginsError::FetchFailed("simulated".into())),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Err(RelatedOriginsError::FetchFailed(_))));
    }

    #[tokio::test]
    async fn no_match_returns_no_matching_origin() {
        let http = MockClient {
            response: Ok(json_ct(r#"{"origins":["https://elsewhere.com"]}"#)),
        };
        let res = validate_related_origins(
            &caller("https://example.com"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Err(RelatedOriginsError::NoMatchingOrigin)));
    }

    #[tokio::test]
    async fn same_origin_with_ipv6_match() {
        // IPv6 host has no registrable label, so the loop skips at step 4.c/4.d
        // before reaching same-origin. This documents that bare IP-literal
        // origins cannot match via related-origins, matching browser behaviour.
        let http = MockClient {
            response: Ok(json_ct(r#"{"origins":["https://[::1]"]}"#)),
        };
        let res = validate_related_origins(
            &caller("https://[::1]"),
            &rp("example.com"),
            &MockPublicSuffixList,
            &http,
        )
        .await;
        assert!(matches!(res, Err(RelatedOriginsError::NoMatchingOrigin)));
    }
}
