//! Related-origins validation (WebAuthn L3 §5.11). Matching lives here in the
//! core. The allowed origins for an rp.id come from a [`RelatedOriginsSource`],
//! the default [`WellKnownRelatedOriginsSource`] fetching the well-known
//! document over an [`HttpClient`].

use std::collections::{BTreeSet, HashMap};

use async_trait::async_trait;
use serde::Deserialize;
use url::{Host, Url};

use super::idl::origin::{Origin, Scheme};
use super::idl::rpid::RelyingPartyId;
use super::psl::PublicSuffixList;

#[cfg(feature = "reqwest-related-origins-source")]
mod reqwest_impl;

#[cfg(feature = "reqwest-related-origins-source")]
pub use reqwest_impl::{HttpPolicy, ReqwestHttpClient, ReqwestRelatedOriginsSource};

/// Cap on distinct registrable-domain labels considered during matching
/// (WebAuthn L3 §5.11). Cannot hold a value below the spec floor of five.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxRegistrableLabels(usize);

impl MaxRegistrableLabels {
    /// Absolute cap, or `None` if below the floor of five.
    pub const fn new(n: usize) -> Option<Self> {
        if n >= 5 {
            Some(Self(n))
        } else {
            None
        }
    }

    /// `n` labels beyond the floor of five.
    pub const fn extra(n: usize) -> Self {
        Self(5usize.saturating_add(n))
    }
}

impl Default for MaxRegistrableLabels {
    fn default() -> Self {
        Self(5)
    }
}

impl From<MaxRegistrableLabels> for usize {
    fn from(value: MaxRegistrableLabels) -> Self {
        value.0
    }
}

/// Transport failure modes for [`HttpClient::get`].
#[derive(thiserror::Error, Debug, Clone)]
pub enum HttpClientError {
    /// TLS, DNS, timeout, rejected redirect, stream interrupt, client build, etc.
    #[error("transport error: {0}")]
    Transport(String),
    /// Body exceeded the implementation's configured size cap before completion.
    #[error("response body exceeded the configured size cap")]
    BodyTooLarge,
}

/// Minimal HTTP GET for fetching the well-known document. Implementations MUST
/// send no credentials or Referer, follow only `https://` redirects, and cap the
/// body size and duration. Status is returned as data, the body unparsed.
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn get(&self, url: &Url) -> Result<http::Response<Vec<u8>>, HttpClientError>;
}

/// Supplies the set of allowed origins for an RP id (WebAuthn L3 §5.11).
/// [`WellKnownRelatedOriginsSource`] is the default, fetching the well-known
/// document; a caller that already holds the list may implement this directly.
#[async_trait]
pub trait RelatedOriginsSource: Send + Sync {
    async fn allowed_origins(
        &self,
        rp_id: &RelyingPartyId,
    ) -> Result<Vec<String>, RelatedOriginsError>;
}

/// How related-origins is handled for a request.
pub enum RelatedOrigins<'a> {
    /// Do not consult related origins; a mismatching rp.id is rejected.
    Disabled,
    /// Resolve allowed origins through `source` and match, considering at most
    /// `max_labels` distinct registrable-domain labels.
    Enabled {
        source: &'a dyn RelatedOriginsSource,
        max_labels: MaxRegistrableLabels,
    },
}

/// Failure modes when resolving or matching related origins.
#[derive(thiserror::Error, Debug, Clone)]
pub enum RelatedOriginsError {
    #[error("http error: {0}")]
    Http(#[from] HttpClientError),
    /// Endpoint replied with a non-200 status (after following redirects).
    #[error("unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
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

pub type RelatedOriginsResult = Result<(), RelatedOriginsError>;

#[derive(Debug, Deserialize)]
struct WellKnownDocument {
    origins: Vec<String>,
}

/// [`RelatedOriginsSource`] that fetches `https://{rp_id}/.well-known/webauthn`
/// over an [`HttpClient`] and returns its `origins` array (WebAuthn L3 §5.11.1
/// step 2). Generic over the transport.
pub struct WellKnownRelatedOriginsSource<C: HttpClient> {
    http: C,
}

impl<C: HttpClient> WellKnownRelatedOriginsSource<C> {
    /// Wrap an [`HttpClient`] as a well-known related-origins source.
    pub fn from_client(http: C) -> Self {
        Self { http }
    }
}

#[async_trait]
impl<C: HttpClient> RelatedOriginsSource for WellKnownRelatedOriginsSource<C> {
    async fn allowed_origins(
        &self,
        rp_id: &RelyingPartyId,
    ) -> Result<Vec<String>, RelatedOriginsError> {
        let url = Url::parse(&format!("https://{}/.well-known/webauthn", rp_id.0))
            .map_err(|e| RelatedOriginsError::MalformedDocument(format!("invalid rp id: {e}")))?;
        let resp = self.http.get(&url).await?;
        if resp.status() != http::StatusCode::OK {
            return Err(RelatedOriginsError::UnexpectedStatus(
                resp.status().as_u16(),
            ));
        }
        let content_type = resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let content_type_ok = content_type
            .as_deref()
            .map(is_application_json)
            .unwrap_or(false);
        if !content_type_ok {
            return Err(RelatedOriginsError::UnexpectedContentType(content_type));
        }

        let value: serde_json::Value = serde_json::from_slice(resp.body())
            .map_err(|e| RelatedOriginsError::MalformedJson(e.to_string()))?;
        if !value.is_object() {
            return Err(RelatedOriginsError::MalformedJson(
                "top-level value is not a JSON object".into(),
            ));
        }
        let doc: WellKnownDocument = serde_json::from_value(value)
            .map_err(|e| RelatedOriginsError::MalformedDocument(e.to_string()))?;
        Ok(doc.origins)
    }
}

/// [`RelatedOriginsSource`] backed by an in-memory map of rp.id to its known
/// related origins, for callers that already hold the list and want no fetch.
pub struct StaticRelatedOriginsSource {
    by_rp_id: HashMap<String, Vec<String>>,
}

impl StaticRelatedOriginsSource {
    /// Source for a single rp.id and its known related origins.
    pub fn new(
        rp_id: impl Into<String>,
        origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let mut by_rp_id = HashMap::new();
        by_rp_id.insert(rp_id.into(), origins.into_iter().map(Into::into).collect());
        Self { by_rp_id }
    }

    /// Source backed by a map of rp.id to its known related origins.
    pub fn from_map(by_rp_id: HashMap<String, Vec<String>>) -> Self {
        Self { by_rp_id }
    }
}

#[async_trait]
impl RelatedOriginsSource for StaticRelatedOriginsSource {
    async fn allowed_origins(
        &self,
        rp_id: &RelyingPartyId,
    ) -> Result<Vec<String>, RelatedOriginsError> {
        Ok(self
            .by_rp_id
            .get(rp_id.0.as_str())
            .cloned()
            .unwrap_or_default())
    }
}

/// Runs the WebAuthn L3 §5.11.1 matching procedure: returns `Ok(())` if
/// `caller_origin` is same-origin with one of `origins`, considering at most
/// `max_labels` distinct registrable-domain labels.
pub fn validate_related_origins(
    caller_origin: &Origin,
    origins: &[String],
    psl: &dyn PublicSuffixList,
    max_labels: MaxRegistrableLabels,
) -> RelatedOriginsResult {
    let cap: usize = max_labels.into();
    let mut labels_seen: BTreeSet<String> = BTreeSet::new();
    for origin_item in origins {
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
        if labels_seen.len() >= cap && !labels_seen.contains(&label) {
            continue;
        }
        if same_origin(caller_origin, &url) {
            return Ok(());
        }
        if labels_seen.len() < cap {
            labels_seen.insert(label);
        }
    }

    Err(RelatedOriginsError::NoMatchingOrigin)
}

/// First label of `host`'s registrable domain (eTLD+1), or `None` if `host` has no registrable domain.
pub(crate) fn registrable_origin_label(host: &str, psl: &dyn PublicSuffixList) -> Option<String> {
    let registrable = psl.registrable_domain(host)?;
    let label = registrable.split('.').next()?;
    if label.is_empty() {
        return None;
    }
    Some(label.to_string())
}

/// Effective domain of `url` per HTML §6.2, or `None` for opaque or host-less URLs.
fn effective_domain_of(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(d) => Some(d.to_string()),
        Host::Ipv4(ip) => Some(ip.to_string()),
        Host::Ipv6(ip) => Some(format!("[{ip}]")),
    }
}

/// Tuple-origin (scheme, host, port) equality per WebAuthn L3 §5.11.1 step 4.f.
fn same_origin(caller: &Origin, listed: &Url) -> bool {
    if caller.scheme.as_str() != listed.scheme() {
        return false;
    }
    let Some(listed_host) = effective_domain_of(listed) else {
        return false;
    };
    if caller.host.as_str() != listed_host {
        return false;
    }
    let caller_port = caller.port.or_else(|| default_port(caller.scheme));
    caller_port == listed.port_or_known_default()
}

/// Default port per the WHATWG URL Standard special-scheme port table.
fn default_port(scheme: Scheme) -> Option<u16> {
    match scheme {
        Scheme::Https => Some(443),
        Scheme::Http => Some(80),
    }
}

/// Fetch §2.5 `application/json` essence check; used for WebAuthn L3 §5.11.1 step 2.a.
fn is_application_json(value: &str) -> bool {
    let essence = value.split(';').next().unwrap_or("").trim();
    essence.eq_ignore_ascii_case("application/json")
}

#[cfg(test)]
mod tests {
    use super::super::psl::MockPublicSuffixList;
    use super::*;

    fn caller(s: &str) -> Origin {
        Origin::try_from(s).unwrap()
    }

    fn rp(s: &str) -> RelyingPartyId {
        RelyingPartyId::try_from(s).unwrap()
    }

    fn origins(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// Matches a caller origin against `items` with the default cap (5).
    fn validate(caller_s: &str, items: &[&str]) -> RelatedOriginsResult {
        validate_related_origins(
            &caller(caller_s),
            &origins(items),
            &MockPublicSuffixList,
            MaxRegistrableLabels::default(),
        )
    }

    // ---- MaxRegistrableLabels ----

    #[test]
    fn max_registrable_labels_enforces_floor() {
        assert_eq!(MaxRegistrableLabels::new(4), None);
        assert_eq!(MaxRegistrableLabels::new(0), None);
        assert_eq!(usize::from(MaxRegistrableLabels::new(5).unwrap()), 5);
        assert_eq!(usize::from(MaxRegistrableLabels::new(50).unwrap()), 50);
        assert_eq!(usize::from(MaxRegistrableLabels::extra(0)), 5);
        assert_eq!(usize::from(MaxRegistrableLabels::extra(3)), 8);
        assert_eq!(usize::from(MaxRegistrableLabels::default()), 5);
    }

    // ---- registrable_origin_label ----

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

    // ---- matching (validate_related_origins) ----

    #[test]
    fn same_origin_caller_listed_first() {
        assert!(matches!(
            validate("https://example.com", &["https://example.com"]),
            Ok(())
        ));
    }

    #[test]
    fn same_origin_with_port_match() {
        assert!(matches!(
            validate("https://example.com:8443", &["https://example.com:8443"]),
            Ok(())
        ));
    }

    #[test]
    fn same_origin_with_port_mismatch_rejected() {
        assert!(matches!(
            validate("https://example.com", &["https://example.com:8443"]),
            Err(RelatedOriginsError::NoMatchingOrigin)
        ));
    }

    #[test]
    fn same_origin_default_port_normalised() {
        assert!(matches!(
            validate("https://example.com", &["https://example.com:443"]),
            Ok(())
        ));
    }

    #[test]
    fn caller_listed_after_other_origins() {
        // Substituted `.de` with `.net` (MockPublicSuffixList lacks `.de`).
        assert!(matches!(
            validate(
                "https://example.com",
                &["https://other.net", "https://example.com"]
            ),
            Ok(())
        ));
    }

    #[test]
    fn label_cap_allows_fifth_distinct_label_match() {
        // The 5th distinct label is still within the cap.
        assert!(matches!(
            validate(
                "https://example.com",
                &[
                    "https://a.com",
                    "https://b.com",
                    "https://c.com",
                    "https://d.com",
                    "https://example.com",
                ]
            ),
            Ok(())
        ));
    }

    #[test]
    fn label_cap_blocks_sixth_distinct_label_match() {
        // A sixth distinct label is silently skipped, so the would-be match
        // never reaches the same-origin check.
        assert!(matches!(
            validate(
                "https://example.com",
                &[
                    "https://a.com",
                    "https://b.com",
                    "https://c.com",
                    "https://d.com",
                    "https://e.com",
                    "https://example.com",
                ]
            ),
            Err(RelatedOriginsError::NoMatchingOrigin)
        ));
    }

    #[test]
    fn higher_cap_allows_sixth_distinct_label_match() {
        // With a cap of 6 the previously-blocked sixth label matches.
        let res = validate_related_origins(
            &caller("https://example.com"),
            &origins(&[
                "https://a.com",
                "https://b.com",
                "https://c.com",
                "https://d.com",
                "https://e.com",
                "https://example.com",
            ]),
            &MockPublicSuffixList,
            MaxRegistrableLabels::extra(1),
        );
        assert!(matches!(res, Ok(())));
    }

    #[test]
    fn label_cap_allows_repeats_of_seen_label() {
        // Once `example` has been recorded, further `example`-label origins
        // still proceed to the same-origin check.
        assert!(matches!(
            validate(
                "https://login.example.com",
                &[
                    "https://a.example.com",
                    "https://b.example.com",
                    "https://c.example.com",
                    "https://d.example.com",
                    "https://e.example.com",
                    "https://login.example.com",
                ]
            ),
            Ok(())
        ));
    }

    #[test]
    fn https_caller_vs_http_listed_rejected() {
        // Scheme differs, so the listed http origin is never same-origin.
        assert!(matches!(
            validate("https://example.com", &["http://example.com"]),
            Err(RelatedOriginsError::NoMatchingOrigin)
        ));
    }

    #[test]
    fn unparseable_origin_item_skipped() {
        assert!(matches!(
            validate("https://example.com", &["not a url", "https://example.com"]),
            Ok(())
        ));
    }

    #[test]
    fn non_https_origin_item_skipped_not_rejected() {
        assert!(matches!(
            validate(
                "https://example.com",
                &["data:text/plain,foo", "https://example.com"]
            ),
            Ok(())
        ));
    }

    #[test]
    fn unknown_suffix_origin_skipped() {
        // `internal.localhost` has no registrable domain in MockPSL.
        assert!(matches!(
            validate(
                "https://example.com",
                &["https://internal.localhost", "https://example.com"]
            ),
            Ok(())
        ));
    }

    #[test]
    fn bare_etld_origin_skipped() {
        // Registrable origin label is None for `co.uk`.
        assert!(matches!(
            validate(
                "https://example.co.uk",
                &["https://co.uk", "https://example.co.uk"]
            ),
            Ok(())
        ));
    }

    #[test]
    fn no_match_returns_no_matching_origin() {
        assert!(matches!(
            validate("https://example.com", &["https://elsewhere.com"]),
            Err(RelatedOriginsError::NoMatchingOrigin)
        ));
    }

    #[test]
    fn empty_origins_no_match() {
        assert!(matches!(
            validate("https://example.com", &[]),
            Err(RelatedOriginsError::NoMatchingOrigin)
        ));
    }

    #[test]
    fn listed_origin_with_path_still_matches() {
        // Same-origin compares (scheme, host, port) only, so a trailing path on
        // the listed entry must not block the match.
        assert!(matches!(
            validate("https://example.com", &["https://example.com/foo"]),
            Ok(())
        ));
    }

    #[test]
    fn ipv6_listed_origin_skipped_no_registrable_label() {
        // IPv6 host has no registrable label; the loop skips it.
        assert!(matches!(
            validate("https://[::1]", &["https://[::1]"]),
            Err(RelatedOriginsError::NoMatchingOrigin)
        ));
    }

    // ---- well-known source fetch/parse ----

    struct MockHttpClient {
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    }

    #[async_trait]
    impl HttpClient for MockHttpClient {
        async fn get(&self, _url: &Url) -> Result<http::Response<Vec<u8>>, HttpClientError> {
            let mut builder = http::Response::builder().status(self.status);
            if let Some(ct) = &self.content_type {
                builder = builder.header(http::header::CONTENT_TYPE, ct);
            }
            Ok(builder.body(self.body.clone()).unwrap())
        }
    }

    struct ErrHttpClient(HttpClientError);

    #[async_trait]
    impl HttpClient for ErrHttpClient {
        async fn get(&self, _url: &Url) -> Result<http::Response<Vec<u8>>, HttpClientError> {
            Err(self.0.clone())
        }
    }

    async fn fetch(
        status: u16,
        content_type: Option<&str>,
        body: &str,
    ) -> Result<Vec<String>, RelatedOriginsError> {
        let source = WellKnownRelatedOriginsSource::from_client(MockHttpClient {
            status,
            content_type: content_type.map(str::to_owned),
            body: body.as_bytes().to_vec(),
        });
        source.allowed_origins(&rp("example.com")).await
    }

    #[tokio::test]
    async fn well_known_returns_origins() {
        let res = fetch(
            200,
            Some("application/json"),
            r#"{"origins":["https://example.com"]}"#,
        )
        .await;
        assert_eq!(res.unwrap(), vec!["https://example.com".to_string()]);
    }

    #[tokio::test]
    async fn non_200_status_rejected() {
        assert!(matches!(
            fetch(404, Some("application/json"), r#"{"origins":[]}"#).await,
            Err(RelatedOriginsError::UnexpectedStatus(404))
        ));
    }

    #[tokio::test]
    async fn wrong_content_type_rejected() {
        assert!(matches!(
            fetch(200, Some("text/html"), r#"{"origins":[]}"#).await,
            Err(RelatedOriginsError::UnexpectedContentType(_))
        ));
    }

    #[tokio::test]
    async fn missing_content_type_rejected() {
        assert!(matches!(
            fetch(200, None, r#"{"origins":[]}"#).await,
            Err(RelatedOriginsError::UnexpectedContentType(None))
        ));
    }

    #[tokio::test]
    async fn content_type_with_charset_accepted() {
        let res = fetch(
            200,
            Some("application/json; charset=utf-8"),
            r#"{"origins":["https://elsewhere.com"]}"#,
        )
        .await;
        assert_eq!(res.unwrap(), vec!["https://elsewhere.com".to_string()]);
    }

    #[tokio::test]
    async fn content_type_case_insensitive() {
        let res = fetch(
            200,
            Some("Application/JSON"),
            r#"{"origins":["https://example.com"]}"#,
        )
        .await;
        assert_eq!(res.unwrap(), vec!["https://example.com".to_string()]);
    }

    #[tokio::test]
    async fn malformed_json_rejected() {
        assert!(matches!(
            fetch(200, Some("application/json"), "{not json}").await,
            Err(RelatedOriginsError::MalformedJson(_))
        ));
    }

    #[tokio::test]
    async fn non_object_json_rejected() {
        assert!(matches!(
            fetch(200, Some("application/json"), "[1,2,3]").await,
            Err(RelatedOriginsError::MalformedJson(_))
        ));
    }

    #[tokio::test]
    async fn missing_origins_key_rejected() {
        assert!(matches!(
            fetch(200, Some("application/json"), "{}").await,
            Err(RelatedOriginsError::MalformedDocument(_))
        ));
    }

    #[tokio::test]
    async fn origins_not_array_rejected() {
        assert!(matches!(
            fetch(
                200,
                Some("application/json"),
                r#"{"origins":"https://example.com"}"#
            )
            .await,
            Err(RelatedOriginsError::MalformedDocument(_))
        ));
    }

    #[tokio::test]
    async fn origins_array_of_non_strings_rejected() {
        assert!(matches!(
            fetch(200, Some("application/json"), r#"{"origins":[1,2,3]}"#).await,
            Err(RelatedOriginsError::MalformedDocument(_))
        ));
    }

    #[tokio::test]
    async fn transport_error_propagates_as_http() {
        let source = WellKnownRelatedOriginsSource::from_client(ErrHttpClient(
            HttpClientError::Transport("simulated".into()),
        ));
        let res = source.allowed_origins(&rp("example.com")).await;
        assert!(matches!(
            res,
            Err(RelatedOriginsError::Http(HttpClientError::Transport(_)))
        ));
    }

    #[tokio::test]
    async fn static_source_returns_listed_origins() {
        let single = StaticRelatedOriginsSource::new("example.com", ["https://app.example.org"]);
        assert_eq!(
            single.allowed_origins(&rp("example.com")).await.unwrap(),
            vec!["https://app.example.org".to_string()]
        );
        assert!(single
            .allowed_origins(&rp("other.com"))
            .await
            .unwrap()
            .is_empty());

        let multi = StaticRelatedOriginsSource::from_map(
            [("a.com".to_string(), vec!["https://x.org".to_string()])]
                .into_iter()
                .collect(),
        );
        assert_eq!(
            multi.allowed_origins(&rp("a.com")).await.unwrap(),
            vec!["https://x.org".to_string()]
        );
    }
}
