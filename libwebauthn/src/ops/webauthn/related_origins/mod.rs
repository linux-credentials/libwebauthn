use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;
use url::Url;
use std::collections::HashSet;
use std::time::Duration;
use std::sync::OnceLock;

use bytes::BytesMut;
use futures::TryStreamExt;

/// Central policy/config for related-origins processing. Consumers may
/// construct a custom `PolicyConfig` and use it when building a client.
#[derive(Clone, Debug)]
struct PolicyConfig {
    pub max_body_bytes: usize,
    pub max_origins: usize,
    pub max_origin_len: usize,
    pub max_labels: usize,
    pub timeout_secs: u64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024, // 64 KiB
            max_origins: 500,
            max_origin_len: 2048,
            max_labels: 100,
            timeout_secs: 60,
        }
    }
}

/// Representation of the well-known JSON document at /.well-known/webauthn
#[derive(Debug, Deserialize)]
pub struct RelatedOriginsDocument {
    pub origins: Vec<String>,
}

/// Response from the HTTP fetch of the well-known document.
pub struct RelatedOriginsHttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: String,
}

#[derive(Error, Debug)]
pub enum RelatedOriginsError {
    #[error("security error")]
    SecurityError,
    #[error("http error: {0}")]
    HttpError(String),
    #[error("parse error: {0}")]
    ParseError(String),
}

/// Pluggable HTTP client used to fetch the well-known document.
#[async_trait]
pub trait RelatedOriginsHttpClient {
    async fn fetch_well_known(&self, rp_id: &str) -> Result<RelatedOriginsHttpResponse, RelatedOriginsError>;
}

/// Validate related origins according to WebAuthn §5.11.1.
///
/// `caller_origin` and `rp_id_requested` are origin strings (e.g. "https://example.com").
/// `client` is a pluggable HTTP client implementing `RelatedOriginsHttpClient`.
/// Validation uses the defaults from `PolicyConfig` for limits and timeouts.
pub async fn validate_related_origins_with_client<C>(
    caller_origin: &str,
    rp_id_requested: &str,
    client: &C,
) -> Result<bool, RelatedOriginsError>
where
    C: RelatedOriginsHttpClient + Sync,
{
    // Use default policy for validation.
    let policy = PolicyConfig::default();

    // Fetch the well-known URL for the RP ID
    let response = client.fetch_well_known(rp_id_requested).await.map_err(|_| RelatedOriginsError::SecurityError)?;

    if response.status != 200 {
        return Err(RelatedOriginsError::SecurityError);
    }

    match response.content_type {
        Some(content_type) => {
            let content_type_lower = content_type.to_ascii_lowercase();
            if !content_type_lower.starts_with("application/json") {
                return Err(RelatedOriginsError::SecurityError);
            }
        }
        None => return Err(RelatedOriginsError::SecurityError),
    }
    
    let doc: RelatedOriginsDocument = serde_json::from_str(&response.body).map_err(|e| RelatedOriginsError::ParseError(e.to_string()))?;

    // Structural checks per the spec: ensure a non-empty origins array within policy bounds
    if doc.origins.is_empty() || doc.origins.len() > policy.max_origins {
        return Err(RelatedOriginsError::SecurityError);
    }

    let mut labels_seen: HashSet<String> = HashSet::new();

    let caller_url = Url::parse(caller_origin).map_err(|e| RelatedOriginsError::ParseError(e.to_string()))?;

    for origin_item in doc.origins.iter() {
        // enforce per-origin checks (length, valid https URL with host)
        if origin_item.len() > policy.max_origin_len {
            return Err(RelatedOriginsError::SecurityError);
        }

        let url = match Url::parse(origin_item) {
            Ok(u) => u,
            Err(_) => continue,
        };

        if url.scheme() != "https" || url.host_str().is_none() {
            return Err(RelatedOriginsError::SecurityError);
        }

        let domain = match url.host_str() {
            Some(d) => d,
            None => continue,
        };

        let label = match registrable_origin_label(domain) {
            Some(l) if !l.is_empty() => l,
            _ => continue,
        };

        if labels_seen.len() >= policy.max_labels && !labels_seen.contains(&label) {
            continue;
        }

        // Check same-origin: scheme, host and port (taking default ports into account)
        let same_origin = caller_url.scheme() == url.scheme()
            && caller_url.host_str() == url.host_str()
            && caller_url.port_or_known_default() == url.port_or_known_default();

        if same_origin {
            return Ok(true);
        }

        if labels_seen.len() < policy.max_labels {
            labels_seen.insert(label);
        }
    }

    Ok(false)
}

/// Public wrapper that constructs a `ReqwestRelatedOriginsClient` and
/// delegates to `validate_related_origins_with_client`.
pub async fn validate_related_origins(
    caller_origin: &str,
    rp_id_requested: &str,
) -> Result<bool, RelatedOriginsError> {
    let client = match client::ReqwestRelatedOriginsClient::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("related_origins: failed to create HTTP client: {:?}", e);
            return Err(e);
        }
    };

    validate_related_origins_with_client(caller_origin, rp_id_requested, &client).await
}

// Client implementation is kept in the `client` submodule.
pub mod client;

/// Implimentation of https://url.spec.whatwg.org/#host-public-suffix
fn registrable_origin_label(domain: &str) -> Option<String> {
    // Implementation note:
    // We first attempt to use the Public Suffix List to compute the public
    // suffix, then derive the registrable label (the label immediately
    // left of the registrable domain). If the PSL is unavailable we fall
    // back to a simple heuristic.
    static PS_LIST: OnceLock<Option<publicsuffix::List>> = OnceLock::new();

    // Strip a trailing dot for processing but remember it (per PSL steps).
    let host = domain.trim_end_matches('.');

    if host.is_empty() {
        return None;
    }

    // Host must look like a domain (contain at least one dot)
    if !host.contains('.') {
        return None;
    }

    if let Some(list_opt) = PS_LIST.get_or_init(|| publicsuffix::List::fetch().ok()) {
        if let Ok(parsed) = list_opt.parse_domain(host) {
            // If the parsed result provides the registrable root (eTLD+1),
            // take the left-most label of that root as the registrable label.
            if let Some(root) = parsed.root() {
                if let Some(first_label) = root.split('.').next() {
                    // Ensure we return an ASCII label. The PSL crate returns
                    // already-normalised components; lower-case to be safe.
                    return Some(first_label.to_ascii_lowercase());
                }
            }
        }
    }

    // Fallback: take the label immediately left of the last dot.
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 2 { return None; }
    Some(parts[parts.len()-2].to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockClient { body: String }

    #[async_trait]
    impl RelatedOriginsHttpClient for MockClient {
        async fn fetch_well_known(&self, _rp_id: &str) -> Result<RelatedOriginsHttpResponse, RelatedOriginsError> {
            Ok(RelatedOriginsHttpResponse { status: 200, content_type: Some("application/json; charset=utf-8".into()), body: self.body.clone() })
        }
    }

    // Tests use the public API and the `registrable_origin_label` helper.

    #[tokio::test]
    async fn test_validate_related_origins_true() {
        let doc = r#"{"origins":["https://example.co.uk","https://example.de"]}"#;
        let client = MockClient { body: doc.into() };
        let res = validate_related_origins_with_client("https://example.co.uk", "example.com", &client).await.unwrap();
        assert!(res);
    }

    #[tokio::test]
    async fn test_validate_related_origins_false() {
        let doc = r#"{"origins":["https://different.example.co.uk"]}"#;
        let client = MockClient { body: doc.into() };
        let res = validate_related_origins_with_client("https://caller.example.com", "example.com", &client).await.unwrap();
        assert!(!res);
    }

    #[test]
    fn test_registrable_origin_label_basic() {
        assert_eq!(registrable_origin_label("example.co.uk"), Some("example".to_string()));
        assert_eq!(registrable_origin_label("example.com"), Some("example".to_string()));
        assert_eq!(registrable_origin_label("localhost"), None);
        assert_eq!(registrable_origin_label("com"), None);
    }

    #[tokio::test]
    async fn test_validate_empty_origins() {
        let doc = r#"{"origins":[]}"#;
        let client = MockClient { body: doc.into() };
        let res = validate_related_origins_with_client("https://caller.example.com", "example.com", &client).await;
        match res {
            Err(RelatedOriginsError::SecurityError) => (),
            other => panic!("expected SecurityError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_validate_non_https_origin() {
        let doc = r#"{"origins":["http://example.com"]}"#;
        let client = MockClient { body: doc.into() };
        let res = validate_related_origins_with_client("https://caller.example.com", "example.com", &client).await;
        match res {
            Err(RelatedOriginsError::SecurityError) => (),
            other => panic!("expected SecurityError for non-https origin, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_validate_origin_too_long() {
        // create a body with an origin string longer than the default max_origin_len
        let long_path = "a".repeat(2100);
        let origin = format!("https://example.com/{}", long_path);
        let doc = serde_json::json!({"origins": [origin]}).to_string();
        let client = MockClient { body: doc };
        let res = validate_related_origins_with_client("https://caller.example.com", "example.com", &client).await;
        match res {
            Err(RelatedOriginsError::SecurityError) => (),
            other => panic!("expected SecurityError for too-long origin, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_validate_labels_limit() {
        // create 101 distinct origins to exceed the default max_labels (100)
        let mut origins = Vec::new();
        for i in 0..101 {
            origins.push(format!("https://unique{}example.com", i));
        }
        let doc = serde_json::json!({"origins": origins}).to_string();
        let client = MockClient { body: doc };
        let res = validate_related_origins_with_client("https://caller.example.org", "example.com", &client).await.unwrap();
        // No same-origin entry, and labels exceed limit -> should be false
        assert!(!res);
    }
}
