use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;
use url::Url;
use std::collections::HashSet;
use std::time::Duration;
use std::sync::OnceLock;

use bytes::BytesMut;
use futures::TryStreamExt;

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
/// `max_labels` is the maximum number of registrable origin labels allowed by policy.
pub async fn validate_related_origins<C>(
    caller_origin: &str,
    rp_id_requested: &str,
    client: &C,
    max_labels: usize,
) -> Result<bool, RelatedOriginsError>
where
    C: RelatedOriginsHttpClient + Sync,
{
    // Enforce the WebAuthn requirement: callers MUST request at least five registrable origin labels.
    if max_labels < 5 {
        return Err(RelatedOriginsError::SecurityError);
    }
    
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
    
    let doc: RelatedOriginsDocument = serde_json::from_str(&response.body).map_err(|_| RelatedOriginsError::SecurityError)?;

    let mut labels_seen: HashSet<String> = HashSet::new();

    let caller_url = Url::parse(caller_origin).map_err(|e| RelatedOriginsError::ParseError(e.to_string()))?;

    for origin_item in doc.origins.iter() {
        let url = match Url::parse(origin_item) {
            Ok(u) => u,
            Err(_) => continue,
        };

        let domain = match url.host_str() {
            Some(d) => d,
            None => continue,
        };

        let label = match registrable_origin_label(domain) {
            Some(l) if !l.is_empty() => l,
            _ => continue,
        };

        if labels_seen.len() >= max_labels && !labels_seen.contains(&label) {
            continue;
        }

        // Check same-origin: scheme, host and port (taking default ports into account)
        let same_origin = caller_url.scheme() == url.scheme()
            && caller_url.host_str() == url.host_str()
            && caller_url.port_or_known_default() == url.port_or_known_default();

        if same_origin {
            return Ok(true);
        }

        if labels_seen.len() < max_labels {
            labels_seen.insert(label);
        }
    }

    Ok(false)
}

// Feature-gated safe HTTP client implementation using `reqwest`.
//#[cfg(feature = "related-origins-client")]
pub mod client {
    use super::*;
    use reqwest::redirect::Policy;
    use reqwest::StatusCode;

    const MAX_BODY_BYTES: usize = 64 * 1024; // 64 KiB
    const MAX_ORIGINS: usize = 500; // policy-configurable
    const MAX_ORIGIN_LEN: usize = 2048;
    const TIMEOUT_SECS: u64 = 5;

    pub struct ReqwestRelatedOriginsClient {
        inner: reqwest::Client,
    }

    impl ReqwestRelatedOriginsClient {
        pub fn new() -> Result<Self, RelatedOriginsError> {
            let policy = Policy::custom(|attempt| {
                // Enforce HTTPS on all redirects
                if attempt.url().scheme() != "https" {
                    return attempt.stop();
                }
                attempt.follow()
            });

            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(TIMEOUT_SECS))
                .redirect(policy)
                .build()
                .map_err(|e| RelatedOriginsError::HttpError(e.to_string()))?;

            Ok(ReqwestRelatedOriginsClient { inner: client })
        }
    }

    #[async_trait::async_trait]
    impl RelatedOriginsHttpClient for ReqwestRelatedOriginsClient {
        async fn fetch_well_known(&self, rp_id: &str) -> Result<RelatedOriginsHttpResponse, RelatedOriginsError> {
            let url = format!("https://{}/.well-known/webauthn", rp_id);

            // When issuing the request, avoid cookies/auth and set no Referer:
            let req = self.inner.get(&url).header(reqwest::header::REFERER, "");
            let resp = req.send().await.map_err(|e| RelatedOriginsError::HttpError(e.to_string()))?;

            let status = resp.status();
            if status != StatusCode::OK {
                return Err(RelatedOriginsError::SecurityError);
            }

            // Content-Type check
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            if let Some(ref ct) = content_type {
                if !ct.to_ascii_lowercase().starts_with("application/json") {
                    return Err(RelatedOriginsError::SecurityError);
                }
            } else {
                return Err(RelatedOriginsError::SecurityError);
            }

            // Enforce Content-Length if present
            if let Some(len) = resp.content_length() {
                if (len as usize) > MAX_BODY_BYTES {
                    return Err(RelatedOriginsError::SecurityError);
                }
            }

            // Stream body with a hard cap to avoid OOM or slowloris-style attacks
            let mut body_buf = BytesMut::with_capacity(1024);
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.try_next().await.map_err(|e| RelatedOriginsError::HttpError(e.to_string()))? {
                if body_buf.len() + chunk.len() > MAX_BODY_BYTES {
                    return Err(RelatedOriginsError::SecurityError);
                }
                body_buf.extend_from_slice(&chunk);
            }

            // Parse JSON and do structural checks before returning
            let doc: RelatedOriginsDocument = serde_json::from_slice(&body_buf)
                .map_err(|e| RelatedOriginsError::ParseError(e.to_string()))?;

            if doc.origins.is_empty() || doc.origins.len() > MAX_ORIGINS {
                return Err(RelatedOriginsError::SecurityError);
            }

            for origin in &doc.origins {
                if origin.len() > MAX_ORIGIN_LEN {
                    return Err(RelatedOriginsError::SecurityError);
                }
                // must parse and be https
                let u = Url::parse(origin).map_err(|_| RelatedOriginsError::SecurityError)?;
                if u.scheme() != "https" || u.host_str().is_none() {
                    return Err(RelatedOriginsError::SecurityError);
                }
            }

            Ok(RelatedOriginsHttpResponse { status: status.as_u16(), content_type, body: String::from_utf8_lossy(&body_buf).to_string() })
        }
    }
}

/// Simple eTLD+1 heuristic: return the label immediately left of the last dot.
/// Returns None if domain has fewer than 2 labels.
fn registrable_origin_label(domain: &str) -> Option<String> {
    // Prefer using the publicsuffix list to compute eTLD+1 when available.
    // Cache the fetched list in a OnceLock to avoid repeated network fetches.
    static PS_LIST: OnceLock<Option<publicsuffix::List>> = OnceLock::new();
    if let Some(list_opt) = PS_LIST.get_or_init(|| publicsuffix::List::fetch().ok()) {
        if let Ok(parsed) = list_opt.parse_domain(domain) {
            if let Some(root) = parsed.root() {
                if let Some(first_label) = root.split('.').next() {
                    return Some(first_label.to_string());
                }
            }
        }
    }

    // Fallback: simple heuristic - take the label immediately left of the last dot
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 { return None; }
    Some(parts[parts.len()-2].to_string())
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

    // previous helper removed; `registrable_origin_label` is used by the implementation

    #[tokio::test]
    async fn test_validate_related_origins_true() {
        let doc = r#"{"origins":["https://example.co.uk","https://example.de"]}"#;
        let client = MockClient { body: doc.into() };
        let res = validate_related_origins("https://example.co.uk", "example.com", &client, 5).await.unwrap();
        assert!(res);
    }

    #[tokio::test]
    async fn test_validate_related_origins_false() {
        let doc = r#"{"origins":["https://different.example.co.uk"]}"#;
        let client = MockClient { body: doc.into() };
        let res = validate_related_origins("https://caller.example.com", "example.com", &client, 1).await.unwrap();
        assert!(!res);
    }
}
