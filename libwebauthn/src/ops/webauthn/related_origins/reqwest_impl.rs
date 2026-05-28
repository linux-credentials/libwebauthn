//! reqwest-backed [`HttpClient`] and the convenience [`ReqwestRelatedOriginsSource`].
//! Gated by the `reqwest-related-origins-source` cargo feature.

use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use http::{HeaderMap, Response, StatusCode};
use reqwest::redirect::Policy;
use reqwest::Client;
use url::Url;

use super::{HttpClient, HttpClientError, WellKnownRelatedOriginsSource};

#[derive(Debug, Clone)]
pub struct HttpPolicy {
    pub request_timeout: Duration,
    pub max_body_bytes: usize,
    pub max_redirects: usize,
}

impl Default for HttpPolicy {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
            max_body_bytes: 256 * 1024,
            max_redirects: 5,
        }
    }
}

/// reqwest-backed [`HttpClient`]. Enforces https-only requests and redirects,
/// sends no credentials or Referer, caps the body size, and bounds the request
/// duration.
#[derive(Debug, Clone)]
pub struct ReqwestHttpClient {
    client: Client,
    max_body_bytes: usize,
}

impl ReqwestHttpClient {
    pub fn new() -> Result<Self, HttpClientError> {
        Self::with_policy(HttpPolicy::default())
    }

    pub fn with_policy(policy: HttpPolicy) -> Result<Self, HttpClientError> {
        let max_redirects = policy.max_redirects;
        let redirect_policy = Policy::custom(move |attempt| {
            if attempt.previous().len() >= max_redirects {
                return attempt.error("redirect limit exceeded");
            }
            if attempt.url().scheme() != "https" {
                return attempt.error("non-https redirect");
            }
            attempt.follow()
        });
        // WebAuthn L3 §5.11.1 step 2: no referrer. The `cookies` feature is off,
        // so reqwest sends no credentials.
        let client = Client::builder()
            .https_only(true)
            .redirect(redirect_policy)
            .referer(false)
            .timeout(policy.request_timeout)
            .build()
            .map_err(|e| HttpClientError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            max_body_bytes: policy.max_body_bytes,
        })
    }
}

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn get(&self, url: &Url) -> Result<Response<Vec<u8>>, HttpClientError> {
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| HttpClientError::Transport(e.to_string()))?;
        let status: StatusCode = response.status();
        let headers: HeaderMap = response.headers().clone();

        let mut body = Vec::with_capacity(8 * 1024);
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| HttpClientError::Transport(e.to_string()))?;
            if body.len() + chunk.len() > self.max_body_bytes {
                return Err(HttpClientError::BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }

        let mut out = Response::new(body);
        *out.status_mut() = status;
        *out.headers_mut() = headers;
        Ok(out)
    }
}

/// reqwest-backed [`RelatedOriginsSource`]: a [`WellKnownRelatedOriginsSource`]
/// over a [`ReqwestHttpClient`].
///
/// [`RelatedOriginsSource`]: super::RelatedOriginsSource
pub type ReqwestRelatedOriginsSource = WellKnownRelatedOriginsSource<ReqwestHttpClient>;

impl WellKnownRelatedOriginsSource<ReqwestHttpClient> {
    /// Build with the default [`HttpPolicy`].
    pub fn new() -> Result<Self, HttpClientError> {
        Ok(Self::from_client(ReqwestHttpClient::new()?))
    }

    /// Build with a custom [`HttpPolicy`].
    pub fn with_policy(policy: HttpPolicy) -> Result<Self, HttpClientError> {
        Ok(Self::from_client(ReqwestHttpClient::with_policy(policy)?))
    }
}
