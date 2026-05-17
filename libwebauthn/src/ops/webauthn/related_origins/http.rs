//! reqwest-backed [`RelatedOriginsHttpClient`]. Gated by the
//! `related-origins-client` cargo feature.

use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};

use super::{RelatedOriginsError, RelatedOriginsHttpClient, WellKnownResponse};
use crate::ops::webauthn::idl::rpid::RelyingPartyId;

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

#[derive(Debug, Clone)]
pub struct ReqwestRelatedOriginsClient {
    client: Client,
    max_body_bytes: usize,
}

impl ReqwestRelatedOriginsClient {
    pub fn new() -> Result<Self, RelatedOriginsError> {
        Self::with_policy(HttpPolicy::default())
    }

    pub fn with_policy(policy: HttpPolicy) -> Result<Self, RelatedOriginsError> {
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
        // WebAuthn L3 §5.11.1 step 2: fetch "without a referrer"; `cookies`
        // feature is off, so reqwest holds no cookie jar.
        let client = Client::builder()
            .https_only(true)
            .redirect(redirect_policy)
            .referer(false)
            .timeout(policy.request_timeout)
            .build()
            .map_err(|e| RelatedOriginsError::FetchFailed(e.to_string()))?;
        Ok(Self {
            client,
            max_body_bytes: policy.max_body_bytes,
        })
    }
}

#[async_trait]
impl RelatedOriginsHttpClient for ReqwestRelatedOriginsClient {
    async fn fetch_well_known(
        &self,
        rp_id: &RelyingPartyId,
    ) -> Result<WellKnownResponse, RelatedOriginsError> {
        let url = format!("https://{}/.well-known/webauthn", rp_id.0);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| RelatedOriginsError::FetchFailed(e.to_string()))?;
        if response.status() != StatusCode::OK {
            return Err(RelatedOriginsError::FetchFailed(format!(
                "status {}",
                response.status()
            )));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        let mut body = Vec::with_capacity(8 * 1024);
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| RelatedOriginsError::FetchFailed(e.to_string()))?;
            if body.len() + chunk.len() > self.max_body_bytes {
                return Err(RelatedOriginsError::FetchFailed(
                    "body exceeded size cap".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(WellKnownResponse { content_type, body })
    }
}
