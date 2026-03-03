use super::*;
use reqwest::redirect::Policy;
use reqwest::StatusCode;

pub struct ReqwestRelatedOriginsClient {
    inner: reqwest::Client,
    config: super::PolicyConfig,
}

impl ReqwestRelatedOriginsClient {
    /// Construct using default `PolicyConfig`.
    pub fn new() -> Result<Self, RelatedOriginsError> {
        Self::with_config(super::PolicyConfig::default())
    }

    /// Construct with a custom `PolicyConfig`.
    fn with_config(config: super::PolicyConfig) -> Result<Self, RelatedOriginsError> {
        let policy = Policy::custom(|attempt| {
            // Enforce HTTPS on all redirects
            if attempt.url().scheme() != "https" {
                return attempt.stop();
            }
            attempt.follow()
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(policy)
            .build()
            .map_err(|e| RelatedOriginsError::HttpError(e.to_string()))?;

        Ok(ReqwestRelatedOriginsClient { inner: client, config })
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
            if (len as usize) > self.config.max_body_bytes {
                return Err(RelatedOriginsError::SecurityError);
            }
        }

        // Stream body with a hard cap to avoid OOM or slowloris-style attacks
        let mut body_buf = BytesMut::with_capacity(1024);
        let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.try_next().await.map_err(|e| RelatedOriginsError::HttpError(e.to_string()))? {
                if body_buf.len() + chunk.len() > self.config.max_body_bytes {
                    return Err(RelatedOriginsError::SecurityError);
                }
                body_buf.extend_from_slice(&chunk);
            }

        // Return the raw body to be parsed/validated by the outer validator
        let body = String::from_utf8_lossy(&body_buf).to_string();
        Ok(RelatedOriginsHttpResponse { status: status.as_u16(), content_type, body })
    }
}
