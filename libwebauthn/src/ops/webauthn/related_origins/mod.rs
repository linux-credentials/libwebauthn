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
pub const MAX_REGISTRABLE_LABELS: usize = 5;

#[derive(Debug, Clone)]
pub struct WellKnownResponse {
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// Fetcher for `https://{rp_id}/.well-known/webauthn`, per WebAuthn L3 §5.11.1
/// step 2. Implementations MUST send no credentials, no Referer, refuse
/// non-`https://` redirects, cap the body size, and bound the request duration.
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
    #[error("malformed JSON body: {0}")]
    MalformedJson(String),
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

    let doc: WellKnownDocument = serde_json::from_slice(&resp.body)
        .map_err(|e| RelatedOriginsError::MalformedJson(e.to_string()))?;

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
