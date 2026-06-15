mod base64url;
pub mod create;
pub mod get;
pub mod origin;
pub mod response;
pub mod rpid;

pub use base64url::Base64UrlString;
pub use response::{
    AuthenticationExtensionsClientOutputsJSON, AuthenticationResponseJSON,
    AuthenticatorAssertionResponseJSON, AuthenticatorAttestationResponseJSON,
    CredentialPropertiesOutputJSON, HMACGetSecretOutputJSON, JsonFormat, LargeBlobOutputJSON,
    PRFOutputJSON, PRFValuesJSON, RegistrationResponseJSON, ResponseSerializationError,
    WebAuthnIDLResponse,
};

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use tracing::debug;

use origin::{is_registrable_domain_suffix_or_equal, RequestOrigin};
use rpid::RelyingPartyId;

use super::psl::PublicSuffixList;
use super::related_origins::{validate_related_origins, RelatedOrigins};

pub type JsonError = serde_json::Error;

/// Per-request settings (currently just the origin-validation policy).
pub struct RequestSettings<'a> {
    pub origin: OriginValidation<'a>,
}

/// How the caller origin is validated against the request rp.id.
pub enum OriginValidation<'a> {
    /// Trust the caller's origin to rp.id binding with no check, for callers
    /// that have already validated it (e.g. a browser). Misuse defeats phishing
    /// resistance, so the caller owns that decision.
    Trust,
    /// Validate rp.id against the caller origin: a registrable suffix of the
    /// effective domain, then related origins on mismatch.
    Validate {
        public_suffix_list: &'a dyn PublicSuffixList,
        related_origins: RelatedOrigins<'a>,
    },
}

/// Builds a request from its parsed IDL model, validating origin against rp.id.
#[async_trait]
pub(crate) trait FromIdlModel<T>: Sized
where
    T: DeserializeOwned + Send,
{
    type Error: std::error::Error + From<JsonError>;

    async fn from_idl_model(
        request_origin: &RequestOrigin,
        settings: &RequestSettings<'_>,
        model: T,
    ) -> Result<Self, Self::Error>;
}

/// Whether `request_origin` may act for `rp_id`. `Trust` accepts any rp.id;
/// `Validate` requires a registrable suffix of the caller's effective domain or
/// a matching related origin.
pub(crate) async fn rp_id_authorised(
    request_origin: &RequestOrigin,
    rp_id: &RelyingPartyId,
    settings: &RequestSettings<'_>,
) -> bool {
    let (public_suffix_list, related_origins) = match &settings.origin {
        OriginValidation::Trust => return true,
        OriginValidation::Validate {
            public_suffix_list,
            related_origins,
        } => (*public_suffix_list, related_origins),
    };
    let effective_rp_id = request_origin.origin.host.as_str();
    if is_registrable_domain_suffix_or_equal(&rp_id.0, effective_rp_id, public_suffix_list) {
        return true;
    }
    match related_origins {
        RelatedOrigins::Disabled => false,
        RelatedOrigins::Enabled { source, max_labels } => {
            match source.allowed_origins(rp_id).await {
                Err(err) => {
                    debug!({ rp_id = %rp_id.0, %err }, "Related-origins resolution failed");
                    false
                }
                Ok(origins) => match validate_related_origins(
                    &request_origin.origin,
                    &origins,
                    public_suffix_list,
                    *max_labels,
                ) {
                    Ok(()) => true,
                    Err(err) => {
                        debug!({ rp_id = %rp_id.0, %err }, "Related-origins match failed");
                        false
                    }
                },
            }
        }
    }
}
