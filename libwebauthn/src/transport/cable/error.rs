//! Errors specific to the caBLE tunnel-server transport.

#[derive(thiserror::Error, Debug, PartialEq, Clone)]
pub enum CableTunnelError {
    /// The tunnel server returned HTTP 410 Gone for the contacted resource.
    #[error("tunnel server reported the resource is gone (HTTP 410)")]
    Gone,
    /// The tunnel server returned an unexpected, non-success HTTP status.
    #[error("tunnel server returned unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
    /// The tunnel server kept redirecting past the allowed limit.
    #[error("tunnel server exceeded the maximum number of redirects")]
    TooManyRedirects,
}
