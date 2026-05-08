use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::str::FromStr;

use url::Host;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum HostParseError {
    #[error("empty host")]
    Empty,
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("invalid domain: {0}")]
    InvalidDomain(String),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum OriginParseError {
    #[error("invalid scheme (only https is supported)")]
    InvalidScheme,
    #[error("missing host")]
    MissingHost,
    #[error("invalid host: {0}")]
    InvalidHost(#[from] HostParseError),
    #[error("invalid port: {0}")]
    InvalidPort(String),
    #[error("unexpected path or fragment: {0}")]
    UnexpectedPath(String),
}

/// Validated host component of an HTTPS origin.
///
/// Parsing follows the WHATWG URL Standard host parser via [`url::Host`], which
/// accepts ASCII / IDNA domains, IPv4 literals, and bracketed IPv6 literals,
/// and rejects everything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginHost(String);

impl OriginHost {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for OriginHost {
    type Err = HostParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(HostParseError::Empty);
        }
        match Host::parse(s) {
            Ok(h) => Ok(OriginHost(h.to_string())),
            Err(err) => {
                let msg = err.to_string();
                if msg.contains("IPv4") || msg.contains("ipv4") {
                    Err(HostParseError::InvalidIp(msg))
                } else if msg.contains("IPv6") || msg.contains("ipv6") {
                    Err(HostParseError::InvalidIp(msg))
                } else {
                    Err(HostParseError::InvalidDomain(msg))
                }
            }
        }
    }
}

impl TryFrom<&str> for OriginHost {
    type Error = HostParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s)
    }
}

impl Display for OriginHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An HTTPS origin: scheme is implicit, port optional.
///
/// Note: an enum variant for `https` is intentionally not used here since we
/// only support a single scheme. If we ever need additional schemes (e.g.
/// `app:` for AppId-style origins) this can become an enum without breaking
/// the field-access pattern at call sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub host: OriginHost,
    pub port: Option<u16>,
}

impl Origin {
    pub fn new(host: OriginHost, port: Option<u16>) -> Self {
        Self { host, port }
    }
}

impl Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}", self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

impl FromStr for Origin {
    type Err = OriginParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("https://")
            .ok_or(OriginParseError::InvalidScheme)?;

        if rest.is_empty() {
            return Err(OriginParseError::MissingHost);
        }

        let (authority, tail_marker) = rest
            .find(['/', '?', '#'])
            .map(|idx| (&rest[..idx], Some(&rest[idx..])))
            .unwrap_or((rest, None));

        if let Some(tail) = tail_marker {
            // Allow a trailing slash with nothing after it; reject anything more.
            if tail != "/" {
                return Err(OriginParseError::UnexpectedPath(tail.to_string()));
            }
        }

        let (host_str, port) = split_host_and_port(authority)?;
        let host = OriginHost::from_str(host_str)?;
        Ok(Origin { host, port })
    }
}

impl TryFrom<&str> for Origin {
    type Error = OriginParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s)
    }
}

fn split_host_and_port(s: &str) -> Result<(&str, Option<u16>), OriginParseError> {
    // IPv6 literals are bracketed. Find the matching `]` first if present so
    // we don't confuse `:` inside the address with the host/port separator.
    if let Some(stripped) = s.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| OriginParseError::InvalidHost(HostParseError::InvalidIp(s.to_string())))?;
        let host = &s[..end + 2]; // include the brackets
        let after = &s[end + 2..];
        if after.is_empty() {
            return Ok((host, None));
        }
        let port_str = after
            .strip_prefix(':')
            .ok_or_else(|| OriginParseError::InvalidPort(after.to_string()))?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| OriginParseError::InvalidPort(port_str.to_string()))?;
        return Ok((host, Some(port)));
    }

    match s.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| OriginParseError::InvalidPort(port_str.to_string()))?;
            Ok((host, Some(port)))
        }
        None => Ok((s, None)),
    }
}

/// The origin context of an incoming WebAuthn request: the request's own
/// origin, plus the top-level origin when the request was made from a nested
/// (cross-origin) browsing context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOrigin {
    pub origin: Origin,
    pub top_origin: Option<Origin>,
}

impl RequestOrigin {
    /// Same-origin request: no top-level origin.
    pub fn new(origin: Origin) -> Self {
        Self {
            origin,
            top_origin: None,
        }
    }

    /// Cross-origin request: the request was made from a nested browsing
    /// context whose top-level origin is `top_origin`.
    pub fn new_cross_origin(origin: Origin, top_origin: Origin) -> Self {
        Self {
            origin,
            top_origin: Some(top_origin),
        }
    }

    /// True iff the request was made from a nested browsing context with a
    /// different top-level origin.
    pub fn is_cross_origin(&self) -> bool {
        self.top_origin.is_some()
    }
}

impl FromStr for RequestOrigin {
    type Err = OriginParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(Origin::from_str(s)?))
    }
}

impl TryFrom<&str> for RequestOrigin {
    type Error = OriginParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s)
    }
}

impl TryFrom<String> for RequestOrigin {
    type Error = OriginParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_parses_domain() {
        let h: OriginHost = "example.org".parse().unwrap();
        assert_eq!(h.as_str(), "example.org");
    }

    #[test]
    fn host_idna_normalises() {
        let h: OriginHost = "例え.テスト".parse().unwrap();
        assert_eq!(h.as_str(), "xn--r8jz45g.xn--zckzah");
    }

    #[test]
    fn host_accepts_ipv4() {
        let h: OriginHost = "127.0.0.1".parse().unwrap();
        assert_eq!(h.as_str(), "127.0.0.1");
    }

    #[test]
    fn host_accepts_bracketed_ipv6() {
        let h: OriginHost = "[::1]".parse().unwrap();
        assert_eq!(h.as_str(), "[::1]");
    }

    #[test]
    fn host_rejects_empty() {
        assert!(matches!(
            "".parse::<OriginHost>(),
            Err(HostParseError::Empty)
        ));
    }

    #[test]
    fn origin_parses_bare_host() {
        let o: Origin = "https://example.org".parse().unwrap();
        assert_eq!(o.host.as_str(), "example.org");
        assert_eq!(o.port, None);
        assert_eq!(o.to_string(), "https://example.org");
    }

    #[test]
    fn origin_parses_host_with_port() {
        let o: Origin = "https://example.org:8443".parse().unwrap();
        assert_eq!(o.host.as_str(), "example.org");
        assert_eq!(o.port, Some(8443));
        assert_eq!(o.to_string(), "https://example.org:8443");
    }

    #[test]
    fn origin_parses_ipv6_with_port() {
        let o: Origin = "https://[::1]:8443".parse().unwrap();
        assert_eq!(o.host.as_str(), "[::1]");
        assert_eq!(o.port, Some(8443));
        assert_eq!(o.to_string(), "https://[::1]:8443");
    }

    #[test]
    fn origin_allows_trailing_slash() {
        let o: Origin = "https://example.org/".parse().unwrap();
        assert_eq!(o.to_string(), "https://example.org");
    }

    #[test]
    fn origin_rejects_non_https() {
        assert!(matches!(
            "http://example.org".parse::<Origin>(),
            Err(OriginParseError::InvalidScheme)
        ));
    }

    #[test]
    fn origin_rejects_path() {
        assert!(matches!(
            "https://example.org/foo".parse::<Origin>(),
            Err(OriginParseError::UnexpectedPath(_))
        ));
    }

    #[test]
    fn origin_rejects_query() {
        assert!(matches!(
            "https://example.org?x=1".parse::<Origin>(),
            Err(OriginParseError::UnexpectedPath(_))
        ));
    }

    #[test]
    fn origin_rejects_invalid_port() {
        assert!(matches!(
            "https://example.org:notaport".parse::<Origin>(),
            Err(OriginParseError::InvalidPort(_))
        ));
    }

    #[test]
    fn request_origin_same_origin() {
        let r: RequestOrigin = "https://example.org".parse().unwrap();
        assert!(!r.is_cross_origin());
        assert_eq!(r.top_origin, None);
    }

    #[test]
    fn request_origin_cross_origin() {
        let inner: Origin = "https://embed.example.org".parse().unwrap();
        let top: Origin = "https://example.org".parse().unwrap();
        let r = RequestOrigin::new_cross_origin(inner.clone(), top.clone());
        assert!(r.is_cross_origin());
        assert_eq!(r.origin, inner);
        assert_eq!(r.top_origin, Some(top));
    }

    #[test]
    fn request_origin_try_from_string() {
        let r = RequestOrigin::try_from("https://example.org:443".to_string()).unwrap();
        assert_eq!(r.origin.host.as_str(), "example.org");
        assert_eq!(r.origin.port, Some(443));
    }
}
