use std::convert::TryFrom;
use std::fmt::{self, Display};
use std::str::FromStr;

use url::{Host, ParseError, Url};

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
    #[error("invalid scheme (only https, or http with localhost, is supported)")]
    InvalidScheme,
    #[error("http scheme is only allowed for localhost, got {0}")]
    InsecureHttpHost(String),
    #[error("missing host")]
    MissingHost,
    #[error("invalid host: {0}")]
    InvalidHost(#[from] HostParseError),
    #[error("invalid port: {0}")]
    InvalidPort(String),
    #[error("unexpected path or fragment: {0}")]
    UnexpectedPath(String),
    #[error("origin must not contain userinfo")]
    UnexpectedUserinfo,
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
        Host::parse(s)
            .map(|h| OriginHost(h.to_string()))
            .map_err(|err| match err {
                ParseError::InvalidIpv4Address | ParseError::InvalidIpv6Address => {
                    HostParseError::InvalidIp(err.to_string())
                }
                _ => HostParseError::InvalidDomain(err.to_string()),
            })
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

/// Scheme of a WebAuthn origin.
///
/// `Https` is the standard case. `Http` is permitted only with the literal
/// `localhost` host, because Web specs (Secure Contexts) treat
/// `http://localhost` as a secure context for development purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Https,
    Http,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Https => "https",
            Scheme::Http => "http",
        }
    }
}

impl Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A WebAuthn origin. The scheme is `https`, or `http` only when the host is
/// the literal `localhost`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub scheme: Scheme,
    pub host: OriginHost,
    pub port: Option<u16>,
}

impl Origin {
    /// Constructs an HTTPS origin. Use [`Origin::from_str`] to parse an
    /// arbitrary origin string (which will also accept `http://localhost`).
    pub fn new(host: OriginHost, port: Option<u16>) -> Self {
        Self {
            scheme: Scheme::Https,
            host,
            port,
        }
    }
}

impl Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

/// Returns true iff `host` qualifies for the `http://` scheme. The W3C Secure
/// Contexts spec considers a broader set of hosts trustworthy (`localhost`,
/// `*.localhost`, `127.0.0.0/8`, `[::1]`). We intentionally restrict to the
/// literal `localhost` here as the minimum dev affordance; this can be
/// widened later without breaking existing callers.
///
/// Case comparison is safe: [`url::Host::parse`] ASCII-lowercases the domain
/// during parsing, so `LOCALHOST` and `localhost` both compare equal here.
fn host_allows_http(host: &OriginHost) -> bool {
    host.as_str() == "localhost"
}

impl FromStr for Origin {
    type Err = OriginParseError;

    /// Parses a WebAuthn origin from a string. Delegates to [`url::Url`] for
    /// scheme, host (including IDNA / IPv4 / IPv6), and port parsing, then
    /// applies WebAuthn-specific rules:
    ///
    /// * scheme must be `https`, or `http` when the host is the literal
    ///   `localhost`
    /// * no userinfo (`user:pw@host`)
    /// * no path beyond `/`, no query, no fragment
    ///
    /// Per the WHATWG URL Standard, default ports (e.g. `:443` for https)
    /// are dropped during parsing, matching the canonical origin form used
    /// in `clientDataJSON.origin`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s).map_err(map_url_parse_error)?;

        let scheme = match url.scheme() {
            "https" => Scheme::Https,
            "http" => Scheme::Http,
            _ => return Err(OriginParseError::InvalidScheme),
        };

        if !url.username().is_empty() || url.password().is_some() {
            return Err(OriginParseError::UnexpectedUserinfo);
        }
        if !matches!(url.path(), "" | "/") {
            return Err(OriginParseError::UnexpectedPath(url.path().to_string()));
        }
        if let Some(q) = url.query() {
            return Err(OriginParseError::UnexpectedPath(format!("?{q}")));
        }
        if let Some(f) = url.fragment() {
            return Err(OriginParseError::UnexpectedPath(format!("#{f}")));
        }

        let host = match url.host() {
            Some(Host::Domain(d)) => OriginHost(d.to_string()),
            Some(Host::Ipv4(ip)) => OriginHost(ip.to_string()),
            // Restore the brackets that `url::Url` strips off internally.
            Some(Host::Ipv6(ip)) => OriginHost(format!("[{ip}]")),
            None => return Err(OriginParseError::MissingHost),
        };

        if matches!(scheme, Scheme::Http) && !host_allows_http(&host) {
            return Err(OriginParseError::InsecureHttpHost(
                host.as_str().to_string(),
            ));
        }

        Ok(Origin {
            scheme,
            host,
            port: url.port(),
        })
    }
}

impl TryFrom<&str> for Origin {
    type Error = OriginParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s)
    }
}

fn map_url_parse_error(err: ParseError) -> OriginParseError {
    match err {
        ParseError::EmptyHost => OriginParseError::MissingHost,
        ParseError::InvalidIpv4Address | ParseError::InvalidIpv6Address => {
            OriginParseError::InvalidHost(HostParseError::InvalidIp(err.to_string()))
        }
        ParseError::InvalidPort => OriginParseError::InvalidPort(err.to_string()),
        ParseError::RelativeUrlWithoutBase => OriginParseError::InvalidScheme,
        ParseError::IdnaError => {
            OriginParseError::InvalidHost(HostParseError::InvalidDomain(err.to_string()))
        }
        _ => OriginParseError::InvalidHost(HostParseError::InvalidDomain(err.to_string())),
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
    fn origin_rejects_unknown_scheme() {
        assert!(matches!(
            "ftp://example.org".parse::<Origin>(),
            Err(OriginParseError::InvalidScheme)
        ));
    }

    #[test]
    fn origin_rejects_http_for_non_localhost() {
        assert!(matches!(
            "http://example.org".parse::<Origin>(),
            Err(OriginParseError::InsecureHttpHost(_))
        ));
    }

    #[test]
    fn origin_accepts_http_localhost() {
        let o: Origin = "http://localhost".parse().unwrap();
        assert_eq!(o.scheme, Scheme::Http);
        assert_eq!(o.host.as_str(), "localhost");
        assert_eq!(o.port, None);
        assert_eq!(o.to_string(), "http://localhost");
    }

    #[test]
    fn origin_accepts_http_localhost_with_port() {
        let o: Origin = "http://localhost:3000".parse().unwrap();
        assert_eq!(o.scheme, Scheme::Http);
        assert_eq!(o.host.as_str(), "localhost");
        assert_eq!(o.port, Some(3000));
        assert_eq!(o.to_string(), "http://localhost:3000");
    }

    #[test]
    fn origin_accepts_https_localhost() {
        let o: Origin = "https://localhost:8443".parse().unwrap();
        assert_eq!(o.scheme, Scheme::Https);
        assert_eq!(o.host.as_str(), "localhost");
        assert_eq!(o.port, Some(8443));
    }

    #[test]
    fn origin_rejects_http_loopback_ip() {
        // Loopback IPs are not covered by this narrow allowance; only the
        // literal "localhost" host qualifies for http://.
        assert!(matches!(
            "http://127.0.0.1".parse::<Origin>(),
            Err(OriginParseError::InsecureHttpHost(_))
        ));
        assert!(matches!(
            "http://[::1]".parse::<Origin>(),
            Err(OriginParseError::InsecureHttpHost(_))
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
        // Default ports are stripped during parsing (WHATWG URL Standard), so
        // `:443` on an https origin normalises to `port = None`.
        let r = RequestOrigin::try_from("https://example.org:443".to_string()).unwrap();
        assert_eq!(r.origin.host.as_str(), "example.org");
        assert_eq!(r.origin.port, None);
        assert_eq!(r.origin.to_string(), "https://example.org");
    }

    #[test]
    fn origin_strips_default_http_port() {
        let o: Origin = "http://localhost:80".parse().unwrap();
        assert_eq!(o.port, None);
        assert_eq!(o.to_string(), "http://localhost");
    }

    #[test]
    fn origin_rejects_userinfo() {
        assert!(matches!(
            "https://user:pw@example.org".parse::<Origin>(),
            Err(OriginParseError::UnexpectedUserinfo)
        ));
    }

    #[test]
    fn origin_normalises_uppercase_scheme_and_host() {
        let o: Origin = "HTTPS://Example.ORG".parse().unwrap();
        assert_eq!(o.scheme, Scheme::Https);
        assert_eq!(o.host.as_str(), "example.org");
        assert_eq!(o.to_string(), "https://example.org");
    }

    #[test]
    fn origin_accepts_port_boundaries() {
        let o: Origin = "https://example.org:1".parse().unwrap();
        assert_eq!(o.port, Some(1));
        let o: Origin = "https://example.org:65535".parse().unwrap();
        assert_eq!(o.port, Some(65535));
    }

    #[test]
    fn origin_accepts_port_zero() {
        // Port 0 is syntactically valid per the WHATWG URL Standard, even
        // though it is not a usable network port. Pin current behavior so a
        // future change is visible.
        let o: Origin = "https://example.org:0".parse().unwrap();
        assert_eq!(o.port, Some(0));
    }

    #[test]
    fn origin_new_defaults_to_https() {
        let host: OriginHost = "example.org".parse().unwrap();
        let origin = Origin::new(host, Some(8443));
        assert_eq!(origin.scheme, Scheme::Https);
        assert_eq!(origin.to_string(), "https://example.org:8443");
    }
}
