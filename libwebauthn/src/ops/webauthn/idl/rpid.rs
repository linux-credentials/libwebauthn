use serde::Deserialize;
use std::{convert::TryFrom, net::IpAddr, ops::Deref};

#[derive(Clone, Debug)]
pub struct RelyingPartyId(pub String);

impl Deref for RelyingPartyId {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<RelyingPartyId> for String {
    fn from(rpid: RelyingPartyId) -> String {
        rpid.0
    }
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("Empty Relying Party ID is not allowed")]
    EmptyRelyingPartyId,
    #[error("Relying Party ID must be a valid domain string: {0}")]
    InvalidRelyingPartyId(String),
    #[error("Relying Party ID must not be an IP address: {0}")]
    IpAddressNotAllowed(String),
    #[error("Relying Party ID exceeds maximum length")]
    DomainTooLong,
    #[error("Relying Party ID label exceeds maximum length: {0}")]
    LabelTooLong(String),
}

impl TryFrom<&str> for RelyingPartyId {
    type Error = Error;

    /// Validates and normalizes a Relying Party ID per WebAuthn L3 §4.
    ///
    /// Required by spec:
    /// - RP ID must be a "valid domain string" (WHATWG URL Standard §3.4)
    /// - IDNA normalization via `domain_to_ascii` (URL Standard §3.3, UTS #46)
    /// - IP addresses are not valid domains (URL Standard §3.1)
    ///
    /// DNS constraints (RFC 1035, enforced by IDNA with beStrict=true):
    /// - Domain max length: 253 characters
    /// - Label max length: 63 characters
    /// - Labels must follow LDH rule (letters, digits, hyphens)
    /// - Labels cannot start/end with hyphens
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(Error::EmptyRelyingPartyId);
        }

        // Check for IP addresses (both IPv4 and IPv6)
        if value.parse::<IpAddr>().is_ok() {
            return Err(Error::IpAddressNotAllowed(value.to_string()));
        }

        let ascii = idna::domain_to_ascii(value)
            .map_err(|_| Error::InvalidRelyingPartyId(value.to_string()))?;

        if ascii.is_empty() {
            return Err(Error::InvalidRelyingPartyId(value.to_string()));
        }

        if ascii.len() > 253 {
            return Err(Error::DomainTooLong);
        }

        if ascii.starts_with('.') || ascii.ends_with('.') {
            return Err(Error::InvalidRelyingPartyId(value.to_string()));
        }

        for label in ascii.split('.') {
            if label.is_empty() {
                return Err(Error::InvalidRelyingPartyId(value.to_string()));
            }
            if label.len() > 63 {
                return Err(Error::LabelTooLong(label.to_string()));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(Error::InvalidRelyingPartyId(value.to_string()));
            }
            if !label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            {
                return Err(Error::InvalidRelyingPartyId(value.to_string()));
            }
        }

        Ok(RelyingPartyId(ascii))
    }
}

impl<'de> Deserialize<'de> for RelyingPartyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RelyingPartyId::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, RelyingPartyId};
    use std::convert::TryFrom;

    #[test]
    fn test_relying_party_id_valid() {
        let rpid = RelyingPartyId::try_from("example.org").unwrap();
        assert_eq!(rpid.0, "example.org");
    }

    #[test]
    fn test_relying_party_id_idna_normalization() {
        // IDNA (UTS #46) example.
        let rpid = RelyingPartyId::try_from("例え.テスト").unwrap();
        assert_eq!(rpid.0, "xn--r8jz45g.xn--zckzah");
    }

    #[test]
    fn test_relying_party_id_empty() {
        let result = RelyingPartyId::try_from("");
        assert!(matches!(result, Err(Error::EmptyRelyingPartyId)));
    }

    #[test]
    fn test_relying_party_id_rejects_ipv4_address() {
        let ipv4_addresses = ["127.0.0.1", "192.168.1.1", "10.0.0.1", "255.255.255.255"];
        for ip in ipv4_addresses {
            let result = RelyingPartyId::try_from(ip);
            assert!(
                matches!(result, Err(Error::IpAddressNotAllowed(_))),
                "Expected IPv4 address '{}' to be rejected",
                ip
            );
        }
    }

    #[test]
    fn test_relying_party_id_rejects_ipv6_address() {
        // Unbracketed format - must be rejected as IP address
        let ipv6_addresses = ["::1", "2001:db8::1", "fe80::1", "::ffff:192.168.1.1"];
        for ip in ipv6_addresses {
            let result = RelyingPartyId::try_from(ip);
            assert!(
                matches!(result, Err(Error::IpAddressNotAllowed(_))),
                "Expected IPv6 address '{}' to be rejected as IP address",
                ip
            );
        }

        // Bracketed format (RFC 2732) - must be rejected (either as IP or invalid domain)
        let bracketed_ipv6 = [
            "[::1]",
            "[2001:db8::1]",
            "[fe80::1]",
            "[::ffff:192.168.1.1]",
        ];
        for ip in bracketed_ipv6 {
            let result = RelyingPartyId::try_from(ip);
            assert!(
                result.is_err(),
                "Expected bracketed IPv6 address '{}' to be rejected",
                ip
            );
        }
    }

    #[test]
    fn test_relying_party_id_invalid_label_chars() {
        let result = RelyingPartyId::try_from("bad_label.example");
        assert!(matches!(result, Err(Error::InvalidRelyingPartyId(_))));
    }

    #[test]
    fn test_relying_party_id_invalid_trailing_dot() {
        let result = RelyingPartyId::try_from("example.org.");
        assert!(matches!(result, Err(Error::InvalidRelyingPartyId(_))));
    }
}
