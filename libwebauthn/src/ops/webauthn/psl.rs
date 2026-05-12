//! Public Suffix List lookup.
//!
//! libwebauthn needs to know whether a host's apparent registrable domain is
//! actually registrable (i.e. has more labels than its public suffix) when it
//! validates that a request's `rp.id` is a registrable suffix of the calling
//! origin's effective domain (HTML §6.5, used by WebAuthn L3 §5.1.3 step 7).
//!
//! Rather than bundle a snapshot of the PSL inside the crate (which would go
//! stale with each release), libwebauthn defines a [`PublicSuffixList`] trait
//! and lets callers plug in an implementation. A simple
//! [`DatFilePublicSuffixList`] is provided that reads the standard `.dat`
//! file shipped by the `publicsuffix-list` distribution package, kept fresh
//! by the system package manager.

use std::path::{Path, PathBuf};

use publicsuffix::{List, Psl};

/// Public Suffix List lookup interface.
///
/// Implementations decide where the PSL data lives (system file, embedded
/// snapshot, HTTP-cached, etc).
pub trait PublicSuffixList: Send + Sync {
    /// Returns the registrable domain (eTLD+1) of `host`, or `None` if
    /// `host` has no registrable domain (e.g. it is itself a public suffix).
    fn registrable_domain(&self, host: &str) -> Option<String>;

    /// Returns the public suffix of `host`, or `None` if none applies.
    fn public_suffix(&self, host: &str) -> Option<String>;
}

#[derive(thiserror::Error, Debug)]
pub enum DatFileLoadError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid PSL data: {0}")]
    Parse(String),
}

/// Standard system path for the Public Suffix List on most Linux distros that
/// ship the `publicsuffix-list` (or equivalent) package.
pub const SYSTEM_PSL_PATH: &str = "/usr/share/publicsuffix/public_suffix_list.dat";

/// `PublicSuffixList` implementation backed by a Public Suffix List `.dat`
/// file loaded from disk at construction time.
pub struct DatFilePublicSuffixList {
    list: List,
    source: PathBuf,
}

impl std::fmt::Debug for DatFilePublicSuffixList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatFilePublicSuffixList")
            .field("source", &self.source)
            .finish()
    }
}

impl DatFilePublicSuffixList {
    /// Reads a PSL `.dat` file from `path`.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, DatFileLoadError> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path)?;
        let list: List = data
            .parse()
            .map_err(|e: publicsuffix::Error| DatFileLoadError::Parse(e.to_string()))?;
        Ok(Self {
            list,
            source: path.to_path_buf(),
        })
    }

    /// Reads the system-managed PSL at [`SYSTEM_PSL_PATH`].
    pub fn from_system_file() -> Result<Self, DatFileLoadError> {
        Self::from_path(SYSTEM_PSL_PATH)
    }
}

impl PublicSuffixList for DatFilePublicSuffixList {
    // `is_known()` filter drops `publicsuffix`'s implicit-wildcard match for
    // unlisted TLDs (e.g. `localhost`), so bare `localhost` stays a valid rp.id.
    fn registrable_domain(&self, host: &str) -> Option<String> {
        let suffix = self.list.suffix(host.as_bytes())?;
        if !suffix.is_known() {
            return None;
        }
        let domain = self.list.domain(host.as_bytes())?;
        std::str::from_utf8(domain.as_bytes())
            .ok()
            .map(String::from)
    }

    fn public_suffix(&self, host: &str) -> Option<String> {
        let suffix = self.list.suffix(host.as_bytes())?;
        if !suffix.is_known() {
            return None;
        }
        std::str::from_utf8(suffix.as_bytes())
            .ok()
            .map(String::from)
    }
}

/// Test-only PSL that recognises a small fixed set of public suffixes.
///
/// Sufficient for unit tests of the suffix-check algorithm without reading
/// the system file. Recognises `com`, `co.uk`, `org`, and `net`.
#[cfg(test)]
pub(crate) struct MockPublicSuffixList;

#[cfg(test)]
impl PublicSuffixList for MockPublicSuffixList {
    fn public_suffix(&self, host: &str) -> Option<String> {
        const KNOWN_SUFFIXES: &[&str] = &["com", "co.uk", "org", "net"];
        for suffix in KNOWN_SUFFIXES {
            if host == *suffix {
                return Some((*suffix).to_string());
            }
            let needle = format!(".{suffix}");
            if host.ends_with(&needle) {
                return Some((*suffix).to_string());
            }
        }
        None
    }

    fn registrable_domain(&self, host: &str) -> Option<String> {
        let suffix = self.public_suffix(host)?;
        if host == suffix {
            return None;
        }
        let prefix = host.strip_suffix(&suffix)?.strip_suffix('.')?;
        let last_label = prefix.rsplit('.').next()?;
        Some(format!("{last_label}.{suffix}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_public_suffix_lookup() {
        let psl = MockPublicSuffixList;
        assert_eq!(psl.public_suffix("example.com").as_deref(), Some("com"));
        assert_eq!(psl.public_suffix("com").as_deref(), Some("com"));
        assert_eq!(psl.public_suffix("bbc.co.uk").as_deref(), Some("co.uk"));
        assert_eq!(psl.public_suffix("co.uk").as_deref(), Some("co.uk"));
        assert_eq!(psl.public_suffix("localhost"), None);
    }

    #[test]
    fn mock_registrable_domain() {
        let psl = MockPublicSuffixList;
        assert_eq!(
            psl.registrable_domain("login.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            psl.registrable_domain("example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(psl.registrable_domain("com"), None);
        assert_eq!(
            psl.registrable_domain("bbc.co.uk").as_deref(),
            Some("bbc.co.uk")
        );
        assert_eq!(psl.registrable_domain("co.uk"), None);
    }
}
