//! Public Suffix List lookup.
//!
//! libwebauthn needs to know whether a host's apparent registrable domain is
//! actually registrable (i.e. has more labels than its public suffix) when it
//! validates that a request's `rp.id` is a registrable suffix of the calling
//! origin's effective domain (HTML §6.5, used by WebAuthn L3 §5.1.3 step 7).
//!
//! Rather than bundle a snapshot of the PSL inside the crate (which would go
//! stale with each release), libwebauthn defines a [`PublicSuffixList`] trait
//! and lets callers plug in an implementation. Two built-in loaders are
//! provided that read system-managed Public Suffix List files kept fresh by
//! the package manager:
//!
//! * [`DatFilePublicSuffixList`] reads the text `.dat` format (shipped on
//!   Debian/Ubuntu, Arch, and Fedora's `publicsuffix-list` package).
//! * [`DafsaFilePublicSuffixList`] reads libpsl's binary `.dafsa` format
//!   (shipped on Debian/Ubuntu, and on Fedora as `publicsuffix-list-dafsa`,
//!   which is required by `libpsl` and thus present on most installs).
//!
//! Most callers should use [`SystemPublicSuffixList::auto`], which probes
//! the standard system paths for whichever format is available.

// Module-scoped until the crate-wide indexing_slicing deny lands.
#![cfg_attr(not(any(test, feature = "virt")), deny(clippy::indexing_slicing))]

pub mod dafsa;
pub mod dat;
mod system;

pub use dafsa::{DafsaFileLoadError, DafsaFilePublicSuffixList, SYSTEM_PSL_DAFSA_PATH};
pub use dat::{DatFileLoadError, DatFilePublicSuffixList, SYSTEM_PSL_PATH};
pub use system::{SystemLoadError, SystemPublicSuffixList};

/// Public Suffix List lookup interface.
///
/// Implementations decide where the PSL data lives (system file, embedded
/// snapshot, HTTP-cached, etc).
pub trait PublicSuffixList: Send + Sync {
    /// Returns the public suffix of `host`, or `None` if none applies.
    fn public_suffix(&self, host: &str) -> Option<String>;

    /// Returns the registrable domain (eTLD+1) of `host`, or `None` if
    /// `host` has no registrable domain (e.g. it is itself a public suffix).
    ///
    /// The default implementation derives this from [`public_suffix`]: the
    /// registrable domain is the public suffix plus one more label. An
    /// implementation whose backing library computes it directly may override
    /// this.
    ///
    /// [`public_suffix`]: PublicSuffixList::public_suffix
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
