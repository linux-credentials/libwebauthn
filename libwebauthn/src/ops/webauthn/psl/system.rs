//! System-managed Public Suffix List loader.
//!
//! Probes the standard distribution paths in priority order and loads the
//! first format that is present. Most callers should use this rather than
//! picking [`DafsaFilePublicSuffixList`] or [`DatFilePublicSuffixList`]
//! directly, since which file is shipped depends on the distribution.

use std::path::PathBuf;

use super::dafsa::{DafsaFileLoadError, DafsaFilePublicSuffixList, SYSTEM_PSL_DAFSA_PATH};
use super::dat::{DatFileLoadError, DatFilePublicSuffixList, SYSTEM_PSL_PATH};
use super::PublicSuffixList;

#[derive(thiserror::Error, Debug)]
pub enum SystemLoadError {
    #[error("no system Public Suffix List found at any of the standard paths: {tried:?}")]
    NoneFound { tried: Vec<PathBuf> },
    #[error("failed to load `.dafsa` PSL: {0}")]
    Dafsa(#[from] DafsaFileLoadError),
    #[error("failed to load `.dat` PSL: {0}")]
    Dat(#[from] DatFileLoadError),
}

enum Inner {
    Dafsa(DafsaFilePublicSuffixList),
    Dat(DatFilePublicSuffixList),
}

/// `PublicSuffixList` implementation that auto-detects which system-managed
/// PSL file is available, preferring the binary `.dafsa` format if present.
pub struct SystemPublicSuffixList {
    inner: Inner,
}

impl std::fmt::Debug for SystemPublicSuffixList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Inner::Dafsa(d) => f.debug_tuple("SystemPublicSuffixList").field(d).finish(),
            Inner::Dat(d) => f.debug_tuple("SystemPublicSuffixList").field(d).finish(),
        }
    }
}

impl SystemPublicSuffixList {
    /// Probes the standard system paths and loads the first format found.
    ///
    /// Order: [`SYSTEM_PSL_DAFSA_PATH`] then [`SYSTEM_PSL_PATH`]. The DAFSA
    /// path is preferred because on Fedora it is the only file that ships
    /// on a default install; on distributions that ship both (Debian/Ubuntu)
    /// either choice has the same content.
    pub fn auto() -> Result<Self, SystemLoadError> {
        let dafsa_path = PathBuf::from(SYSTEM_PSL_DAFSA_PATH);
        let dat_path = PathBuf::from(SYSTEM_PSL_PATH);

        if dafsa_path.exists() {
            let psl = DafsaFilePublicSuffixList::from_path(&dafsa_path)?;
            return Ok(Self {
                inner: Inner::Dafsa(psl),
            });
        }
        if dat_path.exists() {
            let psl = DatFilePublicSuffixList::from_path(&dat_path)?;
            return Ok(Self {
                inner: Inner::Dat(psl),
            });
        }
        Err(SystemLoadError::NoneFound {
            tried: vec![dafsa_path, dat_path],
        })
    }
}

impl PublicSuffixList for SystemPublicSuffixList {
    fn registrable_domain(&self, host: &str) -> Option<String> {
        match &self.inner {
            Inner::Dafsa(d) => d.registrable_domain(host),
            Inner::Dat(d) => d.registrable_domain(host),
        }
    }

    fn public_suffix(&self, host: &str) -> Option<String> {
        match &self.inner {
            Inner::Dafsa(d) => d.public_suffix(host),
            Inner::Dat(d) => d.public_suffix(host),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration test against the actual system PSL. Skipped unless
    /// `LIBWEBAUTHN_PSL_SYSTEM_TEST=1` is set, because the test depends on
    /// the host machine having a PSL package installed.
    #[test]
    fn system_psl_loads_and_resolves_common_suffixes() {
        if std::env::var("LIBWEBAUTHN_PSL_SYSTEM_TEST").as_deref() != Ok("1") {
            return;
        }
        let psl = SystemPublicSuffixList::auto().expect("system PSL must be installed");
        assert_eq!(psl.public_suffix("example.com").as_deref(), Some("com"));
        assert_eq!(psl.public_suffix("bbc.co.uk").as_deref(), Some("co.uk"));
        assert_eq!(
            psl.registrable_domain("login.example.com").as_deref(),
            Some("example.com"),
        );
    }
}
