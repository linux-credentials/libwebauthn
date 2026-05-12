//! `.dat` (text) format Public Suffix List reader.

use std::path::{Path, PathBuf};

use super::PublicSuffixList;

#[derive(thiserror::Error, Debug)]
pub enum DatFileLoadError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid PSL data: {0}")]
    Parse(String),
}

/// Standard system path for the `.dat` Public Suffix List on Linux distros
/// that ship the `publicsuffix-list` (or equivalent) package.
pub const SYSTEM_PSL_PATH: &str = "/usr/share/publicsuffix/public_suffix_list.dat";

/// `PublicSuffixList` implementation backed by a Public Suffix List `.dat`
/// file loaded from disk at construction time.
pub struct DatFilePublicSuffixList {
    list: publicsuffix::List,
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
        let list = publicsuffix::List::from_str(&data)
            .map_err(|e| DatFileLoadError::Parse(e.to_string()))?;
        Ok(Self {
            list,
            source: path.to_path_buf(),
        })
    }

    /// Reads the system-managed `.dat` PSL at [`SYSTEM_PSL_PATH`].
    pub fn from_system_file() -> Result<Self, DatFileLoadError> {
        Self::from_path(SYSTEM_PSL_PATH)
    }
}

impl PublicSuffixList for DatFilePublicSuffixList {
    fn registrable_domain(&self, host: &str) -> Option<String> {
        let domain = self.list.parse_domain(host).ok()?;
        domain.root().map(|s| s.to_string())
    }

    fn public_suffix(&self, host: &str) -> Option<String> {
        let domain = self.list.parse_domain(host).ok()?;
        domain.suffix().map(|s| s.to_string())
    }
}
