//! libpsl binary `.dafsa` format Public Suffix List reader.
//!
//! Format reference: <https://github.com/rockdaboot/libpsl/blob/master/src/psl-make-dafsa>
//! (writer) and <https://github.com/rockdaboot/libpsl/blob/master/src/lookup_string_in_fixed_set.c>
//! (reader). The on-disk file is a 16-byte ASCII header (`.DAFSA@PSL_<ver>` padded
//! to 16 bytes with spaces and terminated by LF) followed by a byte-coded DAFSA,
//! optionally with a trailing `0x01` byte in UTF-8 mode. Only version 0 exists today.
//!
//! Deviations from libpsl `psl_is_public_suffix`:
//!
//! * No prevailing `*` rule for unknown single-label TLDs. libpsl treats any
//!   single-label host as a public suffix; this reader returns `None`, so
//!   `localhost` can be used as a relying-party id against itself.
//! * Multibyte (UTF-8) keys are not supported. WebAuthn rp.ids and origin
//!   hosts are always IDN-ASCII (punycode) by the time they reach the PSL,
//!   and the DAFSA stores IDN rules in punycode form regardless of its
//!   internal encoding mode, so ASCII queries match correctly.

use std::path::{Path, PathBuf};

use super::PublicSuffixList;

const MAGIC: &[u8] = b".DAFSA@PSL_";
const HEADER_LEN: usize = 16;

const FLAG_EXCEPTION: u8 = 1 << 0;
const FLAG_WILDCARD: u8 = 1 << 1;

#[derive(thiserror::Error, Debug)]
pub enum DafsaFileLoadError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("file too small to contain a valid DAFSA header")]
    Truncated,
    #[error("not a libpsl DAFSA file (missing or malformed magic)")]
    BadMagic,
    #[error("unsupported DAFSA version: {0}")]
    UnsupportedVersion(u32),
}

/// Standard system path for the binary `.dafsa` Public Suffix List shipped
/// by libpsl's distribution package (e.g. `publicsuffix-list-dafsa` on
/// Fedora, the `publicsuffix` package on Debian/Ubuntu).
pub const SYSTEM_PSL_DAFSA_PATH: &str = "/usr/share/publicsuffix/public_suffix_list.dafsa";

/// `PublicSuffixList` implementation backed by libpsl's binary `.dafsa` file.
pub struct DafsaFilePublicSuffixList {
    graph: Vec<u8>,
    source: PathBuf,
}

impl std::fmt::Debug for DafsaFilePublicSuffixList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DafsaFilePublicSuffixList")
            .field("source", &self.source)
            .field("graph_bytes", &self.graph.len())
            .finish()
    }
}

impl DafsaFilePublicSuffixList {
    /// Reads a libpsl `.dafsa` file from `path`.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, DafsaFileLoadError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        let graph = parse_header(&bytes)?;
        Ok(Self {
            graph,
            source: path.to_path_buf(),
        })
    }

    /// Reads the system-managed `.dafsa` PSL at [`SYSTEM_PSL_DAFSA_PATH`].
    pub fn from_system_file() -> Result<Self, DafsaFileLoadError> {
        Self::from_path(SYSTEM_PSL_DAFSA_PATH)
    }

    fn is_public_suffix(&self, domain: &str) -> bool {
        if let Some(flags) = lookup(&self.graph, domain.as_bytes()) {
            return (flags & FLAG_EXCEPTION) == 0;
        }
        if let Some(parent_start) = domain.find('.').map(|i| i + 1) {
            let parent = &domain[parent_start..];
            if let Some(flags) = lookup(&self.graph, parent.as_bytes()) {
                return (flags & FLAG_WILDCARD) != 0;
            }
        }
        false
    }
}

impl PublicSuffixList for DafsaFilePublicSuffixList {
    fn public_suffix(&self, host: &str) -> Option<String> {
        let mut current = host;
        loop {
            if self.is_public_suffix(current) {
                return Some(current.to_string());
            }
            match current.find('.') {
                Some(i) => current = &current[i + 1..],
                None => return None,
            }
        }
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

fn parse_header(bytes: &[u8]) -> Result<Vec<u8>, DafsaFileLoadError> {
    if bytes.len() < HEADER_LEN {
        return Err(DafsaFileLoadError::Truncated);
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(DafsaFileLoadError::BadMagic);
    }
    if bytes[HEADER_LEN - 1] != b'\n' {
        return Err(DafsaFileLoadError::BadMagic);
    }
    let version_field = &bytes[MAGIC.len()..HEADER_LEN - 1];
    let digit_count = version_field
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digit_count == 0 {
        return Err(DafsaFileLoadError::BadMagic);
    }
    let version: u32 = std::str::from_utf8(&version_field[..digit_count])
        .map_err(|_| DafsaFileLoadError::BadMagic)?
        .parse()
        .map_err(|_| DafsaFileLoadError::BadMagic)?;
    if version != 0 {
        return Err(DafsaFileLoadError::UnsupportedVersion(version));
    }
    Ok(bytes[HEADER_LEN..].to_vec())
}

/// Port of `LookupStringInFixedSet` from libpsl's `lookup_string_in_fixed_set.c`.
/// Returns the low nibble of the return-value byte (ICANN/PRIVATE/WILDCARD/EXCEPTION
/// flag bits) if `key` is present in `graph`, `None` otherwise. ASCII-only: callers
/// must pass keys already converted to IDN-ASCII (punycode for non-ASCII labels).
fn lookup(graph: &[u8], key: &[u8]) -> Option<u8> {
    let end = graph.len();
    let mut pos: usize = 0;
    let mut offset: usize = 0;
    let mut key_pos: usize = 0;
    let key_end = key.len();

    while let Some(()) = get_next_offset(graph, end, &mut pos, &mut offset) {
        let mut did_consume = false;

        if key_pos < key_end && !is_eol(graph, offset) {
            if !is_match(graph, offset, key, key_pos) {
                continue;
            }
            did_consume = true;
            offset += 1;
            key_pos += 1;

            while !is_eol(graph, offset) && key_pos < key_end {
                if !is_match(graph, offset, key, key_pos) {
                    return None;
                }
                offset += 1;
                key_pos += 1;
            }
        }

        if key_pos == key_end {
            if let Some(rv) = get_return_value(graph, offset) {
                return Some(rv);
            }
            if did_consume {
                return None;
            }
            continue;
        }
        if !is_end_char_match(graph, offset, key, key_pos) {
            if did_consume {
                return None;
            }
            continue;
        }
        offset += 1;
        key_pos += 1;
        // Dive into the child node.
        pos = offset;
    }
    None
}

fn get_next_offset(graph: &[u8], end: usize, pos: &mut usize, offset: &mut usize) -> Option<()> {
    if *pos >= end {
        return None;
    }
    if *pos + 2 >= end {
        return None;
    }
    let b = graph[*pos];
    let consumed = match b & 0x60 {
        0x60 => {
            *offset += ((b as usize & 0x1F) << 16)
                | ((graph[*pos + 1] as usize) << 8)
                | (graph[*pos + 2] as usize);
            3
        }
        0x40 => {
            *offset += ((b as usize & 0x1F) << 8) | (graph[*pos + 1] as usize);
            2
        }
        _ => {
            *offset += (b as usize) & 0x3F;
            1
        }
    };
    if b & 0x80 != 0 {
        *pos = end;
    } else {
        *pos += consumed;
    }
    Some(())
}

fn is_eol(graph: &[u8], offset: usize) -> bool {
    graph.get(offset).is_some_and(|b| b & 0x80 != 0)
}

fn is_match(graph: &[u8], offset: usize, key: &[u8], key_pos: usize) -> bool {
    match (graph.get(offset), key.get(key_pos)) {
        (Some(g), Some(k)) => g == k,
        _ => false,
    }
}

fn is_end_char_match(graph: &[u8], offset: usize, key: &[u8], key_pos: usize) -> bool {
    match (graph.get(offset), key.get(key_pos)) {
        (Some(g), Some(k)) => (g ^ 0x80) == *k,
        _ => false,
    }
}

fn get_return_value(graph: &[u8], offset: usize) -> Option<u8> {
    let b = *graph.get(offset)?;
    if b & 0xE0 == 0x80 {
        Some(b & 0x0F)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture generated by psl-make-dafsa from the rules:
    ///   ICANN: com, uk, co.uk, *.kw, !foo.kw
    ///   PRIVATE: github.io
    /// (ASCII mode; 51 bytes total, 16-byte header + 35-byte graph).
    const FIXTURE: &[u8] = &[
        0x2e, 0x44, 0x41, 0x46, 0x53, 0x41, 0x40, 0x50, 0x53, 0x4c, 0x5f, 0x30, 0x20, 0x20, 0x20,
        0x0a, // header
        0x05, 0x03, 0x0a, 0x07, 0x87, // root offset list
        0x6b, 0x77, 0x86, // kw, flag 6 = WILDCARD | ICANN
        0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x69, 0x6f,
        0x88, // github.io, flag 8 = PRIVATE
        0x66, 0x6f, 0x6f, 0x2e, 0x6b, 0x77, 0x85, // foo.kw, flag 5 = EXCEPTION | ICANN
        0x63, 0xef, // c + end_char 'o'
        0x02, 0x82, // offsets for "com" and "co.uk" branches
        0xed, // end_char 'm'
        0x84, // flag 4 = ICANN (for "com")
        0x2e, 0x75, 0x6b, 0x84, // .uk, flag 4 = ICANN (for "co.uk")
    ];

    fn loaded() -> DafsaFilePublicSuffixList {
        let graph = parse_header(FIXTURE).expect("fixture parses");
        DafsaFilePublicSuffixList {
            graph,
            source: PathBuf::from("<fixture>"),
        }
    }

    #[test]
    fn lookup_simple_icann_rule() {
        let psl = loaded();
        assert_eq!(lookup(&psl.graph, b"com"), Some(4));
        assert_eq!(lookup(&psl.graph, b"uk"), Some(4));
        assert_eq!(lookup(&psl.graph, b"co.uk"), Some(4));
    }

    #[test]
    fn lookup_wildcard_and_exception() {
        let psl = loaded();
        assert_eq!(lookup(&psl.graph, b"kw"), Some(0b0110));
        assert_eq!(lookup(&psl.graph, b"foo.kw"), Some(0b0101));
    }

    #[test]
    fn lookup_private_section() {
        let psl = loaded();
        assert_eq!(lookup(&psl.graph, b"github.io"), Some(0b1000));
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let psl = loaded();
        assert_eq!(lookup(&psl.graph, b"example"), None);
        assert_eq!(lookup(&psl.graph, b"example.com"), None);
        assert_eq!(lookup(&psl.graph, b"c"), None);
        assert_eq!(lookup(&psl.graph, b"comm"), None);
        assert_eq!(lookup(&psl.graph, b""), None);
    }

    #[test]
    fn public_suffix_finds_longest_match() {
        let psl = loaded();
        assert_eq!(psl.public_suffix("example.com").as_deref(), Some("com"));
        assert_eq!(psl.public_suffix("example.co.uk").as_deref(), Some("co.uk"));
        assert_eq!(psl.public_suffix("co.uk").as_deref(), Some("co.uk"));
        assert_eq!(psl.public_suffix("uk").as_deref(), Some("uk"));
    }

    #[test]
    fn public_suffix_wildcard_synthesis() {
        let psl = loaded();
        assert_eq!(
            psl.public_suffix("anything.kw").as_deref(),
            Some("anything.kw")
        );
        assert_eq!(psl.public_suffix("a.b.kw").as_deref(), Some("b.kw"));
    }

    #[test]
    fn public_suffix_exception_overrides_wildcard() {
        let psl = loaded();
        // foo.kw has the EXCEPTION flag so direct lookup returns "not a
        // suffix"; the search then strips a label to "kw", which is in the
        // DAFSA with the WILDCARD flag (no EXCEPTION), so kw itself is the
        // public suffix.
        assert_eq!(psl.public_suffix("foo.kw").as_deref(), Some("kw"));
        // For sub.foo.kw: exact lookup misses; parent foo.kw is found but
        // has no WILDCARD bit, so the wildcard-fallback rejects it; the
        // search then strips down to foo.kw (still excepted) and finally to
        // kw (wildcard, suffix).
        assert_eq!(psl.public_suffix("sub.foo.kw").as_deref(), Some("kw"));
    }

    #[test]
    fn public_suffix_private_section_included() {
        let psl = loaded();
        assert_eq!(
            psl.public_suffix("repo.github.io").as_deref(),
            Some("github.io"),
        );
        assert_eq!(psl.public_suffix("github.io").as_deref(), Some("github.io"));
    }

    #[test]
    fn public_suffix_none_for_non_psl_host() {
        let psl = loaded();
        assert_eq!(psl.public_suffix("localhost"), None);
        assert_eq!(psl.public_suffix("invalid"), None);
    }

    #[test]
    fn registrable_domain_computed_from_suffix() {
        let psl = loaded();
        assert_eq!(
            psl.registrable_domain("login.example.com").as_deref(),
            Some("example.com"),
        );
        assert_eq!(
            psl.registrable_domain("example.com").as_deref(),
            Some("example.com"),
        );
        assert_eq!(psl.registrable_domain("com"), None);
        assert_eq!(
            psl.registrable_domain("a.b.example.co.uk").as_deref(),
            Some("example.co.uk"),
        );
    }

    #[test]
    fn parse_header_rejects_truncated() {
        let too_short = &FIXTURE[..10];
        assert!(matches!(
            parse_header(too_short),
            Err(DafsaFileLoadError::Truncated)
        ));
    }

    #[test]
    fn parse_header_rejects_bad_magic() {
        let mut bad = FIXTURE.to_vec();
        bad[0] = b'X';
        assert!(matches!(
            parse_header(&bad),
            Err(DafsaFileLoadError::BadMagic)
        ));
    }

    #[test]
    fn parse_header_rejects_unsupported_version() {
        let mut v1 = FIXTURE.to_vec();
        v1[11] = b'1';
        assert!(matches!(
            parse_header(&v1),
            Err(DafsaFileLoadError::UnsupportedVersion(1))
        ));
    }

    #[test]
    fn parse_header_rejects_missing_newline() {
        let mut bad = FIXTURE.to_vec();
        bad[HEADER_LEN - 1] = b' ';
        assert!(matches!(
            parse_header(&bad),
            Err(DafsaFileLoadError::BadMagic)
        ));
    }
}
