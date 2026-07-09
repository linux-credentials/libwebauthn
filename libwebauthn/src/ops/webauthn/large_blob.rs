//! WebAuthn `largeBlob` read/write/delete pipeline. Wire-level spec: CTAP 2.2 §6.10.

use std::io::Read;
use std::time::Duration;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use flate2::read::DeflateDecoder;
use sha2::{Digest, Sha256};
use tracing::{debug, trace, warn};

use crate::pin::PinUvAuthProtocol;
use crate::proto::ctap2::cbor::Value;
use crate::proto::ctap2::{Ctap2, Ctap2LargeBlobsRequest, Ctap2PinUvAuthProtocol};
use crate::webauthn::WebAuthnError;

/// Spec default for `maxFragmentLength` when `maxMsgSize` is absent (CTAP 2.2 §6.10.2).
pub(crate) const LARGE_BLOB_DEFAULT_FRAGMENT: u32 = 960;

/// Cap on `origSize` per entry. CTAP 2.2 §6.10.3 RECOMMENDs at least 1 MiB.
const LARGE_BLOB_MAX_ORIG_SIZE: u64 = 1024 * 1024;

/// Static cap on the total serialized array size, to bound a misbehaving device.
const LARGE_BLOB_MAX_ARRAY_BYTES: usize = 4 * 1024 * 1024;

const LARGE_BLOB_HASH_LEN: usize = 16;
const LARGE_BLOB_NONCE_LEN: usize = 12;
const LARGE_BLOB_AD_PREFIX: &[u8] = b"blob";

#[derive(thiserror::Error, Debug)]
pub(crate) enum LargeBlobError<E> {
    #[error("On-device largeBlobArray is malformed: {0}")]
    Corrupted(String),
    /// CTAP 2.2 §6.10.6 line 303 "Return an error": delete called but no entry decrypted under our key.
    #[error("largeBlobArray has no entry to delete for this credential")]
    NoMatch,
    #[error(transparent)]
    Webauthn(#[from] WebAuthnError<E>),
}

/// `maxFragmentLength` per CTAP 2.2 §6.10.2 (`maxMsgSize - 64`, default 960). Floored at 1.
pub(crate) fn max_fragment_length(max_msg_size: Option<u32>) -> u32 {
    match max_msg_size {
        Some(m) => m.saturating_sub(64).max(1),
        None => LARGE_BLOB_DEFAULT_FRAGMENT,
    }
}

/// `LEFT(SHA-256(data), 16)` array trailer (CTAP 2.2 §6.10.2).
fn array_trailer(data: &[u8]) -> [u8; LARGE_BLOB_HASH_LEN] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; LARGE_BLOB_HASH_LEN];
    for (dst, src) in out.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    out
}

/// Fetch + parse the device-wide array once. Multi-credential callers fetch once and
/// try each key via `decrypt_first_matching`.
pub(crate) async fn fetch_large_blob_entries<C: Ctap2 + ?Sized>(
    channel: &mut C,
    max_fragment: u32,
    timeout: Duration,
) -> Result<Vec<LargeBlobMapEntry>, LargeBlobError<C::TransportError>> {
    let serialized = fetch_serialized_array(channel, max_fragment, timeout).await?;
    let array_bytes = strip_array_trailer(&serialized)?;
    parse_large_blob_array(array_bytes)
}

/// Decrypt the first entry that authenticates under `key`.
pub(crate) fn decrypt_first_matching<E>(
    entries: &[LargeBlobMapEntry],
    key: &[u8; 32],
) -> Result<Option<Vec<u8>>, LargeBlobError<E>> {
    for entry in entries {
        if let Some(plaintext) = entry.try_decrypt(key)? {
            return Ok(Some(plaintext));
        }
    }
    Ok(None)
}

/// Fetch and decrypt the largeBlob for one credential.
#[cfg(test)]
async fn read_authenticator_large_blob<C: Ctap2 + ?Sized>(
    channel: &mut C,
    large_blob_key: &[u8; 32],
    max_fragment: u32,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, LargeBlobError<C::TransportError>> {
    let entries = fetch_large_blob_entries(channel, max_fragment, timeout).await?;
    decrypt_first_matching(&entries, large_blob_key)
}

async fn fetch_serialized_array<C: Ctap2 + ?Sized>(
    channel: &mut C,
    max_fragment: u32,
    timeout: Duration,
) -> Result<Vec<u8>, LargeBlobError<C::TransportError>> {
    let mut out: Vec<u8> = Vec::new();
    let mut offset: u32 = 0;
    loop {
        let req = Ctap2LargeBlobsRequest::new_get(offset, max_fragment);
        let resp = channel
            .ctap2_large_blobs(&req, timeout)
            .await
            .map_err(LargeBlobError::Webauthn)?;
        let chunk = resp.config.map(|b| b.into_vec()).unwrap_or_default();
        let chunk_len = chunk.len();
        out.extend_from_slice(&chunk);
        trace!(
            offset,
            chunk_len,
            total = out.len(),
            "authenticatorLargeBlobs(get) chunk"
        );
        if chunk_len < max_fragment as usize {
            debug!(total = out.len(), "largeBlobArray fully fetched");
            break;
        }
        if out.len() > LARGE_BLOB_MAX_ARRAY_BYTES {
            warn!(
                total = out.len(),
                "largeBlobArray exceeded {LARGE_BLOB_MAX_ARRAY_BYTES}, aborting"
            );
            return Err(LargeBlobError::Corrupted(
                "serialized array exceeds platform cap".into(),
            ));
        }
        offset = offset
            .checked_add(chunk_len as u32)
            .ok_or_else(|| LargeBlobError::Corrupted("offset overflow".into()))?;
    }
    Ok(out)
}

const LARGE_BLOB_ENTRY_CIPHERTEXT: i128 = 0x01;
const LARGE_BLOB_ENTRY_NONCE: i128 = 0x02;
const LARGE_BLOB_ENTRY_ORIG_SIZE: i128 = 0x03;

#[derive(Debug)]
pub(crate) struct LargeBlobMapEntry {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    orig_size: u64,
}

impl LargeBlobMapEntry {
    /// `Ok(None)` on AEAD failure (skip to next entry), `Err` only on structural problems.
    fn try_decrypt<E>(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, LargeBlobError<E>> {
        if self.nonce.len() != LARGE_BLOB_NONCE_LEN {
            return Ok(None);
        }
        if self.orig_size > LARGE_BLOB_MAX_ORIG_SIZE {
            warn!(
                orig_size = self.orig_size,
                cap = LARGE_BLOB_MAX_ORIG_SIZE,
                "largeBlob entry origSize exceeds platform cap; skipping"
            );
            return Ok(None);
        }

        let mut ad = Vec::with_capacity(LARGE_BLOB_AD_PREFIX.len() + 8);
        ad.extend_from_slice(LARGE_BLOB_AD_PREFIX);
        ad.extend_from_slice(&self.orig_size.to_le_bytes());

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(&self.nonce);
        let plaintext_compressed = match cipher.decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &self.ciphertext,
                aad: &ad,
            },
        ) {
            Ok(pt) => pt,
            Err(_) => {
                trace!("largeBlob entry: AES-256-GCM verification failed; skipping");
                return Ok(None);
            }
        };

        let cap = self.orig_size as usize;
        let mut decompressed = Vec::with_capacity(cap);
        DeflateDecoder::new(plaintext_compressed.as_slice())
            .take(self.orig_size + 1)
            .read_to_end(&mut decompressed)
            .map_err(|e| LargeBlobError::Corrupted(format!("deflate decompression failed: {e}")))?;

        if decompressed.len() as u64 != self.orig_size {
            return Err(LargeBlobError::Corrupted(format!(
                "decompressed length {} != origSize {}",
                decompressed.len(),
                self.orig_size
            )));
        }
        Ok(Some(decompressed))
    }
}

fn strip_array_trailer<E>(serialized: &[u8]) -> Result<&[u8], LargeBlobError<E>> {
    if serialized.len() < LARGE_BLOB_HASH_LEN {
        return Err(LargeBlobError::Corrupted(format!(
            "serialized array length {} < trailer length {}",
            serialized.len(),
            LARGE_BLOB_HASH_LEN
        )));
    }
    let split = serialized.len() - LARGE_BLOB_HASH_LEN;
    let (array, expected_hash) = serialized.split_at(split);

    if array_trailer(array).as_slice() != expected_hash {
        return Err(LargeBlobError::Corrupted(
            "trailer SHA-256 verification failed".into(),
        ));
    }
    Ok(array)
}

/// Parse entries, skipping any with per-entry structural errors (CTAP 2.2 §6.10.3).
fn parse_large_blob_array<E>(bytes: &[u8]) -> Result<Vec<LargeBlobMapEntry>, LargeBlobError<E>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let value: crate::proto::ctap2::cbor::Value = crate::proto::ctap2::cbor::from_slice(bytes)
        .map_err(|e| {
            LargeBlobError::Corrupted(format!("failed to parse largeBlobArray CBOR: {e}"))
        })?;

    let array = match value {
        crate::proto::ctap2::cbor::Value::Array(a) => a,
        other => {
            return Err(LargeBlobError::Corrupted(format!(
                "expected CBOR array at top level, got {other:?}"
            )));
        }
    };

    let mut entries = Vec::with_capacity(array.len());
    for value in array {
        let crate::proto::ctap2::cbor::Value::Map(map) = value else {
            trace!("largeBlobArray entry is not a CBOR map; skipping");
            continue;
        };

        let mut ciphertext = None;
        let mut nonce = None;
        let mut orig_size: Option<u64> = None;
        for (k, v) in map {
            let crate::proto::ctap2::cbor::Value::Integer(key) = k else {
                continue;
            };
            match key {
                LARGE_BLOB_ENTRY_CIPHERTEXT => {
                    if let crate::proto::ctap2::cbor::Value::Bytes(b) = v {
                        ciphertext = Some(b);
                    }
                }
                LARGE_BLOB_ENTRY_NONCE => {
                    if let crate::proto::ctap2::cbor::Value::Bytes(b) = v {
                        nonce = Some(b);
                    }
                }
                LARGE_BLOB_ENTRY_ORIG_SIZE => {
                    if let crate::proto::ctap2::cbor::Value::Integer(i) = v {
                        if i >= 0 {
                            orig_size = Some(i as u64);
                        }
                    }
                }
                _ => {}
            }
        }
        match (ciphertext, nonce, orig_size) {
            (Some(ciphertext), Some(nonce), Some(orig_size)) => entries.push(LargeBlobMapEntry {
                ciphertext,
                nonce,
                orig_size,
            }),
            _ => trace!("largeBlobArray entry missing one of 0x01/0x02/0x03; skipping"),
        }
    }
    Ok(entries)
}

/// Encrypt+compress one entry under `key`, returning the canonical CBOR map per CTAP 2.2 §6.10.3.
pub(crate) fn encrypt_entry<E>(
    key: &[u8; 32],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, LargeBlobError<E>> {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    if nonce.len() != LARGE_BLOB_NONCE_LEN {
        return Err(LargeBlobError::Corrupted(format!(
            "nonce length {} != 12",
            nonce.len()
        )));
    }
    let mut compressed = Vec::new();
    {
        let mut encoder = DeflateEncoder::new(&mut compressed, Compression::default());
        encoder
            .write_all(plaintext)
            .map_err(|e| LargeBlobError::Corrupted(format!("deflate failure: {e}")))?;
        encoder
            .finish()
            .map_err(|e| LargeBlobError::Corrupted(format!("deflate finish failure: {e}")))?;
    }

    let mut ad = Vec::with_capacity(LARGE_BLOB_AD_PREFIX.len() + 8);
    ad.extend_from_slice(LARGE_BLOB_AD_PREFIX);
    ad.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_obj = Nonce::from_slice(nonce);
    let ciphertext = cipher
        .encrypt(
            nonce_obj,
            aes_gcm::aead::Payload {
                msg: &compressed,
                aad: &ad,
            },
        )
        .map_err(|_| LargeBlobError::Corrupted("AES-256-GCM encryption failed".into()))?;

    use serde_cbor_2::ser::Serializer;
    use serde_cbor_2::value::Value as CborVal;
    use std::collections::BTreeMap;
    let mut map = BTreeMap::new();
    map.insert(CborVal::Integer(1), CborVal::Bytes(ciphertext));
    map.insert(CborVal::Integer(2), CborVal::Bytes(nonce.to_vec()));
    map.insert(
        CborVal::Integer(3),
        CborVal::Integer(plaintext.len() as i128),
    );

    let mut buf = Vec::new();
    let mut ser = Serializer::new(&mut buf);
    serde::Serialize::serialize(&CborVal::Map(map), &mut ser)
        .map_err(|e| LargeBlobError::Corrupted(format!("entry CBOR serialize failure: {e}")))?;
    Ok(buf)
}

/// Assemble a serialized largeBlobArray (entries + 16-byte trailer). CTAP 2.2 §6.10.2 trailer = `LEFT(SHA-256(array_bytes), 16)`.
/// Production write uses `rebuild_serialized_array`; this helper is retained for the read/decrypt unit tests.
#[cfg(test)]
pub(crate) fn build_serialized_array(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    let n = entries.len();
    if n <= 23 {
        out.push(0x80 | n as u8);
    } else if n <= 0xff {
        out.push(0x98);
        out.push(n as u8);
    } else {
        out.push(0x99);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    }
    for entry in entries {
        out.extend_from_slice(entry);
    }
    let mut hasher = Sha256::new();
    hasher.update(&out);
    let h = hasher.finalize();
    out.extend_from_slice(&h[..LARGE_BLOB_HASH_LEN]);
    out
}

/// `pinUvAuthParam` for an `authenticatorLargeBlobs(set)` chunk. CTAP 2.2 §6.10.2:
/// `authenticate(token, 32×0xff || h'0c00' || uint32LittleEndian(offset) || SHA-256(set))`.
pub(crate) fn large_blob_pin_uv_auth_param<E>(
    token: &[u8],
    proto: &dyn PinUvAuthProtocol,
    offset: u32,
    chunk: &[u8],
) -> Result<Vec<u8>, WebAuthnError<E>> {
    let mut buf = Vec::with_capacity(32 + 2 + 4 + 32);
    buf.extend_from_slice(&[0xff; 32]);
    buf.extend_from_slice(&[0x0c, 0x00]);
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(&Sha256::digest(chunk));
    Ok(proto.authenticate(token, &buf)?)
}

/// One array element kept as its exact CBOR bytes, plus a best-effort decode for ownership testing.
struct RawArrayEntry {
    raw: Vec<u8>,
    value: Option<Value>,
}

fn read_byte<E>(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u8, LargeBlobError<E>> {
    use std::io::Read;
    let mut b = [0u8; 1];
    cursor
        .read_exact(&mut b)
        .map_err(|_| LargeBlobError::Corrupted("truncated CBOR".into()))?;
    let [byte] = b;
    Ok(byte)
}

fn read_uint<E>(cursor: &mut std::io::Cursor<&[u8]>, n: usize) -> Result<u64, LargeBlobError<E>> {
    let mut val: u64 = 0;
    for _ in 0..n {
        val = (val << 8) | read_byte(cursor)? as u64;
    }
    Ok(val)
}

/// Read a definite-length CBOR array header (major type 4), returning the element count.
fn read_array_header<E>(cursor: &mut std::io::Cursor<&[u8]>) -> Result<usize, LargeBlobError<E>> {
    let initial = read_byte(cursor)?;
    if initial >> 5 != 4 {
        return Err(LargeBlobError::Corrupted(format!(
            "expected CBOR array, got initial byte {initial:#x}"
        )));
    }
    let count = match initial & 0x1f {
        n @ 0..=23 => n as u64,
        24 => read_uint(cursor, 1)?,
        25 => read_uint(cursor, 2)?,
        26 => read_uint(cursor, 4)?,
        27 => read_uint(cursor, 8)?,
        ai => {
            return Err(LargeBlobError::Corrupted(format!(
                "unsupported CBOR array length encoding (additional info {ai})"
            )))
        }
    };
    usize::try_from(count).map_err(|_| LargeBlobError::Corrupted("array too large".into()))
}

/// CBOR definite-length array header for `n` elements.
fn encode_array_header(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if n <= 23 {
        out.push(0x80 | n as u8);
    } else if n <= 0xff {
        out.push(0x98);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0x99);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0x9a);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    out
}

/// Parse the top-level array into per-element raw byte spans, preserving foreign entries exactly.
fn parse_array_raw_entries<E>(bytes: &[u8]) -> Result<Vec<RawArrayEntry>, LargeBlobError<E>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut cursor = std::io::Cursor::new(bytes);
    let count = read_array_header(&mut cursor)?;
    // Bound the pre-allocation by the remaining bytes (each element is >= 1 byte) so a
    // device-declared count cannot drive an unbounded allocation.
    let remaining = bytes.len().saturating_sub(cursor.position() as usize);
    let mut entries = Vec::with_capacity(count.min(remaining));
    for _ in 0..count {
        let start = cursor.position() as usize;
        let _: serde::de::IgnoredAny = crate::proto::ctap2::cbor::from_cursor(&mut cursor)
            .map_err(|e| LargeBlobError::Corrupted(format!("array element parse: {e}")))?;
        let end = cursor.position() as usize;
        let raw = bytes
            .get(start..end)
            .ok_or_else(|| LargeBlobError::Corrupted("array element span out of range".into()))?
            .to_vec();
        let value = crate::proto::ctap2::cbor::from_slice::<Value>(&raw).ok();
        entries.push(RawArrayEntry { raw, value });
    }
    if cursor.position() as usize != bytes.len() {
        return Err(LargeBlobError::Corrupted(
            "trailing bytes after largeBlobArray".into(),
        ));
    }
    Ok(entries)
}

/// AEAD-verify an entry under `key`. Used to identify the credential's own entry during RMW.
fn entry_decrypts_under_key(entry: &Value, key: &[u8; 32]) -> bool {
    let Value::Map(map) = entry else {
        return false;
    };
    let mut ciphertext: Option<&[u8]> = None;
    let mut nonce: Option<&[u8]> = None;
    let mut orig_size: Option<u64> = None;
    for (k, v) in map.iter() {
        let Value::Integer(ki) = k else { continue };
        match *ki {
            LARGE_BLOB_ENTRY_CIPHERTEXT => {
                if let Value::Bytes(b) = v {
                    ciphertext = Some(b.as_slice());
                }
            }
            LARGE_BLOB_ENTRY_NONCE => {
                if let Value::Bytes(b) = v {
                    nonce = Some(b.as_slice());
                }
            }
            LARGE_BLOB_ENTRY_ORIG_SIZE => {
                if let Value::Integer(i) = v {
                    if *i >= 0 {
                        orig_size = Some(*i as u64);
                    }
                }
            }
            _ => {}
        }
    }
    let (Some(ct), Some(n), Some(os)) = (ciphertext, nonce, orig_size) else {
        return false;
    };
    if n.len() != LARGE_BLOB_NONCE_LEN {
        return false;
    }
    let mut ad = Vec::with_capacity(LARGE_BLOB_AD_PREFIX.len() + 8);
    ad.extend_from_slice(LARGE_BLOB_AD_PREFIX);
    ad.extend_from_slice(&os.to_le_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_obj = Nonce::from_slice(n);
    cipher
        .decrypt(nonce_obj, aes_gcm::aead::Payload { msg: ct, aad: &ad })
        .is_ok()
}

/// Drop entries that AEAD-verify under `drop_key`, optionally append `new_entry`, append the trailer.
/// Foreign entries are spliced back by their original bytes per CTAP 2.2 §6.10.2.
fn rebuild_serialized_array<E>(
    existing: &[RawArrayEntry],
    drop_key: &[u8; 32],
    new_entry: Option<Vec<u8>>,
) -> Result<Vec<u8>, LargeBlobError<E>> {
    let mut kept: Vec<&[u8]> = Vec::with_capacity(existing.len() + 1);
    for entry in existing {
        if entry
            .value
            .as_ref()
            .is_some_and(|v| entry_decrypts_under_key(v, drop_key))
        {
            trace!("largeBlob RMW: dropping entry owned by this credential");
            continue;
        }
        kept.push(&entry.raw);
    }
    if let Some(ref n) = new_entry {
        kept.push(n);
    }
    let mut bytes = encode_array_header(kept.len());
    for element in &kept {
        bytes.extend_from_slice(element);
    }
    bytes.extend_from_slice(&array_trailer(&bytes));
    Ok(bytes)
}

/// Trailer mismatch yields the initial empty array. A valid-trailer parse error is propagated
/// (fail-safe: avoids clobbering a hash-valid foreign array).
async fn fetch_or_initial<C: Ctap2 + ?Sized>(
    channel: &mut C,
    max_fragment: u32,
    timeout: Duration,
) -> Result<Vec<RawArrayEntry>, LargeBlobError<C::TransportError>> {
    let serialized = fetch_serialized_array(channel, max_fragment, timeout).await?;
    match strip_array_trailer::<C::TransportError>(&serialized) {
        Ok(array_bytes) => parse_array_raw_entries(array_bytes),
        Err(_) => {
            warn!("largeBlobArray trailer mismatch; treating as initial empty array (CTAP 2.2 §6.10.2)");
            Ok(Vec::new())
        }
    }
}

/// Drive the chunked write protocol (CTAP 2.2 §6.10.2) for one serialized array.
/// `pin_uv_auth` is `None` for unprotected authenticators (spec line 100, conditional auth block).
async fn upload_serialized_array<C: Ctap2 + ?Sized>(
    channel: &mut C,
    serialized: &[u8],
    max_fragment: u32,
    pin_uv_auth: Option<(&[u8], Ctap2PinUvAuthProtocol)>,
    timeout: Duration,
) -> Result<(), LargeBlobError<C::TransportError>> {
    let total: u32 = serialized
        .len()
        .try_into()
        .map_err(|_| LargeBlobError::Corrupted("serialized array exceeds u32::MAX".into()))?;
    if (total as usize) < 17 {
        // CTAP 2.2 §6.10.2 requires length >= 17 (empty array sentinel).
        return Err(LargeBlobError::Corrupted(format!(
            "serialized array length {total} below 17-byte minimum"
        )));
    }
    if (total as usize) > LARGE_BLOB_MAX_ARRAY_BYTES {
        return Err(LargeBlobError::Corrupted(format!(
            "serialized array {total} exceeds platform cap {LARGE_BLOB_MAX_ARRAY_BYTES}"
        )));
    }
    let proto = pin_uv_auth
        .as_ref()
        .map(|(_, v)| v.create_protocol_object());
    let chunk_cap = max_fragment as usize;
    let mut offset: u32 = 0;
    while (offset as usize) < serialized.len() {
        let end = (offset as usize + chunk_cap).min(serialized.len());
        let Some(chunk) = serialized.get(offset as usize..end) else {
            return Err(LargeBlobError::Corrupted(
                "chunk offset out of range".into(),
            ));
        };
        let chunk_auth = match (&pin_uv_auth, &proto) {
            (Some((token, version)), Some(proto)) => {
                let param = large_blob_pin_uv_auth_param(token, proto.as_ref(), offset, chunk)
                    .map_err(LargeBlobError::Webauthn)?;
                Some((param, *version as u32))
            }
            _ => None,
        };
        let req = if offset == 0 {
            Ctap2LargeBlobsRequest::new_set_first(chunk.to_vec(), total, chunk_auth)
        } else {
            Ctap2LargeBlobsRequest::new_set_continuation(chunk.to_vec(), offset, chunk_auth)
        };
        trace!(
            offset,
            chunk_len = chunk.len(),
            total,
            "authenticatorLargeBlobs(set) chunk"
        );
        channel
            .ctap2_large_blobs(&req, timeout)
            .await
            .map_err(LargeBlobError::Webauthn)?;
        offset = offset
            .checked_add(chunk.len() as u32)
            .ok_or_else(|| LargeBlobError::Corrupted("offset overflow".into()))?;
    }
    debug!(total, "largeBlobArray fully written");
    Ok(())
}

/// Store `blob` against the credential identified by `large_blob_key`, replacing any prior entry.
/// Implements WebAuthn L3 §10.1.5 write atop the §6.10.6 update-or-append loop.
/// `pin_uv_auth` is `None` on unprotected authenticators (CTAP 2.2 §6.10.2).
pub(crate) async fn write_authenticator_large_blob<C: Ctap2 + ?Sized>(
    channel: &mut C,
    large_blob_key: &[u8; 32],
    blob: &[u8],
    max_fragment: u32,
    pin_uv_auth: Option<(&[u8], Ctap2PinUvAuthProtocol)>,
    timeout: Duration,
) -> Result<(), LargeBlobError<C::TransportError>> {
    if (blob.len() as u64) > LARGE_BLOB_MAX_ORIG_SIZE {
        return Err(LargeBlobError::Corrupted(format!(
            "blob length {} exceeds platform cap {LARGE_BLOB_MAX_ORIG_SIZE}",
            blob.len()
        )));
    }
    let existing = fetch_or_initial(channel, max_fragment, timeout).await?;
    let mut nonce = [0u8; LARGE_BLOB_NONCE_LEN];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    let entry_bytes = encrypt_entry(large_blob_key, &nonce, blob)?;
    let serialized = rebuild_serialized_array(&existing, large_blob_key, Some(entry_bytes))?;
    upload_serialized_array(channel, &serialized, max_fragment, pin_uv_auth, timeout).await
}

/// Erase the credential's entry (CTAP 2.2 §6.10.6 "Erase the current array element").
/// No-op if no entry matches.
pub(crate) async fn delete_authenticator_large_blob<C: Ctap2 + ?Sized>(
    channel: &mut C,
    large_blob_key: &[u8; 32],
    max_fragment: u32,
    pin_uv_auth: Option<(&[u8], Ctap2PinUvAuthProtocol)>,
    timeout: Duration,
) -> Result<(), LargeBlobError<C::TransportError>> {
    let existing = fetch_or_initial(channel, max_fragment, timeout).await?;
    let any_owned = existing.iter().any(|e| {
        e.value
            .as_ref()
            .is_some_and(|v| entry_decrypts_under_key(v, large_blob_key))
    });
    if !any_owned {
        // Strict CTAP 2.2 §6.10.6 reading: no matching entry => error path (line 303).
        return Err(LargeBlobError::NoMatch);
    }
    let serialized = rebuild_serialized_array(&existing, large_blob_key, None)?;
    upload_serialized_array(channel, &serialized, max_fragment, pin_uv_auth, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn rp_id_hash(rp_id: &str) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::default();
        hasher.update(rp_id.as_bytes());
        hasher.finalize().to_vec()
    }

    fn raw_entry(bytes: &[u8]) -> RawArrayEntry {
        RawArrayEntry {
            raw: bytes.to_vec(),
            value: crate::proto::ctap2::cbor::from_slice::<Value>(bytes).ok(),
        }
    }

    #[test]
    fn max_fragment_uses_get_info_when_available() {
        assert_eq!(max_fragment_length(Some(2048)), 2048 - 64);
    }

    #[test]
    fn max_fragment_falls_back_to_spec_default() {
        assert_eq!(max_fragment_length(None), LARGE_BLOB_DEFAULT_FRAGMENT);
    }

    #[test]
    fn max_fragment_respects_device_size_with_floor() {
        assert_eq!(max_fragment_length(Some(512)), 512 - 64);
        assert_eq!(max_fragment_length(Some(64)), 1);
        assert_eq!(max_fragment_length(Some(32)), 1);
    }

    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let plaintext = b"the quick brown fox".to_vec();
        let entry_bytes = encrypt_entry::<Infallible>(&key, &nonce, &plaintext).expect("encrypt");

        let serialized = build_serialized_array(&[entry_bytes]);
        let array_bytes = strip_array_trailer::<Infallible>(&serialized).expect("trailer");
        let parsed = parse_large_blob_array::<Infallible>(array_bytes).expect("parse");
        assert_eq!(parsed.len(), 1);
        let plaintext_decoded = parsed[0]
            .try_decrypt::<Infallible>(&key)
            .expect("decrypt")
            .expect("entry should verify under the correct key");
        assert_eq!(plaintext_decoded, plaintext);
    }

    #[test]
    fn decrypt_under_wrong_key_returns_none() {
        let real_key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = [0x07u8; 12];
        let plaintext = b"secret".to_vec();
        let entry_bytes =
            encrypt_entry::<Infallible>(&real_key, &nonce, &plaintext).expect("encrypt");
        let serialized = build_serialized_array(&[entry_bytes]);
        let array_bytes = strip_array_trailer::<Infallible>(&serialized).expect("trailer");
        let parsed = parse_large_blob_array::<Infallible>(array_bytes).expect("parse");
        let res = parsed[0]
            .try_decrypt::<Infallible>(&wrong_key)
            .expect("decrypt should not error on AEAD failure");
        assert!(res.is_none());
    }

    #[test]
    fn corrupted_trailer_is_rejected() {
        let mut serialized = build_serialized_array(&[]);
        let last = serialized.len() - 1;
        serialized[last] ^= 0xff;
        let err = strip_array_trailer::<Infallible>(&serialized).unwrap_err();
        assert!(matches!(err, LargeBlobError::Corrupted(_)));
    }

    #[test]
    fn truncated_serialized_array_is_rejected() {
        let too_short = vec![0u8; 8];
        let err = strip_array_trailer::<Infallible>(&too_short).unwrap_err();
        assert!(matches!(err, LargeBlobError::Corrupted(_)));
    }

    #[test]
    fn empty_array_parses_to_zero_entries() {
        let serialized = build_serialized_array(&[]);
        let array_bytes = strip_array_trailer::<Infallible>(&serialized).unwrap();
        let parsed = parse_large_blob_array::<Infallible>(array_bytes).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn multi_entry_array_finds_matching_key() {
        let key_a = [0xa1u8; 32];
        let key_b = [0xb2u8; 32];
        let key_c = [0xc3u8; 32];
        let nonce = [0x55u8; 12];
        let entry_a = encrypt_entry::<Infallible>(&key_a, &nonce, b"alpha").unwrap();
        let entry_b = encrypt_entry::<Infallible>(&key_b, &nonce, b"bravo").unwrap();
        let entry_c = encrypt_entry::<Infallible>(&key_c, &nonce, b"charlie").unwrap();
        let serialized = build_serialized_array(&[entry_a, entry_b, entry_c]);
        let array_bytes = strip_array_trailer::<Infallible>(&serialized).unwrap();
        let parsed = parse_large_blob_array::<Infallible>(array_bytes).unwrap();
        assert_eq!(parsed.len(), 3);

        let mut found_b = None;
        for e in &parsed {
            if let Some(pt) = e.try_decrypt::<Infallible>(&key_b).unwrap() {
                found_b = Some(pt);
            }
        }
        assert_eq!(found_b.as_deref(), Some(&b"bravo"[..]));
    }

    /// Per CTAP 2.2 §6.10.4, a malformed entry MUST be skipped, not aborted.
    /// Construct an array containing one bad entry (non-map) plus one good
    /// entry; verify we still find the good one.
    #[test]
    fn malformed_entry_is_skipped_not_errored() {
        use serde_cbor_2::value::Value as CborVal;

        let key = [0xCAu8; 32];
        let nonce = [0x33u8; 12];
        let good = encrypt_entry::<Infallible>(&key, &nonce, b"survivor").unwrap();

        let bad_entry_bytes = {
            let mut buf = Vec::new();
            let mut ser = serde_cbor_2::ser::Serializer::new(&mut buf);
            serde::Serialize::serialize(&CborVal::Text("not-a-map".into()), &mut ser).unwrap();
            buf
        };
        let serialized = build_serialized_array(&[bad_entry_bytes, good]);
        let array_bytes = strip_array_trailer::<Infallible>(&serialized).unwrap();
        let parsed =
            parse_large_blob_array::<Infallible>(array_bytes).expect("parse must not error");
        assert_eq!(parsed.len(), 1, "bad entry skipped, good entry kept");
        let pt = parsed[0].try_decrypt::<Infallible>(&key).unwrap().unwrap();
        assert_eq!(pt, b"survivor");
    }

    /// Entry missing the ciphertext field is skipped without erroring.
    #[test]
    fn entry_missing_required_field_is_skipped() {
        use serde_cbor_2::value::Value as CborVal;
        use std::collections::BTreeMap;

        let key = [0xCBu8; 32];
        let nonce = [0x44u8; 12];
        let good = encrypt_entry::<Infallible>(&key, &nonce, b"present").unwrap();

        let incomplete = {
            let mut map = BTreeMap::new();
            map.insert(CborVal::Integer(2), CborVal::Bytes(vec![0u8; 12]));
            map.insert(CborVal::Integer(3), CborVal::Integer(5));
            let mut buf = Vec::new();
            let mut ser = serde_cbor_2::ser::Serializer::new(&mut buf);
            serde::Serialize::serialize(&CborVal::Map(map), &mut ser).unwrap();
            buf
        };
        let serialized = build_serialized_array(&[incomplete, good]);
        let array_bytes = strip_array_trailer::<Infallible>(&serialized).unwrap();
        let parsed =
            parse_large_blob_array::<Infallible>(array_bytes).expect("parse must not error");
        assert_eq!(parsed.len(), 1);
        let pt = parsed[0].try_decrypt::<Infallible>(&key).unwrap().unwrap();
        assert_eq!(pt, b"present");
    }

    #[tokio::test]
    async fn read_authenticator_large_blob_via_mock_channel() {
        use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
        use crate::proto::ctap2::{Ctap2CommandCode, Ctap2LargeBlobsResponse};
        use crate::transport::mock::channel::MockChannel;

        let key = [0xC0u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"hello, largeBlob".to_vec();
        let entry = encrypt_entry::<Infallible>(&key, &nonce, &plaintext).unwrap();
        let serialized = build_serialized_array(&[entry]);
        assert!(
            serialized.len() < LARGE_BLOB_DEFAULT_FRAGMENT as usize,
            "test fixture should fit in one chunk"
        );

        let req = Ctap2LargeBlobsRequest::new_get(0, LARGE_BLOB_DEFAULT_FRAGMENT);
        let req_bytes = crate::proto::ctap2::cbor::to_vec(&req).unwrap();
        let expected = CborRequest {
            command: Ctap2CommandCode::AuthenticatorLargeBlobs,
            encoded_data: req_bytes,
        };

        let resp = Ctap2LargeBlobsResponse {
            config: Some(serde_bytes::ByteBuf::from(serialized)),
        };
        let resp_bytes = crate::proto::ctap2::cbor::to_vec(&resp).unwrap();
        let response = CborResponse::new_success_from_slice(&resp_bytes);

        let mut channel = MockChannel::new();
        channel.push_command_pair(expected, response);

        let got = read_authenticator_large_blob(
            &mut channel,
            &key,
            LARGE_BLOB_DEFAULT_FRAGMENT,
            Duration::from_secs(5),
        )
        .await
        .expect("read should succeed");
        assert_eq!(got.as_deref(), Some(plaintext.as_slice()));
    }

    #[tokio::test]
    async fn read_authenticator_large_blob_empty_array_returns_none() {
        use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
        use crate::proto::ctap2::{Ctap2CommandCode, Ctap2LargeBlobsResponse};
        use crate::transport::mock::channel::MockChannel;

        let serialized = build_serialized_array(&[]);
        let req = Ctap2LargeBlobsRequest::new_get(0, LARGE_BLOB_DEFAULT_FRAGMENT);
        let req_bytes = crate::proto::ctap2::cbor::to_vec(&req).unwrap();
        let expected = CborRequest {
            command: Ctap2CommandCode::AuthenticatorLargeBlobs,
            encoded_data: req_bytes,
        };
        let resp = Ctap2LargeBlobsResponse {
            config: Some(serde_bytes::ByteBuf::from(serialized)),
        };
        let resp_bytes = crate::proto::ctap2::cbor::to_vec(&resp).unwrap();
        let response = CborResponse::new_success_from_slice(&resp_bytes);

        let mut channel = MockChannel::new();
        channel.push_command_pair(expected, response);

        let got = read_authenticator_large_blob(
            &mut channel,
            &[0xAA; 32],
            LARGE_BLOB_DEFAULT_FRAGMENT,
            Duration::from_secs(5),
        )
        .await
        .expect("read");
        assert!(got.is_none());
    }

    /// End-to-end check of the read path through `webauthn_get_assertion`:
    /// drives the CTAP exchange, array parsing, AES-256-GCM decrypt, deflate
    /// decompress, and surfaces the plaintext as the WebAuthn JSON output.
    #[tokio::test]
    async fn webauthn_get_assertion_returns_decrypted_large_blob() {
        use crate::ops::webauthn::{
            GetAssertionLargeBlobExtension, GetAssertionRequest, GetAssertionRequestExtensions,
            UserVerificationRequirement,
        };
        use crate::proto::ctap2::cbor::{to_vec, CborRequest, CborResponse, Value};
        use crate::proto::ctap2::{
            Ctap2CommandCode, Ctap2GetInfoResponse, Ctap2LargeBlobsResponse,
        };
        use crate::transport::mock::channel::MockChannel;
        use crate::webauthn::WebAuthn;
        use std::collections::{BTreeMap, HashMap};

        let large_blob_key = [0x77u8; 32];
        let nonce = [0x22u8; 12];
        let plaintext = b"webauthn end-to-end largeBlob".to_vec();
        let entry = encrypt_entry::<Infallible>(&large_blob_key, &nonce, &plaintext).unwrap();
        let serialized_array = build_serialized_array(&[entry]);

        let credential_id = b"cred-id".to_vec();
        let mut auth_data = vec![0u8; 37];
        auth_data[..32].copy_from_slice(&rp_id_hash("example.com"));
        auth_data[32] = 0x01; // USER_PRESENT flag
        let mut cred_id_map = BTreeMap::new();
        cred_id_map.insert(Value::Text("type".into()), Value::Text("public-key".into()));
        cred_id_map.insert(
            Value::Text("id".into()),
            Value::Bytes(credential_id.clone()),
        );
        let mut response_map = BTreeMap::new();
        response_map.insert(Value::Integer(1), Value::Map(cred_id_map));
        response_map.insert(Value::Integer(2), Value::Bytes(auth_data));
        response_map.insert(Value::Integer(3), Value::Bytes(vec![0u8; 32]));
        response_map.insert(Value::Integer(7), Value::Bytes(large_blob_key.to_vec()));
        let assertion_resp_cbor = to_vec(&Value::Map(response_map)).unwrap();

        let mut info = Ctap2GetInfoResponse {
            versions: vec!["FIDO_2_1".into()],
            ..Default::default()
        };
        let mut options = HashMap::new();
        options.insert("largeBlobs".into(), true);
        info.options = Some(options);
        let info_cbor = to_vec(&info).unwrap();

        let mut channel = MockChannel::new();

        // 1. get_assertion_fido2 calls ctap2_get_info().
        channel.push_command_pair(
            CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo),
            CborResponse::new_success_from_slice(&info_cbor),
        );
        // 2. user_verification calls ctap2_get_info() again.
        channel.push_command_pair(
            CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo),
            CborResponse::new_success_from_slice(&info_cbor),
        );
        // 3. ctap2_get_assertion. Discouraged UV path → up=true, uv=false.
        let req = crate::proto::ctap2::Ctap2GetAssertionRequest::from(GetAssertionRequest {
            hints: vec![],
            relying_party_id: "example.com".into(),
            challenge: vec![0u8; 32],
            origin: "example.com".into(),
            top_origin: None,
            allow: vec![],
            extensions: Some(GetAssertionRequestExtensions {
                appid: None,
                cred_blob: false,
                prf: None,
                large_blob: Some(GetAssertionLargeBlobExtension::Read),
            }),
            user_verification: UserVerificationRequirement::Discouraged,
            timeout: Duration::from_secs(5),
        });
        let assertion_req_cbor = crate::proto::ctap2::cbor::to_vec(&req).unwrap();
        channel.push_command_pair(
            CborRequest {
                command: Ctap2CommandCode::AuthenticatorGetAssertion,
                encoded_data: assertion_req_cbor,
            },
            CborResponse::new_success_from_slice(&assertion_resp_cbor),
        );
        // 4. authenticatorLargeBlobs(get). Info omits max_msg_size, so we
        //    expect the spec default fragment.
        let blobs_req = Ctap2LargeBlobsRequest::new_get(0, LARGE_BLOB_DEFAULT_FRAGMENT);
        let blobs_resp = Ctap2LargeBlobsResponse {
            config: Some(serde_bytes::ByteBuf::from(serialized_array)),
        };
        channel.push_command_pair(
            CborRequest {
                command: Ctap2CommandCode::AuthenticatorLargeBlobs,
                encoded_data: crate::proto::ctap2::cbor::to_vec(&blobs_req).unwrap(),
            },
            CborResponse::new_success_from_slice(
                &crate::proto::ctap2::cbor::to_vec(&blobs_resp).unwrap(),
            ),
        );

        let request = GetAssertionRequest {
            hints: vec![],
            relying_party_id: "example.com".into(),
            challenge: vec![0u8; 32],
            origin: "example.com".into(),
            top_origin: None,
            allow: vec![],
            extensions: Some(GetAssertionRequestExtensions {
                appid: None,
                cred_blob: false,
                prf: None,
                large_blob: Some(GetAssertionLargeBlobExtension::Read),
            }),
            user_verification: UserVerificationRequirement::Discouraged,
            timeout: Duration::from_secs(5),
        };

        let response = channel
            .webauthn_get_assertion(&request)
            .await
            .expect("webauthn_get_assertion should succeed");
        assert_eq!(response.assertions.len(), 1);
        let large_blob = response.assertions[0]
            .unsigned_extensions_output
            .as_ref()
            .expect("unsigned extensions present")
            .large_blob
            .as_ref()
            .expect("largeBlob extension output present");
        assert_eq!(large_blob.blob.as_deref(), Some(plaintext.as_slice()));
    }

    /// L5: a multi-credential assertion fetches the device-wide array ONCE and decrypts per
    /// credential. A second authenticatorLargeBlobs(get) would have no programmed pair and panic.
    #[tokio::test]
    async fn webauthn_get_assertion_fetches_large_blob_array_once_for_multiple_credentials() {
        use crate::ops::webauthn::{
            GetAssertionLargeBlobExtension, GetAssertionRequest, GetAssertionRequestExtensions,
            UserVerificationRequirement,
        };
        use crate::proto::ctap2::cbor::{to_vec, CborRequest, CborResponse, Value};
        use crate::proto::ctap2::{
            Ctap2CommandCode, Ctap2GetInfoResponse, Ctap2LargeBlobsResponse,
        };
        use crate::transport::mock::channel::MockChannel;
        use crate::webauthn::WebAuthn;
        use std::collections::{BTreeMap, HashMap};

        let key0 = [0x11u8; 32];
        let key1 = [0x22u8; 32];
        let pt0 = b"blob for credential zero".to_vec();
        let pt1 = b"blob for credential one".to_vec();
        let entry0 = encrypt_entry::<Infallible>(&key0, &[0xa0u8; 12], &pt0).unwrap();
        let entry1 = encrypt_entry::<Infallible>(&key1, &[0xb1u8; 12], &pt1).unwrap();
        let serialized_array = build_serialized_array(&[entry0, entry1]);
        assert!(
            serialized_array.len() < LARGE_BLOB_DEFAULT_FRAGMENT as usize,
            "array must fit one fragment"
        );

        let assertion_cbor = |cred: &[u8], lbk: &[u8; 32], count: Option<i128>| {
            let mut auth_data = vec![0u8; 37];
            auth_data[..32].copy_from_slice(&rp_id_hash("example.com"));
            auth_data[32] = 0x01; // USER_PRESENT
            let mut cred_map = BTreeMap::new();
            cred_map.insert(Value::Text("type".into()), Value::Text("public-key".into()));
            cred_map.insert(Value::Text("id".into()), Value::Bytes(cred.to_vec()));
            let mut m = BTreeMap::new();
            m.insert(Value::Integer(1), Value::Map(cred_map));
            m.insert(Value::Integer(2), Value::Bytes(auth_data));
            m.insert(Value::Integer(3), Value::Bytes(vec![0u8; 32]));
            if let Some(c) = count {
                m.insert(Value::Integer(5), Value::Integer(c));
            }
            m.insert(Value::Integer(7), Value::Bytes(lbk.to_vec()));
            to_vec(&Value::Map(m)).unwrap()
        };

        let mut info = Ctap2GetInfoResponse {
            versions: vec!["FIDO_2_1".into()],
            ..Default::default()
        };
        let mut options = HashMap::new();
        options.insert("largeBlobs".into(), true);
        info.options = Some(options);
        let info_cbor = to_vec(&info).unwrap();

        let mut channel = MockChannel::new();
        channel.push_command_pair(
            CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo),
            CborResponse::new_success_from_slice(&info_cbor),
        );
        channel.push_command_pair(
            CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo),
            CborResponse::new_success_from_slice(&info_cbor),
        );

        let make_req = || GetAssertionRequest {
            hints: vec![],
            relying_party_id: "example.com".into(),
            challenge: vec![0u8; 32],
            origin: "example.com".into(),
            top_origin: None,
            allow: vec![],
            extensions: Some(GetAssertionRequestExtensions {
                appid: None,
                cred_blob: false,
                prf: None,
                large_blob: Some(GetAssertionLargeBlobExtension::Read),
            }),
            user_verification: UserVerificationRequirement::Discouraged,
            timeout: Duration::from_secs(5),
        };
        let req = crate::proto::ctap2::Ctap2GetAssertionRequest::from(make_req());
        channel.push_command_pair(
            CborRequest {
                command: Ctap2CommandCode::AuthenticatorGetAssertion,
                encoded_data: to_vec(&req).unwrap(),
            },
            CborResponse::new_success_from_slice(&assertion_cbor(b"cred-0", &key0, Some(2))),
        );
        channel.push_command_pair(
            CborRequest::new(Ctap2CommandCode::AuthenticatorGetNextAssertion),
            CborResponse::new_success_from_slice(&assertion_cbor(b"cred-1", &key1, None)),
        );
        let blobs_req = Ctap2LargeBlobsRequest::new_get(0, LARGE_BLOB_DEFAULT_FRAGMENT);
        channel.push_command_pair(
            CborRequest {
                command: Ctap2CommandCode::AuthenticatorLargeBlobs,
                encoded_data: to_vec(&blobs_req).unwrap(),
            },
            CborResponse::new_success_from_slice(
                &to_vec(&Ctap2LargeBlobsResponse {
                    config: Some(serde_bytes::ByteBuf::from(serialized_array)),
                })
                .unwrap(),
            ),
        );

        let response = channel
            .webauthn_get_assertion(&make_req())
            .await
            .expect("get_assertion should succeed");
        assert_eq!(response.assertions.len(), 2);
        let blob = |i: usize| {
            response.assertions[i]
                .unsigned_extensions_output
                .as_ref()
                .unwrap()
                .large_blob
                .as_ref()
                .unwrap()
                .blob
                .clone()
        };
        assert_eq!(blob(0).as_deref(), Some(pt0.as_slice()));
        assert_eq!(blob(1).as_deref(), Some(pt1.as_slice()));
    }

    /// Spot-check the CTAP 2.2 §6.10.2 auth-param construction byte-for-byte:
    /// the message MUST be `32×0xff || 0x0c, 0x00 || u32_le(offset) || SHA-256(chunk)`.
    #[test]
    fn large_blob_pin_uv_auth_param_matches_spec_message() {
        use crate::pin::PinUvAuthProtocolTwo;
        use hmac::Mac;

        let token = [0x11u8; 32];
        let chunk = b"some chunk bytes";
        let offset: u32 = 0x12345678;

        let proto = PinUvAuthProtocolTwo::new();
        let got = large_blob_pin_uv_auth_param::<Infallible>(&token, &proto, offset, chunk)
            .expect("auth_param");

        let mut expected_msg = Vec::new();
        expected_msg.extend_from_slice(&[0xff; 32]);
        expected_msg.extend_from_slice(&[0x0c, 0x00]);
        expected_msg.extend_from_slice(&offset.to_le_bytes());
        expected_msg.extend_from_slice(&Sha256::digest(chunk));
        let mut mac = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(&token).unwrap();
        mac.update(&expected_msg);
        let expected = mac.finalize().into_bytes();

        assert_eq!(got, expected.as_slice());
    }

    #[test]
    fn entry_decrypts_under_key_matches_owned_entry() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let entry_bytes = encrypt_entry::<Infallible>(&key, &nonce, b"owned blob").unwrap();
        let entry: Value = crate::proto::ctap2::cbor::from_slice(&entry_bytes).unwrap();
        assert!(entry_decrypts_under_key(&entry, &key));
    }

    #[test]
    fn entry_decrypts_under_key_rejects_foreign_entry() {
        let owner = [0xa1u8; 32];
        let other = [0xb2u8; 32];
        let nonce = [0x33u8; 12];
        let entry_bytes =
            encrypt_entry::<Infallible>(&owner, &nonce, b"someone else's blob").unwrap();
        let entry: Value = crate::proto::ctap2::cbor::from_slice(&entry_bytes).unwrap();
        assert!(!entry_decrypts_under_key(&entry, &other));
    }

    #[test]
    fn entry_decrypts_under_key_rejects_non_map() {
        let v = Value::Text("not a map".into());
        assert!(!entry_decrypts_under_key(&v, &[0u8; 32]));
    }

    #[test]
    fn rebuild_appends_and_drops_only_owned() {
        let owner_a = [0xa1u8; 32];
        let owner_b = [0xb2u8; 32];
        let nonce = [0x55u8; 12];
        let entry_a = encrypt_entry::<Infallible>(&owner_a, &nonce, b"alpha").unwrap();
        let entry_b = encrypt_entry::<Infallible>(&owner_b, &nonce, b"bravo").unwrap();

        let new_entry = encrypt_entry::<Infallible>(&owner_a, &[0x99u8; 12], b"alpha v2").unwrap();

        let rebuilt = rebuild_serialized_array::<Infallible>(
            &[raw_entry(&entry_a), raw_entry(&entry_b)],
            &owner_a,
            Some(new_entry),
        )
        .unwrap();

        let array_bytes = strip_array_trailer::<Infallible>(&rebuilt).unwrap();
        let parsed = parse_array_raw_entries::<Infallible>(array_bytes).unwrap();
        assert_eq!(
            parsed.len(),
            2,
            "owner_b entry kept + new owner_a entry appended"
        );
        assert!(entry_decrypts_under_key(
            parsed[0].value.as_ref().unwrap(),
            &owner_b
        ));
        assert!(entry_decrypts_under_key(
            parsed[1].value.as_ref().unwrap(),
            &owner_a
        ));
    }

    #[test]
    fn rebuild_delete_drops_only_owned() {
        let owner_a = [0xa1u8; 32];
        let owner_b = [0xb2u8; 32];
        let nonce = [0x55u8; 12];
        let entry_a = encrypt_entry::<Infallible>(&owner_a, &nonce, b"alpha").unwrap();
        let entry_b = encrypt_entry::<Infallible>(&owner_b, &nonce, b"bravo").unwrap();

        let rebuilt = rebuild_serialized_array::<Infallible>(
            &[raw_entry(&entry_a), raw_entry(&entry_b)],
            &owner_a,
            None,
        )
        .unwrap();
        let array_bytes = strip_array_trailer::<Infallible>(&rebuilt).unwrap();
        let parsed = parse_array_raw_entries::<Infallible>(array_bytes).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(entry_decrypts_under_key(
            parsed[0].value.as_ref().unwrap(),
            &owner_b
        ));
    }

    /// Delete with no matching entry is a no-op: array returns unchanged (+ valid trailer).
    #[test]
    fn rebuild_delete_no_match_is_noop() {
        let owner_a = [0xa1u8; 32];
        let owner_b = [0xb2u8; 32];
        let nonce = [0x55u8; 12];
        let entry_b = encrypt_entry::<Infallible>(&owner_b, &nonce, b"bravo").unwrap();
        let rebuilt =
            rebuild_serialized_array::<Infallible>(&[raw_entry(&entry_b)], &owner_a, None).unwrap();
        let array_bytes = strip_array_trailer::<Infallible>(&rebuilt).unwrap();
        let parsed = parse_array_raw_entries::<Infallible>(array_bytes).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(entry_decrypts_under_key(
            parsed[0].value.as_ref().unwrap(),
            &owner_b
        ));
    }

    /// Foreign entries with unknown CBOR fields must round-trip unmodified through RMW.
    #[test]
    fn rebuild_preserves_unknown_fields_in_foreign_entries() {
        let owner_a = [0xa1u8; 32];
        let owner_b = [0xb2u8; 32];

        let entry_a_bytes = encrypt_entry::<Infallible>(&owner_a, &[0x55u8; 12], b"alpha").unwrap();

        // Foreign entry under owner_b carrying an extra (future) key 0x07.
        let entry_b_base = encrypt_entry::<Infallible>(&owner_b, &[0x66u8; 12], b"bravo").unwrap();
        let Value::Map(mut map_b) = crate::proto::ctap2::cbor::from_slice(&entry_b_base).unwrap()
        else {
            panic!("entry_b is a map");
        };
        map_b.insert(Value::Integer(0x07), Value::Text("future field".into()));
        // Non-canonical indefinite-length map: decodes to the same Value but re-encodes to a
        // definite-length map, so this fixture only round-trips byte-for-byte under the raw splice.
        let canonical = crate::proto::ctap2::cbor::to_vec(&Value::Map(map_b)).unwrap();
        let mut entry_b_bytes = vec![0xBF];
        entry_b_bytes.extend_from_slice(&canonical[1..]);
        entry_b_bytes.push(0xFF);

        let new_entry = encrypt_entry::<Infallible>(&owner_a, &[0x99u8; 12], b"alpha v2").unwrap();

        let rebuilt = rebuild_serialized_array::<Infallible>(
            &[raw_entry(&entry_a_bytes), raw_entry(&entry_b_bytes)],
            &owner_a,
            Some(new_entry),
        )
        .unwrap();
        let array_bytes = strip_array_trailer::<Infallible>(&rebuilt).unwrap();
        let parsed = parse_array_raw_entries::<Infallible>(array_bytes).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[0].raw, entry_b_bytes,
            "foreign entry preserved byte-for-byte"
        );
        let Value::Map(map_b) = parsed[0].value.as_ref().unwrap() else {
            panic!("kept_b is a map");
        };
        assert_eq!(
            map_b.get(&Value::Integer(0x07)),
            Some(&Value::Text("future field".into())),
            "unknown field 0x07 preserved"
        );
    }

    #[test]
    fn parse_array_raw_entries_rejects_hostile_headers() {
        let e0 = encrypt_entry::<Infallible>(&[0x01u8; 32], &[0u8; 12], b"a").unwrap();
        let e1 = encrypt_entry::<Infallible>(&[0x02u8; 32], &[0u8; 12], b"b").unwrap();
        let mut canonical = encode_array_header(2);
        canonical.extend_from_slice(&e0);
        canonical.extend_from_slice(&e1);
        assert_eq!(
            parse_array_raw_entries::<Infallible>(&canonical)
                .unwrap()
                .len(),
            2
        );

        // Huge declared count (array(2^32-1)) with no element bytes: bounded alloc, errors fast.
        assert!(parse_array_raw_entries::<Infallible>(&[0x9a, 0xff, 0xff, 0xff, 0xff]).is_err());

        // Valid array plus one trailing byte: rejected by the full-consumption check.
        let mut trailing = canonical.clone();
        trailing.push(0x00);
        assert!(parse_array_raw_entries::<Infallible>(&trailing).is_err());

        // Header count smaller than the actual element bytes: rejected.
        let mut short = encode_array_header(1);
        short.extend_from_slice(&e0);
        short.extend_from_slice(&e1);
        assert!(parse_array_raw_entries::<Infallible>(&short).is_err());
    }

    #[test]
    fn rebuild_meets_minimum_17_bytes_when_empty() {
        // CTAP 2.2 §6.10.2: serialized array length MUST be >= 17.
        let rebuilt = rebuild_serialized_array::<Infallible>(&[], &[0u8; 32], None).unwrap();
        assert!(rebuilt.len() >= 17);
        // Empty array: 0x80 (1 byte) + 16-byte trailer = 17 bytes.
        assert_eq!(rebuilt.len(), 17);
        assert_eq!(rebuilt[0], 0x80);
    }

    /// CTAP 2.2 §6.10 spec text: "The initial serialized large-blob array ... is the byte string
    /// `h'8076be8b528d0075f7aae98d6fa57a6d3c'`". Asserting byte-for-byte locks our canonical CBOR
    /// emission against future serializer drift.
    #[test]
    fn rebuild_empty_array_matches_spec_initial_bytes() {
        let rebuilt = rebuild_serialized_array::<Infallible>(&[], &[0u8; 32], None).unwrap();
        assert_eq!(hex::encode(&rebuilt), "8076be8b528d0075f7aae98d6fa57a6d3c");
    }

    /// `upload_serialized_array` issues set_first with the precise pinUvAuthParam derived per CTAP 2.2 §6.10.2.
    #[tokio::test]
    async fn upload_single_chunk_uses_set_first_with_correct_auth_param() {
        use crate::pin::{PinUvAuthProtocol, PinUvAuthProtocolTwo};
        use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
        use crate::proto::ctap2::{Ctap2CommandCode, Ctap2LargeBlobsResponse};
        use crate::transport::mock::channel::MockChannel;

        let key = [0xC0u8; 32];
        let token = [0x11u8; 32];
        let proto = PinUvAuthProtocolTwo::new();
        let plaintext = b"round-trip blob".to_vec();

        let nonce = [0x07u8; 12];
        let entry_bytes = encrypt_entry::<Infallible>(&key, &nonce, &plaintext).unwrap();
        let serialized =
            rebuild_serialized_array::<Infallible>(&[], &key, Some(entry_bytes)).unwrap();
        assert!(
            serialized.len() <= LARGE_BLOB_DEFAULT_FRAGMENT as usize,
            "test fixture must fit in one chunk"
        );

        let auth_param = large_blob_pin_uv_auth_param::<Infallible>(&token, &proto, 0, &serialized)
            .expect("auth_param");
        let set_req = Ctap2LargeBlobsRequest::new_set_first(
            serialized.clone(),
            serialized.len() as u32,
            Some((auth_param, proto.version() as u32)),
        );
        let mut channel = MockChannel::new();
        channel.push_command_pair(
            CborRequest {
                command: Ctap2CommandCode::AuthenticatorLargeBlobs,
                encoded_data: crate::proto::ctap2::cbor::to_vec(&set_req).unwrap(),
            },
            CborResponse::new_success_from_slice(
                &crate::proto::ctap2::cbor::to_vec(&Ctap2LargeBlobsResponse { config: None })
                    .unwrap(),
            ),
        );

        upload_serialized_array(
            &mut channel,
            &serialized,
            LARGE_BLOB_DEFAULT_FRAGMENT,
            Some((&token, Ctap2PinUvAuthProtocol::Two)),
            Duration::from_secs(5),
        )
        .await
        .expect("upload");
    }

    #[tokio::test]
    async fn upload_chunks_when_array_exceeds_max_fragment() {
        use crate::pin::{PinUvAuthProtocol, PinUvAuthProtocolTwo};
        use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
        use crate::proto::ctap2::{Ctap2CommandCode, Ctap2LargeBlobsResponse};
        use crate::transport::mock::channel::MockChannel;

        let token = [0x22u8; 32];
        let proto = PinUvAuthProtocolTwo::new();
        // Small max_fragment to force chunking with a small payload.
        const MF: u32 = 32;
        // Build a synthetic 70-byte "serialized array" (the helpers only check length >= 17).
        let serialized: Vec<u8> = (0u8..70).collect();
        assert_eq!(serialized.len(), 70);

        let mut channel = MockChannel::new();
        // Chunks: 0..32, 32..64, 64..70. Three calls.
        for (offset, chunk_len) in [(0u32, 32), (32u32, 32), (64u32, 6)] {
            let chunk = serialized[offset as usize..(offset as usize + chunk_len)].to_vec();
            let auth_param =
                large_blob_pin_uv_auth_param::<Infallible>(&token, &proto, offset, &chunk)
                    .expect("auth_param");
            let req = if offset == 0 {
                Ctap2LargeBlobsRequest::new_set_first(
                    chunk,
                    70,
                    Some((auth_param, proto.version() as u32)),
                )
            } else {
                Ctap2LargeBlobsRequest::new_set_continuation(
                    chunk,
                    offset,
                    Some((auth_param, proto.version() as u32)),
                )
            };
            channel.push_command_pair(
                CborRequest {
                    command: Ctap2CommandCode::AuthenticatorLargeBlobs,
                    encoded_data: crate::proto::ctap2::cbor::to_vec(&req).unwrap(),
                },
                CborResponse::new_success_from_slice(
                    &crate::proto::ctap2::cbor::to_vec(&Ctap2LargeBlobsResponse { config: None })
                        .unwrap(),
                ),
            );
        }

        upload_serialized_array(
            &mut channel,
            &serialized,
            MF,
            Some((&token, Ctap2PinUvAuthProtocol::Two)),
            Duration::from_secs(5),
        )
        .await
        .expect("chunked upload");
    }

    /// Pseudo-random (incompressible) bytes, so the serialized array length is predictable.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut state: u32 = 0x1234_5678;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect()
    }

    /// Serve `serialized` to `fetch_serialized_array` in `max_fragment`-sized get() fragments,
    /// mirroring the device side: one command/response pair per fragment at increasing offsets,
    /// plus the trailing empty get() when the length is an exact multiple.
    fn serve_get_fragments(
        channel: &mut crate::transport::mock::channel::MockChannel,
        serialized: &[u8],
        max_fragment: u32,
    ) {
        use crate::proto::ctap2::cbor::{to_vec, CborRequest, CborResponse};
        use crate::proto::ctap2::{Ctap2CommandCode, Ctap2LargeBlobsResponse};
        use serde_bytes::ByteBuf;

        let mf = max_fragment as usize;
        let mut offset = 0usize;
        loop {
            let end = (offset + mf).min(serialized.len());
            let chunk = serialized[offset..end].to_vec();
            let chunk_len = chunk.len();
            let req = Ctap2LargeBlobsRequest::new_get(offset as u32, max_fragment);
            let expected = CborRequest {
                command: Ctap2CommandCode::AuthenticatorLargeBlobs,
                encoded_data: to_vec(&req).unwrap(),
            };
            let resp = Ctap2LargeBlobsResponse {
                config: Some(ByteBuf::from(chunk)),
            };
            channel.push_command_pair(
                expected,
                CborResponse::new_success_from_slice(&to_vec(&resp).unwrap()),
            );
            offset = end;
            if chunk_len < mf {
                break;
            }
        }
    }

    #[tokio::test]
    async fn fetch_reassembles_multi_fragment_read_with_short_final_fragment() {
        use crate::transport::mock::channel::MockChannel;

        const MF: u32 = 32;
        let key = [0xC0u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = incompressible(31);
        let entry = encrypt_entry::<Infallible>(&key, &nonce, &plaintext).unwrap();
        let serialized = build_serialized_array(&[entry]);
        assert!(
            serialized.len() > 2 * MF as usize,
            "should span several fragments"
        );
        assert_ne!(
            serialized.len() % MF as usize,
            0,
            "final fragment must be shorter than max_fragment"
        );

        let mut channel = MockChannel::new();
        serve_get_fragments(&mut channel, &serialized, MF);

        let entries = fetch_large_blob_entries(&mut channel, MF, Duration::from_secs(5))
            .await
            .expect("fetch");
        let got = decrypt_first_matching::<Infallible>(&entries, &key).expect("decrypt");
        assert_eq!(got.as_deref(), Some(plaintext.as_slice()));
    }

    #[tokio::test]
    async fn fetch_reassembles_exact_multiple_read_via_trailing_empty_get() {
        use crate::transport::mock::channel::MockChannel;

        const MF: u32 = 32;
        let key = [0xD0u8; 32];
        let nonce = [0x22u8; 12];
        let plaintext = incompressible(37);
        let entry = encrypt_entry::<Infallible>(&key, &nonce, &plaintext).unwrap();
        let serialized = build_serialized_array(&[entry]);
        assert!(
            serialized.len() > 2 * MF as usize,
            "should span several fragments"
        );
        assert_eq!(
            serialized.len() % MF as usize,
            0,
            "exact multiple: loop terminates on a trailing empty get"
        );

        let mut channel = MockChannel::new();
        serve_get_fragments(&mut channel, &serialized, MF);

        let entries = fetch_large_blob_entries(&mut channel, MF, Duration::from_secs(5))
            .await
            .expect("fetch");
        let got = decrypt_first_matching::<Infallible>(&entries, &key).expect("decrypt");
        assert_eq!(got.as_deref(), Some(plaintext.as_slice()));
    }

    /// `try_decrypt` rejects an oversize `origSize` (skip) and a decompression bomb (Corrupted).
    #[test]
    fn try_decrypt_enforces_orig_size_and_inflation_caps() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let key = [0x42u8; 32];

        // (a) origSize above the platform cap is skipped at the cap check, before AEAD. The entry
        // is otherwise valid, so without the cap it would reach the length-mismatch Err instead.
        let over = LARGE_BLOB_MAX_ORIG_SIZE + 1;
        let nonce_a = [0x09u8; 12];
        let mut compressed_a = Vec::new();
        {
            let mut enc = DeflateEncoder::new(&mut compressed_a, Compression::default());
            enc.write_all(b"small").unwrap();
            enc.finish().unwrap();
        }
        let mut aad_a = Vec::new();
        aad_a.extend_from_slice(b"blob");
        aad_a.extend_from_slice(&over.to_le_bytes());
        let ct_a = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
            .encrypt(
                Nonce::from_slice(&nonce_a),
                aes_gcm::aead::Payload {
                    msg: &compressed_a,
                    aad: &aad_a,
                },
            )
            .unwrap();
        let oversize = LargeBlobMapEntry {
            ciphertext: ct_a,
            nonce: nonce_a.to_vec(),
            orig_size: over,
        };
        assert!(oversize
            .try_decrypt::<Infallible>(&key)
            .expect("must not error")
            .is_none());

        // (b) Authenticated entry claiming origSize=4 but inflating to 1024 bytes.
        let nonce = [0x07u8; 12];
        let mut compressed = Vec::new();
        {
            let mut encoder = DeflateEncoder::new(&mut compressed, Compression::default());
            encoder.write_all(&[0x41u8; 1024]).unwrap();
            encoder.finish().unwrap();
        }
        let mut aad = Vec::new();
        aad.extend_from_slice(b"blob");
        aad.extend_from_slice(&4u64.to_le_bytes());
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: &compressed,
                    aad: &aad,
                },
            )
            .unwrap();

        let bomb = LargeBlobMapEntry {
            ciphertext,
            nonce: nonce.to_vec(),
            orig_size: 4,
        };
        let err = bomb.try_decrypt::<Infallible>(&key).unwrap_err();
        assert!(
            matches!(&err, LargeBlobError::Corrupted(msg) if msg.contains("decompressed length")),
            "expected length-mismatch Corrupted, got {err:?}"
        );
    }

    /// `encrypt_entry` MUST emit raw DEFLATE (RFC1951), not zlib (RFC1950). Recover the
    /// compressed bytes via AES-256-GCM and confirm they inflate raw yet are not a zlib stream.
    #[test]
    fn encrypt_entry_uses_raw_deflate_not_zlib() {
        use flate2::read::ZlibDecoder;

        let key = [0x5Au8; 32];
        let nonce = [0x07u8; 12];
        let plaintext = b"largeBlob deflate rawness payload ".repeat(16);

        let entry_bytes = encrypt_entry::<Infallible>(&key, &nonce, &plaintext).expect("encrypt");

        let Value::Map(map) = crate::proto::ctap2::cbor::from_slice::<Value>(&entry_bytes).unwrap()
        else {
            panic!("entry must be a CBOR map");
        };
        let mut ciphertext: Option<Vec<u8>> = None;
        let mut entry_nonce: Option<Vec<u8>> = None;
        let mut orig_size: Option<u64> = None;
        for (k, v) in map.iter() {
            let Value::Integer(ki) = k else { continue };
            match *ki {
                LARGE_BLOB_ENTRY_CIPHERTEXT => {
                    if let Value::Bytes(b) = v {
                        ciphertext = Some(b.clone());
                    }
                }
                LARGE_BLOB_ENTRY_NONCE => {
                    if let Value::Bytes(b) = v {
                        entry_nonce = Some(b.clone());
                    }
                }
                LARGE_BLOB_ENTRY_ORIG_SIZE => {
                    if let Value::Integer(i) = v {
                        orig_size = Some(*i as u64);
                    }
                }
                _ => {}
            }
        }
        let ciphertext = ciphertext.expect("ciphertext field");
        let entry_nonce = entry_nonce.expect("nonce field");
        let orig_size = orig_size.expect("origSize field");
        assert_eq!(entry_nonce.as_slice(), &nonce[..]);
        assert_eq!(orig_size, plaintext.len() as u64);

        let mut ad = Vec::new();
        ad.extend_from_slice(LARGE_BLOB_AD_PREFIX);
        ad.extend_from_slice(&orig_size.to_le_bytes());
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let compressed = cipher
            .decrypt(
                Nonce::from_slice(&entry_nonce),
                aes_gcm::aead::Payload {
                    msg: &ciphertext,
                    aad: &ad,
                },
            )
            .expect("AES-256-GCM decrypt");

        let mut inflated = Vec::new();
        DeflateDecoder::new(compressed.as_slice())
            .read_to_end(&mut inflated)
            .expect("raw DEFLATE inflate");
        assert_eq!(inflated, plaintext, "raw DEFLATE round-trips");

        let mut zlib_out = Vec::new();
        let zlib_roundtrips = ZlibDecoder::new(compressed.as_slice())
            .read_to_end(&mut zlib_out)
            .is_ok()
            && zlib_out == plaintext;
        assert!(
            !zlib_roundtrips,
            "compressed bytes must not be a zlib stream"
        );
        assert_ne!(
            compressed[0], 0x78,
            "raw DEFLATE must not begin with a zlib CMF byte"
        );
    }

    /// Fixed-nonce reuse is catastrophic for AES-GCM. Two writes of the same blob
    /// under the same key MUST emit distinct nonces.
    #[tokio::test]
    async fn each_write_uses_a_distinct_nonce() {
        use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse};
        use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
        use crate::proto::ctap2::Ctap2LargeBlobsResponse;
        use crate::transport::mock::channel::MockChannel;
        use crate::transport::{
            device::SupportedProtocols, AuthTokenData, Channel, ChannelStatus, Ctap2AuthTokenStore,
        };
        use crate::UvUpdate;
        use std::fmt::{self, Display};
        use tokio::sync::broadcast;

        // Records each uploaded array; a get() replays the most recent one (RMW round-trip).
        struct RecordingChannel {
            inner: MockChannel,
            current: Vec<u8>,
            sets: Vec<Vec<u8>>,
            pending_get: bool,
        }

        impl Display for RecordingChannel {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "RecordingChannel")
            }
        }

        impl Ctap2AuthTokenStore for RecordingChannel {
            fn store_auth_data(&mut self, data: AuthTokenData) {
                self.inner.store_auth_data(data);
            }
            fn get_auth_data(&self) -> Option<&AuthTokenData> {
                self.inner.get_auth_data()
            }
            fn clear_uv_auth_token_store(&mut self) {
                self.inner.clear_uv_auth_token_store();
            }
            fn set_cred_mgmt_preview(&mut self, uses_preview: bool) {
                self.inner.set_cred_mgmt_preview(uses_preview);
            }
            fn cred_mgmt_preview(&self) -> bool {
                self.inner.cred_mgmt_preview()
            }
        }

        #[async_trait::async_trait]
        impl Channel for RecordingChannel {
            type UxUpdate = UvUpdate;
            type TransportError = Infallible;

            fn get_ux_update_sender(&self) -> &broadcast::Sender<Self::UxUpdate> {
                self.inner.get_ux_update_sender()
            }
            async fn supported_protocols(
                &self,
            ) -> Result<SupportedProtocols, WebAuthnError<Self::TransportError>> {
                self.inner.supported_protocols().await
            }
            async fn status(&self) -> ChannelStatus {
                ChannelStatus::Ready
            }
            async fn close(&mut self) {}
            async fn apdu_send(
                &mut self,
                _request: &ApduRequest,
                _timeout: Duration,
            ) -> Result<(), Self::TransportError> {
                unimplemented!()
            }
            async fn apdu_recv(
                &mut self,
                _timeout: Duration,
            ) -> Result<ApduResponse, Self::TransportError> {
                unimplemented!()
            }
            async fn cbor_send(
                &mut self,
                request: &CborRequest,
                _timeout: Duration,
            ) -> Result<(), Self::TransportError> {
                let Value::Map(map) =
                    crate::proto::ctap2::cbor::from_slice::<Value>(&request.encoded_data).unwrap()
                else {
                    panic!("largeBlobs request must be a CBOR map");
                };
                let mut set_bytes: Option<Vec<u8>> = None;
                let mut is_get = false;
                for (k, v) in map.iter() {
                    let Value::Integer(key) = k else { continue };
                    match *key {
                        1 => is_get = true,
                        2 => {
                            if let Value::Bytes(b) = v {
                                set_bytes = Some(b.clone());
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(bytes) = set_bytes {
                    self.current = bytes.clone();
                    self.sets.push(bytes);
                    self.pending_get = false;
                } else if is_get {
                    self.pending_get = true;
                } else {
                    panic!("largeBlobs request was neither get nor set");
                }
                Ok(())
            }
            async fn cbor_recv(
                &mut self,
                _timeout: Duration,
            ) -> Result<CborResponse, Self::TransportError> {
                let resp = if self.pending_get {
                    Ctap2LargeBlobsResponse {
                        config: Some(serde_bytes::ByteBuf::from(self.current.clone())),
                    }
                } else {
                    Ctap2LargeBlobsResponse::default()
                };
                let bytes = crate::proto::ctap2::cbor::to_vec(&resp).unwrap();
                Ok(CborResponse::new_success_from_slice(&bytes))
            }
        }

        fn entry_nonce(serialized: &[u8]) -> Vec<u8> {
            let array_bytes = strip_array_trailer::<Infallible>(serialized).expect("trailer");
            let parsed = parse_large_blob_array::<Infallible>(array_bytes).expect("parse");
            assert_eq!(parsed.len(), 1, "exactly one entry per write");
            parsed[0].nonce.clone()
        }

        let key = [0x5Au8; 32];
        let blob = b"distinct-nonce blob".to_vec();

        let mut channel = RecordingChannel {
            inner: MockChannel::new(),
            current: build_serialized_array(&[]),
            sets: Vec::new(),
            pending_get: false,
        };
        for _ in 0..2 {
            write_authenticator_large_blob(
                &mut channel,
                &key,
                &blob,
                LARGE_BLOB_DEFAULT_FRAGMENT,
                None,
                Duration::from_secs(5),
            )
            .await
            .expect("write should succeed");
        }

        assert_eq!(channel.sets.len(), 2, "each write is a single-chunk set()");
        let nonce_a = entry_nonce(&channel.sets[0]);
        let nonce_b = entry_nonce(&channel.sets[1]);
        assert_eq!(nonce_a.len(), LARGE_BLOB_NONCE_LEN);
        assert_eq!(nonce_b.len(), LARGE_BLOB_NONCE_LEN);
        assert_ne!(
            nonce_a, nonce_b,
            "each write must generate a fresh AES-GCM nonce"
        );
    }

    #[test]
    fn large_blob_pin_uv_auth_param_protocol_one_truncates_to_16() {
        use crate::pin::PinUvAuthProtocolOne;
        use hmac::Mac;

        let token = [0x11u8; 32];
        let chunk = b"some chunk bytes";
        let offset: u32 = 0x12345678;

        let proto = PinUvAuthProtocolOne::new();
        let got = large_blob_pin_uv_auth_param::<Infallible>(&token, &proto, offset, chunk)
            .expect("auth_param");

        let mut expected_msg = Vec::new();
        expected_msg.extend_from_slice(&[0xff; 32]);
        expected_msg.extend_from_slice(&[0x0c, 0x00]);
        expected_msg.extend_from_slice(&offset.to_le_bytes());
        expected_msg.extend_from_slice(&Sha256::digest(chunk));
        let mut mac = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(&token).unwrap();
        mac.update(&expected_msg);
        let full = mac.finalize().into_bytes();

        assert_eq!(got, full[..16]);
        assert_eq!(got.len(), 16);
    }
}
