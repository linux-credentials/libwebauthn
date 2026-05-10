//! WebAuthn `largeBlob` storage abstraction.
//!
//! [`LargeBlobStorage`] is the pluggable backend libwebauthn uses for the
//! WebAuthn L3 `largeBlob` extension. Two backends ship with the library:
//! [`AuthenticatorLargeBlobStorage`] (drives CTAP `authenticatorLargeBlobs`)
//! and [`MemoryLargeBlobStorage`] (in-memory, for tests).
//!
//! Only the read path is implemented; [`LargeBlobStorage::write`] returns
//! [`LargeBlobError::Unsupported`] in the bundled impls.

use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use async_trait::async_trait;
use flate2::read::DeflateDecoder;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, trace, warn};

use crate::proto::ctap2::{Ctap2, Ctap2LargeBlobsRequest};
use crate::webauthn::Error;

/// Default chunk size for paginated `authenticatorLargeBlobs(get)` calls.
pub const LARGE_BLOB_DEFAULT_CHUNK: u32 = 1024;

const LARGE_BLOB_HASH_LEN: usize = 16;
const LARGE_BLOB_NONCE_LEN: usize = 12;
const LARGE_BLOB_AD_PREFIX: &[u8] = b"blob";

/// Errors surfaced by a [`LargeBlobStorage`] backend.
#[derive(thiserror::Error, Debug)]
pub enum LargeBlobError {
    #[error("Operation not supported by this LargeBlobStorage backend")]
    Unsupported,
    #[error("On-device largeBlobArray is malformed: {0}")]
    Corrupted(String),
    #[error("No entry in largeBlobArray verifies under this credential key")]
    EntryNotFound,
    #[error(transparent)]
    Webauthn(#[from] Error),
}

/// Read/write API for WebAuthn `largeBlob` payloads. Methods take `&self`
/// so a backend instance can be shared concurrently.
#[async_trait]
pub trait LargeBlobStorage: Send + Sync {
    /// Returns the decrypted, decompressed blob for `credential_id`, or
    /// `Ok(None)` if no blob is stored.
    async fn read(&self, credential_id: &[u8]) -> Result<Option<Vec<u8>>, LargeBlobError>;

    /// Stores `data` for `credential_id`, replacing any existing blob.
    /// Bundled backends currently return [`LargeBlobError::Unsupported`].
    async fn write(&self, credential_id: &[u8], data: &[u8]) -> Result<(), LargeBlobError>;
}

/// In-memory [`LargeBlobStorage`]. The backing map is shared across `clone()`
/// via an inner `Arc<Mutex<_>>`.
#[derive(Debug, Default, Clone)]
pub struct MemoryLargeBlobStorage {
    inner: std::sync::Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl MemoryLargeBlobStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, credential_id: &[u8], data: Vec<u8>) {
        if let Ok(mut map) = self.inner.lock() {
            map.insert(credential_id.to_vec(), data);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl LargeBlobStorage for MemoryLargeBlobStorage {
    async fn read(&self, credential_id: &[u8]) -> Result<Option<Vec<u8>>, LargeBlobError> {
        Ok(self
            .inner
            .lock()
            .ok()
            .and_then(|m| m.get(credential_id).cloned()))
    }

    async fn write(&self, credential_id: &[u8], data: &[u8]) -> Result<(), LargeBlobError> {
        if let Ok(mut m) = self.inner.lock() {
            m.insert(credential_id.to_vec(), data.to_vec());
        }
        Ok(())
    }
}

/// Authenticator-backed [`LargeBlobStorage`] scoped to a single credential.
///
/// Holds the `largeBlobKey` returned by `authenticatorGetAssertion` for one
/// credential, plus a borrowed [`Ctap2`] channel. `read` paginates
/// `authenticatorLargeBlobs(get)`, AES-256-GCM-authenticates each entry under
/// the held key, and RFC 1951 raw-deflate decompresses the plaintext.
pub struct AuthenticatorLargeBlobStorage<'a, C: Ctap2 + ?Sized> {
    pub(crate) channel: AsyncMutex<&'a mut C>,
    pub(crate) credential_id: Vec<u8>,
    pub(crate) large_blob_key: [u8; 32],
    pub(crate) max_chunk: u32,
    pub(crate) timeout: Duration,
}

impl<'a, C: Ctap2 + ?Sized> AuthenticatorLargeBlobStorage<'a, C> {
    pub fn new(
        channel: &'a mut C,
        credential_id: Vec<u8>,
        large_blob_key: [u8; 32],
        timeout: Duration,
    ) -> Self {
        Self {
            channel: AsyncMutex::new(channel),
            credential_id,
            large_blob_key,
            max_chunk: LARGE_BLOB_DEFAULT_CHUNK,
            timeout,
        }
    }

    pub fn with_chunk_size(mut self, max_chunk: u32) -> Self {
        self.max_chunk = max_chunk;
        self
    }
}

#[async_trait]
impl<C: Ctap2 + Send + ?Sized> LargeBlobStorage for AuthenticatorLargeBlobStorage<'_, C> {
    async fn read(&self, credential_id: &[u8]) -> Result<Option<Vec<u8>>, LargeBlobError> {
        // This backend is scoped to one credential's largeBlobKey; reject
        // queries for any other credential without contacting the device.
        if credential_id != self.credential_id.as_slice() {
            return Ok(None);
        }

        let serialized = self.fetch_serialized_array().await?;
        let array_bytes = strip_array_trailer(&serialized)?;
        let array: Vec<LargeBlobMapEntry> = parse_large_blob_array(array_bytes)?;
        for entry in &array {
            if let Some(plaintext) = entry.try_decrypt(&self.large_blob_key)? {
                return Ok(Some(plaintext));
            }
        }
        Ok(None)
    }

    async fn write(&self, _credential_id: &[u8], _data: &[u8]) -> Result<(), LargeBlobError> {
        Err(LargeBlobError::Unsupported)
    }
}

impl<C: Ctap2 + Send + ?Sized> AuthenticatorLargeBlobStorage<'_, C> {
    async fn fetch_serialized_array(&self) -> Result<Vec<u8>, LargeBlobError> {
        // Static cap to bound a misbehaving device.
        const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
        let mut out: Vec<u8> = Vec::new();
        let mut offset: u32 = 0;
        loop {
            let req = Ctap2LargeBlobsRequest::new_get(offset, self.max_chunk);
            let resp = {
                let mut guard = self.channel.lock().await;
                guard.ctap2_large_blobs(&req, self.timeout).await
            }
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
            if chunk_len < self.max_chunk as usize {
                debug!(total = out.len(), "largeBlobArray fully fetched");
                break;
            }
            if out.len() > MAX_TOTAL_BYTES {
                warn!(
                    total = out.len(),
                    "largeBlobArray exceeded {}, aborting", MAX_TOTAL_BYTES
                );
                return Err(LargeBlobError::Corrupted(
                    "serialized array exceeds platform cap".into(),
                ));
            }
            offset = offset.saturating_add(chunk_len as u32);
        }
        Ok(out)
    }
}

const LARGE_BLOB_ENTRY_CIPHERTEXT: i128 = 0x01;
const LARGE_BLOB_ENTRY_NONCE: i128 = 0x02;
const LARGE_BLOB_ENTRY_ORIG_SIZE: i128 = 0x03;

#[derive(Debug)]
struct LargeBlobMapEntry {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    orig_size: u64,
}

impl LargeBlobMapEntry {
    /// `Ok(Some)` on AEAD success, `Ok(None)` on tag mismatch (caller continues
    /// iterating to find an entry encrypted under this credential's key),
    /// `Err` on structural errors.
    fn try_decrypt(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, LargeBlobError> {
        if self.nonce.len() != LARGE_BLOB_NONCE_LEN {
            return Err(LargeBlobError::Corrupted(format!(
                "nonce length {} != 12",
                self.nonce.len()
            )));
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

        let mut decoder = DeflateDecoder::new(plaintext_compressed.as_slice());
        let mut decompressed = Vec::with_capacity(self.orig_size as usize);
        decoder
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

fn strip_array_trailer(serialized: &[u8]) -> Result<&[u8], LargeBlobError> {
    if serialized.len() < LARGE_BLOB_HASH_LEN {
        return Err(LargeBlobError::Corrupted(format!(
            "serialized array length {} < trailer length {}",
            serialized.len(),
            LARGE_BLOB_HASH_LEN
        )));
    }
    let split = serialized.len() - LARGE_BLOB_HASH_LEN;
    let (array, expected_hash) = serialized.split_at(split);

    let mut hasher = Sha256::new();
    hasher.update(array);
    let full_hash = hasher.finalize();
    if &full_hash[..LARGE_BLOB_HASH_LEN] != expected_hash {
        return Err(LargeBlobError::Corrupted(
            "trailer SHA-256 verification failed".into(),
        ));
    }
    Ok(array)
}

fn parse_large_blob_array(bytes: &[u8]) -> Result<Vec<LargeBlobMapEntry>, LargeBlobError> {
    if bytes == [0x80] || bytes.is_empty() {
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
        let map = match value {
            crate::proto::ctap2::cbor::Value::Map(m) => m,
            other => {
                return Err(LargeBlobError::Corrupted(format!(
                    "expected CBOR map in array, got {other:?}"
                )));
            }
        };

        let mut ciphertext = None;
        let mut nonce = None;
        let mut orig_size = None;
        for (k, v) in map {
            let key = match k {
                crate::proto::ctap2::cbor::Value::Integer(i) => i,
                _ => continue,
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
                        if i < 0 {
                            return Err(LargeBlobError::Corrupted(format!(
                                "negative origSize: {i}"
                            )));
                        }
                        orig_size = Some(i as u64);
                    }
                }
                _ => {} // Unknown keys ignored for forward compatibility.
            }
        }
        let ciphertext =
            ciphertext.ok_or_else(|| LargeBlobError::Corrupted("entry missing 0x01".into()))?;
        let nonce = nonce.ok_or_else(|| LargeBlobError::Corrupted("entry missing 0x02".into()))?;
        let orig_size =
            orig_size.ok_or_else(|| LargeBlobError::Corrupted("entry missing 0x03".into()))?;
        entries.push(LargeBlobMapEntry {
            ciphertext,
            nonce,
            orig_size,
        });
    }
    Ok(entries)
}

/// Test helper: encrypt+compress `plaintext` into a single CBOR-encoded
/// `LargeBlobMap` entry under `key`.
#[cfg(test)]
pub(crate) fn encrypt_entry(
    key: &[u8; 32],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, LargeBlobError> {
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

/// Test helper: assemble a CBOR array of entries plus the 16-byte SHA-256
/// trailer, producing a complete serialized largeBlobArray.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_storage_round_trips_one_blob() {
        let store = MemoryLargeBlobStorage::new();
        assert!(store.is_empty());
        let cred_id = b"cred-1";
        store
            .write(cred_id, b"hello world")
            .await
            .expect("write should succeed");
        let got = store.read(cred_id).await.expect("read");
        assert_eq!(got.as_deref(), Some(&b"hello world"[..]));
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn memory_storage_missing_credential_returns_none() {
        let store = MemoryLargeBlobStorage::new();
        let got = store
            .read(b"absent-cred")
            .await
            .expect("read should succeed even for missing entries");
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn memory_storage_supports_multiple_credentials() {
        let store = MemoryLargeBlobStorage::new();
        store.write(b"a", b"alpha").await.unwrap();
        store.write(b"b", b"bravo").await.unwrap();
        assert_eq!(
            store.read(b"a").await.unwrap().as_deref(),
            Some(&b"alpha"[..])
        );
        assert_eq!(
            store.read(b"b").await.unwrap().as_deref(),
            Some(&b"bravo"[..])
        );
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let plaintext = b"the quick brown fox".to_vec();
        let entry_bytes = encrypt_entry(&key, &nonce, &plaintext).expect("encrypt");

        let serialized = build_serialized_array(&[entry_bytes]);
        let array_bytes = strip_array_trailer(&serialized).expect("trailer");
        let parsed = parse_large_blob_array(array_bytes).expect("parse");
        assert_eq!(parsed.len(), 1);
        let plaintext_decoded = parsed[0]
            .try_decrypt(&key)
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
        let entry_bytes = encrypt_entry(&real_key, &nonce, &plaintext).expect("encrypt");
        let serialized = build_serialized_array(&[entry_bytes]);
        let array_bytes = strip_array_trailer(&serialized).expect("trailer");
        let parsed = parse_large_blob_array(array_bytes).expect("parse");
        let res = parsed[0]
            .try_decrypt(&wrong_key)
            .expect("decrypt should not error on AEAD failure");
        assert!(res.is_none());
    }

    #[test]
    fn corrupted_trailer_is_rejected() {
        let mut serialized = build_serialized_array(&[]);
        let last = serialized.len() - 1;
        serialized[last] ^= 0xff;
        let err = strip_array_trailer(&serialized).unwrap_err();
        assert!(matches!(err, LargeBlobError::Corrupted(_)));
    }

    #[test]
    fn truncated_serialized_array_is_rejected() {
        let too_short = vec![0u8; 8];
        let err = strip_array_trailer(&too_short).unwrap_err();
        assert!(matches!(err, LargeBlobError::Corrupted(_)));
    }

    #[test]
    fn empty_array_parses_to_zero_entries() {
        let serialized = build_serialized_array(&[]);
        let array_bytes = strip_array_trailer(&serialized).unwrap();
        let parsed = parse_large_blob_array(array_bytes).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn multi_entry_array_finds_matching_key() {
        let key_a = [0xa1u8; 32];
        let key_b = [0xb2u8; 32];
        let key_c = [0xc3u8; 32];
        let nonce = [0x55u8; 12];
        let entry_a = encrypt_entry(&key_a, &nonce, b"alpha").unwrap();
        let entry_b = encrypt_entry(&key_b, &nonce, b"bravo").unwrap();
        let entry_c = encrypt_entry(&key_c, &nonce, b"charlie").unwrap();
        let serialized = build_serialized_array(&[entry_a, entry_b, entry_c]);
        let array_bytes = strip_array_trailer(&serialized).unwrap();
        let parsed = parse_large_blob_array(array_bytes).unwrap();
        assert_eq!(parsed.len(), 3);

        let mut found_b = None;
        for e in &parsed {
            if let Some(pt) = e.try_decrypt(&key_b).unwrap() {
                found_b = Some(pt);
            }
        }
        assert_eq!(found_b.as_deref(), Some(&b"bravo"[..]));
    }

    #[tokio::test]
    async fn authenticator_storage_reads_from_mock_channel() {
        use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
        use crate::proto::ctap2::{Ctap2CommandCode, Ctap2LargeBlobsResponse};
        use crate::transport::mock::channel::MockChannel;

        let key = [0xC0u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"hello, largeBlob".to_vec();
        let entry = encrypt_entry(&key, &nonce, &plaintext).unwrap();
        let serialized = build_serialized_array(&[entry]);
        assert!(
            serialized.len() < LARGE_BLOB_DEFAULT_CHUNK as usize,
            "test fixture should fit in one chunk"
        );

        let req = Ctap2LargeBlobsRequest::new_get(0, LARGE_BLOB_DEFAULT_CHUNK);
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

        let credential_id = b"my-cred".to_vec();
        let storage = AuthenticatorLargeBlobStorage::new(
            &mut channel,
            credential_id.clone(),
            key,
            Duration::from_secs(5),
        );
        let got = storage
            .read(&credential_id)
            .await
            .expect("read should succeed");
        assert_eq!(got.as_deref(), Some(plaintext.as_slice()));
    }

    #[tokio::test]
    async fn authenticator_storage_returns_none_for_different_credential() {
        use crate::transport::mock::channel::MockChannel;

        let mut channel = MockChannel::new();
        let storage = AuthenticatorLargeBlobStorage::new(
            &mut channel,
            b"cred-A".to_vec(),
            [0u8; 32],
            Duration::from_secs(5),
        );
        let got = storage.read(b"cred-B").await.expect("read");
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn authenticator_storage_write_returns_unsupported() {
        use crate::transport::mock::channel::MockChannel;

        let mut channel = MockChannel::new();
        let storage = AuthenticatorLargeBlobStorage::new(
            &mut channel,
            b"cred-A".to_vec(),
            [0u8; 32],
            Duration::from_secs(5),
        );
        let err = storage
            .write(b"cred-A", b"payload")
            .await
            .expect_err("write should be unsupported");
        assert!(matches!(err, LargeBlobError::Unsupported));
    }

    #[tokio::test]
    async fn authenticator_storage_handles_empty_array() {
        use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
        use crate::proto::ctap2::{Ctap2CommandCode, Ctap2LargeBlobsResponse};
        use crate::transport::mock::channel::MockChannel;

        let serialized = build_serialized_array(&[]);
        let req = Ctap2LargeBlobsRequest::new_get(0, LARGE_BLOB_DEFAULT_CHUNK);
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

        let storage = AuthenticatorLargeBlobStorage::new(
            &mut channel,
            b"cred-A".to_vec(),
            [0xAA; 32],
            Duration::from_secs(5),
        );
        let got = storage.read(b"cred-A").await.expect("read");
        assert!(got.is_none());
    }
}
