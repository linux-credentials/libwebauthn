//! WebAuthn `largeBlob` read path (CTAP 2.1 §6.10). Write is deferred.

use std::io::Read;
use std::time::Duration;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use flate2::read::DeflateDecoder;
use sha2::{Digest, Sha256};
use tracing::{debug, trace, warn};

use crate::proto::ctap2::{Ctap2, Ctap2LargeBlobsRequest};
use crate::webauthn::Error;

/// Spec default for `maxFragmentLength` when `maxMsgSize` is absent (CTAP 2.1 §6.10.2).
pub(crate) const LARGE_BLOB_DEFAULT_FRAGMENT: u32 = 960;

/// Cap on `origSize` per entry. CTAP 2.1 §6.10.3 RECOMMENDs at least 1 MiB.
const LARGE_BLOB_MAX_ORIG_SIZE: u64 = 1024 * 1024;

/// Static cap on the total serialized array size, to bound a misbehaving device.
const LARGE_BLOB_MAX_ARRAY_BYTES: usize = 4 * 1024 * 1024;

const LARGE_BLOB_HASH_LEN: usize = 16;
const LARGE_BLOB_NONCE_LEN: usize = 12;
const LARGE_BLOB_AD_PREFIX: &[u8] = b"blob";

#[derive(thiserror::Error, Debug)]
pub(crate) enum LargeBlobError {
    #[error("On-device largeBlobArray is malformed: {0}")]
    Corrupted(String),
    #[error(transparent)]
    Webauthn(#[from] Error),
}

/// `maxFragmentLength` per CTAP 2.1 §6.10.2 (`maxMsgSize - 64`, default 960).
pub(crate) fn max_fragment_length(max_msg_size: Option<u32>) -> u32 {
    max_msg_size
        .and_then(|m| m.checked_sub(64))
        .unwrap_or(LARGE_BLOB_DEFAULT_FRAGMENT)
        .max(LARGE_BLOB_DEFAULT_FRAGMENT)
}

/// Fetch and decrypt the largeBlob for one credential.
pub(crate) async fn read_authenticator_large_blob<C: Ctap2 + ?Sized>(
    channel: &mut C,
    large_blob_key: &[u8; 32],
    max_fragment: u32,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, LargeBlobError> {
    let serialized = fetch_serialized_array(channel, max_fragment, timeout).await?;
    let array_bytes = strip_array_trailer(&serialized)?;
    let entries = parse_large_blob_array(array_bytes)?;
    for entry in &entries {
        if let Some(plaintext) = entry.try_decrypt(large_blob_key)? {
            return Ok(Some(plaintext));
        }
    }
    Ok(None)
}

async fn fetch_serialized_array<C: Ctap2 + ?Sized>(
    channel: &mut C,
    max_fragment: u32,
    timeout: Duration,
) -> Result<Vec<u8>, LargeBlobError> {
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
struct LargeBlobMapEntry {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    orig_size: u64,
}

impl LargeBlobMapEntry {
    /// `Ok(None)` on AEAD failure (skip to next entry), `Err` only on structural problems.
    fn try_decrypt(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, LargeBlobError> {
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

/// Parse entries, skipping any with per-entry structural errors (CTAP 2.1 §6.10.3).
fn parse_large_blob_array(bytes: &[u8]) -> Result<Vec<LargeBlobMapEntry>, LargeBlobError> {
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

/// Test helper: encrypt+compress one entry under `key`.
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

/// Test helper: assemble a serialized largeBlobArray (entries + 16-byte trailer).
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

    #[test]
    fn max_fragment_uses_get_info_when_available() {
        assert_eq!(max_fragment_length(Some(2048)), 2048 - 64);
    }

    #[test]
    fn max_fragment_falls_back_to_spec_default() {
        assert_eq!(max_fragment_length(None), LARGE_BLOB_DEFAULT_FRAGMENT);
    }

    #[test]
    fn max_fragment_does_not_underflow() {
        assert_eq!(max_fragment_length(Some(32)), LARGE_BLOB_DEFAULT_FRAGMENT);
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

    /// Per CTAP 2.1 §6.10.3, a malformed entry MUST be skipped, not aborted.
    /// Construct an array containing one bad entry (non-map) plus one good
    /// entry; verify we still find the good one.
    #[test]
    fn malformed_entry_is_skipped_not_errored() {
        use serde_cbor_2::value::Value as CborVal;

        let key = [0xCAu8; 32];
        let nonce = [0x33u8; 12];
        let good = encrypt_entry(&key, &nonce, b"survivor").unwrap();

        let bad_entry_bytes = {
            let mut buf = Vec::new();
            let mut ser = serde_cbor_2::ser::Serializer::new(&mut buf);
            serde::Serialize::serialize(&CborVal::Text("not-a-map".into()), &mut ser).unwrap();
            buf
        };
        let serialized = build_serialized_array(&[bad_entry_bytes, good]);
        let array_bytes = strip_array_trailer(&serialized).unwrap();
        let parsed = parse_large_blob_array(array_bytes).expect("parse must not error");
        assert_eq!(parsed.len(), 1, "bad entry skipped, good entry kept");
        let pt = parsed[0].try_decrypt(&key).unwrap().unwrap();
        assert_eq!(pt, b"survivor");
    }

    /// Entry missing the ciphertext field is skipped without erroring.
    #[test]
    fn entry_missing_required_field_is_skipped() {
        use serde_cbor_2::value::Value as CborVal;
        use std::collections::BTreeMap;

        let key = [0xCBu8; 32];
        let nonce = [0x44u8; 12];
        let good = encrypt_entry(&key, &nonce, b"present").unwrap();

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
        let array_bytes = strip_array_trailer(&serialized).unwrap();
        let parsed = parse_large_blob_array(array_bytes).expect("parse must not error");
        assert_eq!(parsed.len(), 1);
        let pt = parsed[0].try_decrypt(&key).unwrap().unwrap();
        assert_eq!(pt, b"present");
    }

    /// An entry advertising an oversized origSize must not OOM the platform.
    /// `try_decrypt` returns `Ok(None)` rather than allocating.
    #[test]
    fn oversized_orig_size_is_skipped_without_allocating() {
        let entry = LargeBlobMapEntry {
            ciphertext: vec![0u8; 16],
            nonce: vec![0u8; 12],
            orig_size: LARGE_BLOB_MAX_ORIG_SIZE + 1,
        };
        let key = [0u8; 32];
        let res = entry.try_decrypt(&key).expect("must not error");
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn read_authenticator_large_blob_via_mock_channel() {
        use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
        use crate::proto::ctap2::{Ctap2CommandCode, Ctap2LargeBlobsResponse};
        use crate::transport::mock::channel::MockChannel;

        let key = [0xC0u8; 32];
        let nonce = [0x11u8; 12];
        let plaintext = b"hello, largeBlob".to_vec();
        let entry = encrypt_entry(&key, &nonce, &plaintext).unwrap();
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
        let entry = encrypt_entry(&large_blob_key, &nonce, &plaintext).unwrap();
        let serialized_array = build_serialized_array(&[entry]);

        let credential_id = b"cred-id".to_vec();
        let mut auth_data = vec![0u8; 37];
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
}
