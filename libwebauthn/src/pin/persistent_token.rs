use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut};
use async_trait::async_trait;
use cbc::cipher::KeyIvInit;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use tokio::sync::Mutex;
use tracing::{debug, error, trace, warn};
use zeroize::ZeroizeOnDrop;

use crate::proto::ctap2::{Ctap2GetInfoResponse, Ctap2PinUvAuthProtocol};
use crate::proto::CtapError;
use crate::webauthn::error::{Error, PlatformError};

type Aes128CbcDecryptor = cbc::Decryptor<aes::Aes128>;

/// HKDF salt for `encIdentifier`/`encCredStoreState`: 32 zero bytes (CTAP 2.3-PS 6.4).
const ENC_IDENTIFIER_HKDF_SALT: [u8; 32] = [0u8; 32];
/// HKDF info string binding the derived key to the `encIdentifier` use.
const ENC_IDENTIFIER_HKDF_INFO: &[u8] = b"encIdentifier";

/// Opaque identifier for a stored persistent-token record. Random per record.
pub type PersistentTokenRecordId = String;

/// A persistent pinUvAuthToken (`pcmr`) together with the data needed to recognize
/// the authenticator it belongs to and to reuse the token on later connections.
#[derive(Clone, ZeroizeOnDrop)]
pub struct PersistentTokenRecord {
    /// Decrypted pcmr token; the HMAC key used to authenticate reuse.
    pub persistent_token: Vec<u8>,
    /// PIN/UV auth protocol the token was minted under.
    #[zeroize(skip)]
    pub pin_uv_auth_protocol: Ctap2PinUvAuthProtocol,
    /// 128-bit device identifier recovered from `encIdentifier`; the recognition key.
    #[zeroize(skip)]
    pub device_identifier: [u8; 16],
    /// Authenticator AAGUID; a non-secret label, used only for orphan reaping.
    #[zeroize(skip)]
    pub aaguid: [u8; 16],
}

impl fmt::Debug for PersistentTokenRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentTokenRecord")
            .field("persistent_token", &"<redacted>")
            .field("pin_uv_auth_protocol", &self.pin_uv_auth_protocol)
            .field("device_identifier", &self.device_identifier)
            .field("aaguid", &self.aaguid)
            .finish()
    }
}

/// Caller-supplied store for persistent pinUvAuthTokens (`pcmr`), surviving the
/// authenticator power cycle so a credential manager need not re-prompt for the PIN
/// on every launch or replug.
///
/// # Security
///
/// Each [`PersistentTokenRecord::persistent_token`] is a cleartext, long-lived bearer
/// secret. Implementations MUST persist it with confidentiality equivalent to other
/// credential secrets: an OS keyring, or encrypted-at-rest with OS access control.
/// Implementations MUST NOT write it to world- or group-readable files, to logs, or to
/// unprotected sync/backup. A leaked token lets an attacker, with no PIN and no user
/// presence, perform read-only credential management on that one authenticator
/// (enumerate RPs, usernames, display names, user handles, credential metadata). It
/// grants no assertion, creation, update, or deletion.
///
/// libwebauthn ships only the in-memory [`MemoryPersistentTokenStore`] and leaves the
/// choice of any durable backend to the embedder.
///
/// All methods are infallible by design: a failed read behaves as a cache miss and the
/// flow falls back to a normal PIN/UV ceremony, and a failed write is best-effort.
#[async_trait]
pub trait PersistentTokenStore: fmt::Debug + Send + Sync {
    /// Returns every stored record. Recognition trial-decrypts `encIdentifier` against
    /// each, so the whole set is enumerated on connect.
    async fn list(&self) -> Vec<(PersistentTokenRecordId, PersistentTokenRecord)>;
    /// Inserts or replaces the record under `id`.
    async fn put(&self, id: &PersistentTokenRecordId, record: &PersistentTokenRecord);
    /// Removes the record under `id`, if present.
    async fn delete(&self, id: &PersistentTokenRecordId);
}

/// In-memory [`PersistentTokenStore`], holding records for the lifetime of the process.
/// Suitable for tests and for long-lived processes such as a system daemon.
#[derive(Debug, Default, Clone)]
pub struct MemoryPersistentTokenStore {
    records: Arc<Mutex<HashMap<PersistentTokenRecordId, PersistentTokenRecord>>>,
}

impl MemoryPersistentTokenStore {
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl PersistentTokenStore for MemoryPersistentTokenStore {
    async fn list(&self) -> Vec<(PersistentTokenRecordId, PersistentTokenRecord)> {
        let records = self.records.lock().await;
        debug!(count = records.len(), "Listing persistent token records");
        records
            .iter()
            .map(|(id, record)| (id.clone(), record.clone()))
            .collect()
    }

    async fn put(&self, id: &PersistentTokenRecordId, record: &PersistentTokenRecord) {
        debug!(?id, "Storing persistent token record");
        trace!(?record);
        self.records.lock().await.insert(id.clone(), record.clone());
    }

    async fn delete(&self, id: &PersistentTokenRecordId) {
        debug!(?id, "Deleting persistent token record");
        self.records.lock().await.remove(id);
    }
}

/// Derive the 16-byte AES-128 key for `encIdentifier` from a persistent token, per
/// CTAP 2.3-PS 6.4: `HKDF-SHA-256(salt = 32 zero bytes, IKM = token, L = 16, info = "encIdentifier")`.
fn enc_identifier_key(token: &[u8]) -> Result<[u8; 16], Error> {
    let hkdf = Hkdf::<Sha256>::new(Some(&ENC_IDENTIFIER_HKDF_SALT), token);
    let mut key = [0u8; 16];
    hkdf.expand(ENC_IDENTIFIER_HKDF_INFO, &mut key)
        .map_err(|e| {
            error!("HKDF expand error deriving encIdentifier key: {e}");
            Error::Platform(PlatformError::CryptoError(format!(
                "HKDF expand error: {e}"
            )))
        })?;
    Ok(key)
}

/// Recover the 128-bit device identifier from an `encIdentifier` (`iv || ct`) using a
/// persistent token. `ct` is exactly one AES block, so decryption uses no padding.
pub(crate) fn decrypt_enc_identifier(
    token: &[u8],
    enc_identifier: &[u8],
) -> Result<[u8; 16], Error> {
    if enc_identifier.len() != 32 {
        error!(
            len = enc_identifier.len(),
            "encIdentifier is not a 16-byte IV followed by one 16-byte ciphertext block"
        );
        return Err(Error::Ctap(CtapError::Other));
    }
    let (iv, ciphertext) = enc_identifier.split_at(16);
    let key = enc_identifier_key(token)?;
    let Ok(decryptor) = Aes128CbcDecryptor::new_from_slices(&key, iv) else {
        error!("Invalid key or IV for AES-128-CBC encIdentifier decryption");
        return Err(Error::Ctap(CtapError::Other));
    };
    let Ok(plaintext) = decryptor.decrypt_padded_vec_mut::<NoPadding>(ciphertext) else {
        error!("Decrypt error while recovering device identifier");
        return Err(Error::Ctap(CtapError::Other));
    };
    plaintext.try_into().map_err(|_| {
        error!("Recovered device identifier was not 16 bytes");
        Error::Ctap(CtapError::Other)
    })
}

/// Find the stored record whose persistent token reproduces this authenticator's
/// `encIdentifier`. The IV is fresh on every getInfo, so raw bytes never compare equal
/// across connections; recognition is decrypt-and-compare against each record's stored
/// device identifier. Returns the first match, or `None` if no stored token fits.
pub(crate) async fn recognize_authenticator(
    store: &dyn PersistentTokenStore,
    info: &Ctap2GetInfoResponse,
) -> Option<(PersistentTokenRecordId, PersistentTokenRecord)> {
    let enc_identifier = info.enc_identifier.as_ref()?;
    for (id, record) in store.list().await {
        match decrypt_enc_identifier(&record.persistent_token, enc_identifier) {
            Ok(device_identifier) if device_identifier == record.device_identifier => {
                debug!(?id, "Recognized authenticator from persistent token store");
                return Some((id, record));
            }
            _ => {}
        }
    }
    None
}

/// A fresh, opaque record id: 16 random bytes, hex-encoded. Random rather than derived
/// from the device, so a record survives device-identifier changes only via reaping.
fn new_record_id() -> PersistentTokenRecordId {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Capture a freshly minted pcmr token for cross-session reuse: recover this device's
/// identifier from `encIdentifier`, then store a new record under a fresh id. Returns the
/// id. Callers treat failures as best-effort (the current operation still proceeds with
/// the minted token).
pub(crate) async fn store_minted_token(
    store: &dyn PersistentTokenStore,
    info: &Ctap2GetInfoResponse,
    token: &[u8],
    pin_uv_auth_protocol: Ctap2PinUvAuthProtocol,
) -> Result<PersistentTokenRecordId, Error> {
    let Some(enc_identifier) = info.enc_identifier.as_ref() else {
        warn!("perCredMgmtRO advertised but no encIdentifier returned; cannot persist token");
        return Err(Error::Ctap(CtapError::Other));
    };
    let device_identifier = decrypt_enc_identifier(token, enc_identifier)?;
    let aaguid: [u8; 16] = info.aaguid[..].try_into().map_err(|_| {
        error!(len = info.aaguid.len(), "AAGUID was not 16 bytes");
        Error::Ctap(CtapError::Other)
    })?;
    reap_superseded_records(store, &device_identifier).await;
    let id = new_record_id();
    let record = PersistentTokenRecord {
        persistent_token: token.to_vec(),
        pin_uv_auth_protocol,
        device_identifier,
        aaguid,
    };
    store.put(&id, &record).await;
    debug!(?id, "Stored freshly minted persistent token");
    Ok(id)
}

/// Delete every stored record for this device epoch (matching device identifier). Run at
/// mint time, this replaces a token superseded out of band, e.g. a PIN change made on
/// another platform: the device identifier is stable across PIN changes, only the token
/// resets. Records for other devices carry a different identifier and are left untouched,
/// so a sibling key of the same model keeps its own token. A record left behind by an
/// authenticatorReset (which regenerates the identifier) is indistinguishable from a
/// sibling's and is therefore left for the embedder to prune rather than risk evicting a
/// live sibling token.
async fn reap_superseded_records(store: &dyn PersistentTokenStore, device_identifier: &[u8; 16]) {
    for (id, record) in store.list().await {
        if &record.device_identifier == device_identifier {
            debug!(?id, "Reaping superseded persistent token record");
            store.delete(&id).await;
        }
    }
}

/// Test-only: build an `encIdentifier` (`iv || ct`) for a device identifier under a
/// token, using the production key derivation. Shared across test modules.
#[cfg(test)]
pub(crate) fn build_enc_identifier(
    token: &[u8],
    device_identifier: &[u8; 16],
    iv: &[u8; 16],
) -> Vec<u8> {
    use aes::cipher::BlockEncryptMut;
    type Aes128CbcEncryptor = cbc::Encryptor<aes::Aes128>;
    let key = enc_identifier_key(token).expect("encIdentifier key derivation");
    let encryptor = Aes128CbcEncryptor::new_from_slices(&key, iv).expect("valid key/iv");
    let ciphertext = encryptor.encrypt_padded_vec_mut::<NoPadding>(device_identifier);
    let mut enc = iv.to_vec();
    enc.extend_from_slice(&ciphertext);
    enc
}

#[cfg(test)]
mod test {
    use super::*;

    use serde_bytes::ByteBuf;

    use crate::proto::ctap2::Ctap2GetInfoResponse;

    fn sample_record() -> PersistentTokenRecord {
        PersistentTokenRecord {
            persistent_token: vec![0xAB; 32],
            pin_uv_auth_protocol: Ctap2PinUvAuthProtocol::Two,
            device_identifier: [0x11; 16],
            aaguid: [0x22; 16],
        }
    }

    fn record_with(token: Vec<u8>, device_identifier: [u8; 16]) -> PersistentTokenRecord {
        PersistentTokenRecord {
            persistent_token: token,
            pin_uv_auth_protocol: Ctap2PinUvAuthProtocol::Two,
            device_identifier,
            aaguid: [0x22; 16],
        }
    }

    fn info_with_enc_identifier(enc_identifier: Vec<u8>) -> Ctap2GetInfoResponse {
        Ctap2GetInfoResponse {
            enc_identifier: Some(ByteBuf::from(enc_identifier)),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn put_list_delete_round_trip() {
        let store = MemoryPersistentTokenStore::new();
        assert!(store.list().await.is_empty());

        let id = "record-1".to_string();
        store.put(&id, &sample_record()).await;

        let listed = store.list().await;
        assert_eq!(listed.len(), 1);
        let (listed_id, listed_record) = &listed[0];
        assert_eq!(listed_id, &id);
        assert_eq!(listed_record.persistent_token, vec![0xAB; 32]);
        assert_eq!(listed_record.device_identifier, [0x11; 16]);

        store.delete(&id).await;
        assert!(store.list().await.is_empty());
    }

    #[tokio::test]
    async fn put_replaces_existing_id() {
        let store = MemoryPersistentTokenStore::new();
        let id = "record-1".to_string();
        store.put(&id, &sample_record()).await;

        let mut replacement = sample_record();
        replacement.persistent_token = vec![0xCD; 32];
        store.put(&id, &replacement).await;

        let listed = store.list().await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1.persistent_token, vec![0xCD; 32]);
    }

    #[test]
    fn debug_redacts_token() {
        let rendered = format!("{:?}", sample_record());
        assert!(rendered.contains("<redacted>"));
        // The token bytes (0xAB repeated) must never appear in any rendering.
        assert!(!rendered.contains("171, 171"));
        assert!(!rendered.contains("ab, ab"));
    }

    #[test]
    fn record_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<PersistentTokenRecord>();
    }

    #[test]
    fn decrypt_enc_identifier_round_trips() {
        let token = vec![0x07; 32];
        let device_identifier = [0x42; 16];
        let enc = build_enc_identifier(&token, &device_identifier, &[0x99; 16]);
        assert_eq!(
            decrypt_enc_identifier(&token, &enc).unwrap(),
            device_identifier
        );
    }

    #[test]
    fn decrypt_enc_identifier_rejects_bad_length() {
        let token = vec![0x07; 32];
        assert!(decrypt_enc_identifier(&token, &[0u8; 31]).is_err());
        assert!(decrypt_enc_identifier(&token, &[0u8; 33]).is_err());
        assert!(decrypt_enc_identifier(&token, &[]).is_err());
    }

    // Known-answer vector for the encIdentifier construction (CTAP 2.3-PS 6.4). The
    // expected key and ciphertext were computed independently of this crate (RFC 5869
    // HKDF-SHA-256 via Python hashlib/hmac, AES-128-CBC via openssl), so a self-
    // consistent but spec-wrong change to the HKDF salt, info string, output length, or
    // cipher is caught here even though the round-trip tests would still pass.
    #[test]
    fn enc_identifier_matches_known_answer_vector() {
        let token: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let device_identifier: [u8; 16] = [
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ];
        // HKDF-SHA-256(salt = 32 zero bytes, IKM = token, L = 16, info = "encIdentifier").
        let expected_key: [u8; 16] = [
            0x24, 0x15, 0x4D, 0xBE, 0x7E, 0xF3, 0xCE, 0x2D, 0x6A, 0xDD, 0x02, 0xC4, 0xE4, 0x8D,
            0xBB, 0x69,
        ];
        assert_eq!(enc_identifier_key(&token).unwrap(), expected_key);

        // iv (0x30..0x3F) || ct, where ct = AES-128-CBC(expected_key, iv, device_identifier)
        // with no padding (the device identifier is exactly one block).
        let enc_identifier: [u8; 32] = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
            0x3E, 0x3F, 0xF4, 0xD6, 0x82, 0xA3, 0x6E, 0x94, 0x0D, 0x68, 0xD8, 0x62, 0xE3, 0x09,
            0x9C, 0x6C, 0xE9, 0xB4,
        ];
        assert_eq!(
            decrypt_enc_identifier(&token, &enc_identifier).unwrap(),
            device_identifier
        );
    }

    #[tokio::test]
    async fn recognizes_matching_record() {
        let store = MemoryPersistentTokenStore::new();
        let token = vec![0x07; 32];
        let device_identifier = [0x42; 16];
        store
            .put(
                &"id-1".to_string(),
                &record_with(token.clone(), device_identifier),
            )
            .await;

        // A second getInfo uses a fresh IV, so the bytes differ but recognition holds.
        let info = info_with_enc_identifier(build_enc_identifier(
            &token,
            &device_identifier,
            &[0x33; 16],
        ));
        let (id, record) = recognize_authenticator(&store, &info).await.unwrap();
        assert_eq!(id, "id-1");
        assert_eq!(record.device_identifier, device_identifier);
    }

    #[tokio::test]
    async fn rejects_wrong_token() {
        let store = MemoryPersistentTokenStore::new();
        let real_token = vec![0x07; 32];
        let device_identifier = [0x42; 16];
        // Stored record carries a different token, so its key cannot reproduce the id.
        store
            .put(
                &"id-1".to_string(),
                &record_with(vec![0xFF; 32], device_identifier),
            )
            .await;

        let info = info_with_enc_identifier(build_enc_identifier(
            &real_token,
            &device_identifier,
            &[0x33; 16],
        ));
        assert!(recognize_authenticator(&store, &info).await.is_none());
    }

    #[tokio::test]
    async fn rejects_stale_device_identifier() {
        let store = MemoryPersistentTokenStore::new();
        let token = vec![0x07; 32];
        // Right token, but the stored device identifier is stale (e.g. after a reset).
        store
            .put(&"id-1".to_string(), &record_with(token.clone(), [0x00; 16]))
            .await;

        let info = info_with_enc_identifier(build_enc_identifier(&token, &[0x42; 16], &[0x33; 16]));
        assert!(recognize_authenticator(&store, &info).await.is_none());
    }

    #[tokio::test]
    async fn picks_correct_record_among_many() {
        let store = MemoryPersistentTokenStore::new();
        store
            .put(
                &"other".to_string(),
                &record_with(vec![0x01; 32], [0xAA; 16]),
            )
            .await;
        let token = vec![0x07; 32];
        let device_identifier = [0x42; 16];
        store
            .put(
                &"target".to_string(),
                &record_with(token.clone(), device_identifier),
            )
            .await;

        let info = info_with_enc_identifier(build_enc_identifier(
            &token,
            &device_identifier,
            &[0x33; 16],
        ));
        let (id, _) = recognize_authenticator(&store, &info).await.unwrap();
        assert_eq!(id, "target");
    }

    #[tokio::test]
    async fn none_without_enc_identifier() {
        let store = MemoryPersistentTokenStore::new();
        store.put(&"id-1".to_string(), &sample_record()).await;
        let info = Ctap2GetInfoResponse::default();
        assert!(recognize_authenticator(&store, &info).await.is_none());
    }

    #[tokio::test]
    async fn mint_reaps_same_device_and_preserves_sibling() {
        let store = MemoryPersistentTokenStore::new();
        let device = [0x42; 16];
        let sibling = [0x99; 16];
        let aaguid = [0x07; 16];

        // A stale record for this device, plus a sibling key of the same model.
        store
            .put(&"old".to_string(), &record_with(vec![0x11; 32], device))
            .await;
        store
            .put(
                &"sibling".to_string(),
                &record_with(vec![0x22; 32], sibling),
            )
            .await;

        let minted = vec![0x33; 32];
        let info = Ctap2GetInfoResponse {
            aaguid: ByteBuf::from(aaguid.to_vec()),
            enc_identifier: Some(ByteBuf::from(build_enc_identifier(
                &minted,
                &device,
                &[0x55; 16],
            ))),
            ..Default::default()
        };

        let new_id = store_minted_token(&store, &info, &minted, Ctap2PinUvAuthProtocol::One)
            .await
            .unwrap();

        let listed = store.list().await;
        // The old same-device record is reaped; the sibling and the new record remain.
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|(id, _)| id != "old"));
        let new = listed.iter().find(|(id, _)| id == &new_id).unwrap();
        assert_eq!(new.1.device_identifier, device);
        assert_eq!(new.1.persistent_token, minted);
        let sib = listed.iter().find(|(id, _)| id == "sibling").unwrap();
        assert_eq!(sib.1.device_identifier, sibling);
        assert_eq!(sib.1.persistent_token, vec![0x22; 32]);
    }
}
