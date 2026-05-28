use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut};
use async_trait::async_trait;
use cbc::cipher::KeyIvInit;
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::sync::Mutex;
use tracing::{debug, error, trace};
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
#[allow(dead_code)] // wired into the acquisition/reuse flow in a later change
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
#[allow(dead_code)] // wired into the acquisition/reuse flow in a later change
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
#[allow(dead_code)] // wired into the acquisition/reuse flow in a later change
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

#[cfg(test)]
mod test {
    use super::*;

    use aes::cipher::{block_padding::NoPadding as TestNoPadding, BlockEncryptMut};
    use cbc::cipher::KeyIvInit as TestKeyIvInit;
    use serde_bytes::ByteBuf;

    use crate::proto::ctap2::Ctap2GetInfoResponse;

    type Aes128CbcEncryptor = cbc::Encryptor<aes::Aes128>;

    fn sample_record() -> PersistentTokenRecord {
        PersistentTokenRecord {
            persistent_token: vec![0xAB; 32],
            pin_uv_auth_protocol: Ctap2PinUvAuthProtocol::Two,
            device_identifier: [0x11; 16],
            aaguid: [0x22; 16],
        }
    }

    /// The authenticator side: produce `iv || ct` for a device identifier under a token,
    /// using the same key derivation the recognition path uses.
    fn build_enc_identifier(token: &[u8], device_identifier: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
        let key = enc_identifier_key(token).unwrap();
        let encryptor = Aes128CbcEncryptor::new_from_slices(&key, iv).unwrap();
        let ciphertext = encryptor.encrypt_padded_vec_mut::<TestNoPadding>(device_identifier);
        let mut enc = iv.to_vec();
        enc.extend_from_slice(&ciphertext);
        enc
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
}
