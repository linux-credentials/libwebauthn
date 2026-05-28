use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{debug, trace};
use zeroize::ZeroizeOnDrop;

use crate::proto::ctap2::Ctap2PinUvAuthProtocol;

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

#[cfg(test)]
mod test {
    use super::*;

    fn sample_record() -> PersistentTokenRecord {
        PersistentTokenRecord {
            persistent_token: vec![0xAB; 32],
            pin_uv_auth_protocol: Ctap2PinUvAuthProtocol::Two,
            device_identifier: [0x11; 16],
            aaguid: [0x22; 16],
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
}
