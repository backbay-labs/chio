//! Redacted tee payload spool backed by encrypted SQLite BLOB storage.

use chio_store_sqlite::{BlobHandle, EncryptedBlob, TenantId, TenantKey};

use crate::persist::{PersistedBlob, PersistenceError, TeeBlobPersistence};

/// Persisted request/response pair for one tee observation.
pub struct SpooledTraffic {
    /// Redacted request body persisted as an encrypted BLOB.
    pub request: PersistedBlob,
    /// Redacted response body persisted as an encrypted BLOB.
    pub response: PersistedBlob,
}

/// Spool-level error wrapper.
#[derive(Debug)]
pub enum SpoolError {
    /// Persistence failed while writing or reading a BLOB.
    Persistence(PersistenceError),
}

impl std::fmt::Display for SpoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Persistence(error) => write!(f, "tee spool persistence error: {error}"),
        }
    }
}

impl std::error::Error for SpoolError {}

impl From<PersistenceError> for SpoolError {
    fn from(error: PersistenceError) -> Self {
        Self::Persistence(error)
    }
}

/// Tee payload spool. It receives already-redacted traffic and delegates
/// all at-rest encryption to the persistence facade.
pub struct TeeBlobSpool {
    persistence: TeeBlobPersistence,
}

impl TeeBlobSpool {
    /// Construct from a persistence facade.
    #[must_use]
    pub fn new(persistence: TeeBlobPersistence) -> Self {
        Self { persistence }
    }

    /// Persist a redacted request and response pair.
    pub fn persist_traffic(
        &self,
        tenant_id: &TenantId,
        key: &TenantKey,
        request_payload: &[u8],
        response_payload: &[u8],
    ) -> Result<SpooledTraffic, SpoolError> {
        let request = self
            .persistence
            .persist_redacted_blob(tenant_id, key, request_payload)?;
        let response = self
            .persistence
            .persist_redacted_blob(tenant_id, key, response_payload)?;
        Ok(SpooledTraffic { request, response })
    }

    /// Read and decrypt a spooled BLOB.
    pub fn read_blob(&self, handle: &BlobHandle, key: &TenantKey) -> Result<Vec<u8>, SpoolError> {
        self.persistence
            .read_blob(handle, key)
            .map_err(SpoolError::from)
    }

    /// Load encrypted material for a spooled BLOB without returning
    /// plaintext.
    pub fn load_encrypted_blob(&self, handle: &BlobHandle) -> Result<EncryptedBlob, SpoolError> {
        self.persistence
            .load_encrypted_blob(handle)
            .map_err(SpoolError::from)
    }
}
