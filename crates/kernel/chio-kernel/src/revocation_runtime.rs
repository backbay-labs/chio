use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard};

use crate::{budget_store::RevocationCommitMetadata, RevocationStoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationObservation {
    pub revoked: bool,
    pub commit: Option<RevocationCommitMetadata>,
}

/// Trait for checking whether a capability has been revoked.
///
/// Implementations may be in-memory, SQLite-backed, or subscribe to a
/// distributed revocation feed via Spine/NATS.
pub trait RevocationStore: Send + Sync {
    /// Check if a capability ID has been revoked.
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError>;

    /// Revoke a capability. Returns `true` if it was newly revoked.
    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError>;

    fn observe_revocation(
        &self,
        capability_id: &str,
    ) -> Result<RevocationObservation, RevocationStoreError> {
        Ok(RevocationObservation {
            revoked: self.is_revoked(capability_id)?,
            commit: None,
        })
    }

    /// Whether this store loses its revocation set on process restart. The
    /// default is the safe (loud) assumption so an unknown store is treated as
    /// ephemeral; durable and remote stores override to `false`.
    fn is_ephemeral(&self) -> bool {
        true
    }
}

/// In-memory revocation store for development and testing.
#[derive(Debug, Default)]
pub struct InMemoryRevocationStore {
    revoked: Mutex<HashSet<String>>,
}

impl InMemoryRevocationStore {
    /// Create an empty revocation store.
    pub fn new() -> Self {
        Self::default()
    }

    fn revoked(&self) -> Result<MutexGuard<'_, HashSet<String>>, RevocationStoreError> {
        self.revoked.lock().map_err(|_| {
            RevocationStoreError::Sync("in-memory revocation store lock poisoned".to_string())
        })
    }
}

impl RevocationStore for InMemoryRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        Ok(self.revoked()?.contains(capability_id))
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        Ok(self.revoked()?.insert(capability_id.to_owned()))
    }
}
