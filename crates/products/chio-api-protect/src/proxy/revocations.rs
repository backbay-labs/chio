//! Combine local releases with live operator and control-service revocations.

use std::sync::Arc;

use chio_kernel::{RevocationStore, RevocationStoreError};

/// Every configured authority must be consulted before admission. Revocations
/// are monotonic, so a positive observation can short-circuit, while a failed
/// read can never be interpreted as permission. Keep the local store when a
/// remote authority is configured so previously persisted releases still apply.
pub(super) struct LiveRevocationStore {
    pub(super) local: Arc<dyn RevocationStore>,
    pub(super) authorities: Vec<Arc<dyn RevocationStore>>,
}

impl RevocationStore for LiveRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        if self.local.is_revoked(capability_id)? {
            return Ok(true);
        }
        for authority in &self.authorities {
            if authority.is_revoked(capability_id)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        // Persist the local refusal before contacting other authorities. If a
        // remote publication fails, return the error; retrying can safely finish
        // propagation and the local gateway already refuses the released grant.
        let mut newly_revoked = self.local.revoke(capability_id)?;
        for authority in &self.authorities {
            newly_revoked |= authority.revoke(capability_id)?;
        }
        Ok(newly_revoked)
    }

    fn is_ephemeral(&self) -> bool {
        self.local.is_ephemeral()
            && self
                .authorities
                .iter()
                .all(|authority| authority.is_ephemeral())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_kernel::InMemoryRevocationStore;
    use chio_store_sqlite::SqliteRevocationStore;
    use chio_test_support::prelude::*;

    struct Unavailable;

    impl RevocationStore for Unavailable {
        fn is_revoked(&self, _: &str) -> Result<bool, RevocationStoreError> {
            Err(RevocationStoreError::Sync("authority unavailable".into()))
        }

        fn revoke(&self, _: &str) -> Result<bool, RevocationStoreError> {
            Err(RevocationStoreError::Sync("authority unavailable".into()))
        }
    }

    #[test]
    fn observes_operator_revocations_after_startup_and_restart() {
        let directory = tempfile::tempdir().test_unwrap();
        let path = directory.path().join("operator.db");
        let operator = SqliteRevocationStore::open(&path).test_unwrap();
        let local: Arc<dyn RevocationStore> = Arc::new(InMemoryRevocationStore::new());
        local.revoke("old-local-release").test_unwrap();
        let store = LiveRevocationStore {
            local,
            authorities: vec![Arc::new(SqliteRevocationStore::open(&path).test_unwrap())],
        };
        assert!(store.is_revoked("old-local-release").test_unwrap());
        assert!(!store.is_revoked("live-grant").test_unwrap());
        operator.revoke("live-grant").test_unwrap();
        assert!(store.is_revoked("live-grant").test_unwrap());
        assert!(!store.is_ephemeral());
        assert!(store.revoke("local-release").test_unwrap());
        assert!(!store.revoke("local-release").test_unwrap());
        drop(store);
        let reopened = SqliteRevocationStore::open(path).test_unwrap();
        assert!(reopened.is_revoked("live-grant").test_unwrap());
        assert!(reopened.is_revoked("local-release").test_unwrap());
    }

    #[test]
    fn unavailable_authority_never_admits_or_reports_successful_propagation() {
        let local: Arc<dyn RevocationStore> = Arc::new(InMemoryRevocationStore::new());
        let store = LiveRevocationStore {
            local: Arc::clone(&local),
            authorities: vec![Arc::new(Unavailable)],
        };
        assert!(store.is_revoked("live-grant").is_err());
        assert!(store.revoke("live-grant").is_err());
        assert!(local.is_revoked("live-grant").test_unwrap());
        assert!(store.is_revoked("live-grant").test_unwrap());
    }
}
