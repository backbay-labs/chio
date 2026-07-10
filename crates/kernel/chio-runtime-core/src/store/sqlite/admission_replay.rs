use rusqlite::{params, OptionalExtension, TransactionBehavior};

use chio_swarm_authority::SwarmAuthorityBundle;

use super::{sqlite_error, SqliteRuntimeOrchestrationStore};
use crate::hash::runtime_admission_bundle_sha256;
use crate::store::traits::RuntimeAdmissionStore;
use crate::types::{RuntimeAdmissionBundle, RuntimeTrustFloorEntry, TreatyRuntimeArtifactRecord};
use crate::ChioRuntimeError;

impl SqliteRuntimeOrchestrationStore {
    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        let bundle_sha256 = runtime_admission_bundle_sha256(&bundle)?;
        let raw_json = serde_json::to_string(&bundle)
            .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT bundle_sha256 FROM runtime_admission_bundles WHERE admission_id = ?1",
                params![bundle.admission_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(existing) = existing {
            if existing == bundle_sha256 {
                tx.commit().map_err(sqlite_error)?;
                return Ok(());
            }
            return Err(ChioRuntimeError::Rejected {
                code: "duplicate_admission_bundle_mismatch",
                detail: "runtime admission bundle id already exists with a different hash"
                    .to_string(),
            });
        }
        tx.execute(
            "INSERT INTO runtime_admission_bundles (admission_id, bundle_sha256, raw_json, created_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
            params![bundle.admission_id, bundle_sha256, raw_json, 0_i64],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }
}

impl RuntimeAdmissionStore for SqliteRuntimeOrchestrationStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        let connection = self.lock_connection()?;
        let raw_json: Option<String> = connection
            .query_row(
                "SELECT raw_json FROM runtime_admission_bundles WHERE admission_id = ?1",
                params![admission_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        raw_json
            .map(|json| {
                serde_json::from_str(&json)
                    .map_err(|error| ChioRuntimeError::Json(error.to_string()))
            })
            .transpose()
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        SqliteRuntimeOrchestrationStore::treaty_runtime_artifact(self, evidence_kind, evidence_id)
    }

    fn swarm_authority_bundle(
        &self,
        task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        self.load_swarm_authority_bundle(task_graph_id)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let connection = self.lock_connection()?;
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO runtime_consumed_leases (lease_id, admission_id) VALUES (?1, ?2)",
                params![lease_id, admission_id],
            )
            .map_err(sqlite_error)?;
        if inserted == 0 {
            return Err(ChioRuntimeError::Rejected {
                code: "destructive_lease_replay",
                detail: format!("destructive lease {lease_id} was already consumed"),
            });
        }
        Ok(())
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let connection = self.lock_connection()?;
        connection
            .execute(
                "DELETE FROM runtime_consumed_leases WHERE lease_id = ?1 AND admission_id = ?2",
                params![lease_id, admission_id],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let connection = self.lock_connection()?;
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO runtime_consumed_treaty_continuations (continuation_id, admission_id) VALUES (?1, ?2)",
                params![continuation_id, admission_id],
            )
            .map_err(sqlite_error)?;
        if inserted == 0 {
            return Err(ChioRuntimeError::Rejected {
                code: "chio_treaty_continuation_replay",
                detail: format!("treaty continuation {continuation_id} was already consumed"),
            });
        }
        Ok(())
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let connection = self.lock_connection()?;
        connection
            .execute(
                "DELETE FROM runtime_consumed_treaty_continuations WHERE continuation_id = ?1 AND admission_id = ?2",
                params![continuation_id, admission_id],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn consume_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let connection = self.lock_connection()?;
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO runtime_consumed_swarm_continuations (continuation_id, admission_id) VALUES (?1, ?2)",
                params![continuation_id, admission_id],
            )
            .map_err(sqlite_error)?;
        if inserted == 0 {
            return Err(ChioRuntimeError::Rejected {
                code: "chio_swarm_continuation_replay",
                detail: format!("swarm continuation {continuation_id} was already consumed"),
            });
        }
        Ok(())
    }

    fn release_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let connection = self.lock_connection()?;
        connection
            .execute(
                "DELETE FROM runtime_consumed_swarm_continuations WHERE continuation_id = ?1 AND admission_id = ?2",
                params![continuation_id, admission_id],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        self.load_runtime_trust_floor(verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        self.store_runtime_trust_floor(entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        self.validate_and_store_runtime_trust_floor(entry, previous_hash_sha256)
    }
}
