use rusqlite::params;

use super::{sqlite_error, sqlite_i64, SqliteRuntimeOrchestrationStore};
use crate::types::RuntimeEvidenceManifestEntry;
use crate::validation::{ensure_sha256_hash, validate_relative_evidence_path};
use crate::ChioRuntimeError;

impl SqliteRuntimeOrchestrationStore {
    pub fn record_evidence_artifact(
        &self,
        run_id: &str,
        entry: &RuntimeEvidenceManifestEntry,
        recorded_at_unix_ms: u64,
    ) -> Result<(), ChioRuntimeError> {
        validate_relative_evidence_path(&entry.path, "runtime_evidence_manifest_invalid_path")?;
        ensure_sha256_hash(
            &entry.sha256,
            "runtime_evidence_manifest_invalid_artifact_hash",
        )?;
        let connection = self.lock_connection()?;
        connection
            .execute(
                r#"
                INSERT INTO runtime_evidence_artifacts (
                    run_id, artifact_sha256, role, relative_path, byte_count, recorded_at_unix_ms
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(run_id, artifact_sha256) DO UPDATE SET
                    role = excluded.role,
                    relative_path = excluded.relative_path,
                    byte_count = excluded.byte_count,
                    recorded_at_unix_ms = excluded.recorded_at_unix_ms
                "#,
                params![
                    run_id,
                    entry.sha256,
                    entry.role,
                    entry.path,
                    sqlite_i64(entry.byte_count, "runtime evidence byte count")?,
                    sqlite_i64(recorded_at_unix_ms, "runtime evidence timestamp")?
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }
}
