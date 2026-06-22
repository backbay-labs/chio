use std::collections::BTreeSet;

use rusqlite::Connection;

use super::{sqlite_error, ChioRuntimeError, SqliteRuntimeOrchestrationStore};

impl SqliteRuntimeOrchestrationStore {
    pub(super) fn init_schema(&self) -> Result<(), ChioRuntimeError> {
        let connection = self.lock_connection()?;
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS runtime_admission_bundles (
                    admission_id TEXT PRIMARY KEY NOT NULL,
                    bundle_sha256 TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at_unix_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_consumed_leases (
                    lease_id TEXT PRIMARY KEY NOT NULL,
                    admission_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_consumed_treaty_continuations (
                    continuation_id TEXT PRIMARY KEY NOT NULL,
                    admission_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_consumed_swarm_continuations (
                    continuation_id TEXT PRIMARY KEY NOT NULL,
                    admission_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_trust_floors (
                    verifier_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    highest_version INTEGER NOT NULL,
                    latest_bundle_sha256 TEXT NOT NULL,
                    latest_revocation_checkpoint_sha256 TEXT NOT NULL,
                    PRIMARY KEY (verifier_id, key_id)
                );
                CREATE TABLE IF NOT EXISTS runtime_runs (
                    run_id TEXT PRIMARY KEY NOT NULL,
                    status TEXT NOT NULL,
                    started_at_unix_ms INTEGER NOT NULL,
                    updated_at_unix_ms INTEGER NOT NULL,
                    failure_code TEXT,
                    workflow_report_sha256 TEXT,
                    proof_regeneration_report_sha256 TEXT
                );
                CREATE TABLE IF NOT EXISTS runtime_step_states (
                    run_id TEXT NOT NULL,
                    step_index INTEGER NOT NULL,
                    admission_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    destructive INTEGER NOT NULL,
                    admission_report_sha256 TEXT,
                    tool_receipt_sha256 TEXT,
                    lease_id TEXT,
                    PRIMARY KEY (run_id, step_index)
                );
                CREATE TABLE IF NOT EXISTS runtime_evidence_artifacts (
                    run_id TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    role TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    byte_count INTEGER NOT NULL,
                    recorded_at_unix_ms INTEGER NOT NULL,
                    PRIMARY KEY (run_id, artifact_sha256)
                );
                CREATE TABLE IF NOT EXISTS runtime_treaty_artifacts (
                    evidence_kind TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at_unix_ms INTEGER NOT NULL,
                    PRIMARY KEY (evidence_kind, evidence_id)
                );
                CREATE TABLE IF NOT EXISTS runtime_swarm_authority_bundles (
                    task_graph_id TEXT PRIMARY KEY NOT NULL,
                    bundle_sha256 TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at_unix_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_run_leases (
                    run_id TEXT PRIMARY KEY NOT NULL,
                    lease_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    acquired_at_unix_ms INTEGER NOT NULL,
                    expires_at_unix_ms INTEGER NOT NULL,
                    heartbeat_at_unix_ms INTEGER NOT NULL,
                    fencing_token INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    reason_code TEXT
                );
                CREATE TABLE IF NOT EXISTS runtime_scheduler_ticks (
                    tick_id TEXT PRIMARY KEY NOT NULL,
                    owner_id TEXT NOT NULL,
                    generated_at_unix_ms INTEGER NOT NULL,
                    claimed_count INTEGER NOT NULL,
                    blocked_count INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_recovery_drills (
                    run_id TEXT NOT NULL,
                    generated_at_unix_ms INTEGER NOT NULL,
                    accepted INTEGER NOT NULL,
                    failure_code TEXT,
                    PRIMARY KEY (run_id, generated_at_unix_ms)
                );
                CREATE TABLE IF NOT EXISTS runtime_provider_health (
                    provider_id TEXT PRIMARY KEY NOT NULL,
                    generated_at_unix_ms INTEGER NOT NULL,
                    healthy INTEGER NOT NULL,
                    failure_code TEXT
                );
                CREATE TABLE IF NOT EXISTS runtime_evidence_sink_health (
                    run_id TEXT PRIMARY KEY NOT NULL,
                    generated_at_unix_ms INTEGER NOT NULL,
                    healthy INTEGER NOT NULL,
                    failure_code TEXT
                );
                "#,
            )
            .map_err(sqlite_error)?;
        Self::migrate_evidence_artifacts_schema(&connection)
    }

    pub(super) fn migrate_evidence_artifacts_schema(
        connection: &Connection,
    ) -> Result<(), ChioRuntimeError> {
        let mut statement = connection
            .prepare("PRAGMA table_info(runtime_evidence_artifacts)")
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?))
            })
            .map_err(sqlite_error)?;
        let mut primary_key_columns = BTreeSet::new();
        for row in rows {
            let (name, primary_key_index) = row.map_err(sqlite_error)?;
            if primary_key_index > 0 {
                primary_key_columns.insert(name);
            }
        }
        if primary_key_columns.contains("run_id") && primary_key_columns.contains("artifact_sha256")
        {
            return Ok(());
        }
        connection
            .execute_batch(
                r#"
                CREATE TABLE runtime_evidence_artifacts_v2 (
                    run_id TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    role TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    byte_count INTEGER NOT NULL,
                    recorded_at_unix_ms INTEGER NOT NULL,
                    PRIMARY KEY (run_id, artifact_sha256)
                );
                INSERT OR REPLACE INTO runtime_evidence_artifacts_v2 (
                    run_id, artifact_sha256, role, relative_path, byte_count, recorded_at_unix_ms
                )
                SELECT run_id, artifact_sha256, role, relative_path, byte_count, recorded_at_unix_ms
                FROM runtime_evidence_artifacts;
                DROP TABLE runtime_evidence_artifacts;
                ALTER TABLE runtime_evidence_artifacts_v2 RENAME TO runtime_evidence_artifacts;
                "#,
            )
            .map_err(sqlite_error)
    }
}
