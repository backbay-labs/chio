use rusqlite::params;

use super::{sqlite_error, sqlite_i64, SqliteRuntimeOrchestrationStore};
use crate::types::RuntimeOrchestrationStepState;
use crate::validation::{
    validate_non_empty, validate_runtime_orchestration_step_state, validate_state_label,
};
use crate::ChiodosRuntimeError;

impl SqliteRuntimeOrchestrationStore {
    pub fn record_run_state(
        &self,
        run_id: &str,
        status: &str,
        failure_code: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<(), ChiodosRuntimeError> {
        validate_non_empty(run_id, "runtime_run_empty_id")?;
        validate_state_label(status, "runtime_run_invalid_status")?;
        let now = sqlite_i64(now_unix_ms, "runtime run timestamp")?;
        let connection = self.lock_connection()?;
        connection
            .execute(
                r#"
                INSERT INTO runtime_runs (run_id, status, started_at_unix_ms, updated_at_unix_ms, failure_code)
                VALUES (?1, ?2, ?3, ?3, ?4)
                ON CONFLICT(run_id) DO UPDATE SET
                    status = excluded.status,
                    updated_at_unix_ms = excluded.updated_at_unix_ms,
                    failure_code = excluded.failure_code
                "#,
                params![run_id, status, now, failure_code],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn record_step_state(
        &self,
        state: RuntimeOrchestrationStepState,
    ) -> Result<(), ChiodosRuntimeError> {
        self.record_run_step_state("default", state)
    }

    pub fn record_run_step_state(
        &self,
        run_id: &str,
        state: RuntimeOrchestrationStepState,
    ) -> Result<(), ChiodosRuntimeError> {
        validate_non_empty(run_id, "runtime_run_empty_id")?;
        validate_runtime_orchestration_step_state(&state)?;
        let connection = self.lock_connection()?;
        connection
            .execute(
                r#"
                INSERT INTO runtime_step_states (
                    run_id, step_index, admission_id, state, destructive,
                    admission_report_sha256, tool_receipt_sha256, lease_id
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(run_id, step_index) DO UPDATE SET
                    admission_id = excluded.admission_id,
                    state = excluded.state,
                    destructive = excluded.destructive,
                    admission_report_sha256 = excluded.admission_report_sha256,
                    tool_receipt_sha256 = excluded.tool_receipt_sha256,
                    lease_id = excluded.lease_id
                "#,
                params![
                    run_id,
                    sqlite_i64(state.step_index, "runtime step index")?,
                    state.admission_id,
                    state.state,
                    if state.destructive { 1_i64 } else { 0_i64 },
                    state.admission_report_sha256,
                    state.tool_receipt_sha256,
                    state.lease_id
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub(super) fn pending_run_ids(&self) -> Result<Vec<String>, ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT runs.run_id
                FROM runtime_runs runs
                WHERE runs.status IN ('pending', 'planned', 'proof_pending')
                  AND NOT EXISTS (
                    SELECT 1
                    FROM runtime_run_leases leases
                    WHERE leases.run_id = runs.run_id
                      AND leases.state = 'active'
                  )
                ORDER BY runs.updated_at_unix_ms, runs.run_id
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sqlite_error)?;
        let mut run_ids = Vec::new();
        for row in rows {
            run_ids.push(row.map_err(sqlite_error)?);
        }
        Ok(run_ids)
    }
}
