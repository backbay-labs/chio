use std::collections::BTreeMap;

use chio_core_types::crypto::sha256_hex;
use rusqlite::{params, Connection, OptionalExtension};

use super::leases_scheduler::{lease_count_by_state, stale_lease_count};
use super::{query_count, sqlite_error, sqlite_i64, sqlite_u64, SqliteRuntimeOrchestrationStore};
use crate::hash::canonical_sha256;
use crate::schema::{
    CHIODOS_RUNTIME_OPS_STATUS_REPORT_SCHEMA, CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA,
    CHIODOS_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA,
};
use crate::types::{
    RuntimeOpsStatusReport, RuntimeOrchestrationProfile, RuntimeOrchestrationStatusReport,
    RuntimeRecoveryDrillReport, RuntimeSupervisorProfile,
};
use crate::validation::{
    validate_non_empty, validate_runtime_ops_status_report, validate_runtime_orchestration_profile,
    validate_runtime_orchestration_status_report, validate_runtime_recovery_drill_report,
    validate_runtime_supervisor_profile,
};
use crate::ChiodosRuntimeError;

impl SqliteRuntimeOrchestrationStore {
    pub fn status_report(
        &self,
        profile: &RuntimeOrchestrationProfile,
        profile_sha256: String,
        now_unix_ms: u64,
        evidence_sink_healthy: bool,
    ) -> Result<RuntimeOrchestrationStatusReport, ChiodosRuntimeError> {
        validate_runtime_orchestration_profile(profile)?;
        let connection = self.lock_connection()?;
        let mut run_counts = BTreeMap::new();
        {
            let mut statement = connection
                .prepare("SELECT status, COUNT(*) FROM runtime_runs GROUP BY status")
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(sqlite_error)?;
            for row in rows {
                let (status, count) = row.map_err(sqlite_error)?;
                run_counts.insert(status, sqlite_u64(count, "runtime run count")?);
            }
        }
        let consumed_lease_count = query_count(&connection, "runtime_consumed_leases")?;
        let trust_floor_count = query_count(&connection, "runtime_trust_floors")?;
        let latest_failure_code: Option<String> = connection
            .query_row(
                "SELECT failure_code FROM runtime_runs WHERE failure_code IS NOT NULL ORDER BY updated_at_unix_ms DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        let profile_stale =
            now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms;
        let degraded = profile_stale || !evidence_sink_healthy || latest_failure_code.is_some();
        let failure_code = if profile_stale {
            Some("runtime_orchestration_profile_stale".to_string())
        } else if degraded {
            Some(
                latest_failure_code
                    .clone()
                    .unwrap_or_else(|| "runtime_ops_status_degraded".to_string()),
            )
        } else {
            None
        };
        let report = RuntimeOrchestrationStatusReport {
            schema: CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA.to_string(),
            accepted: !degraded,
            failure_code,
            generated_at_unix_ms: now_unix_ms,
            profile_sha256,
            store_backend: "sqlite".to_string(),
            store_path_sha256: sha256_hex(self.path.to_string_lossy().as_bytes()),
            run_counts,
            consumed_lease_count,
            trust_floor_count,
            latest_failure_code,
            evidence_sink_healthy,
            ready: !profile.profile_id.trim().is_empty() && !degraded,
            degraded,
        };
        validate_runtime_orchestration_status_report(&report)?;
        Ok(report)
    }

    pub fn recovery_drill_report(
        &self,
        run_id: &str,
        now_unix_ms: u64,
    ) -> Result<RuntimeRecoveryDrillReport, ChiodosRuntimeError> {
        validate_non_empty(run_id, "runtime_recovery_empty_run_id")?;
        let connection = self.lock_connection()?;
        let run_exists = connection
            .query_row(
                "SELECT 1 FROM runtime_runs WHERE run_id = ?1 LIMIT 1",
                params![run_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(sqlite_error)?
            .is_some();
        if !run_exists {
            let report = RuntimeRecoveryDrillReport {
                schema: CHIODOS_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA.to_string(),
                run_id: run_id.to_string(),
                accepted: false,
                failure_code: Some("runtime_recovery_run_not_found".to_string()),
                generated_at_unix_ms: now_unix_ms,
                resumable: false,
                blocked: true,
                next_step_index: None,
                reusable_step_indices: Vec::new(),
                recovery_required_reason: Some("runtime_recovery_run_not_found".to_string()),
                checks: vec!["runtime_ops.recovery_run_lookup".to_string()],
            };
            validate_runtime_recovery_drill_report(&report)?;
            return Ok(report);
        }
        let mut reusable_step_indices = Vec::new();
        let mut destructive_terminal_without_evidence = false;
        {
            let mut statement = connection
                .prepare(
                    "SELECT step_index, destructive, tool_receipt_sha256, state FROM runtime_step_states WHERE run_id = ?1 ORDER BY step_index",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map(params![run_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(sqlite_error)?;
            for row in rows {
                let (index, destructive, receipt, state) = row.map_err(sqlite_error)?;
                let index = sqlite_u64(index, "runtime recovery step index")?;
                if state == "proof_accepted" || state == "completed" {
                    reusable_step_indices.push(index);
                } else if state == "terminal_failure" {
                    destructive_terminal_without_evidence = true;
                }
                if destructive != 0 && receipt.is_some() {
                    let artifact_count: i64 = connection
                        .query_row(
                            "SELECT COUNT(*) FROM runtime_evidence_artifacts WHERE run_id = ?1",
                            params![run_id],
                            |row| row.get(0),
                        )
                        .map_err(sqlite_error)?;
                    destructive_terminal_without_evidence = artifact_count == 0;
                }
            }
        }
        let blocked = destructive_terminal_without_evidence;
        let failure_code = if blocked {
            Some("runtime_resume_destructive_repair_required".to_string())
        } else {
            None
        };
        let next_step_index = reusable_step_indices
            .last()
            .map(|last| last.saturating_add(1))
            .or(Some(0));
        let report = RuntimeRecoveryDrillReport {
            schema: CHIODOS_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            accepted: !blocked,
            failure_code: failure_code.clone(),
            generated_at_unix_ms: now_unix_ms,
            resumable: !blocked,
            blocked,
            next_step_index,
            reusable_step_indices,
            recovery_required_reason: failure_code,
            checks: vec!["runtime_ops.recovery_drill".to_string()],
        };
        validate_runtime_recovery_drill_report(&report)?;
        connection
            .execute(
                "INSERT OR REPLACE INTO runtime_recovery_drills (run_id, generated_at_unix_ms, accepted, failure_code) VALUES (?1, ?2, ?3, ?4)",
                params![
                    run_id,
                    sqlite_i64(now_unix_ms, "runtime recovery timestamp")?,
                    if report.accepted { 1_i64 } else { 0_i64 },
                    report.failure_code
                ],
            )
            .map_err(sqlite_error)?;
        Ok(report)
    }

    pub fn recovery_drill_report_for_profile(
        &self,
        profile: &RuntimeSupervisorProfile,
        run_id: &str,
        now_unix_ms: u64,
    ) -> Result<RuntimeRecoveryDrillReport, ChiodosRuntimeError> {
        validate_runtime_supervisor_profile(profile)?;
        validate_non_empty(run_id, "runtime_recovery_empty_run_id")?;
        if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
            let report = RuntimeRecoveryDrillReport {
                schema: CHIODOS_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA.to_string(),
                run_id: run_id.to_string(),
                accepted: false,
                failure_code: Some("runtime_recovery_supervisor_profile_stale".to_string()),
                generated_at_unix_ms: now_unix_ms,
                resumable: false,
                blocked: true,
                next_step_index: None,
                reusable_step_indices: Vec::new(),
                recovery_required_reason: Some(
                    "runtime_recovery_supervisor_profile_stale".to_string(),
                ),
                checks: vec!["runtime_ops.recovery_supervisor_profile_window".to_string()],
            };
            validate_runtime_recovery_drill_report(&report)?;
            return Ok(report);
        }
        self.recovery_drill_report(run_id, now_unix_ms)
    }

    pub fn ops_status_report(
        &self,
        profile: &RuntimeSupervisorProfile,
        now_unix_ms: u64,
        evidence_sink_healthy: bool,
        provider_healthy: bool,
    ) -> Result<RuntimeOpsStatusReport, ChiodosRuntimeError> {
        validate_runtime_supervisor_profile(profile)?;
        let connection = self.lock_connection()?;
        let profile_stale =
            now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms;
        let run_counts = runtime_run_counts(&connection)?;
        let consumed_lease_count = query_count(&connection, "runtime_consumed_leases")?;
        let active_lease_count = lease_count_by_state(&connection, "active")?;
        let stale_lease_count =
            stale_lease_count(&connection, now_unix_ms, profile.stale_run_after_ms)?;
        let latest_failure_code: Option<String> = connection
            .query_row(
                "SELECT failure_code FROM runtime_runs WHERE failure_code IS NOT NULL ORDER BY updated_at_unix_ms DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        let degraded = profile_stale
            || !evidence_sink_healthy
            || !provider_healthy
            || stale_lease_count > 0
            || latest_failure_code.is_some();
        let failure_code = if profile_stale {
            Some("runtime_ops_supervisor_profile_stale".to_string())
        } else if degraded {
            Some("runtime_ops_status_degraded".to_string())
        } else {
            None
        };
        let report = RuntimeOpsStatusReport {
            schema: CHIODOS_RUNTIME_OPS_STATUS_REPORT_SCHEMA.to_string(),
            accepted: !degraded,
            failure_code,
            generated_at_unix_ms: now_unix_ms,
            supervisor_profile_sha256: canonical_sha256(profile)?,
            run_counts,
            active_lease_count,
            stale_lease_count,
            consumed_lease_count,
            evidence_sink_healthy,
            provider_healthy,
            ready: !degraded,
            degraded,
            latest_failure_code,
            checks: vec!["runtime_ops.status_aggregated".to_string()],
        };
        validate_runtime_ops_status_report(&report)?;
        Ok(report)
    }
}

fn runtime_run_counts(
    connection: &Connection,
) -> Result<BTreeMap<String, u64>, ChiodosRuntimeError> {
    let mut run_counts = BTreeMap::new();
    let mut statement = connection
        .prepare("SELECT status, COUNT(*) FROM runtime_runs GROUP BY status")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(sqlite_error)?;
    for row in rows {
        let (status, count) = row.map_err(sqlite_error)?;
        run_counts.insert(status, sqlite_u64(count, "runtime run count")?);
    }
    Ok(run_counts)
}
