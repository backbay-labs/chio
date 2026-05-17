use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{sqlite_error, sqlite_i64, sqlite_u64, SqliteRuntimeOrchestrationStore};
use crate::schema::{
    CHIODOS_RUNTIME_RUN_LEASE_SCHEMA, CHIODOS_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA,
};
use crate::types::{RuntimeRunLease, RuntimeSchedulerTickReport, RuntimeSupervisorProfile};
use crate::validation::{
    validate_non_empty, validate_runtime_run_lease, validate_runtime_scheduler_tick_report,
    validate_runtime_supervisor_profile,
};
use crate::ChiodosRuntimeError;

impl SqliteRuntimeOrchestrationStore {
    pub fn acquire_run_lease(
        &self,
        run_id: &str,
        owner_id: &str,
        now_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<RuntimeRunLease, ChiodosRuntimeError> {
        validate_non_empty(run_id, "runtime_run_empty_id")?;
        validate_non_empty(owner_id, "runtime_run_lease_empty_owner")?;
        if ttl_ms == 0 {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_run_lease_invalid_ttl",
                detail: "runtime run lease ttl must be positive".to_string(),
            });
        }
        let now = sqlite_i64(now_unix_ms, "runtime run lease timestamp")?;
        let expires_at = sqlite_i64(
            now_unix_ms.saturating_add(ttl_ms),
            "runtime run lease expiry",
        )?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<(String, i64, i64, String)> = tx
            .query_row(
                "SELECT owner_id, expires_at_unix_ms, fencing_token, state FROM runtime_run_leases WHERE run_id = ?1",
                params![run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        let fencing_token =
            if let Some((_existing_owner, existing_expires, existing_token, state)) = existing {
                if state == "active" && existing_expires > now {
                    return Err(ChiodosRuntimeError::Rejected {
                        code: "runtime_run_lease_conflict",
                        detail: format!("runtime run {run_id} already has an active lease"),
                    });
                }
                sqlite_u64(existing_token, "runtime run lease fencing token")?.saturating_add(1)
            } else {
                1
            };
        let lease = RuntimeRunLease {
            schema: CHIODOS_RUNTIME_RUN_LEASE_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            lease_id: format!("{run_id}:{owner_id}:{fencing_token}"),
            owner_id: owner_id.to_string(),
            acquired_at_unix_ms: now_unix_ms,
            expires_at_unix_ms: now_unix_ms.saturating_add(ttl_ms),
            heartbeat_at_unix_ms: now_unix_ms,
            fencing_token,
            state: "active".to_string(),
            reason_code: None,
        };
        validate_runtime_run_lease(&lease)?;
        tx.execute(
            r#"
            INSERT INTO runtime_run_leases (
                run_id, lease_id, owner_id, acquired_at_unix_ms, expires_at_unix_ms,
                heartbeat_at_unix_ms, fencing_token, state, reason_code
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(run_id) DO UPDATE SET
                lease_id = excluded.lease_id,
                owner_id = excluded.owner_id,
                acquired_at_unix_ms = excluded.acquired_at_unix_ms,
                expires_at_unix_ms = excluded.expires_at_unix_ms,
                heartbeat_at_unix_ms = excluded.heartbeat_at_unix_ms,
                fencing_token = excluded.fencing_token,
                state = excluded.state,
                reason_code = excluded.reason_code
            "#,
            params![
                lease.run_id,
                lease.lease_id,
                lease.owner_id,
                now,
                expires_at,
                now,
                sqlite_i64(lease.fencing_token, "runtime run lease fencing token")?,
                lease.state,
                lease.reason_code
            ],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(lease)
    }

    pub fn heartbeat_run_lease(
        &self,
        run_id: &str,
        owner_id: &str,
        fencing_token: u64,
        now_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<RuntimeRunLease, ChiodosRuntimeError> {
        validate_non_empty(run_id, "runtime_run_empty_id")?;
        validate_non_empty(owner_id, "runtime_run_lease_empty_owner")?;
        let now = sqlite_i64(now_unix_ms, "runtime run lease heartbeat timestamp")?;
        let expires_at = sqlite_i64(
            now_unix_ms.saturating_add(ttl_ms),
            "runtime run lease heartbeat expiry",
        )?;
        let connection = self.lock_connection()?;
        let row: Option<(String, String, i64, i64, i64, String)> = connection
            .query_row(
                r#"
                SELECT lease_id, owner_id, acquired_at_unix_ms, expires_at_unix_ms,
                       fencing_token, state
                FROM runtime_run_leases
                WHERE run_id = ?1
                "#,
                params![run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let Some((lease_id, existing_owner, acquired_at, existing_expires, existing_token, state)) =
            row
        else {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_run_lease_missing",
                detail: format!("runtime run {run_id} has no lease"),
            });
        };
        if existing_owner != owner_id
            || sqlite_u64(existing_token, "runtime run lease fencing token")? != fencing_token
            || state != "active"
        {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_run_stale_fencing_token",
                detail: format!("runtime run {run_id} heartbeat used stale fencing token"),
            });
        }
        if existing_expires <= now {
            connection
                .execute(
                    "UPDATE runtime_run_leases SET state = 'expired', reason_code = 'runtime_run_lease_expired' WHERE run_id = ?1 AND state = 'active'",
                    params![run_id],
                )
                .map_err(sqlite_error)?;
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_run_lease_expired",
                detail: format!("runtime run {run_id} lease expired before heartbeat"),
            });
        }
        connection
            .execute(
                "UPDATE runtime_run_leases SET heartbeat_at_unix_ms = ?1, expires_at_unix_ms = ?2 WHERE run_id = ?3",
                params![now, expires_at, run_id],
            )
            .map_err(sqlite_error)?;
        let lease = RuntimeRunLease {
            schema: CHIODOS_RUNTIME_RUN_LEASE_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            lease_id,
            owner_id: owner_id.to_string(),
            acquired_at_unix_ms: sqlite_u64(acquired_at, "runtime run lease acquired timestamp")?,
            expires_at_unix_ms: now_unix_ms.saturating_add(ttl_ms),
            heartbeat_at_unix_ms: now_unix_ms,
            fencing_token,
            state,
            reason_code: None,
        };
        validate_runtime_run_lease(&lease)?;
        Ok(lease)
    }

    pub fn scheduler_tick_report(
        &self,
        profile: &RuntimeSupervisorProfile,
        owner_id: &str,
        now_unix_ms: u64,
        max_runs: u64,
    ) -> Result<RuntimeSchedulerTickReport, ChiodosRuntimeError> {
        validate_runtime_supervisor_profile(profile)?;
        validate_non_empty(owner_id, "runtime_scheduler_empty_owner")?;
        let mut claimed_run_ids = Vec::new();
        let mut expired_run_ids = Vec::new();
        let blocked_run_ids = Vec::new();
        let mut skipped_run_count = 0_u64;
        let mut accepted = true;
        let mut failure_code = None;
        if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
            accepted = false;
            failure_code = Some("runtime_scheduler_profile_stale".to_string());
        } else {
            let now = sqlite_i64(now_unix_ms, "runtime scheduler tick timestamp")?;
            let stale_before = sqlite_i64(
                now_unix_ms.saturating_sub(profile.stale_run_after_ms),
                "runtime scheduler stale heartbeat timestamp",
            )?;
            {
                let connection = self.lock_connection()?;
                let mut statement = connection
                    .prepare(
                        "SELECT run_id FROM runtime_run_leases WHERE state = 'active' AND (expires_at_unix_ms <= ?1 OR heartbeat_at_unix_ms <= ?2)",
                    )
                    .map_err(sqlite_error)?;
                let rows = statement
                    .query_map(params![now, stale_before], |row| row.get::<_, String>(0))
                    .map_err(sqlite_error)?;
                for row in rows {
                    expired_run_ids.push(row.map_err(sqlite_error)?);
                }
                connection
                    .execute(
                        "UPDATE runtime_run_leases SET state = 'expired', reason_code = 'runtime_run_lease_expired' WHERE state = 'active' AND (expires_at_unix_ms <= ?1 OR heartbeat_at_unix_ms <= ?2)",
                        params![now, stale_before],
                    )
                    .map_err(sqlite_error)?;
            }
            let active_lease_count = {
                let connection = self.lock_connection()?;
                active_nonterminal_lease_count(&connection)?
            };
            let claim_limit = max_runs
                .min(profile.max_concurrent_runs)
                .saturating_sub(active_lease_count);
            let pending_runs = self.pending_run_ids()?;
            skipped_run_count = pending_runs
                .len()
                .saturating_sub(usize::try_from(claim_limit).unwrap_or(usize::MAX))
                .try_into()
                .unwrap_or(u64::MAX);
            for run_id in pending_runs
                .into_iter()
                .take(usize::try_from(claim_limit).unwrap_or(usize::MAX))
            {
                match self.acquire_run_lease(
                    &run_id,
                    owner_id,
                    now_unix_ms,
                    profile.run_lease_ttl_ms,
                ) {
                    Ok(_) => claimed_run_ids.push(run_id),
                    Err(_) => skipped_run_count = skipped_run_count.saturating_add(1),
                }
            }
        }
        let tick_id = format!("{owner_id}:{now_unix_ms}");
        {
            let connection = self.lock_connection()?;
            connection
                .execute(
                    "INSERT OR REPLACE INTO runtime_scheduler_ticks (tick_id, owner_id, generated_at_unix_ms, claimed_count, blocked_count) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        tick_id,
                        owner_id,
                        sqlite_i64(now_unix_ms, "runtime scheduler tick timestamp")?,
                        sqlite_i64(u64::try_from(claimed_run_ids.len()).unwrap_or(u64::MAX), "runtime scheduler claimed count")?,
                        sqlite_i64(u64::try_from(blocked_run_ids.len()).unwrap_or(u64::MAX), "runtime scheduler blocked count")?
                    ],
                )
                .map_err(sqlite_error)?;
        }
        let report = RuntimeSchedulerTickReport {
            schema: CHIODOS_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA.to_string(),
            accepted,
            failure_code,
            tick_id,
            owner_id: owner_id.to_string(),
            generated_at_unix_ms: now_unix_ms,
            max_runs,
            claimed_run_ids,
            expired_run_ids,
            blocked_run_ids,
            skipped_run_count,
            checks: vec!["runtime_ops.scheduler_tick".to_string()],
        };
        validate_runtime_scheduler_tick_report(&report)?;
        Ok(report)
    }
}

pub(super) fn lease_count_by_state(
    connection: &Connection,
    state: &str,
) -> Result<u64, ChiodosRuntimeError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_run_leases WHERE state = ?1",
            params![state],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    sqlite_u64(count, "runtime lease count")
}

fn active_nonterminal_lease_count(connection: &Connection) -> Result<u64, ChiodosRuntimeError> {
    let count: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM runtime_run_leases leases
            LEFT JOIN runtime_runs runs ON runs.run_id = leases.run_id
            WHERE leases.state = 'active'
              AND (
                runs.status IS NULL
                OR runs.status NOT IN ('proof_accepted', 'terminal_failure', 'completed')
              )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    sqlite_u64(count, "runtime active nonterminal lease count")
}

pub(super) fn stale_lease_count(
    connection: &Connection,
    now_unix_ms: u64,
    stale_run_after_ms: u64,
) -> Result<u64, ChiodosRuntimeError> {
    let stale_before = now_unix_ms.saturating_sub(stale_run_after_ms);
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_run_leases WHERE state = 'active' AND (expires_at_unix_ms <= ?1 OR heartbeat_at_unix_ms <= ?2)",
            params![
                sqlite_i64(now_unix_ms, "runtime stale lease timestamp")?,
                sqlite_i64(stale_before, "runtime stale heartbeat timestamp")?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    sqlite_u64(count, "runtime stale lease count")
}
