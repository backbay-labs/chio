use super::traits::RuntimeAdmissionStore;
use crate::*;

pub struct SqliteRuntimeOrchestrationStore {
    path: PathBuf,
    connection: Mutex<Connection>,
}

impl SqliteRuntimeOrchestrationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChiodosRuntimeError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    ChiodosRuntimeError::Io(format!(
                        "failed to create runtime orchestration store directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }
        let connection = Connection::open(&path).map_err(sqlite_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(sqlite_error)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(sqlite_error)?;
        connection
            .busy_timeout(std::time::Duration::from_millis(5_000))
            .map_err(sqlite_error)?;
        let store = Self {
            path,
            connection: Mutex::new(connection),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), ChiodosRuntimeError> {
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

    fn migrate_evidence_artifacts_schema(
        connection: &Connection,
    ) -> Result<(), ChiodosRuntimeError> {
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

    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChiodosRuntimeError> {
        let bundle_sha256 = runtime_admission_bundle_sha256(&bundle)?;
        let raw_json = serde_json::to_string(&bundle)
            .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
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
            return Err(ChiodosRuntimeError::Rejected {
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

    pub fn record_evidence_artifact(
        &self,
        run_id: &str,
        entry: &RuntimeEvidenceManifestEntry,
        recorded_at_unix_ms: u64,
    ) -> Result<(), ChiodosRuntimeError> {
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

    pub fn insert_treaty_runtime_artifact<T: Serialize>(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
        artifact: &T,
    ) -> Result<(), ChiodosRuntimeError> {
        validate_state_label(evidence_kind, "runtime_treaty_artifact_invalid_kind")?;
        validate_non_empty(evidence_id, "runtime_treaty_artifact_empty_id")?;
        let artifact_sha256 = canonical_sha256(artifact)?;
        let raw_json = serde_json::to_string(artifact)
            .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT artifact_sha256 FROM runtime_treaty_artifacts WHERE evidence_kind = ?1 AND evidence_id = ?2",
                params![evidence_kind, evidence_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(existing) = existing {
            if existing == artifact_sha256 {
                tx.commit().map_err(sqlite_error)?;
                return Ok(());
            }
            return Err(ChiodosRuntimeError::Rejected {
                code: "duplicate_treaty_runtime_artifact_mismatch",
                detail: "runtime treaty artifact id already exists with a different hash"
                    .to_string(),
            });
        }
        tx.execute(
            r#"
            INSERT INTO runtime_treaty_artifacts (
                evidence_kind, evidence_id, artifact_sha256, raw_json, created_at_unix_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![evidence_kind, evidence_id, artifact_sha256, raw_json, 0_i64],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }

    pub fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChiodosRuntimeError> {
        validate_state_label(evidence_kind, "runtime_treaty_artifact_invalid_kind")?;
        validate_non_empty(evidence_id, "runtime_treaty_artifact_empty_id")?;
        let connection = self.lock_connection()?;
        let row = connection
            .query_row(
                r#"
                SELECT artifact_sha256, raw_json
                FROM runtime_treaty_artifacts
                WHERE evidence_kind = ?1 AND evidence_id = ?2
                "#,
                params![evidence_kind, evidence_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        row.map(|(artifact_sha256, raw_json)| {
            let raw_json = serde_json::from_str(&raw_json)
                .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
            Ok(TreatyRuntimeArtifactRecord {
                evidence_kind: evidence_kind.to_string(),
                evidence_id: evidence_id.to_string(),
                artifact_sha256,
                raw_json,
            })
        })
        .transpose()
    }

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
                lease_count_by_state(&connection, "active")?
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
                    "SELECT step_index, destructive, tool_receipt_sha256 FROM runtime_step_states WHERE run_id = ?1 ORDER BY step_index",
                )
                .map_err(sqlite_error)?;
            let rows = statement
                .query_map(params![run_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })
                .map_err(sqlite_error)?;
            for row in rows {
                let (index, destructive, receipt) = row.map_err(sqlite_error)?;
                let index = sqlite_u64(index, "runtime recovery step index")?;
                reusable_step_indices.push(index);
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

    fn pending_run_ids(&self) -> Result<Vec<String>, ChiodosRuntimeError> {
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

    fn lock_connection(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Connection>, ChiodosRuntimeError> {
        self.connection.lock().map_err(|_| {
            ChiodosRuntimeError::Store("runtime orchestration sqlite store is poisoned".to_string())
        })
    }
}

impl RuntimeAdmissionStore for SqliteRuntimeOrchestrationStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChiodosRuntimeError> {
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
                    .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
            })
            .transpose()
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChiodosRuntimeError> {
        SqliteRuntimeOrchestrationStore::treaty_runtime_artifact(self, evidence_kind, evidence_id)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO runtime_consumed_leases (lease_id, admission_id) VALUES (?1, ?2)",
                params![lease_id, admission_id],
            )
            .map_err(sqlite_error)?;
        if inserted == 0 {
            return Err(ChiodosRuntimeError::Rejected {
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
    ) -> Result<(), ChiodosRuntimeError> {
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
    ) -> Result<(), ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO runtime_consumed_treaty_continuations (continuation_id, admission_id) VALUES (?1, ?2)",
                params![continuation_id, admission_id],
            )
            .map_err(sqlite_error)?;
        if inserted == 0 {
            return Err(ChiodosRuntimeError::Rejected {
                code: "chiodos_treaty_continuation_replay",
                detail: format!("treaty continuation {continuation_id} was already consumed"),
            });
        }
        Ok(())
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        connection
            .execute(
                "DELETE FROM runtime_consumed_treaty_continuations WHERE continuation_id = ?1 AND admission_id = ?2",
                params![continuation_id, admission_id],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        let row: Option<(String, String, i64, String, String)> = connection
            .query_row(
                r#"
                SELECT verifier_id, key_id, highest_version, latest_bundle_sha256,
                       latest_revocation_checkpoint_sha256
                FROM runtime_trust_floors
                WHERE verifier_id = ?1 AND key_id = ?2
                "#,
                params![verifier_id, key_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        row.map(
            |(
                verifier_id,
                key_id,
                highest_version,
                latest_bundle_sha256,
                latest_revocation_checkpoint_sha256,
            )| {
                Ok(RuntimeTrustFloorEntry {
                    verifier_id,
                    key_id,
                    highest_version: sqlite_u64(highest_version, "runtime trust floor version")?,
                    latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256,
                })
            },
        )
        .transpose()
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        connection
            .execute(
                r#"
                INSERT INTO runtime_trust_floors (
                    verifier_id, key_id, highest_version, latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256
                )
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(verifier_id, key_id) DO UPDATE SET
                    highest_version = excluded.highest_version,
                    latest_bundle_sha256 = excluded.latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256 = excluded.latest_revocation_checkpoint_sha256
                "#,
                params![
                    entry.verifier_id,
                    entry.key_id,
                    sqlite_i64(entry.highest_version, "runtime trust floor version")?,
                    entry.latest_bundle_sha256,
                    entry.latest_revocation_checkpoint_sha256
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<(String, String, i64, String, String)> = tx
            .query_row(
                r#"
                SELECT verifier_id, key_id, highest_version, latest_bundle_sha256,
                       latest_revocation_checkpoint_sha256
                FROM runtime_trust_floors
                WHERE verifier_id = ?1 AND key_id = ?2
                "#,
                params![entry.verifier_id, entry.key_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let existing = existing
            .map(
                |(
                    verifier_id,
                    key_id,
                    highest_version,
                    latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256,
                )| {
                    Ok(RuntimeTrustFloorEntry {
                        verifier_id,
                        key_id,
                        highest_version: sqlite_u64(
                            highest_version,
                            "runtime trust floor version",
                        )?,
                        latest_bundle_sha256,
                        latest_revocation_checkpoint_sha256,
                    })
                },
            )
            .transpose()?;
        validate_runtime_trust_floor_transition(existing, &entry, previous_hash_sha256)?;
        tx.execute(
            r#"
            INSERT INTO runtime_trust_floors (
                verifier_id, key_id, highest_version, latest_bundle_sha256,
                latest_revocation_checkpoint_sha256
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(verifier_id, key_id) DO UPDATE SET
                highest_version = excluded.highest_version,
                latest_bundle_sha256 = excluded.latest_bundle_sha256,
                latest_revocation_checkpoint_sha256 = excluded.latest_revocation_checkpoint_sha256
            "#,
            params![
                entry.verifier_id,
                entry.key_id,
                sqlite_i64(entry.highest_version, "runtime trust floor version")?,
                entry.latest_bundle_sha256,
                entry.latest_revocation_checkpoint_sha256
            ],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
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

fn lease_count_by_state(connection: &Connection, state: &str) -> Result<u64, ChiodosRuntimeError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_run_leases WHERE state = ?1",
            params![state],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    sqlite_u64(count, "runtime lease count")
}

fn stale_lease_count(
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

fn sqlite_error(error: rusqlite::Error) -> ChiodosRuntimeError {
    ChiodosRuntimeError::Store(format!("runtime orchestration sqlite: {error}"))
}

fn sqlite_i64(value: u64, field: &str) -> Result<i64, ChiodosRuntimeError> {
    i64::try_from(value).map_err(|_| ChiodosRuntimeError::Rejected {
        code: "runtime_sqlite_integer_out_of_range",
        detail: format!("{field} does not fit sqlite i64"),
    })
}

fn sqlite_u64(value: i64, field: &str) -> Result<u64, ChiodosRuntimeError> {
    u64::try_from(value).map_err(|_| ChiodosRuntimeError::Rejected {
        code: "runtime_sqlite_integer_negative",
        detail: format!("{field} is negative"),
    })
}

fn query_count(connection: &Connection, table: &str) -> Result<u64, ChiodosRuntimeError> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let count: i64 = connection
        .query_row(&sql, [], |row| row.get(0))
        .map_err(sqlite_error)?;
    sqlite_u64(count, table)
}
