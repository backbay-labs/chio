use super::*;

pub(crate) fn receipt_checkpoint_report_error(
    report: &chio_kernel::ReceiptCheckpointStatusReport,
) -> CliError {
    CliError::cli_other_error(
        report
            .checkpoint_error
            .as_deref()
            .unwrap_or("receipt checkpoint verification failed")
            .to_string(),
    )
}

pub(crate) fn receipt_health_report_error(report: &chio_kernel::ReceiptStoreHealthReport) -> CliError {
    CliError::cli_other_error(
        report
            .checkpoint_error
            .as_deref()
            .unwrap_or("receipt store health check failed")
            .to_string(),
    )
}

pub(crate) fn local_receipt_store(
    backend: &QueryBackend<'_>,
    command_name: &str,
) -> Result<chio_store_sqlite::SqliteReceiptStore, CliError> {
    if backend.control_url.is_some() {
        return Err(CliError::cli_other_error(format!(
            "{command_name} requires local --receipt-db; remote receipt operator operations are not supported in this release"
        )));
    }
    let path = backend.receipt_db_path.ok_or_else(|| {
        CliError::cli_other_error(format!("{command_name} requires --receipt-db <path>"))
    })?;
    if !path.is_file() {
        return Err(CliError::cli_other_error(format!(
            "{command_name} requires an existing --receipt-db <path>: {}",
            path.display()
        )));
    }
    chio_store_sqlite::SqliteReceiptStore::open_existing(path).map_err(CliError::from)
}

pub(crate) fn load_existing_kernel_checkpoint_keypair(path: &Path) -> Result<chio_core::Keypair, CliError> {
    let seed_hex = std::fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CliError::cli_other_error(format!(
                "receipt checkpoint create requires an existing kernel seed file: {}",
                path.display()
            ))
        } else {
            CliError::Io(error)
        }
    })?;
    chio_core::Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
}

pub(crate) fn cmd_receipt_health(backend: QueryBackend<'_>) -> Result<(), CliError> {
    let store = local_receipt_store(&backend, "receipt health")?;
    let report = store.receipt_store_health()?;
    if backend.json_output {
        print_receipt_operator_json(CHIO_CLI_RECEIPT_HEALTH_SCHEMA, &report)?;
    } else {
        print!("{}", render_receipt_health_human(&report));
    }
    if report.healthy {
        Ok(())
    } else {
        Err(receipt_health_report_error(&report))
    }
}

pub(crate) fn cmd_receipt_flush(
    timeout_ms: u64,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let store = local_receipt_store(&backend, "receipt flush")?;
    let report =
        store.flush_receipt_writes_with_timeout(std::time::Duration::from_millis(timeout_ms))?;
    if backend.json_output {
        print_receipt_operator_json(CHIO_CLI_RECEIPT_FLUSH_SCHEMA, &report)?;
    } else {
        print!("{}", render_receipt_flush_human(&report));
    }
    Ok(())
}

pub(crate) fn cmd_receipt_checkpoint_status(
    max_batch: u64,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let store = local_receipt_store(&backend, "receipt checkpoint status")?;
    let report = store.receipt_checkpoint_status(Some(max_batch))?;
    if backend.json_output {
        print_receipt_operator_json(CHIO_CLI_RECEIPT_CHECKPOINT_STATUS_SCHEMA, &report)?;
    } else {
        print!("{}", render_receipt_checkpoint_status_human(&report));
    }
    if report.healthy {
        Ok(())
    } else {
        Err(receipt_checkpoint_report_error(&report))
    }
}

pub(crate) fn cmd_receipt_checkpoint_create(
    kernel_seed_file: &Path,
    max_batch: u64,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let store = local_receipt_store(&backend, "receipt checkpoint create")?;
    let keypair = load_existing_kernel_checkpoint_keypair(kernel_seed_file)?;
    let report = store.create_next_receipt_checkpoint(max_batch, &keypair)?;
    if backend.json_output {
        print_receipt_operator_json(CHIO_CLI_RECEIPT_CHECKPOINT_CREATE_SCHEMA, &report)?;
    } else {
        print!("{}", render_receipt_checkpoint_create_human(&report));
    }
    Ok(())
}

/// Retained as a documented compatibility alias for `chio receipt audit`
/// (read-only: never passes `--repair`). Keeps emitting the legacy
/// `CHIO_CLI_RECEIPT_CHECKPOINT_VERIFY_SCHEMA` envelope so existing
/// automation parsing that schema does not break.
pub(crate) fn cmd_receipt_checkpoint_verify(backend: QueryBackend<'_>) -> Result<(), CliError> {
    receipt_audit_with_schema(false, CHIO_CLI_RECEIPT_CHECKPOINT_VERIFY_SCHEMA, backend)
}

/// `chio receipt audit [--repair]`: the promoted full-verification surface
/// (rollout step 3). Runs validate_claim_receipt_log_entries plus a
/// complete checkpoint-chain verification via receipt_checkpoint_status.
///
/// `--repair` is an OFFLINE operation. It opens a
/// LOCAL throwaway store and revalidates/reseeds the ON-DISK state on that
/// connection. The CLI runs in a separate process from a live kernel and cannot
/// reach that kernel's in-memory writer head, so `--repair` does NOT clear a
/// live poisoned writer. Run it with the kernel stopped and restart the kernel
/// to seed a clean verified head from the validated on-disk state.
pub(crate) fn cmd_receipt_audit(repair: bool, backend: QueryBackend<'_>) -> Result<(), CliError> {
    receipt_audit_with_schema(repair, CHIO_CLI_RECEIPT_AUDIT_SCHEMA, backend)
}

/// Honest, cross-process description of what `chio receipt audit --repair`
/// actually does: it validates the on-disk receipt
/// state OFFLINE and cannot reseed a running kernel's in-memory writer head.
/// Kept as a pure function so the wording is unit-testable.
pub(crate) fn offline_repair_notice() -> &'static str {
    "receipt audit --repair ran OFFLINE: the on-disk receipt state was revalidated on a local \
     connection. A running kernel keeps its verified head in-memory in a separate process the CLI \
     cannot reach, so a live poisoned writer was NOT reseeded. Run this with the kernel stopped, \
     then restart the kernel to seed a clean verified head from the validated on-disk state."
}

/// `chio receipt retention repair --archive <path>`: the operator recovery
/// path for a store whose claim-log projection rows survived a source-row
/// delete. Opens via `local_receipt_store` (which uses `open_existing`,
/// skipping backfill), so the recovery tool itself never bricks trying to
/// diagnose a bricked store.
pub(crate) fn cmd_receipt_retention_repair(
    archive: &Path,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let archive = archive
        .to_str()
        .ok_or_else(|| CliError::cli_other_error("archive path is not valid utf-8".to_string()))?;
    let store = local_receipt_store(&backend, "receipt retention repair")?;
    let removed = store.retention_repair(archive)?;
    if backend.json_output {
        // `retention_repair` returns Ok as soon as the extra rows are removed,
        // but on a mixed-drift store the follow-up head reseed leaves the head
        // poisoned (the next append is still rejected). Automation reads only the
        // JSON, so it must carry the ACTUAL post-repair writability, not just the
        // removed count, and the command must fail-closed when the store is still
        // not writable. A health error or an unhealthy report both mean the drift
        // survived the extra-shape repair.
        let health = store.receipt_store_health();
        let writable = matches!(&health, Ok(report) if report.healthy);
        print_receipt_operator_json(
            CHIO_CLI_RECEIPT_RETENTION_REPAIR_SCHEMA,
            &serde_json::json!({
                "removed_extra_claim_log_rows": removed,
                "writable": writable,
            }),
        )?;
        if !writable {
            return Err(match health {
                Ok(report) => receipt_health_report_error(&report),
                Err(error) => CliError::from(error),
            });
        }
    } else {
        // `retention_repair` returns Ok as soon as the extra rows are removed,
        // but on a mixed-drift store the follow-up head reseed leaves the head
        // poisoned (the next append is still rejected). Ask the store for its
        // real post-repair state and only claim it is writable when a health
        // check confirms it, fail-closed: an unhealthy report or a health error
        // both mean the drift survived the extra-shape repair. The default human
        // mode must then EXIT non-zero exactly as the JSON branch does, so an
        // operator is never told a repair that left the store unwritable
        // succeeded.
        let health = store.receipt_store_health();
        let writable = matches!(&health, Ok(report) if report.healthy);
        print!("{}", render_receipt_retention_repair_human(removed, writable));
        if !writable {
            return Err(match health {
                Ok(report) => receipt_health_report_error(&report),
                Err(error) => CliError::from(error),
            });
        }
    }
    Ok(())
}

fn receipt_audit_with_schema(
    repair: bool,
    schema: &'static str,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let store = local_receipt_store(&backend, "receipt audit")?;
    if repair {
        // Revalidate + reseed the ON-DISK state on this throwaway local store.
        // This validates the persisted chain (fail-closed) but cannot reach a
        // live kernel's in-memory writer head; see `offline_repair_notice`.
        store.reseed_verified_head()?;
    }
    let report = store.receipt_checkpoint_status(Some(1))?;
    if backend.json_output {
        print_receipt_operator_json(schema, &report)?;
        // Keep stdout pure JSON; surface the honest offline-repair note on stderr.
        if repair {
            eprintln!("{}", offline_repair_notice());
        }
    } else {
        print!("{}", render_receipt_checkpoint_status_human(&report));
        if repair {
            println!("{}", offline_repair_notice());
        }
    }
    if report.healthy {
        Ok(())
    } else {
        Err(receipt_checkpoint_report_error(&report))
    }
}

#[cfg(test)]
mod receipt_operator_tests {
    use super::*;
    use chio_kernel::ReceiptStore;

    fn unique_temp_path(name: &str, suffix: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("chio-{name}-{}-{stamp}.{suffix}", std::process::id()))
    }

    fn operator_sample_receipt() -> Result<chio_core::receipt::body::ChioReceipt, chio_core::Error> {
        let keypair = chio_core::crypto::Keypair::generate();
        operator_sample_receipt_with_keypair(&keypair)
    }

    fn operator_sample_receipt_with_keypair(
        keypair: &chio_core::crypto::Keypair,
    ) -> Result<chio_core::receipt::body::ChioReceipt, chio_core::Error> {
        operator_sample_receipt_with_id_and_keypair("receipt-operator-1", keypair)
    }

    fn operator_sample_receipt_with_id_and_keypair(
        id: &str,
        keypair: &chio_core::crypto::Keypair,
    ) -> Result<chio_core::receipt::body::ChioReceipt, chio_core::Error> {
        chio_core::receipt::body::ChioReceipt::sign(
            chio_core::receipt::body::ChioReceiptBody {
                id: id.to_string(),
                timestamp: 1_775_137_626,
                capability_id: "cap-operator-1".to_string(),
                tool_server: "operator".to_string(),
                tool_name: "flush".to_string(),
                action: chio_core::receipt::decision::ToolCallAction::from_parameters(
                    serde_json::json!({"operation":"flush"}),
                )?,
                decision: Some(chio_core::receipt::decision::Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content-operator-1".to_string(),
                policy_hash: "policy-operator-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            keypair,
        )
    }

    fn backend<'a>(
        receipt_db_path: Option<&'a Path>,
        control_url: Option<&'a str>,
    ) -> QueryBackend<'a> {
        QueryBackend {
            json_output: true,
            receipt_db_path,
            control_url,
            control_token: None,
        }
    }

    #[test]
    fn receipt_operator_json_envelope_includes_schema_and_null_fields() -> Result<(), CliError> {
        let health = chio_kernel::ReceiptStoreHealthReport {
            healthy: true,
            ..chio_kernel::ReceiptStoreHealthReport::default()
        };
        let flush = chio_kernel::ReceiptFlushReport::default();
        let status = chio_kernel::ReceiptCheckpointStatusReport {
            healthy: true,
            ..chio_kernel::ReceiptCheckpointStatusReport::default()
        };
        let create = chio_kernel::ReceiptCheckpointCreateReport::default();

        for (schema, report) in [
            (
                CHIO_CLI_RECEIPT_HEALTH_SCHEMA,
                receipt_operator_json_value(CHIO_CLI_RECEIPT_HEALTH_SCHEMA, &health)?,
            ),
            (
                CHIO_CLI_RECEIPT_FLUSH_SCHEMA,
                receipt_operator_json_value(CHIO_CLI_RECEIPT_FLUSH_SCHEMA, &flush)?,
            ),
            (
                CHIO_CLI_RECEIPT_CHECKPOINT_STATUS_SCHEMA,
                receipt_operator_json_value(CHIO_CLI_RECEIPT_CHECKPOINT_STATUS_SCHEMA, &status)?,
            ),
            (
                CHIO_CLI_RECEIPT_CHECKPOINT_CREATE_SCHEMA,
                receipt_operator_json_value(CHIO_CLI_RECEIPT_CHECKPOINT_CREATE_SCHEMA, &create)?,
            ),
            (
                CHIO_CLI_RECEIPT_CHECKPOINT_VERIFY_SCHEMA,
                receipt_operator_json_value(CHIO_CLI_RECEIPT_CHECKPOINT_VERIFY_SCHEMA, &status)?,
            ),
        ] {
            assert_eq!(report["schema"].as_str(), Some(schema));
        }

        let value = receipt_operator_json_value(CHIO_CLI_RECEIPT_HEALTH_SCHEMA, &health)?;
        assert!(value["report"]["latestCheckpointSeq"].is_null());
        assert!(value["report"]["uncheckpointedStartSeq"].is_null());
        assert!(value["report"]["writer"]["lastError"].is_null());

        let create_value =
            receipt_operator_json_value(CHIO_CLI_RECEIPT_CHECKPOINT_CREATE_SCHEMA, &create)?;
        assert!(create_value["report"]["checkpointSeq"].is_null());
        assert!(create_value["report"]["batchStartSeq"].is_null());
        Ok(())
    }

    /// The retention-repair human output must reflect the ACTUAL post-repair
    /// writability: only the writable branch may claim the store is writable; a
    /// mixed-drift store (extras removed, head still poisoned) must report the
    /// surviving drift fail-closed. The removed count stays accurate either way.
    #[test]
    fn retention_repair_human_output_reflects_actual_writability() {
        let writable = render_receipt_retention_repair_human(3, true);
        assert!(writable.contains("removed 3 extra claim-log row(s)"));
        assert!(writable.contains("store is writable"));
        assert!(!writable.contains("not writable"));

        let not_writable = render_receipt_retention_repair_human(3, false);
        assert!(not_writable.contains("removed 3 extra claim-log row(s)"));
        assert!(not_writable.contains("not writable"));
        assert!(not_writable.contains("further recovery is required"));
    }

    /// `chio receipt retention repair --json` must fail closed and surface the
    /// post-repair writability, not just the removed-row count: on a store that
    /// stays not writable after the repair, automation reading only the JSON has
    /// to see a non-zero exit rather than a silent success.
    #[test]
    fn retention_repair_json_fails_closed_when_store_not_writable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_temp_path("retention-repair-json", "sqlite3");
        let archive = unique_temp_path("retention-repair-json-archive", "sqlite3");
        let keypair = chio_core::crypto::Keypair::generate();

        // Build a store, then corrupt it into a state that health rejects but
        // retention repair cannot fix: delete a projection row whose source
        // receipt still exists (source-without-projection drift). No rows are
        // orphaned, so `retention_repair` returns Ok(0) while the store stays not
        // writable.
        {
            let store = chio_store_sqlite::SqliteReceiptStore::open(&path)?;
            for i in 0..2u64 {
                let receipt =
                    operator_sample_receipt_with_id_and_keypair(&format!("rr-json-{i}"), &keypair)?;
                store.append_chio_receipt_returning_seq(&receipt)?;
            }
            store.flush_receipt_writes()?;
        }
        {
            let connection = rusqlite::Connection::open(&path)?;
            connection.execute_batch(
                "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                 DELETE FROM claim_receipt_log_entries WHERE entry_seq = 1;",
            )?;
        }

        // Precondition: the corrupted store is genuinely not writable.
        let store = chio_store_sqlite::SqliteReceiptStore::open_existing(&path)?;
        assert!(
            !matches!(store.receipt_store_health(), Ok(report) if report.healthy),
            "the corrupted store must report not-writable"
        );
        drop(store);

        // JSON mode must fail closed, matching the human path.
        let result = cmd_receipt_retention_repair(&archive, backend(Some(&path), None));
        assert!(
            result.is_err(),
            "json retention repair must fail closed on a not-writable store"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&archive);
        Ok(())
    }

    /// `chio receipt retention repair` in the DEFAULT human mode (no `--json`)
    /// must fail closed too: on a store left not writable after the repair, an
    /// operator gets a non-zero exit rather than a silent success. Mirrors the
    /// JSON fail-closed contract on the path most operators actually run.
    #[test]
    fn retention_repair_human_fails_closed_when_store_not_writable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_temp_path("retention-repair-human", "sqlite3");
        let archive = unique_temp_path("retention-repair-human-archive", "sqlite3");
        let keypair = chio_core::crypto::Keypair::generate();

        // Source-without-projection drift: delete a projection row whose source
        // receipt still exists. No rows are orphaned, so `retention_repair`
        // returns Ok(0) while the store stays not writable.
        {
            let store = chio_store_sqlite::SqliteReceiptStore::open(&path)?;
            for i in 0..2u64 {
                let receipt = operator_sample_receipt_with_id_and_keypair(
                    &format!("rr-human-{i}"),
                    &keypair,
                )?;
                store.append_chio_receipt_returning_seq(&receipt)?;
            }
            store.flush_receipt_writes()?;
        }
        {
            let connection = rusqlite::Connection::open(&path)?;
            connection.execute_batch(
                "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
                 DELETE FROM claim_receipt_log_entries WHERE entry_seq = 1;",
            )?;
        }

        // Precondition: the corrupted store is genuinely not writable.
        let store = chio_store_sqlite::SqliteReceiptStore::open_existing(&path)?;
        assert!(
            !matches!(store.receipt_store_health(), Ok(report) if report.healthy),
            "the corrupted store must report not-writable"
        );
        drop(store);

        // Human mode must fail closed, matching the JSON path.
        let human_backend = QueryBackend {
            json_output: false,
            receipt_db_path: Some(path.as_path()),
            control_url: None,
            control_token: None,
        };
        let result = cmd_receipt_retention_repair(&archive, human_backend);
        assert!(
            result.is_err(),
            "human retention repair must fail closed on a not-writable store"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&archive);
        Ok(())
    }

    #[test]
    fn receipt_operator_human_output_includes_operational_fields() {
        let counters = chio_kernel::ReceiptWriterCounters {
            accepted_total: 10,
            committed_total: 9,
            failed_total: 1,
            saturated_total: 2,
            inflight: 3,
            queue_depth: 2,
            last_commit_unix_ms: Some(1234),
            first_accept_unix_ms: Some(1000),
            last_error: Some("writer lag".to_string()),
        };
        let health = chio_kernel::ReceiptStoreHealthReport {
            healthy: false,
            writer: counters.clone(),
            writer_liveness: "wedged".to_string(),
            latest_committed_entry_seq: 12,
            latest_checkpoint_seq: Some(2),
            latest_checkpointed_entry_seq: 8,
            uncheckpointed_start_seq: Some(9),
            uncheckpointed_end_seq: Some(12),
            checkpoint_error: Some("projection drift".to_string()),
            db_size_bytes: Some(4096),
            retention_watermark_entry_seq: Some(6),
            retention_error: Some("archive path is unwritable".to_string()),
        };
        let health_output = render_receipt_health_human(&health);
        assert!(health_output.contains("checkpoint_seq: 2"));
        assert!(health_output.contains("uncheckpointed_range: 9..=12"));
        assert!(health_output.contains("writer_accepted_total: 10"));
        assert!(health_output.contains("writer_saturated_total: 2"));
        assert!(health_output.contains("db_size_bytes: 4096"));
        assert!(health_output.contains("checkpoint_error: projection drift"));
        assert!(health_output.contains("writer_last_error: writer lag"));
        assert!(health_output.contains("retention_error: archive path is unwritable"));

        let flush = chio_kernel::ReceiptFlushReport {
            writer: counters,
            latest_committed_entry_seq: 12,
            latest_checkpoint_seq: Some(2),
            latest_checkpointed_entry_seq: 8,
            uncheckpointed_start_seq: Some(9),
            uncheckpointed_end_seq: Some(12),
            wal_checkpoint: Some(chio_kernel::ReceiptWalCheckpointReport {
                busy: 0,
                log_frames: 7,
                checkpointed_frames: 6,
            }),
            db_size_bytes: Some(4096),
        };
        let flush_output = render_receipt_flush_human(&flush);
        assert!(flush_output.contains("wal_checkpoint_log_frames: 7"));
        assert!(flush_output.contains("wal_checkpoint_checkpointed_frames: 6"));

        let create = chio_kernel::ReceiptCheckpointCreateReport {
            created: true,
            checkpoint_seq: Some(3),
            batch_start_seq: Some(9),
            batch_end_seq: Some(12),
            latest_committed_entry_seq: 12,
            latest_checkpointed_entry_seq: 12,
        };
        let create_output = render_receipt_checkpoint_create_human(&create);
        assert!(create_output.contains("checkpoint_seq: 3"));
        assert!(create_output.contains("checkpoint_range: 9..=12"));
    }

    /// The retention watermark must be visible in the DEFAULT (non-JSON) health
    /// and checkpoint-status output, not only in the JSON payload, so operators
    /// on the plain CLI can see committed progress floored by an archived prefix.
    #[test]
    fn receipt_human_output_surfaces_retention_watermark() {
        let health = chio_kernel::ReceiptStoreHealthReport {
            healthy: true,
            retention_watermark_entry_seq: Some(42),
            ..chio_kernel::ReceiptStoreHealthReport::default()
        };
        assert!(
            render_receipt_health_human(&health).contains("retention_watermark_entry_seq: 42"),
            "health human output must surface the retention watermark"
        );

        let status = chio_kernel::ReceiptCheckpointStatusReport {
            healthy: true,
            retention_watermark_entry_seq: Some(42),
            ..chio_kernel::ReceiptCheckpointStatusReport::default()
        };
        assert!(
            render_receipt_checkpoint_status_human(&status)
                .contains("retention_watermark_entry_seq: 42"),
            "checkpoint status human output must surface the retention watermark"
        );

        // A never-archived store renders `none` rather than omitting the field.
        let never = chio_kernel::ReceiptStoreHealthReport::default();
        assert!(
            render_receipt_health_human(&never).contains("retention_watermark_entry_seq: none")
        );
    }

    fn assert_remote_unsupported(result: Result<(), CliError>) {
        let error = match result {
            Ok(()) => panic!("remote receipt operator command should be deferred"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("requires local --receipt-db; remote receipt operator operations are not supported in this release"));
        assert!(!error.to_string().contains("requires --receipt-db"));
    }

    #[test]
    fn receipt_operator_commands_reject_remote_control_backend_first() {
        let error = match local_receipt_store(
            &backend(None, Some("http://127.0.0.1:9977")),
            "receipt flush",
        ) {
            Ok(_) => panic!("remote receipt flush should be deferred"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("requires local --receipt-db; remote receipt operator operations are not supported in this release"));
        assert!(!error.to_string().contains("requires --receipt-db"));
    }

    #[test]
    fn receipt_operator_entrypoints_reject_remote_control_backend_first() {
        let control_url = Some("http://127.0.0.1:9977");

        assert_remote_unsupported(cmd_receipt_health(backend(None, control_url)));
        assert_remote_unsupported(cmd_receipt_flush(5000, backend(None, control_url)));
        assert_remote_unsupported(cmd_receipt_checkpoint_status(
            1000,
            backend(None, control_url),
        ));
        assert_remote_unsupported(cmd_receipt_checkpoint_create(
            Path::new("kernel.seed"),
            1000,
            backend(None, control_url),
        ));
        assert_remote_unsupported(cmd_receipt_checkpoint_verify(backend(None, control_url)));
    }

    #[test]
    fn receipt_operator_entrypoints_work_against_local_temp_db(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let db_path = unique_temp_path("receipt-operator", "sqlite3");
        let seed_path = unique_temp_path("receipt-operator-kernel", "seed");
        let keypair = chio_core::crypto::Keypair::generate();
        let store = chio_store_sqlite::SqliteReceiptStore::open(&db_path)?;
        store.append_chio_receipt(&operator_sample_receipt_with_keypair(&keypair)?)?;
        drop(store);
        std::fs::write(&seed_path, keypair.seed_hex())?;

        cmd_receipt_health(backend(Some(&db_path), None))?;
        cmd_receipt_flush(5000, backend(Some(&db_path), None))?;
        cmd_receipt_checkpoint_status(10, backend(Some(&db_path), None))?;
        cmd_receipt_checkpoint_create(&seed_path, 10, backend(Some(&db_path), None))?;
        cmd_receipt_checkpoint_verify(backend(Some(&db_path), None))?;

        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(seed_path);
        Ok(())
    }

    #[test]
    fn receipt_operator_commands_require_local_receipt_db() {
        let error = match local_receipt_store(&backend(None, None), "receipt health") {
            Ok(_) => panic!("local receipt health should require a database"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("receipt health requires --receipt-db <path>"));
    }

    #[test]
    fn receipt_operator_commands_reject_missing_receipt_db_path() {
        let db_path = unique_temp_path("receipt-missing", "sqlite3");
        let error = match local_receipt_store(&backend(Some(&db_path), None), "receipt health") {
            Ok(_) => panic!("missing receipt database must not be created"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("receipt health requires an existing --receipt-db"));
        assert!(
            !db_path.exists(),
            "receipt operator command must not create a missing database"
        );
    }

    #[test]
    fn receipt_operator_commands_reject_touched_empty_receipt_db_file() -> Result<(), CliError> {
        let db_path = unique_temp_path("receipt-empty", "sqlite3");
        std::fs::write(&db_path, "")?;

        let error = match local_receipt_store(&backend(Some(&db_path), None), "receipt health") {
            Ok(_) => panic!("empty receipt database file must not be initialized"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("not an initialized Chio receipt store"),
            "unexpected error: {error}"
        );
        assert!(
            db_path.is_file(),
            "receipt operator command should refuse, not remove, an empty database file"
        );

        let _ = std::fs::remove_file(db_path);
        Ok(())
    }

    #[test]
    fn receipt_checkpoint_create_requires_existing_kernel_seed() -> Result<(), CliError> {
        let db_path = unique_temp_path("receipt-checkpoint-seed", "sqlite3");
        let seed_path = unique_temp_path("receipt-checkpoint-missing-seed", "seed");
        let store = chio_store_sqlite::SqliteReceiptStore::open(&db_path)?;
        store.append_chio_receipt(&operator_sample_receipt()?)?;
        drop(store);

        let error = match cmd_receipt_checkpoint_create(&seed_path, 10, backend(Some(&db_path), None))
        {
            Ok(_) => panic!("checkpoint create must not generate a missing seed"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("receipt checkpoint create requires an existing kernel seed file"),
            "unexpected error: {error}"
        );
        assert!(
            !seed_path.exists(),
            "checkpoint create must not create a new kernel seed"
        );

        let _ = std::fs::remove_file(db_path);
        Ok(())
    }

    #[test]
    fn receipt_audit_runs_full_verification_and_repair_reseeds(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let db_path = unique_temp_path("receipt-audit", "sqlite3");
        let keypair = chio_core::crypto::Keypair::generate();
        let store = chio_store_sqlite::SqliteReceiptStore::open(&db_path)?;
        store.append_chio_receipt(&operator_sample_receipt_with_keypair(&keypair)?)?;
        store.flush_receipt_writes()?;
        drop(store);

        cmd_receipt_audit(false, backend(Some(&db_path), None))?;
        cmd_receipt_audit(true, backend(Some(&db_path), None))?;

        assert_remote_unsupported(cmd_receipt_audit(false, backend(None, Some("http://127.0.0.1:9977"))));

        let _ = std::fs::remove_file(db_path);
        Ok(())
    }

    /// `chio receipt audit` (no `--repair`) is the read-only surface: it must
    /// return `Err` on an unhealthy report, carrying the divergence detail in
    /// the error string, rather than reporting success on a diverged store.
    #[test]
    fn receipt_audit_without_repair_fails_closed_on_a_diverged_checkpoint(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let db_path = unique_temp_path("receipt-audit-unhealthy", "sqlite3");
        let keypair = chio_core::crypto::Keypair::generate();
        let store = chio_store_sqlite::SqliteReceiptStore::open(&db_path)?;
        store.append_chio_receipt(&operator_sample_receipt_with_keypair(&keypair)?)?;
        store.flush_receipt_writes()?;
        store.create_next_receipt_checkpoint(10, &keypair)?;
        drop(store);

        // Tamper the persisted checkpoint out of band, same mechanics as the
        // store-side reseed fixtures (drop the immutability trigger, then
        // mutate a real body field so it no longer matches the batch_end_seq
        // column recorded alongside it).
        let connection = rusqlite::Connection::open(&db_path)?;
        connection.execute_batch("DROP TRIGGER IF EXISTS kernel_checkpoints_reject_update;")?;
        connection.execute(
            "UPDATE kernel_checkpoints SET statement_json = replace(statement_json, '\"batch_end_seq\":1', '\"batch_end_seq\":0')",
            [],
        )?;
        drop(connection);

        let error = match cmd_receipt_audit(false, backend(Some(&db_path), None)) {
            Ok(()) => panic!(
                "receipt audit without --repair must fail closed on a diverged checkpoint"
            ),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("batch_end_seq") && message.contains("checkpoint"),
            "receipt audit error must carry the divergence detail, got: {message}"
        );

        let _ = std::fs::remove_file(db_path);
        Ok(())
    }

    /// `chio receipt audit --repair` cannot reach a
    /// running kernel's in-memory writer head (a separate process), so its
    /// operator-facing wording must be honest about being an OFFLINE on-disk
    /// operation and must instruct restarting the kernel to clear a live poison
    /// rather than claim to have reseeded the live writer.
    #[test]
    fn receipt_audit_repair_notice_is_offline_honest() {
        let notice = offline_repair_notice();
        assert!(
            notice.contains("OFFLINE"),
            "repair notice must state it is offline: {notice}"
        );
        assert!(
            notice.contains("restart the kernel"),
            "repair notice must instruct restarting the kernel: {notice}"
        );
        assert!(
            notice.contains("NOT reseeded") && notice.contains("cannot reach"),
            "repair notice must be explicit that a live writer was not reseeded: {notice}"
        );
    }
}
