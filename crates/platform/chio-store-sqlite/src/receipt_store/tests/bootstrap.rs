use super::super::*;
use super::support::*;

#[test]
fn sqlite_receipt_store_persists_across_reopen() {
    let path = unique_db_path("chio-receipts");
    {
        let store = SqliteReceiptStore::open(&path).test_unwrap();
        store.append_chio_receipt(&sample_receipt()).test_unwrap();
        store
            .append_child_receipt(&sample_child_receipt())
            .test_unwrap();
        assert_eq!(store.tool_receipt_count().test_unwrap(), 1);
        assert_eq!(store.child_receipt_count().test_unwrap(), 1);
    }

    let reopened = SqliteReceiptStore::open(&path).test_unwrap();
    assert_eq!(reopened.tool_receipt_count().test_unwrap(), 1);
    assert_eq!(reopened.child_receipt_count().test_unwrap(), 1);

    let _ = fs::remove_file(path);
}

#[cfg(feature = "pq")]
#[test]
fn receipt_verify_accepts_hybrid_receipts_for_persistence() {
    let path = unique_db_path("chio-receipts-hybrid");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let tool_seq = store
        .append_chio_receipt_returning_seq(&sample_hybrid_receipt())
        .test_unwrap();
    let child_seq = store
        .append_child_receipt_record(&sample_hybrid_child_receipt())
        .test_unwrap();

    assert_eq!(tool_seq, 1);
    assert_eq!(child_seq, 2);
    assert_eq!(store.tool_receipt_count().test_unwrap(), 1);
    assert_eq!(store.child_receipt_count().test_unwrap(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn request_lineage_record_persistence_rejects_unsupported_schema() {
    let path = unique_db_path("chio-request-lineage-schema");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let mut lineage_json = request_lineage_json("req-schema", "anchor-schema", None);
    lineage_json["schema"] = serde_json::Value::String("chio.request_lineage.v1".to_string());

    let result = store.record_request_lineage_record(
        "sess-schema",
        "req-schema",
        None,
        Some("anchor-schema"),
        1_710_000_000,
        Some("req-schema-fingerprint"),
        &lineage_json,
    );

    let error = match result {
        Ok(()) => panic!("unsupported request lineage schema should fail"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("unsupported request lineage record schema"));

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_receipt_store_configures_durable_pragmas() {
    let path = unique_db_path("chio-receipts-pragmas");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let connection = store.connection().test_unwrap();

    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .test_unwrap();
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .test_unwrap();
    let busy_timeout: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .test_unwrap();
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .test_unwrap();

    assert!(journal_mode.eq_ignore_ascii_case("wal"));
    assert_eq!(synchronous, 2);
    assert!(busy_timeout >= 5000);
    assert_eq!(foreign_keys, 1);

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_receipt_store_stamps_application_id_and_refuses_future_database() {
    let path = unique_db_path("chio-receipts-schema-stamp");

    // A fresh open stamps the Chio application_id and leaves the database-wide
    // user_version untouched: the schema revision lives in keyed metadata so
    // co-located stores can version independently.
    {
        let store = SqliteReceiptStore::open(&path).test_unwrap();
        let connection = store.connection().test_unwrap();
        let app_id: i32 = connection
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .test_unwrap();
        assert_eq!(app_id, crate::CHIO_SQLITE_APPLICATION_ID);
        let user_version: i32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .test_unwrap();
        assert_eq!(user_version, 0);
    }

    // Simulate a database written by a newer binary and confirm the older binary
    // refuses to open it rather than silently misreading a future schema. The
    // receipt store records its revision under its own key in the shared metadata
    // table, so the future revision is staged there.
    {
        let connection = rusqlite::Connection::open(&path).test_unwrap();
        crate::stamp_schema_version(&connection, "receipt", 99).test_unwrap();
    }
    assert!(
        SqliteReceiptStore::open_existing(&path).is_err(),
        "a future-version receipt database must be refused"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn open_refuses_foreign_database_without_switching_it_to_wal() {
    let path = unique_db_path("chio-receipts-foreign-no-wal");

    // A pre-existing, unrelated SQLite database on the target path, in the
    // default rollback-journal mode.
    {
        let foreign = rusqlite::Connection::open(&path).test_unwrap();
        foreign
            .execute_batch("CREATE TABLE someone_elses_table (id TEXT PRIMARY KEY);")
            .test_unwrap();
        let journal_mode: String = foreign
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .test_unwrap();
        assert!(
            !journal_mode.eq_ignore_ascii_case("wal"),
            "precondition: the foreign database is not in WAL mode"
        );
    }

    // Opening it as a receipt store must fail closed as foreign.
    let error = SqliteReceiptStore::open(&path).test_unwrap_err();
    assert!(
        error.to_string().contains("not a Chio store"),
        "unexpected error: {error}"
    );

    // The refused foreign database must be left untouched: the durability
    // pragmas must not have rewritten its header into WAL mode.
    let reopened = rusqlite::Connection::open(&path).test_unwrap();
    let journal_mode: String = reopened
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .test_unwrap();
    assert!(
        !journal_mode.eq_ignore_ascii_case("wal"),
        "a refused foreign database must not be switched to WAL, got {journal_mode}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn open_refuses_a_foreign_db_with_a_lookalike_legacy_receipt_table() {
    let path = unique_db_path("chio-receipts-foreign-lookalike");

    // An unrelated SQLite database that merely happens to carry a table named
    // `tool_receipts` with an unrelated shape (no receipt payload column).
    {
        let foreign = rusqlite::Connection::open(&path).test_unwrap();
        foreign
            .execute_batch("CREATE TABLE tool_receipts (id INTEGER PRIMARY KEY, note TEXT);")
            .test_unwrap();
    }

    let error = SqliteReceiptStore::open(&path).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("refusing to adopt a foreign database"),
        "unexpected error: {error}"
    );

    // The refused database must not be stamped as a Chio store.
    let reopened = rusqlite::Connection::open(&path).test_unwrap();
    let app_id: i32 = reopened
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .test_unwrap();
    assert_eq!(app_id, 0, "a refused foreign database must not be stamped");

    let _ = fs::remove_file(path);
}

#[test]
fn open_adopts_a_legacy_receipt_db_carrying_the_payload_column() {
    let path = unique_db_path("chio-receipts-legacy-adopt");

    // A pre-stamping receipt database: a legacy anchor table carrying the
    // receipt payload column, which the store must still adopt and upgrade.
    {
        let legacy = rusqlite::Connection::open(&path).test_unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE tool_receipts (id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL);",
            )
            .test_unwrap();
    }

    let store = SqliteReceiptStore::open(&path).test_unwrap();
    drop(store);

    let reopened = rusqlite::Connection::open(&path).test_unwrap();
    let app_id: i32 = reopened
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .test_unwrap();
    assert_eq!(
        app_id,
        crate::CHIO_SQLITE_APPLICATION_ID,
        "a legacy receipt database with the payload column is adopted and stamped"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn flush_receipt_writes_reports_prior_committed_entries() {
    let path = unique_db_path("chio-receipts-flush");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    store
        .append_chio_receipt(&sample_receipt_with_id("rcpt-flush-1"))
        .test_unwrap();
    store
        .append_child_receipt(&sample_child_receipt_with_id_and_timestamp("flush-2", 2))
        .test_unwrap();

    let report = store.flush_receipt_writes().test_unwrap();

    assert!(report.writer.accepted_total >= 1);
    assert!(report.writer.committed_total >= 1);
    assert_eq!(report.latest_committed_entry_seq, 2);
    assert_eq!(report.latest_checkpointed_entry_seq, 0);
    assert_eq!(report.uncheckpointed_start_seq, Some(1));
    assert_eq!(report.uncheckpointed_end_seq, Some(2));
    assert!(report.wal_checkpoint.is_some());

    let _ = fs::remove_file(path);
}

/// The SIEM watchdog samples receipt health via a READ-ONLY open (no
/// create/WAL/writer-pool). Against a live store the sampler reads the same
/// committed/checkpointed progress as `receipt_store_health`. The writer is kept
/// alive (WAL/-shm in place), matching the production deployment where the
/// kernel owns the DB and the watchdog only reads.
#[test]
fn receipt_store_health_read_only_samples_a_live_store() {
    let path = unique_db_path("chio-receipts-health-ro");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id("rcpt-ro-1"))
        .test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id_and_timestamp("rcpt-ro-2", 2))
        .test_unwrap();

    let report = SqliteReceiptStore::receipt_store_health_read_only(&path).test_unwrap();
    assert!(report.healthy);
    assert_eq!(report.latest_committed_entry_seq, 2);
    assert_eq!(report.latest_checkpointed_entry_seq, 0);
    assert_eq!(report.uncheckpointed_start_seq, Some(1));
    assert_eq!(report.uncheckpointed_end_seq, Some(2));

    let _ = fs::remove_file(path);
}

/// A missing receipt DB must report NotFound and must NOT be created. `open`
/// creates a fresh empty DB on a mistyped path; the read-only sampler never
/// writes.
#[test]
fn receipt_store_health_read_only_missing_db_reports_not_found_without_creating() {
    let path = unique_db_path("chio-receipts-health-ro-missing");
    let _ = fs::remove_file(&path);
    assert!(!path.exists(), "precondition: the DB path must be absent");

    let error = SqliteReceiptStore::receipt_store_health_read_only(&path).test_unwrap_err();
    assert!(
        matches!(error, chio_kernel::ReceiptStoreError::NotFound(_)),
        "unexpected error: {error:?}"
    );
    assert!(
        !path.exists(),
        "the read-only sampler must not create the missing DB"
    );
}

#[test]
fn empty_store_reports_zero_committed_entry_for_operator_surfaces() {
    let path = unique_db_path("chio-receipts-empty-operator-surfaces");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    assert_eq!(store.latest_committed_entry_seq().test_unwrap(), 0);

    let health = store.receipt_store_health().test_unwrap();
    assert!(health.healthy);
    assert_eq!(health.latest_committed_entry_seq, 0);
    assert_eq!(health.latest_checkpointed_entry_seq, 0);
    assert_eq!(health.uncheckpointed_start_seq, None);
    assert_eq!(health.uncheckpointed_end_seq, None);

    let flush = store.flush_receipt_writes().test_unwrap();
    assert_eq!(flush.latest_committed_entry_seq, 0);
    assert_eq!(flush.latest_checkpointed_entry_seq, 0);
    assert_eq!(flush.uncheckpointed_start_seq, None);
    assert_eq!(flush.uncheckpointed_end_seq, None);

    let status = store.receipt_checkpoint_status(Some(10)).test_unwrap();
    assert!(status.healthy);
    assert_eq!(status.latest_committed_entry_seq, 0);
    assert_eq!(status.latest_checkpointed_entry_seq, 0);
    assert_eq!(status.next_range, None);

    let created = <SqliteReceiptStore as ReceiptStore>::create_next_receipt_checkpoint(
        &store,
        10,
        &receipt_test_keypair(),
    )
    .test_unwrap();
    assert!(!created.created);
    assert_eq!(created.latest_committed_entry_seq, 0);
    assert_eq!(created.latest_checkpointed_entry_seq, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn checkpoint_range_requires_contiguous_claim_log() {
    let path = unique_db_path("chio-receipts-checkpoint-gap");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    store
        .append_chio_receipt(&sample_receipt_with_id("rcpt-gap-1"))
        .test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id_and_timestamp("rcpt-gap-2", 2))
        .test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id_and_timestamp("rcpt-gap-3", 3))
        .test_unwrap();
    let connection = store.connection().test_unwrap();
    connection
        .execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;")
        .test_unwrap();
    connection
        .execute(
            "DELETE FROM claim_receipt_log_entries WHERE entry_seq = 2",
            [],
        )
        .test_unwrap();

    let error = store.next_checkpoint_range(3).test_unwrap_err();

    assert!(error
        .to_string()
        .contains("claim receipt log has a gap in checkpoint range"));

    let _ = fs::remove_file(path);
}

#[test]
fn canonical_bytes_range_rejects_partial_checkpoint_range() {
    let path = unique_db_path("chio-receipts-partial-range");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    store
        .append_chio_receipt(&sample_receipt_with_id("rcpt-range-1"))
        .test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id_and_timestamp("rcpt-range-2", 2))
        .test_unwrap();
    let connection = store.connection().test_unwrap();
    connection
        .execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;")
        .test_unwrap();
    connection
        .execute(
            "DELETE FROM claim_receipt_log_entries WHERE entry_seq = 2",
            [],
        )
        .test_unwrap();

    let error = store.receipts_canonical_bytes_range(1, 2).test_unwrap_err();

    assert!(error
        .to_string()
        .contains("claim receipt log has a gap in range 1..=2"));

    let _ = fs::remove_file(path);
}

#[test]
fn open_creates_kernel_checkpoints_table() {
    let path = unique_db_path("chio-receipts-cp-table");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    // Query the table to confirm it exists.
    let connection = store.connection().test_unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM kernel_checkpoints", [], |row| {
            row.get(0)
        })
        .test_unwrap();
    assert_eq!(count, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn open_creates_checkpoint_publication_metadata_table() {
    let path = unique_db_path("chio-receipts-cp-publication-table");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let connection = store.connection().test_unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM checkpoint_publication_metadata",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(count, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn open_existing_missing_path_does_not_create_database_file() {
    let path = unique_db_path("chio-receipts-open-existing-missing");

    let error = SqliteReceiptStore::open_existing(&path).test_unwrap_err();
    assert!(matches!(
        error,
        chio_kernel::ReceiptStoreError::NotFound(message)
            if message.contains("does not exist")
    ));
    assert!(
        !path.exists(),
        "open_existing must not create {}",
        path.display()
    );
}

#[test]
fn open_existing_rejects_touched_empty_database_file() {
    let path = unique_db_path("chio-receipts-open-existing-empty");
    fs::write(&path, "").test_unwrap();

    let error = SqliteReceiptStore::open_existing(&path).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("not an initialized Chio receipt store"),
        "unexpected error: {error}"
    );
    assert!(
        path.exists(),
        "open_existing should refuse, not remove, an empty database file"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_pool_sizes_reject_zero_capacity() {
    let path = unique_db_path("chio-receipts-zero-pool");

    let reader_error = match SqliteReceiptStore::open_with_pool_sizes(&path, 0, 1) {
        Ok(_) => panic!("expected zero reader pool capacity to fail"),
        Err(error) => error,
    };
    assert!(matches!(
        reader_error,
        chio_kernel::ReceiptStoreError::Pool(message)
            if message.contains("reader receipt sqlite pool max_size")
    ));

    let writer_error = match SqliteReceiptStore::open_with_pool_sizes(&path, 1, 0) {
        Ok(_) => panic!("expected zero writer pool capacity to fail"),
        Err(error) => error,
    };
    assert!(matches!(
        writer_error,
        chio_kernel::ReceiptStoreError::Pool(message)
            if message.contains("writer receipt sqlite pool max_size")
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn open_existing_reinstalls_projection_guards() {
    // `SqliteReceiptStore::open_existing` runs
    // `ensure_transparency_projection_guards` against the connection it
    // opens, which must reinstall every immutability trigger that
    // protects the transparency projection rows. Drop a representative
    // subset before reopening and confirm the reopen restores the full
    // guard set.
    let path = unique_db_path("chio-receipts-open-existing-guards");

    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id("rcpt-open-existing-guards"))
        .test_unwrap();
    drop(store);

    let store = SqliteReceiptStore::open(&path).test_unwrap();
    for trigger in TRANSPARENCY_PROJECTION_GUARD_TRIGGER_NAMES {
        assert!(
            trigger_exists(&store, trigger),
            "trigger {trigger} should be present after initial open"
        );
    }

    let dropped_triggers: &[&str] = &[
        "chio_tool_receipts_reject_update",
        "chio_tool_receipts_reject_delete",
        "claim_receipt_log_entries_reject_update",
        "claim_receipt_log_entries_reject_delete",
    ];
    {
        let connection = store.connection().test_unwrap();
        for trigger in dropped_triggers {
            connection
                .execute_batch(&format!("DROP TRIGGER IF EXISTS {trigger};"))
                .test_unwrap();
        }
    }
    for trigger in dropped_triggers {
        assert!(
            !trigger_exists(&store, trigger),
            "trigger {trigger} should be absent after explicit drop"
        );
    }
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path).test_unwrap();
    for trigger in TRANSPARENCY_PROJECTION_GUARD_TRIGGER_NAMES {
        assert!(
            trigger_exists(&reopened, trigger),
            "trigger {trigger} should be reinstalled by open_existing"
        );
    }

    let _ = fs::remove_file(path);
}
