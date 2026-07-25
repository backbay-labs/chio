use super::super::*;
use super::support::*;

fn stage_receipt_schema_v0(path: &std::path::Path) {
    drop(SqliteReceiptStore::open(path).test_unwrap());
    let connection = rusqlite::Connection::open(path).test_unwrap();
    connection
        .execute("DROP INDEX idx_capability_lineage_federated_parent", [])
        .test_unwrap();
    for table in ["capability_lineage", "federated_share_capability_lineage"] {
        for column in [
            "provenance",
            "federated_parent_capability_id",
            "signed_capability_json",
        ] {
            connection
                .execute(&format!("ALTER TABLE {table} DROP COLUMN {column}"), [])
                .test_unwrap();
        }
    }
    crate::stamp_schema_version(&connection, "receipt", 0).test_unwrap();
}

fn table_has_column(connection: &rusqlite::Connection, table: &str, column: &str) -> bool {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
            rusqlite::params![table, column],
            |row| row.get(0),
        )
        .test_unwrap()
}

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
fn open_existing_rejects_v0_until_writable_open_migrates_it() {
    let path = unique_db_path("chio-receipts-v0-open-existing");
    stage_receipt_schema_v0(&path);

    let error = SqliteReceiptStore::open_existing(&path).test_unwrap_err();
    assert!(
        error.to_string().contains("requires writable migration"),
        "unexpected error: {error}"
    );
    let unmigrated = rusqlite::Connection::open(&path).test_unwrap();
    assert!(!table_has_column(
        &unmigrated,
        "capability_lineage",
        "signed_capability_json"
    ));
    assert!(!table_has_column(
        &unmigrated,
        "capability_lineage",
        "provenance"
    ));
    drop(unmigrated);

    let migrated = SqliteReceiptStore::open(&path).test_unwrap();
    let connection = migrated.connection().test_unwrap();
    assert!(table_has_column(
        &connection,
        "capability_lineage",
        "signed_capability_json"
    ));
    assert!(table_has_column(
        &connection,
        "federated_share_capability_lineage",
        "signed_capability_json"
    ));
    assert!(table_has_column(
        &connection,
        "capability_lineage",
        "federated_parent_capability_id"
    ));
    assert!(table_has_column(
        &connection,
        "capability_lineage",
        "provenance"
    ));
    let version: i32 = connection
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(
        version,
        crate::receipt_store::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
    );
    drop(connection);
    drop(migrated);

    let _ = fs::remove_file(path);
}

#[test]
fn concurrent_writable_opens_serialize_lineage_migration_and_stamp() {
    let path = unique_db_path("chio-receipts-v1-concurrent-migration");
    stage_receipt_schema_v0(&path);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            SqliteReceiptStore::open(&path).map(drop)
        }));
    }
    barrier.wait();
    for worker in workers {
        worker.join().test_unwrap().test_unwrap();
    }

    let connection = rusqlite::Connection::open(&path).test_unwrap();
    assert!(table_has_column(
        &connection,
        "capability_lineage",
        "signed_capability_json"
    ));
    assert!(table_has_column(
        &connection,
        "federated_share_capability_lineage",
        "signed_capability_json"
    ));
    assert!(table_has_column(
        &connection,
        "capability_lineage",
        "federated_parent_capability_id"
    ));
    assert!(table_has_column(
        &connection,
        "capability_lineage",
        "provenance"
    ));
    let version: i32 = connection
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(
        version,
        crate::receipt_store::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
    );
    drop(connection);

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_cost_projection_migration_backfills_full_u64_domain(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-cost-projection-migration");
    let store = SqliteReceiptStore::open(&path)?;
    let signed_max = u64::try_from(i64::MAX)?;
    store.append_chio_receipt(&sample_receipt_with_id("no-cost"))?;
    for (id, cost) in [
        ("signed-max", signed_max),
        ("unsigned-boundary", signed_max + 1),
        ("unsigned-max", u64::MAX),
    ] {
        store.append_chio_receipt(&sample_financial_receipt(id, cost)?)?;
    }
    drop(store);

    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch(
        "DROP INDEX IF EXISTS idx_chio_tool_receipts_cost;\
         DROP INDEX IF EXISTS idx_chio_tool_receipts_cost_global;\
         ALTER TABLE chio_tool_receipts DROP COLUMN cost_charged_be;\
         ALTER TABLE chio_tool_receipts DROP COLUMN cost_currency;",
    )?;
    crate::stamp_schema_version(&connection, "receipt", 2)?;
    drop(connection);

    let migrated = SqliteReceiptStore::open(&path)?;
    let connection = migrated.connection()?;
    let rows = connection
        .prepare("SELECT cost_currency, cost_charged_be FROM chio_tool_receipts ORDER BY seq ASC")?
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        rows,
        vec![
            (None, None),
            (
                Some("USD".to_string()),
                Some(signed_max.to_be_bytes().to_vec())
            ),
            (
                Some("USD".to_string()),
                Some((signed_max + 1).to_be_bytes().to_vec())
            ),
            (
                Some("USD".to_string()),
                Some(u64::MAX.to_be_bytes().to_vec())
            ),
        ]
    );
    let index_columns = connection
        .prepare("PRAGMA index_info(idx_chio_tool_receipts_cost)")?
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        index_columns,
        vec!["tenant_id", "cost_currency", "cost_charged_be", "seq"]
    );
    let global_index_columns = connection
        .prepare("PRAGMA index_info(idx_chio_tool_receipts_cost_global)")?
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        global_index_columns,
        vec!["cost_currency", "cost_charged_be", "seq"]
    );
    let version: i32 = connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        version,
        crate::receipt_store::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
    );

    drop(connection);
    drop(migrated);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn receipt_cost_projection_migration_rolls_back_malformed_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-cost-projection-malformed");
    let store = SqliteReceiptStore::open(&path)?;
    store.append_chio_receipt(&sample_financial_receipt("valid-cost", 7)?)?;
    store.append_chio_receipt(&sample_financial_receipt("malformed-cost", 8)?)?;
    drop(store);

    let mut connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch(
        "DROP TRIGGER chio_tool_receipts_reject_update;\
         DROP INDEX idx_chio_tool_receipts_cost;\
         DROP INDEX idx_chio_tool_receipts_cost_global;\
         ALTER TABLE chio_tool_receipts DROP COLUMN cost_charged_be;\
         ALTER TABLE chio_tool_receipts DROP COLUMN cost_currency;\
         UPDATE chio_tool_receipts SET raw_json = '{' WHERE seq = 2;",
    )?;
    let migration =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let error = match migrate_receipt_cost_projection(&migration) {
        Ok(()) => {
            return Err(std::io::Error::other("malformed receipt migration succeeded").into())
        }
        Err(error) => error,
    };
    assert!(error.to_string().contains("failed to decode"));
    migration.rollback()?;
    let projected_columns: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('chio_tool_receipts') \
         WHERE name IN ('cost_currency', 'cost_charged_be')",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(projected_columns, 0);

    drop(connection);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn receipt_cost_projection_migration_rolls_back_divergent_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-cost-projection-divergent");
    let store = SqliteReceiptStore::open(&path)?;
    store.append_chio_receipt(&sample_financial_receipt("missing-cost", 7)?)?;
    store.append_chio_receipt(&sample_financial_receipt("divergent-cost", 8)?)?;
    drop(store);

    let mut connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("DROP TRIGGER chio_tool_receipts_reject_update")?;
    connection.execute(
        "UPDATE chio_tool_receipts SET cost_currency = NULL, cost_charged_be = NULL WHERE seq = 1",
        [],
    )?;
    connection.execute(
        "UPDATE chio_tool_receipts SET cost_charged_be = ?1 WHERE seq = 2",
        [0_u64.to_be_bytes().as_slice()],
    )?;
    let migration =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let error = match migrate_receipt_cost_projection(&migration) {
        Ok(()) => {
            return Err(std::io::Error::other("divergent projection migration succeeded").into())
        }
        Err(error) => error,
    };
    assert!(error.to_string().contains("different cost projection"));
    migration.rollback()?;
    let first_projection = connection.query_row(
        "SELECT cost_currency, cost_charged_be FROM chio_tool_receipts WHERE seq = 1",
        [],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
            ))
        },
    )?;
    assert_eq!(first_projection, (None, None));

    drop(connection);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn receipt_cost_projection_columns_reject_invalid_pairs() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-receipts-cost-projection-constraints");
    drop(SqliteReceiptStore::open(&path)?);
    let mut connection = rusqlite::Connection::open(&path)?;
    let transaction = connection.transaction()?;

    for (index, currency, cost) in [
        (0, Some("USD"), None),
        (1, None, Some(vec![0_u8; 8])),
        (2, Some("usd"), Some(vec![0_u8; 8])),
        (3, Some("USD"), Some(vec![0_u8; 7])),
    ] {
        let result = transaction.execute(
            "INSERT INTO chio_tool_receipts (
                 receipt_id, timestamp, capability_id, tool_server, tool_name,
                 decision_kind, policy_hash, content_hash, raw_json,
                 cost_currency, cost_charged_be
             ) VALUES (?1, 1, 'cap', 'server', 'tool', 'allow', 'policy', 'content', '{}', ?2, ?3)",
            rusqlite::params![format!("invalid-{index}"), currency, cost],
        );
        assert!(
            result.is_err(),
            "invalid cost projection {index} was accepted"
        );
    }

    transaction.rollback()?;
    drop(connection);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn explicit_audit_rejects_missing_or_divergent_cost_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    for (suffix, replacement) in [("missing", None), ("divergent", Some(0_u64.to_be_bytes()))] {
        let path = unique_db_path(&format!("chio-receipts-cost-projection-{suffix}"));
        let store = SqliteReceiptStore::open(&path)?;
        store.append_chio_receipt(&sample_financial_receipt(suffix, u64::MAX)?)?;
        drop(store);

        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch("DROP TRIGGER chio_tool_receipts_reject_update")?;
        match replacement {
            Some(key) => {
                connection.execute(
                    "UPDATE chio_tool_receipts SET cost_charged_be = ?1",
                    [key.as_slice()],
                )?;
            }
            None => {
                connection.execute(
                    "UPDATE chio_tool_receipts SET cost_currency = NULL, cost_charged_be = NULL",
                    [],
                )?;
            }
        }
        ensure_transparency_projection_guards(&connection)?;
        drop(connection);

        let reopened = SqliteReceiptStore::open_existing(&path)?;
        let Err(error) = reopened.audit_receipt_cost_projection() else {
            return Err("cost projection audit unexpectedly succeeded".into());
        };
        assert!(error.to_string().contains("different cost projection"));
        drop(reopened);
        let _ = fs::remove_file(path);
    }
    Ok(())
}

#[test]
fn current_receipt_schema_rejects_substituted_cost_indexes(
) -> Result<(), Box<dyn std::error::Error>> {
    for (name, columns) in [
        (
            "idx_chio_tool_receipts_cost",
            "tenant_id, cost_currency, seq, cost_charged_be",
        ),
        (
            "idx_chio_tool_receipts_cost_global",
            "cost_currency, seq, cost_charged_be",
        ),
    ] {
        let path = unique_db_path(&format!("chio-receipts-{name}-substituted"));
        drop(SqliteReceiptStore::open(&path)?);

        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(&format!(
            "DROP INDEX {name}; CREATE INDEX {name} ON chio_tool_receipts({columns});"
        ))?;
        drop(connection);

        let error = match SqliteReceiptStore::open_existing(&path) {
            Ok(_) => {
                return Err(std::io::Error::other("substituted cost index was accepted").into())
            }
            Err(error) => error,
        };
        assert!(error.to_string().contains("cost projection schema"));

        let _ = fs::remove_file(path);
    }
    Ok(())
}

#[test]
fn current_receipt_schema_rejects_substituted_immutability_guard(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-cost-guard-substituted");
    drop(SqliteReceiptStore::open(&path)?);

    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch(
        "DROP TRIGGER chio_tool_receipts_reject_update;
         CREATE TRIGGER chio_tool_receipts_reject_update
         BEFORE UPDATE ON chio_tool_receipts
         BEGIN
             SELECT 1;
         END;",
    )?;
    drop(connection);

    let error = match SqliteReceiptStore::open_existing(&path) {
        Ok(_) => {
            return Err(std::io::Error::other("substituted immutability guard was accepted").into())
        }
        Err(error) => error,
    };
    assert!(error.to_string().contains("cost projection schema"));

    let _ = fs::remove_file(path);
    Ok(())
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
