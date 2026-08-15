use super::super::*;
use super::support::*;
use chio_credit::IouEnvelopeStore as _;

#[cfg(unix)]
#[test]
fn qualified_receipt_sink_binds_validation_to_the_borrowed_database_file(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let database = directory.path().join("qualified-original.sqlite3");
    let replacement = directory.path().join("qualified-copy.sqlite3");
    let store = SqliteReceiptStore::open(&database)?;
    store.flush_receipt_writes()?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    let sink_id = connection.query_row(
        "SELECT sink_id FROM chio_receipt_sink_identity WHERE singleton = 1",
        [],
        |row| row.get::<_, String>(0),
    )?;
    drop(connection);
    drop(store);
    std::fs::copy(&database, &replacement)?;

    let qualification = ReceiptSinkQualification::capture(&database, &sink_id)?;
    let borrowed_replacement = rusqlite::Connection::open(&replacement)?;
    let error = qualification
        .validate_connection(&borrowed_replacement)
        .err()
        .ok_or("qualified validation accepted a different borrowed SQLite file")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("borrowed file identity changed")),
        "unexpected borrowed-file identity error: {error}"
    );
    Ok(())
}

#[test]
fn qualified_receipt_sink_rejects_atomic_database_replacement(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-replacement-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("qualified-replacement.sqlite3");
    let replacement = directory.path().join("qualified-replacement-copy.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    let iou_store = crate::SqliteIouEnvelopeStore::open_alongside(&store)?;
    let receipt = super::support::sample_receipt_with_id("qualified-before-replacement");
    chio_kernel::ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt)?;
    store.flush_receipt_writes()?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    std::fs::copy(&database, &replacement)?;
    std::fs::rename(&replacement, &database)?;

    let error = store
        .max_tool_receipt_seq()
        .err()
        .ok_or("atomically replaced qualified receipt database was served")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("filesystem identity changed")),
        "unexpected replacement error: {error}"
    );
    let error = iou_store
        .get_by_receipt_id("qualified-before-replacement")
        .err()
        .ok_or("shared qualified receipt pool served an atomically replaced database")?;
    assert!(
        matches!(error, chio_credit::IouEnvelopeStoreError::Backend(ref message) if message.contains("filesystem identity changed")),
        "unexpected shared-pool replacement error: {error}"
    );
    let replacement_receipt = super::support::sample_receipt_with_id("qualified-after-replacement");
    let error =
        chio_kernel::ReceiptStore::append_chio_receipt_returning_seq(&store, &replacement_receipt)
            .err()
            .ok_or("atomically replaced qualified receipt database accepted a write")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("filesystem identity changed")),
        "unexpected replacement write error: {error}"
    );
    Ok(())
}

#[test]
fn qualified_receipt_sink_rejects_internal_sink_identity_change(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-sink-id-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("qualified-sink-id.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute(
        "UPDATE chio_receipt_sink_identity SET sink_id = ?1 WHERE singleton = 1",
        [uuid::Uuid::now_v7().to_string()],
    )?;
    drop(connection);

    let error = store
        .max_tool_receipt_seq()
        .err()
        .ok_or("qualified receipt store accepted a changed internal sink identity")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("internal sink identity changed")),
        "unexpected sink identity error: {error}"
    );
    Ok(())
}

#[test]
fn qualified_receipt_sink_rejects_read_only_sqlite_uris() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-read-only-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("read-only.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    store.flush_receipt_writes()?;
    drop(store);

    for query in [
        "mode=ro",
        "immutable=1",
        "immutable=true",
        "immutable=2",
        "immutable=01",
        "immutable=-1",
        "immutable=",
        "immutable=maybe",
    ] {
        let uri = format!("file:{}?{query}", database.display());
        let error = match SqliteReceiptStore::open_existing_for_finding_pool(
            std::path::PathBuf::from(uri),
            anchor_directory.path(),
        ) {
            Ok(_) => return Err("read-only URI was accepted".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ReceiptStoreError::Conflict(message) if message.contains("read-only")
        ));
    }
    Ok(())
}

#[test]
fn qualified_receipt_sink_allows_explicitly_false_immutable_sqlite_uris(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-mutable-uri-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("mutable.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    store.flush_receipt_writes()?;
    drop(store);

    for value in ["0", "off", "false", "no", "FALSE"] {
        let uri = format!("file:{}?immutable={value}", database.display());
        let store = SqliteReceiptStore::open_existing_for_finding_pool(
            std::path::PathBuf::from(uri),
            anchor_directory.path(),
        )?;
        store.flush_receipt_writes()?;
    }
    Ok(())
}

#[test]
fn qualified_receipt_sink_rejects_nonlocal_sqlite_uri_authorities(
) -> Result<(), Box<dyn std::error::Error>> {
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-uri-authority-anchor")?;
    for uri in [
        "file://remote-host/var/lib/chio/receipts.db",
        "file://%72emote-host/var/lib/chio/receipts.db",
    ] {
        let error = SqliteReceiptStore::open_for_finding_pool(
            std::path::PathBuf::from(uri),
            anchor_directory.path(),
        )
        .err()
        .ok_or("non-local SQLite URI authority was accepted")?;
        assert!(matches!(
            error,
            ReceiptStoreError::Conflict(message) if message.contains("non-local authority")
        ));
    }
    Ok(())
}

#[test]
fn qualified_receipt_sink_rejects_anchor_on_the_database_snapshot_device(
) -> Result<(), Box<dyn std::error::Error>> {
    for use_database_root in [true, false] {
        let directory = tempfile::tempdir()?;
        let sibling_anchor = tempfile::tempdir()?;
        #[cfg(unix)]
        for root in [directory.path(), sibling_anchor.path()] {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        }
        let anchor_root = if use_database_root {
            directory.path()
        } else {
            sibling_anchor.path()
        };
        let error = SqliteReceiptStore::open_for_finding_pool(
            directory.path().join("receipts.sqlite3"),
            anchor_root,
        )
        .err()
        .ok_or("co-located receipt rollback anchor qualified")?;
        assert!(matches!(
            error,
            ReceiptStoreError::Conflict(message)
                if message.contains("shares the protected database snapshot domain")
        ));
    }
    Ok(())
}

#[test]
fn qualified_receipt_sink_anchors_lineage_only_duplicate_mutations(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-lineage-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("qualified-lineage.sqlite3");
    let snapshot = directory.path().join("before-lineage.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    let receipt =
        super::insert::sample_receipt_with_id_and_call_chain("anchored-lineage-duplicate");
    let value = serde_json::to_value(&receipt)?;
    let canonical = Arc::new(CanonicalBytes::from_value(&value)?);

    store.append_chio_receipt_canonical_returning_seq(Arc::clone(&canonical))?;
    store.flush_receipt_writes()?;
    let connection = rusqlite::Connection::open(&database)?;
    let lineage_before: i64 = connection.query_row(
        "SELECT COUNT(*) FROM receipt_lineage_statements WHERE receipt_id = ?1",
        [receipt.id.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(lineage_before, 0);
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    std::fs::copy(&database, &snapshot)?;

    chio_kernel::ReceiptStore::append_chio_receipt_canonical(&store, &receipt, canonical.as_ref())?;
    store.flush_receipt_writes()?;
    let connection = rusqlite::Connection::open(&database)?;
    let lineage_after: i64 = connection.query_row(
        "SELECT COUNT(*) FROM receipt_lineage_statements WHERE receipt_id = ?1",
        [receipt.id.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(lineage_after, 1);
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);

    std::fs::copy(&snapshot, &database)?;
    let error = store
        .max_child_receipt_seq()
        .err()
        .ok_or("lineage-only rollback must fail a qualified receipt read")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("rollback protection")),
        "unexpected lineage-only rollback error: {error}"
    );
    Ok(())
}

#[test]
fn qualified_receipt_sink_verifies_rollback_anchor_before_metadata_jobs(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-metadata-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("qualified-metadata.sqlite3");
    let snapshot = directory.path().join("before-receipt.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    store.flush_receipt_writes()?;
    let checkpoint = rusqlite::Connection::open(&database)?;
    checkpoint.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(checkpoint);
    std::fs::copy(&database, &snapshot)?;

    let receipt = super::support::sample_receipt_with_id("metadata-anchor-advance");
    chio_kernel::ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt)?;
    store.flush_receipt_writes()?;
    let checkpoint = rusqlite::Connection::open(&database)?;
    checkpoint.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(checkpoint);
    std::fs::copy(&snapshot, &database)?;

    let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ran_in_job = Arc::clone(&ran);
    let error = store
        .writer_handle()
        .run_write(move |_connection| {
            ran_in_job.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .err()
        .ok_or("metadata job ran against a rolled-back qualified database")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("rollback protection")),
        "unexpected metadata rollback error: {error}"
    );
    assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

#[test]
fn qualified_receipt_sink_anchors_standalone_lineage_mutations(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-standalone-lineage-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory
        .path()
        .join("qualified-standalone-lineage.sqlite3");
    let snapshot = directory.path().join("before-standalone-lineage.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    let receipt = super::support::sample_receipt_with_id("anchored-standalone-lineage");
    chio_kernel::ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt)?;
    store.flush_receipt_writes()?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    std::fs::copy(&database, &snapshot)?;

    store.record_receipt_lineage_statement_record(
        &receipt.id,
        None,
        None,
        None,
        None,
        None,
        Some("standalone-lineage-chain"),
        2_101,
        &serde_json::json!({"evidenceClass": "standalone"}),
    )?;
    let connection = rusqlite::Connection::open(&database)?;
    let lineage_after: i64 = connection.query_row(
        "SELECT COUNT(*) FROM receipt_lineage_statements WHERE receipt_id = ?1",
        [receipt.id.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(lineage_after, 1);
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);

    std::fs::copy(&snapshot, &database)?;
    let error = store
        .max_child_receipt_seq()
        .err()
        .ok_or("standalone lineage rollback must fail a qualified receipt read")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("rollback protection")),
        "unexpected standalone lineage rollback error: {error}"
    );
    Ok(())
}

#[test]
fn qualified_settlement_state_writes_advance_the_rollback_anchor(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_settle::{
        RetryPolicy, SettlementOutcomeStore as _, SettlementRoute, SettlementRoutingInput,
    };

    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-settlement-state-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("qualified-settlement-state.sqlite3");
    let snapshot = directory.path().join("before-terminal-settlement.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    let outcomes = crate::SqliteSettlementOutcomeStore::open_alongside(&store)?;
    let receipt =
        super::support::sample_receipt_with_id_and_timestamp("qualified-settlement-state", 1);
    let pending = chio_kernel::PendingSettlementObservation {
        next_visible_at_ms: 1,
    };
    chio_kernel::ReceiptStore::append_chio_receipt_with_pending_observation(
        &store, &receipt, &pending,
    )?;
    store.flush_receipt_writes()?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    std::fs::copy(&database, &snapshot)?;

    let claim = outcomes
        .claim_receipt(&receipt.id, "qualified-settlement-worker", 1, 100)?
        .ok_or("qualified settlement attempt was not claimable")?;
    assert_eq!(
        outcomes.record_claimed_outcome(
            &claim,
            &SettlementRoutingInput::Accepted,
            RetryPolicy::default(),
            2,
        )?,
        SettlementRoute::NoAction
    );
    store.flush_receipt_writes()?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    std::fs::copy(&snapshot, &database)?;

    let error = store
        .max_tool_receipt_seq()
        .err()
        .ok_or("rolled-back terminal settlement state was served")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("rollback protection")),
        "unexpected settlement-state rollback error: {error}"
    );
    Ok(())
}

#[test]
fn qualified_receipt_sink_anchors_standalone_checkpoint_commits(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-checkpoint-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("qualified-checkpoint.sqlite3");
    let snapshot = directory.path().join("before-checkpoint.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    let receipt = super::support::sample_receipt_with_id("anchored-standalone-checkpoint");
    chio_kernel::ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt)?;
    store.flush_receipt_writes()?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    std::fs::copy(&database, &snapshot)?;

    let report =
        store.create_next_receipt_checkpoint(1, &super::support::receipt_test_keypair())?;
    assert!(report.created);
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);

    std::fs::copy(&snapshot, &database)?;
    let error = store
        .max_child_receipt_seq()
        .err()
        .ok_or("standalone checkpoint rollback must fail a qualified receipt read")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("rollback protection")),
        "unexpected standalone checkpoint rollback error: {error}"
    );
    Ok(())
}

#[test]
fn qualified_receipt_sink_anchors_imported_checkpoint_commits(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-import-checkpoint-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("qualified-import-checkpoint.sqlite3");
    let snapshot = directory.path().join("before-import-checkpoint.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    let receipt = super::support::sample_receipt_with_id("anchored-import-checkpoint");
    let seq = chio_kernel::ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt)?
        .ok_or("qualified receipt store did not return a sequence")?;
    store.flush_receipt_writes()?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    std::fs::copy(&database, &snapshot)?;

    let checkpoint = build_checkpoint(
        1,
        seq,
        seq,
        &canonical_receipt_bytes(&store, seq, seq),
        &receipt_test_keypair(),
    )?;
    store.store_checkpoint(&checkpoint)?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);

    std::fs::copy(&snapshot, &database)?;
    let error = store
        .max_child_receipt_seq()
        .err()
        .ok_or("imported checkpoint rollback must fail a qualified receipt read")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("rollback protection")),
        "unexpected imported checkpoint rollback error: {error}"
    );
    Ok(())
}

#[test]
fn qualified_receipt_sink_anchors_checkpoint_publication_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-publication-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory
        .path()
        .join("qualified-publication-binding.sqlite3");
    let snapshot = directory.path().join("before-publication-binding.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    let receipt = super::support::sample_receipt_with_id("anchored-publication-binding");
    chio_kernel::ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt)?;
    let report = store.create_next_receipt_checkpoint(1, &receipt_test_keypair())?;
    let checkpoint_seq = report
        .checkpoint_seq
        .ok_or("qualified receipt store did not create a checkpoint")?;
    let checkpoint = store
        .load_checkpoint_by_seq(checkpoint_seq)?
        .ok_or("qualified receipt store did not retain its checkpoint")?;
    let publication = build_checkpoint_publication(&checkpoint)?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    std::fs::copy(&database, &snapshot)?;

    let binding = chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding {
        publication_identity: chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
            chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::LocalLog,
            publication.log_id,
        ),
        trust_anchor_identity: chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
            chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::TransparencyRoot,
            "qualified-root-set",
        ),
        trust_anchor_ref: "qualified-anchor-root".to_owned(),
        signer_cert_ref: "qualified-cert-chain".to_owned(),
        publication_profile_version: "phase4-pilot".to_owned(),
    };
    store.record_checkpoint_publication_trust_anchor_binding(checkpoint_seq, &binding)?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);

    std::fs::copy(&snapshot, &database)?;
    let error = store
        .max_child_receipt_seq()
        .err()
        .ok_or("publication binding rollback must fail a qualified receipt read")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("rollback protection")),
        "unexpected publication binding rollback error: {error}"
    );
    Ok(())
}

#[test]
fn qualified_receipt_sink_anchors_background_checkpoint_commits(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let anchor_directory = rollback_anchor_tempdir("chio-receipt-background-anchor")?;
    #[cfg(unix)]
    for root in [directory.path(), anchor_directory.path()] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("qualified-background.sqlite3");
    let snapshot = directory
        .path()
        .join("before-background-checkpoint.sqlite3");
    let store = SqliteReceiptStore::open_for_finding_pool(&database, anchor_directory.path())?;
    let receipt = super::support::sample_receipt_with_id("anchored-background-checkpoint");
    chio_kernel::ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt)?;
    store.flush_receipt_writes()?;
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);
    std::fs::copy(&database, &snapshot)?;

    store.enable_background_checkpoints(BackgroundCheckpointSigner {
        keypair: Arc::new(super::support::receipt_test_keypair()),
        max_batch: 1,
    })?;
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(1)?.is_some());
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    drop(connection);

    std::fs::copy(&snapshot, &database)?;
    let error = store
        .max_child_receipt_seq()
        .err()
        .ok_or("background checkpoint rollback must fail a qualified receipt read")?;
    assert!(
        matches!(error, ReceiptStoreError::Conflict(ref message) if message.contains("rollback protection")),
        "unexpected background checkpoint rollback error: {error}"
    );
    Ok(())
}
