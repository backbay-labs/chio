use super::super::*;
use super::support::*;

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
