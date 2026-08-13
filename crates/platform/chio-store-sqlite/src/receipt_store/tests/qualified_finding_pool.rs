use super::super::*;
use super::support::rollback_anchor_tempdir;

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

    for query in ["mode=ro", "immutable=1", "immutable=true"] {
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
