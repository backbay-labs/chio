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
