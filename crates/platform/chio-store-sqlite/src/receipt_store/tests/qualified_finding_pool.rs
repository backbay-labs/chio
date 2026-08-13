use super::super::*;

#[test]
fn qualified_receipt_sink_rejects_read_only_sqlite_uris() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let anchor_directory = tempfile::tempdir()?;
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
