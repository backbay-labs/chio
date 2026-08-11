use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::ReceiptStore;

fn unique_archive_path() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "chio-schema-stamp-archive-{}-{nonce}.sqlite3",
        std::process::id()
    ))
}

#[test]
fn archive_schema_is_stamped_and_rejects_older_binaries() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::receipt_store::evidence_retention::create_archive_schema;

    let archive = unique_archive_path();
    let escaped_archive = archive
        .to_str()
        .ok_or("archive path invalid")?
        .replace('\'', "''");
    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
    create_archive_schema(&mut connection)?;
    let first_sink_id: String = connection.query_row(
        "SELECT sink_id FROM archive.chio_receipt_sink_identity WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        uuid::Uuid::parse_str(&first_sink_id)?.to_string(),
        first_sink_id
    );
    create_archive_schema(&mut connection)?;
    let replayed_sink_id: String = connection.query_row(
        "SELECT sink_id FROM archive.chio_receipt_sink_identity WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(replayed_sink_id, first_sink_id);
    connection.execute_batch("DETACH DATABASE archive")?;

    let reopened = crate::SqliteReceiptStore::open_existing(&archive)?;
    assert_eq!(reopened.durable_sink_id(), Some(first_sink_id.as_str()));
    drop(reopened);

    let archived = rusqlite::Connection::open(&archive)?;
    let application_id: i32 = archived.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    assert_eq!(application_id, crate::CHIO_SQLITE_APPLICATION_ID);
    let version: i32 = archived.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        version,
        crate::receipt_store::support::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
    );
    assert!(matches!(
        crate::check_schema_version(&archived, "receipt", 0, &["chio_tool_receipts"]),
        Err(crate::SchemaVersionError::FutureSchema { found, supported })
            if found == crate::receipt_store::support::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
                && supported == 0
    ));

    drop(archived);
    let _ = std::fs::remove_file(archive);
    Ok(())
}

#[test]
fn archive_schema_migrates_and_verifies_cost_projection() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::receipt_store::evidence_retention::create_archive_schema;

    let archive = unique_archive_path();
    let store = crate::SqliteReceiptStore::open(&archive)?;
    store.append_chio_receipt(&super::support::sample_financial_receipt(
        "archive-cost-migration",
        u64::MAX,
    )?)?;
    drop(store);

    let archived = rusqlite::Connection::open(&archive)?;
    crate::receipt_store::support::drop_transparency_projection_guards(&archived)?;
    archived.execute_batch(
        "DROP INDEX idx_chio_tool_receipts_cost;\
         DROP INDEX idx_chio_tool_receipts_cost_global;\
         ALTER TABLE chio_tool_receipts DROP COLUMN cost_charged_be;\
         ALTER TABLE chio_tool_receipts DROP COLUMN cost_currency;",
    )?;
    crate::stamp_schema_version(&archived, "receipt", 2)?;
    drop(archived);

    let escaped_archive = archive
        .to_str()
        .ok_or("archive path invalid")?
        .replace('\'', "''");
    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
    create_archive_schema(&mut connection)?;
    let projection = connection.query_row(
        "SELECT cost_currency, cost_charged_be FROM archive.chio_tool_receipts",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    assert_eq!(
        projection,
        ("USD".to_string(), u64::MAX.to_be_bytes().to_vec())
    );
    connection.execute_batch("DETACH DATABASE archive")?;

    let _ = std::fs::remove_file(archive);
    Ok(())
}

#[test]
fn current_archive_schema_rejects_substituted_cost_indexes(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::create_archive_schema;

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
        let archive = unique_archive_path();
        drop(crate::SqliteReceiptStore::open(&archive)?);

        let archived = rusqlite::Connection::open(&archive)?;
        crate::receipt_store::support::drop_transparency_projection_guards(&archived)?;
        archived.execute_batch(&format!(
            "DROP INDEX {name}; CREATE INDEX {name} ON chio_tool_receipts({columns});"
        ))?;
        drop(archived);

        let escaped_archive = archive
            .to_str()
            .ok_or("archive path invalid")?
            .replace('\'', "''");
        let mut connection = rusqlite::Connection::open_in_memory()?;
        connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
        let Err(error) = create_archive_schema(&mut connection) else {
            return Err("archive cost projection schema unexpectedly passed".into());
        };
        assert!(error.to_string().contains("cost projection schema"));

        drop(connection);
        let _ = std::fs::remove_file(archive);
    }
    Ok(())
}
