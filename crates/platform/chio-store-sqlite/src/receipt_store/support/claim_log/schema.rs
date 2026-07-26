use super::*;

const RECEIPT_COST_CURRENCY_COLUMN: &str = r#"cost_currency TEXT CHECK (
    cost_currency IS NULL OR (
        typeof(cost_currency) = 'text' AND
        length(cost_currency) = 3 AND
        cost_currency NOT GLOB '*[^A-Z]*'
    )
)"#;
const RECEIPT_COST_KEY_COLUMN: &str = r#"cost_charged_be BLOB CHECK (
    (cost_currency IS NULL AND cost_charged_be IS NULL) OR
    (
        cost_currency IS NOT NULL AND
        typeof(cost_charged_be) = 'blob' AND
        length(cost_charged_be) = 8
    )
)"#;
const RECEIPT_COST_INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS \
    idx_chio_tool_receipts_cost ON \
    chio_tool_receipts(tenant_id, cost_currency, cost_charged_be, seq)";
const RECEIPT_GLOBAL_COST_INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS \
    idx_chio_tool_receipts_cost_global ON \
    chio_tool_receipts(cost_currency, cost_charged_be, seq)";
const ARCHIVE_RECEIPT_COST_INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS \
    archive.idx_chio_tool_receipts_cost ON \
    chio_tool_receipts(tenant_id, cost_currency, cost_charged_be, seq)";
const ARCHIVE_RECEIPT_GLOBAL_COST_INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS \
    archive.idx_chio_tool_receipts_cost_global ON \
    chio_tool_receipts(cost_currency, cost_charged_be, seq)";
const RECEIPT_COST_REFERENCE_SCHEMA: &str = r#"
CREATE TABLE chio_tool_receipts (
    seq INTEGER,
    tenant_id TEXT,
    cost_currency TEXT,
    cost_charged_be BLOB
);
CREATE TABLE chio_child_receipts (id INTEGER);
CREATE TABLE claim_receipt_log_entries (id INTEGER);
CREATE TABLE checkpoint_tree_heads (id INTEGER);
CREATE TABLE checkpoint_predecessor_witnesses (id INTEGER);
CREATE TABLE checkpoint_publication_metadata (id INTEGER);
CREATE TABLE checkpoint_publication_trust_anchor_bindings (id INTEGER);
"#;

#[derive(Debug, PartialEq, Eq)]
struct ReceiptCostSchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

pub(crate) fn receipt_cost_projection(
    receipt: &ChioReceipt,
) -> Result<(Option<String>, Option<Vec<u8>>), ReceiptStoreError> {
    let Some(financial) = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
    else {
        return Ok((None, None));
    };
    if financial.is_null() {
        return Ok((None, None));
    }
    let financial =
        serde_json::from_value::<FinancialReceiptMetadata>(financial.clone()).map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "tool receipt `{}` has invalid financial metadata: {error}",
                receipt.id
            ))
        })?;
    if financial.currency.len() != 3
        || !financial
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return Err(ReceiptStoreError::Conflict(format!(
            "tool receipt `{}` has invalid financial currency",
            receipt.id
        )));
    }
    Ok((
        Some(financial.currency),
        Some(financial.cost_charged.to_be_bytes().to_vec()),
    ))
}

pub(crate) fn migrate_receipt_cost_projection(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), ReceiptStoreError> {
    migrate_receipt_cost_projection_table(
        transaction,
        "chio_tool_receipts",
        "PRAGMA table_info(chio_tool_receipts)",
        RECEIPT_COST_INDEX_SQL,
        RECEIPT_GLOBAL_COST_INDEX_SQL,
        "tool receipt cost projection migration",
    )
}

pub(crate) fn verify_receipt_cost_projection(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    verify_receipt_cost_projection_schema(
        connection,
        "sqlite_schema",
        "PRAGMA table_info(chio_tool_receipts)",
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'chio_tool_receipts'",
        true,
    )
}

pub(crate) fn audit_receipt_cost_projection(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    reconcile_receipt_cost_projection(
        connection,
        "chio_tool_receipts",
        "persisted tool receipt cost projection",
        false,
    )
}

pub(crate) fn migrate_archive_receipt_cost_projection(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), ReceiptStoreError> {
    migrate_receipt_cost_projection_table(
        transaction,
        "archive.chio_tool_receipts",
        "PRAGMA archive.table_info(chio_tool_receipts)",
        ARCHIVE_RECEIPT_COST_INDEX_SQL,
        ARCHIVE_RECEIPT_GLOBAL_COST_INDEX_SQL,
        "archived tool receipt cost projection migration",
    )
}

pub(crate) fn verify_archive_receipt_cost_projection(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    verify_receipt_cost_projection_schema(
        connection,
        "archive.sqlite_schema",
        "PRAGMA archive.table_info(chio_tool_receipts)",
        "SELECT sql FROM archive.sqlite_schema WHERE type = 'table' AND name = 'chio_tool_receipts'",
        false,
    )
}

fn verify_receipt_cost_projection_schema(
    connection: &Connection,
    schema_catalog: &str,
    table_info: &str,
    table_schema: &str,
    include_guards: bool,
) -> Result<(), ReceiptStoreError> {
    let mut columns = connection
        .prepare(table_info)?
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    columns.retain(|(name, _)| name == "cost_currency" || name == "cost_charged_be");
    columns.sort();
    if columns
        != [
            ("cost_charged_be".to_string(), "BLOB".to_string()),
            ("cost_currency".to_string(), "TEXT".to_string()),
        ]
    {
        return Err(receipt_cost_schema_error());
    }

    let table_sql = connection
        .query_row(table_schema, [], |row| row.get::<_, String>(0))
        .optional()?
        .ok_or_else(receipt_cost_schema_error)?;
    let normalized_table_sql = normalize_schema_sql(&table_sql);
    if !normalized_table_sql.contains(&normalize_schema_sql(RECEIPT_COST_CURRENCY_COLUMN))
        || !normalized_table_sql.contains(&normalize_schema_sql(RECEIPT_COST_KEY_COLUMN))
    {
        return Err(receipt_cost_schema_error());
    }

    let reference = Connection::open_in_memory()?;
    reference.execute_batch(RECEIPT_COST_REFERENCE_SCHEMA)?;
    reference.execute(RECEIPT_COST_INDEX_SQL, [])?;
    reference.execute(RECEIPT_GLOBAL_COST_INDEX_SQL, [])?;
    if include_guards {
        ensure_transparency_projection_guards(&reference)?;
    }
    if receipt_cost_schema_catalog(connection, schema_catalog)?
        != receipt_cost_schema_catalog(&reference, "sqlite_schema")?
    {
        return Err(receipt_cost_schema_error());
    }
    Ok(())
}

fn receipt_cost_schema_catalog(
    connection: &Connection,
    schema_catalog: &str,
) -> Result<Vec<ReceiptCostSchemaObject>, ReceiptStoreError> {
    let sql = format!(
        "SELECT type, name, tbl_name, sql FROM {schema_catalog} \
         WHERE name IN (\
             'idx_chio_tool_receipts_cost', \
             'idx_chio_tool_receipts_cost_global', \
             'chio_tool_receipts_reject_update', \
             'chio_tool_receipts_reject_delete'\
         ) ORDER BY type ASC, name ASC"
    );
    connection
        .prepare(&sql)?
        .query_map([], |row| {
            Ok(ReceiptCostSchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ReceiptStoreError::from)
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn receipt_cost_schema_error() -> ReceiptStoreError {
    ReceiptStoreError::Conflict(
        "receipt cost projection schema differs from the canonical definition".to_string(),
    )
}

fn migrate_receipt_cost_projection_table(
    transaction: &rusqlite::Transaction<'_>,
    table: &str,
    table_info: &str,
    create_index: &str,
    create_global_index: &str,
    context: &str,
) -> Result<(), ReceiptStoreError> {
    let columns = transaction
        .prepare(table_info)?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "cost_currency") {
        transaction.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {RECEIPT_COST_CURRENCY_COLUMN}"),
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "cost_charged_be") {
        transaction.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {RECEIPT_COST_KEY_COLUMN}"),
            [],
        )?;
    }

    reconcile_receipt_cost_projection(transaction, table, context, true)?;
    transaction.execute(create_index, [])?;
    transaction.execute(create_global_index, [])?;
    Ok(())
}

fn reconcile_receipt_cost_projection(
    connection: &Connection,
    table: &str,
    context: &str,
    backfill_missing: bool,
) -> Result<(), ReceiptStoreError> {
    let mut previous_seq = 0_i64;
    loop {
        let sql = format!(
            "SELECT seq, raw_json, cost_currency, cost_charged_be FROM {table} \
             WHERE seq > ?1 ORDER BY seq ASC LIMIT 1"
        );
        let row = connection
            .query_row(&sql, [previous_seq], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })
            .optional()?;
        let Some((seq, raw_json, existing_currency, existing_key)) = row else {
            break;
        };
        let receipt = decode_verified_chio_receipt(
            &raw_json,
            context,
            Some(sqlite_positive_u64(seq, "tool receipt source_seq")?),
        )?;
        let (expected_currency, expected_key) = receipt_cost_projection(&receipt)?;
        if existing_currency.is_none() && existing_key.is_none() {
            if expected_currency.is_some() {
                if backfill_missing {
                    connection.execute(
                        &format!(
                            "UPDATE {table} SET cost_currency = ?1, cost_charged_be = ?2 WHERE seq = ?3"
                        ),
                        params![expected_currency.as_deref(), expected_key.as_deref(), seq],
                    )?;
                } else {
                    return Err(ReceiptStoreError::Conflict(format!(
                        "tool receipt `{}` already exists with different cost projection",
                        receipt.id
                    )));
                }
            }
        } else if existing_currency != expected_currency || existing_key != expected_key {
            return Err(ReceiptStoreError::Conflict(format!(
                "tool receipt `{}` already exists with different cost projection",
                receipt.id
            )));
        }
        previous_seq = seq;
    }
    Ok(())
}

pub(crate) fn ensure_tool_receipt_attribution_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(chio_tool_receipts)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;

    if !columns.iter().any(|column| column == "subject_key") {
        connection.execute(
            "ALTER TABLE chio_tool_receipts ADD COLUMN subject_key TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "issuer_key") {
        connection.execute(
            "ALTER TABLE chio_tool_receipts ADD COLUMN issuer_key TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "grant_index") {
        connection.execute(
            "ALTER TABLE chio_tool_receipts ADD COLUMN grant_index INTEGER",
            [],
        )?;
    }

    // Multi-tenant receipt isolation: tenant_id column.
    //
    // Pre-multitenant receipts migrate to NULL, which the
    // tenant-scoped WHERE clause treats as a "public" fallback set (a
    // tenant A query returns its own rows AND the NULL-tagged pre-multitenant
    // set), so historical data remains visible under query modes that
    // opt into backward compatibility. Operators that need strict
    // isolation across the pre-multitenant set can enable
    // [`SqliteReceiptStore::with_strict_tenant_isolation`].
    //
    // Migration fails closed: if the column cannot be added we bail
    // out and the caller treats the store as unreadable, per the
    // kernel's fail-closed convention.
    if !columns.iter().any(|column| column == "tenant_id") {
        connection.execute(
            "ALTER TABLE chio_tool_receipts ADD COLUMN tenant_id TEXT",
            [],
        )?;
    }

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_subject ON chio_tool_receipts(subject_key)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_grant ON chio_tool_receipts(capability_id, grant_index)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_tenant ON chio_tool_receipts(tenant_id)",
        [],
    )?;
    Ok(())
}

pub(crate) fn ensure_receipt_lineage_statement_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(receipt_lineage_statements)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;

    if !columns.iter().any(|column| column == "statement_id") {
        connection.execute(
            "ALTER TABLE receipt_lineage_statements ADD COLUMN statement_id TEXT",
            [],
        )?;
    }

    connection.execute(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_lineage_statement_id
            ON receipt_lineage_statements(statement_id)
            WHERE statement_id IS NOT NULL
        "#,
        [],
    )?;
    connection.execute(
        r#"
        UPDATE receipt_lineage_statements
        SET statement_id = json_extract(raw_json, '$.id')
        WHERE statement_id IS NULL
          AND json_extract(raw_json, '$.schema') = ?1
        "#,
        params![chio_core::receipt::lineage::CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA],
    )?;
    Ok(())
}

pub(crate) fn backfill_tool_receipt_attribution_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        UPDATE chio_tool_receipts
        SET grant_index = CAST(COALESCE(
            json_extract(raw_json, '$.metadata.attribution.grant_index'),
            json_extract(raw_json, '$.metadata.financial.grant_index')
        ) AS INTEGER)
        WHERE grant_index IS NULL
          AND COALESCE(
                json_extract(raw_json, '$.metadata.attribution.grant_index'),
                json_extract(raw_json, '$.metadata.financial.grant_index')
              ) IS NOT NULL;

        UPDATE chio_tool_receipts
        SET subject_key = COALESCE(
            subject_key,
            CAST(json_extract(raw_json, '$.metadata.attribution.subject_key') AS TEXT),
            (SELECT cl.subject_key FROM capability_lineage cl WHERE cl.capability_id = chio_tool_receipts.capability_id)
        )
        WHERE subject_key IS NULL
          AND COALESCE(
                CAST(json_extract(raw_json, '$.metadata.attribution.subject_key') AS TEXT),
                (SELECT cl.subject_key FROM capability_lineage cl WHERE cl.capability_id = chio_tool_receipts.capability_id)
              ) IS NOT NULL;

        UPDATE chio_tool_receipts
        SET issuer_key = COALESCE(
            issuer_key,
            CAST(json_extract(raw_json, '$.metadata.attribution.issuer_key') AS TEXT),
            (SELECT cl.issuer_key FROM capability_lineage cl WHERE cl.capability_id = chio_tool_receipts.capability_id)
        )
        WHERE issuer_key IS NULL
          AND COALESCE(
                CAST(json_extract(raw_json, '$.metadata.attribution.issuer_key') AS TEXT),
                (SELECT cl.issuer_key FROM capability_lineage cl WHERE cl.capability_id = chio_tool_receipts.capability_id)
              ) IS NOT NULL;

        -- Multi-tenant receipt isolation: hydrate tenant_id
        -- from the canonical receipt body. Pre-multitenant receipts (NULL-tagged)
        -- that were stored before the field existed stay NULL, which
        -- means "public / visible to any tenant under the default
        -- compat query mode". Operators who want to purge those
        -- pre-multitenant rows can enable strict tenant isolation on queries.
        --
        -- The receipt body uses snake_case field names (no rename_all),
        -- so the JSON key is `tenant_id`, not `tenantId`.
        UPDATE chio_tool_receipts
        SET tenant_id = CAST(json_extract(raw_json, '$.tenant_id') AS TEXT)
        WHERE tenant_id IS NULL
          AND json_extract(raw_json, '$.tenant_id') IS NOT NULL;
        "#,
    )?;
    Ok(())
}
