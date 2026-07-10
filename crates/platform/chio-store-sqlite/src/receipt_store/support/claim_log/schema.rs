use super::*;

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
