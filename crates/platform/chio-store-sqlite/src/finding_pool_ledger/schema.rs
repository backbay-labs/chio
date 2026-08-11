use chio_kernel::finding_pool::{FindingPoolLedgerError, FindingPoolLedgerError::Storage};

use super::invariant;

pub(super) fn ensure_lifecycle_columns(
    connection: &rusqlite::Connection,
) -> Result<(), FindingPoolLedgerError> {
    ensure_column(
        connection,
        "finding_pool_debits",
        "debit_request_binding_sha256",
        "ALTER TABLE finding_pool_debits ADD COLUMN debit_request_binding_sha256 TEXT",
    )?;
    ensure_column(
        connection,
        "finding_pool_allocations",
        "reserved_units",
        "ALTER TABLE finding_pool_allocations \
         ADD COLUMN reserved_units TEXT NOT NULL DEFAULT '0'",
    )?;
    ensure_column(
        connection,
        "finding_pool_debits",
        "state",
        "ALTER TABLE finding_pool_debits ADD COLUMN state TEXT NOT NULL \
         DEFAULT 'finalized' CHECK (state IN ('reserved', 'finalized', 'released'))",
    )?;
    ensure_column(
        connection,
        "finding_pool_debits",
        "reserved_after_units",
        "ALTER TABLE finding_pool_debits \
         ADD COLUMN reserved_after_units TEXT NOT NULL DEFAULT '0'",
    )?;
    ensure_column(
        connection,
        "finding_pool_debits",
        "claim_deadline_unix_ms",
        "ALTER TABLE finding_pool_debits \
         ADD COLUMN claim_deadline_unix_ms TEXT NOT NULL DEFAULT '0'",
    )?;
    ensure_column(
        connection,
        "finding_pool_debits",
        "claimed_at_unix_ms",
        "ALTER TABLE finding_pool_debits ADD COLUMN claimed_at_unix_ms TEXT",
    )?;
    ensure_column(
        connection,
        "finding_pool_debits",
        "durable_admission_operation_id",
        "ALTER TABLE finding_pool_debits ADD COLUMN durable_admission_operation_id TEXT",
    )?;
    connection
        .execute(
            "UPDATE finding_pool_debits SET claimed_at_unix_ms = '0' \
             WHERE state = 'reserved' AND claim_deadline_unix_ms = '0' \
               AND claimed_at_unix_ms IS NULL",
            [],
        )
        .map_err(|error| Storage(error.to_string()))?;
    let unbound_claims = connection
        .query_row(
            "SELECT COUNT(*) FROM finding_pool_debits \
             WHERE state = 'reserved' AND claimed_at_unix_ms IS NOT NULL \
               AND durable_admission_operation_id IS NULL",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| Storage(error.to_string()))?;
    if unbound_claims != 0 {
        return Err(invariant(
            "claimed reservation lacks its durable admission operation binding",
        ));
    }
    connection
        .execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS finding_pool_debits_admission_operation \
             ON finding_pool_debits(durable_admission_operation_id) \
             WHERE durable_admission_operation_id IS NOT NULL;",
        )
        .map_err(|error| Storage(error.to_string()))?;
    Ok(())
}

pub(super) fn ensure_outbox_delivery_claim_columns(
    connection: &rusqlite::Connection,
) -> Result<(), FindingPoolLedgerError> {
    ensure_column(
        connection,
        "finding_pool_receipt_outbox",
        "delivery_claim_owner",
        "ALTER TABLE finding_pool_receipt_outbox ADD COLUMN delivery_claim_owner TEXT",
    )?;
    ensure_column(
        connection,
        "finding_pool_receipt_outbox",
        "delivery_claim_expires_at_unix_ms",
        "ALTER TABLE finding_pool_receipt_outbox \
         ADD COLUMN delivery_claim_expires_at_unix_ms INTEGER",
    )?;
    ensure_column(
        connection,
        "finding_pool_receipt_outbox",
        "delivery_sequence",
        "ALTER TABLE finding_pool_receipt_outbox ADD COLUMN delivery_sequence INTEGER",
    )?;
    connection
        .execute(
            "UPDATE finding_pool_receipt_outbox SET delivery_sequence = rowid \
             WHERE delivery_sequence IS NULL",
            [],
        )
        .map_err(|error| Storage(error.to_string()))?;
    let missing = connection
        .query_row(
            "SELECT COUNT(*) FROM finding_pool_receipt_outbox \
             WHERE delivery_sequence IS NULL",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| Storage(error.to_string()))?;
    if missing != 0 {
        return Err(invariant(
            "mutation receipt outbox row lacks a delivery sequence",
        ));
    }
    Ok(())
}

pub(super) fn ensure_query_indexes(
    connection: &rusqlite::Connection,
) -> Result<(), FindingPoolLedgerError> {
    connection
        .execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS finding_pool_receipt_outbox_delivery_sequence \
                 ON finding_pool_receipt_outbox(delivery_sequence); \
             DROP INDEX IF EXISTS finding_pool_receipt_outbox_pending; \
             CREATE INDEX finding_pool_receipt_outbox_pending \
                 ON finding_pool_receipt_outbox(delivery_sequence) \
                 WHERE acknowledged_at_unix_ms IS NULL; \
             CREATE INDEX IF NOT EXISTS finding_pool_debits_expiration_reclamation \
                 ON finding_pool_debits(\
                     allocation_envelope_sha256, state, claimed_at_unix_ms, purchase_id\
                 ); \
             CREATE INDEX IF NOT EXISTS finding_pool_debits_expiration_reclamation_v2 \
                 ON finding_pool_debits(\
                     allocation_envelope_sha256, length(claim_deadline_unix_ms), \
                     claim_deadline_unix_ms, purchase_id\
                 ) WHERE state = 'reserved' AND claimed_at_unix_ms IS NULL;",
        )
        .map_err(|error| Storage(error.to_string()))
}

pub(super) fn ensure_column(
    connection: &rusqlite::Connection,
    table: &str,
    column: &str,
    ddl: &str,
) -> Result<(), FindingPoolLedgerError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|error| Storage(error.to_string()))?;
    let mut rows = statement
        .query([])
        .map_err(|error| Storage(error.to_string()))?;
    while let Some(row) = rows.next().map_err(|error| Storage(error.to_string()))? {
        let name = row
            .get::<_, String>(1)
            .map_err(|error| Storage(error.to_string()))?;
        if name == column {
            return Ok(());
        }
    }
    drop(rows);
    drop(statement);
    connection
        .execute_batch(ddl)
        .map_err(|error| Storage(error.to_string()))
}
