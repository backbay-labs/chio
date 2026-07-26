//! SQLite-backed persistence for [`DeadLetterRecord`] rows.
//!
//! The `settle_dead_letters` table is keyed by `receipt_id` so a
//! finalized receipt can have at most one dead-letter row at any time.
//! Re-inserting the same record is idempotent: a byte-identical row
//! returns `Ok(false)`; a different row returns
//! [`DeadLetterStoreError::Conflict`].
//!
//! Fail-closed: once a row is persisted the kernel observer slot
//! MUST NOT replay the failed settlement until an operator clears
//! the row via [`SqliteDeadLetterStore::clear`]. There is no
//! auto-retry past the documented bound.
//!
//! The migration is `CREATE TABLE IF NOT EXISTS` plus
//! `CREATE INDEX IF NOT EXISTS`, so it can run repeatedly against a
//! receipt-store database that already holds other tables.

use chio_core::canonical::canonical_json_bytes;
use chio_settle::{DeadLetterRecord, SETTLE_DEAD_LETTER_SCHEMA};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use thiserror::Error;

/// SQL migration applied by [`SqliteDeadLetterStore::open_with_pool`]
/// to create the `settle_dead_letters` table.
pub const SETTLE_DEAD_LETTERS_MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS settle_dead_letters (
    receipt_id TEXT PRIMARY KEY,
    finalized_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL,
    reason TEXT NOT NULL,
    pipeline_error TEXT,
    canonical_json TEXT NOT NULL,
    recorded_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_settle_dead_letters_finalized_at
    ON settle_dead_letters(finalized_at);
"#;

/// Errors surfaced from the SQLite-backed dead-letter store.
#[derive(Debug, Error)]
pub enum DeadLetterStoreError {
    /// Connection-pool or SQLite error.
    #[error("dead letter backend error: {0}")]
    Backend(String),
    /// A different dead-letter row already exists for this receipt.
    /// Operators should clear the row explicitly before replacing it.
    #[error("dead letter conflict: {0}")]
    Conflict(String),
    /// The record is not valid for the schema understood by this build.
    #[error("invalid dead letter record: {0}")]
    InvalidRecord(String),
}

fn dead_letter_row_error(error: rusqlite::Error) -> DeadLetterStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => DeadLetterStoreError::InvalidRecord(
            "dead-letter row contains an invalid SQLite value".to_string(),
        ),
        other => DeadLetterStoreError::Backend(other.to_string()),
    }
}

struct StoredDeadLetterRow {
    receipt_id: String,
    finalized_at: i64,
    attempts: i64,
    reason: String,
    pipeline_error: Option<String>,
    canonical: String,
}

#[derive(Deserialize)]
struct DeadLetterSchemaProbe {
    schema: String,
}

/// SQLite-backed dead-letter store. Wraps an existing connection pool
/// from [`crate::SqliteReceiptStore`] so dead-letter writes share the
/// same SQLite database and journal mode.
pub struct SqliteDeadLetterStore {
    pool: Pool<SqliteConnectionManager>,
    writer: Option<crate::receipt_store::WriterHandle>,
}

fn encode_dead_letter(record: &DeadLetterRecord) -> Result<(i64, Vec<u8>), DeadLetterStoreError> {
    if !record.has_supported_schema() {
        return Err(DeadLetterStoreError::InvalidRecord(
            "unsupported programmatic settlement dead-letter schema".to_string(),
        ));
    }
    if record.receipt_id.is_empty() {
        return Err(DeadLetterStoreError::InvalidRecord(
            "receipt_id must not be empty".to_string(),
        ));
    }
    if record.attempts == 0 {
        return Err(DeadLetterStoreError::InvalidRecord(
            "attempts must be at least one".to_string(),
        ));
    }

    let finalized_at =
        record
            .finalized_at
            .try_into()
            .map_err(|err: std::num::TryFromIntError| {
                DeadLetterStoreError::InvalidRecord(err.to_string())
            })?;
    let canonical = canonical_json_bytes(record)
        .map_err(|err| DeadLetterStoreError::InvalidRecord(err.to_string()))?;
    Ok((finalized_at, canonical))
}

fn read_stored_dead_letter_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredDeadLetterRow> {
    Ok(StoredDeadLetterRow {
        receipt_id: row.get(0)?,
        finalized_at: row.get(1)?,
        attempts: row.get(2)?,
        reason: row.get(3)?,
        pipeline_error: row.get(4)?,
        canonical: row.get(5)?,
    })
}

fn decode_stored_dead_letter(
    row: StoredDeadLetterRow,
) -> Result<DeadLetterRecord, DeadLetterStoreError> {
    let finalized_at: u64 =
        row.finalized_at
            .try_into()
            .map_err(|_: std::num::TryFromIntError| {
                DeadLetterStoreError::InvalidRecord(
                    "persisted finalized_at is outside the u64 range".to_string(),
                )
            })?;
    let attempts: u32 = row
        .attempts
        .try_into()
        .map_err(|_: std::num::TryFromIntError| {
            DeadLetterStoreError::InvalidRecord(
                "persisted attempts is outside the u32 range".to_string(),
            )
        })?;
    let schema: DeadLetterSchemaProbe = serde_json::from_str(&row.canonical)
        .map_err(|err| DeadLetterStoreError::InvalidRecord(err.to_string()))?;
    if schema.schema != SETTLE_DEAD_LETTER_SCHEMA {
        return Err(DeadLetterStoreError::InvalidRecord(
            "unsupported persisted settlement dead-letter schema".to_string(),
        ));
    }
    let record: DeadLetterRecord = serde_json::from_str(&row.canonical)
        .map_err(|err| DeadLetterStoreError::InvalidRecord(err.to_string()))?;
    let (_, canonical) = encode_dead_letter(&record)?;
    let columns_match = record.receipt_id == row.receipt_id
        && record.finalized_at == finalized_at
        && record.attempts == attempts
        && record.reason.code().as_str() == row.reason
        && row.pipeline_error.is_none()
        && canonical.as_slice() == row.canonical.as_bytes();
    if columns_match {
        Ok(record)
    } else {
        Err(DeadLetterStoreError::InvalidRecord(
            "SQLite columns do not match canonical dead-letter bytes".to_string(),
        ))
    }
}

fn select_dead_letter_row(
    connection: &rusqlite::Connection,
    receipt_id: &str,
) -> Result<Option<StoredDeadLetterRow>, DeadLetterStoreError> {
    connection
        .query_row(
            "SELECT receipt_id, finalized_at, attempts, reason, pipeline_error, canonical_json \
             FROM settle_dead_letters WHERE receipt_id = ?1",
            params![receipt_id],
            read_stored_dead_letter_row,
        )
        .optional()
        .map_err(dead_letter_row_error)
}

/// Insert a current-schema row or verify a byte-identical existing row.
///
/// The caller owns transaction boundaries. This function is suitable for a
/// larger settlement transition that already holds an immediate transaction.
pub(crate) fn insert_dead_letter_on_connection(
    connection: &rusqlite::Connection,
    record: &DeadLetterRecord,
) -> Result<bool, DeadLetterStoreError> {
    let (finalized_at, canonical) = encode_dead_letter(record)?;
    let canonical = std::str::from_utf8(&canonical)
        .map_err(|err| DeadLetterStoreError::InvalidRecord(err.to_string()))?;
    let inserted = connection
        .execute(
            "INSERT INTO settle_dead_letters \
                (receipt_id, finalized_at, attempts, reason, pipeline_error, canonical_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(receipt_id) DO NOTHING",
            params![
                record.receipt_id.as_str(),
                finalized_at,
                i64::from(record.attempts),
                record.reason.code().as_str(),
                Option::<&str>::None,
                canonical,
            ],
        )
        .map_err(|err| {
            if err.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                DeadLetterStoreError::Conflict(
                    "dead letter conflicts with active settlement work".to_string(),
                )
            } else {
                DeadLetterStoreError::Backend(err.to_string())
            }
        })?;
    if inserted == 1 {
        return Ok(true);
    }

    let existing = select_dead_letter_row(connection, record.receipt_id.as_str())?;
    match existing {
        Some(existing) if existing.canonical.as_bytes() == canonical.as_bytes() => {
            decode_stored_dead_letter(existing)?;
            Ok(false)
        }
        Some(_) => Err(DeadLetterStoreError::Conflict(format!(
            "settle_dead_letters row for receipt_id={} already exists with different bytes",
            record.receipt_id
        ))),
        None => Err(DeadLetterStoreError::Backend(format!(
            "settle_dead_letters conflict for receipt_id={} but no row was readable",
            record.receipt_id
        ))),
    }
}

/// Read and decode one dead-letter row.
pub(crate) fn read_dead_letter_on_connection(
    connection: &rusqlite::Connection,
    receipt_id: &str,
) -> Result<Option<DeadLetterRecord>, DeadLetterStoreError> {
    select_dead_letter_row(connection, receipt_id)?
        .map(decode_stored_dead_letter)
        .transpose()
}

fn insert_dead_letter_transaction(
    connection: &mut rusqlite::Connection,
    record: &DeadLetterRecord,
) -> Result<bool, DeadLetterStoreError> {
    let tx = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
    let inserted = insert_dead_letter_on_connection(&tx, record)?;
    tx.commit()
        .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
    Ok(inserted)
}

fn clear_dead_letter_on_connection(
    connection: &rusqlite::Connection,
    receipt_id: &str,
) -> Result<bool, DeadLetterStoreError> {
    connection
        .execute(
            "DELETE FROM settle_dead_letters WHERE receipt_id = ?1",
            params![receipt_id],
        )
        .map(|affected| affected > 0)
        .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))
}

const WRITER_BACKEND_TAG: &str = "chio-store-sqlite/dead-letter/backend:";
const WRITER_CONFLICT_TAG: &str = "chio-store-sqlite/dead-letter/conflict:";
const WRITER_INVALID_RECORD_TAG: &str = "chio-store-sqlite/dead-letter/invalid-record:";

fn dead_letter_error_into_receipt_store(
    error: DeadLetterStoreError,
) -> chio_kernel::ReceiptStoreError {
    match error {
        DeadLetterStoreError::Conflict(message) => {
            chio_kernel::ReceiptStoreError::Conflict(format!("{WRITER_CONFLICT_TAG}{message}"))
        }
        DeadLetterStoreError::InvalidRecord(message) => chio_kernel::ReceiptStoreError::Canonical(
            format!("{WRITER_INVALID_RECORD_TAG}{message}"),
        ),
        DeadLetterStoreError::Backend(message) => {
            chio_kernel::ReceiptStoreError::Pool(format!("{WRITER_BACKEND_TAG}{message}"))
        }
    }
}

fn dead_letter_error_from_receipt_store(
    error: chio_kernel::ReceiptStoreError,
) -> DeadLetterStoreError {
    match error {
        chio_kernel::ReceiptStoreError::Conflict(message) => {
            if let Some(message) = message.strip_prefix(WRITER_CONFLICT_TAG) {
                DeadLetterStoreError::Conflict(message.to_string())
            } else {
                DeadLetterStoreError::Backend(format!("receipt writer conflict: {message}"))
            }
        }
        chio_kernel::ReceiptStoreError::Canonical(message) => {
            if let Some(message) = message.strip_prefix(WRITER_INVALID_RECORD_TAG) {
                DeadLetterStoreError::InvalidRecord(message.to_string())
            } else {
                DeadLetterStoreError::Backend(format!("receipt writer canonical error: {message}"))
            }
        }
        chio_kernel::ReceiptStoreError::Pool(message) => {
            if let Some(message) = message.strip_prefix(WRITER_BACKEND_TAG) {
                DeadLetterStoreError::Backend(message.to_string())
            } else {
                DeadLetterStoreError::Backend(format!("receipt writer pool error: {message}"))
            }
        }
        other => DeadLetterStoreError::Backend(other.to_string()),
    }
}

impl SqliteDeadLetterStore {
    /// Open a store backed by the same pool as a sibling receipt
    /// store. Runs the additive migration if the table is absent.
    pub fn open_with_pool(
        pool: Pool<SqliteConnectionManager>,
    ) -> Result<Self, DeadLetterStoreError> {
        let connection = pool
            .get()
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        connection
            .execute_batch(SETTLE_DEAD_LETTERS_MIGRATION)
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        Ok(Self { pool, writer: None })
    }

    /// Construct the store sharing the connection pool of an existing
    /// [`crate::SqliteReceiptStore`].
    pub fn open_alongside(store: &crate::SqliteReceiptStore) -> Result<Self, DeadLetterStoreError> {
        let writer = store.writer_handle();
        writer
            .run_write(|connection| {
                connection
                    .execute_batch(SETTLE_DEAD_LETTERS_MIGRATION)
                    .map_err(chio_kernel::ReceiptStoreError::from)
            })
            .map_err(dead_letter_error_from_receipt_store)?;
        Ok(Self {
            pool: store.pool.clone(),
            writer: Some(writer),
        })
    }

    /// Persist a dead-letter record. Idempotent on byte-identical
    /// re-inserts; returns [`DeadLetterStoreError::Conflict`] if a
    /// different record already exists for the same receipt.
    pub fn insert(&self, record: &DeadLetterRecord) -> Result<bool, DeadLetterStoreError> {
        match &self.writer {
            Some(writer) => {
                let record = record.clone();
                writer
                    .run_write(move |connection| {
                        insert_dead_letter_transaction(connection, &record)
                            .map_err(dead_letter_error_into_receipt_store)
                    })
                    .map_err(dead_letter_error_from_receipt_store)
            }
            None => {
                let mut connection = self
                    .pool
                    .get()
                    .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
                insert_dead_letter_transaction(&mut connection, record)
            }
        }
    }

    /// Look up a single dead-letter record by `receipt_id`.
    pub fn get(&self, receipt_id: &str) -> Result<Option<DeadLetterRecord>, DeadLetterStoreError> {
        let connection = self
            .pool
            .get()
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        read_dead_letter_on_connection(&connection, receipt_id)
    }

    /// List all dead-letter records sorted by finalization time then
    /// receipt id (matching the deterministic settlement ordering).
    pub fn list(&self) -> Result<Vec<DeadLetterRecord>, DeadLetterStoreError> {
        let connection = self
            .pool
            .get()
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        let mut stmt = connection
            .prepare(
                "SELECT receipt_id, finalized_at, attempts, reason, pipeline_error, canonical_json \
                 FROM settle_dead_letters \
                 ORDER BY finalized_at ASC, receipt_id ASC",
            )
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        let rows = stmt
            .query_map([], read_stored_dead_letter_row)
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            let row = row.map_err(dead_letter_row_error)?;
            out.push(decode_stored_dead_letter(row)?);
        }
        Ok(out)
    }

    /// Remove a dead-letter row. Returns `true` if a row was deleted.
    pub fn clear(&self, receipt_id: &str) -> Result<bool, DeadLetterStoreError> {
        match &self.writer {
            Some(writer) => {
                let receipt_id = receipt_id.to_string();
                writer
                    .run_write(move |connection| {
                        clear_dead_letter_on_connection(connection, &receipt_id)
                            .map_err(dead_letter_error_into_receipt_store)
                    })
                    .map_err(dead_letter_error_from_receipt_store)
            }
            None => {
                let connection = self
                    .pool
                    .get()
                    .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
                clear_dead_letter_on_connection(&connection, receipt_id)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chio_core::canonical::canonical_json_bytes;
    use chio_settle::{DeadLetterRecord, SettlementFailureCode, SettlementFailureReason};
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;
    use rusqlite::params;
    use tempfile::tempdir;

    use chio_test_support::prelude::*;

    const UNBOUNDED_V1_FIXTURE: &str = r#"{"schema":"chio.settle.dead-letter.v1","receipt_id":"old-1","finalized_at":17,"attempts":2,"reason":"rpc unavailable","pipeline_error":"settlement pipeline error: rpc unavailable"}"#;

    fn pool() -> Pool<SqliteConnectionManager> {
        let manager = SqliteConnectionManager::memory();
        Pool::builder()
            .max_size(2)
            .build(manager)
            .test_expect("test pool builds")
    }

    fn sample_record(receipt_id: &str, attempts: u32) -> DeadLetterRecord {
        DeadLetterRecord::new(
            receipt_id,
            100,
            attempts,
            SettlementFailureReason::from_detail(SettlementFailureCode::Rpc, "connection refused"),
        )
    }

    #[test]
    fn migration_is_idempotent() {
        let pool = pool();
        SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("first open");
        SqliteDeadLetterStore::open_with_pool(pool).test_expect("second open");
    }

    #[test]
    fn insert_persists_and_get_round_trips() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");
        let record = sample_record("rcpt-1", 4);
        assert!(store.insert(&record).test_expect("insert ok"));
        let loaded = store
            .get("rcpt-1")
            .test_expect("get ok")
            .test_expect("row present");
        assert_eq!(loaded, record);
    }

    #[test]
    fn insert_writes_rfc_8785_bytes_and_bounded_columns() {
        let pool = pool();
        let store = SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("store opens");
        let record = sample_record("rcpt-canonical", 4);
        store.insert(&record).test_expect("insert succeeds");

        let connection = pool.get().test_expect("connection opens");
        let (reason, pipeline_error, canonical): (String, Option<String>, String) = connection
            .query_row(
                "SELECT reason, pipeline_error, canonical_json FROM settle_dead_letters WHERE receipt_id = ?1",
                params![record.receipt_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .test_expect("row loads");
        let expected = canonical_json_bytes(&record).test_expect("record canonicalizes");

        assert_eq!(reason, "rpc");
        assert_eq!(pipeline_error, None);
        assert_eq!(canonical.as_bytes(), expected);
        assert!(canonical.starts_with("{\"attempts\":"));
    }

    #[test]
    fn insert_rejects_an_unsupported_schema() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");
        let mut record = sample_record("rcpt-schema", 1);
        record.schema = "chio.settle.dead-letter.v99".to_string();

        assert!(matches!(
            store.insert(&record),
            Err(DeadLetterStoreError::InvalidRecord(message))
                if message.contains("schema")
        ));
        assert!(store
            .get("rcpt-schema")
            .test_expect("get succeeds")
            .is_none());
    }

    #[test]
    fn insert_is_idempotent_on_byte_identical_replays() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");
        let record = sample_record("rcpt-2", 3);
        assert!(store
            .insert(&record)
            .test_expect("first insert returns true"));
        assert!(!store
            .insert(&record)
            .test_expect("second insert returns false"));
    }

    #[test]
    fn byte_identical_replay_rejects_mismatched_sql_columns() {
        let pool = pool();
        let store = SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("store opens");
        let record = sample_record("rcpt-tampered-columns", 3);
        store.insert(&record).test_expect("first insert succeeds");
        pool.get()
            .test_expect("connection opens")
            .execute(
                "UPDATE settle_dead_letters SET reason = ?1, pipeline_error = ?2 \
                 WHERE receipt_id = ?3",
                params!["backend", "raw pipeline detail", record.receipt_id.as_str()],
            )
            .test_expect("row columns change");

        assert!(matches!(
            store.insert(&record),
            Err(DeadLetterStoreError::InvalidRecord(_))
        ));
        assert!(matches!(
            store.get(record.receipt_id.as_str()),
            Err(DeadLetterStoreError::InvalidRecord(_))
        ));
        assert!(matches!(
            store.list(),
            Err(DeadLetterStoreError::InvalidRecord(_))
        ));
    }

    #[test]
    fn malformed_persisted_numeric_type_is_invalid_record() {
        let pool = pool();
        let store = SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("store opens");
        let record = sample_record("malformed-number", 1);
        store.insert(&record).test_expect("record inserts");
        pool.get()
            .test_expect("connection opens")
            .execute(
                "UPDATE settle_dead_letters SET finalized_at = 'not-a-number' \
                 WHERE receipt_id = ?1",
                [record.receipt_id.as_str()],
            )
            .test_expect("malformed numeric value persists");

        assert!(matches!(
            store.get(&record.receipt_id),
            Err(DeadLetterStoreError::InvalidRecord(_))
        ));
    }

    #[test]
    fn insert_with_different_bytes_returns_conflict() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");
        let record = sample_record("rcpt-3", 2);
        store.insert(&record).test_expect("first insert");
        let mut conflicting = record.clone();
        conflicting.reason =
            SettlementFailureReason::from_detail(SettlementFailureCode::Rpc, "different reason");
        let err = store
            .insert(&conflicting)
            .test_expect_err("byte-different second insert errors");
        match err {
            DeadLetterStoreError::Conflict(message) => {
                assert!(message.contains("rcpt-3"));
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn unbounded_v1_body_fails_closed() {
        let pool = pool();
        let store = SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("store opens");
        let connection = pool.get().test_expect("connection opens");
        connection
            .execute(
                "INSERT INTO settle_dead_letters \
                 (receipt_id, finalized_at, attempts, reason, pipeline_error, canonical_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    "old-1",
                    17_i64,
                    2_i64,
                    "rpc unavailable",
                    "settlement pipeline error: rpc unavailable",
                    UNBOUNDED_V1_FIXTURE,
                ],
            )
            .test_expect("old row inserts");
        drop(connection);

        assert!(matches!(
            store.get("old-1"),
            Err(DeadLetterStoreError::InvalidRecord(_))
        ));
    }

    #[test]
    fn unknown_persisted_schema_fails_closed() {
        let pool = pool();
        let store = SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("store opens");
        let connection = pool.get().test_expect("connection opens");
        connection
            .execute(
                "INSERT INTO settle_dead_letters \
                 (receipt_id, finalized_at, attempts, reason, canonical_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    "unknown-1",
                    17_i64,
                    1_i64,
                    "rpc",
                    r#"{"schema":"chio.settle.dead-letter.v99","receipt_id":"unknown-1","finalized_at":17,"attempts":1,"reason":"rpc"}"#,
                ],
            )
            .test_expect("unknown row inserts");
        drop(connection);

        assert!(matches!(
            store.get("unknown-1"),
            Err(DeadLetterStoreError::InvalidRecord(message))
                if message.contains("unsupported")
        ));
    }

    #[test]
    fn noncanonical_body_fails_closed_on_read() {
        let pool = pool();
        let store = SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("store opens");
        let record = sample_record("noncanonical", 1);
        let noncanonical = serde_json::to_string(&record).test_expect("record serializes");
        assert_ne!(
            noncanonical.as_bytes(),
            canonical_json_bytes(&record)
                .test_expect("record canonicalizes")
                .as_slice()
        );
        pool.get()
            .test_expect("connection opens")
            .execute(
                "INSERT INTO settle_dead_letters \
                 (receipt_id, finalized_at, attempts, reason, pipeline_error, canonical_json) \
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
                params![
                    record.receipt_id.as_str(),
                    100_i64,
                    1_i64,
                    record.reason.code().as_str(),
                    noncanonical,
                ],
            )
            .test_expect("noncanonical row inserts");

        assert!(matches!(
            store.get(record.receipt_id.as_str()),
            Err(DeadLetterStoreError::InvalidRecord(_))
        ));
    }

    #[test]
    fn list_orders_by_finalization_time_then_receipt_id() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");
        let mut a = sample_record("rcpt-b", 1);
        a.finalized_at = 5;
        let mut b = sample_record("rcpt-a", 1);
        b.finalized_at = 5;
        let mut c = sample_record("rcpt-c", 1);
        c.finalized_at = 10;
        store.insert(&a).test_expect("insert a");
        store.insert(&b).test_expect("insert b");
        store.insert(&c).test_expect("insert c");
        let listed = store.list().test_expect("list ok");
        assert_eq!(
            listed
                .iter()
                .map(|record| record.receipt_id.as_str())
                .collect::<Vec<_>>(),
            vec!["rcpt-a", "rcpt-b", "rcpt-c"]
        );
    }

    #[test]
    fn clear_removes_existing_row() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");
        let record = sample_record("rcpt-4", 1);
        store.insert(&record).test_expect("insert");
        assert!(store.clear("rcpt-4").test_expect("clear ok"));
        assert!(store.get("rcpt-4").test_expect("get ok").is_none());
        assert!(!store.clear("rcpt-4").test_expect("idempotent clear ok"));
    }

    #[test]
    fn open_alongside_routes_failures_through_receipt_writer_health() {
        let dir = tempdir().test_expect("temporary directory creates");
        let path = dir.path().join("dead-letter-writer.sqlite3");
        let receipt_store =
            crate::SqliteReceiptStore::open(&path).test_expect("receipt store opens");
        let store = SqliteDeadLetterStore::open_alongside(&receipt_store)
            .test_expect("dead-letter store opens");
        assert!(store.writer.is_some());

        let first = sample_record("rcpt-writer", 1);
        let mut conflicting = first.clone();
        conflicting.attempts = 2;
        store.insert(&first).test_expect("first insert succeeds");
        let failed_before = receipt_store
            .flush_receipt_writes()
            .test_expect("writer flushes")
            .writer
            .failed_total;
        assert!(matches!(
            store.insert(&conflicting),
            Err(DeadLetterStoreError::Conflict(_))
        ));
        let failed_after = receipt_store
            .flush_receipt_writes()
            .test_expect("writer flushes after conflict")
            .writer
            .failed_total;

        assert_eq!(failed_after, failed_before + 1);
    }

    #[test]
    fn untagged_receipt_writer_errors_remain_backend_errors() {
        for error in [
            chio_kernel::ReceiptStoreError::Canonical("writer job panicked".to_string()),
            chio_kernel::ReceiptStoreError::Conflict("head resync conflict".to_string()),
        ] {
            assert!(matches!(
                dead_letter_error_from_receipt_store(error),
                DeadLetterStoreError::Backend(_)
            ));
        }
    }
}
