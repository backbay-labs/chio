//! SQLite-backed persistence for [`DeadLetterRecord`] rows.
//!
//! Adds an additive `settle_dead_letters` table on the existing
//! `chio-store-sqlite` connection. The table is keyed by `receipt_id`
//! so a finalized receipt can have at most one dead-letter row at any
//! time. Re-inserting the same record is idempotent: a byte-identical
//! row returns `Ok(false)`; a different row returns
//! [`DeadLetterStoreError::Conflict`].
//!
//! Fail-closed: once a row is persisted the kernel observer slot
//! MUST NOT replay the failed settlement until an operator clears
//! the row via [`SqliteDeadLetterStore::clear`]. There is no
//! auto-retry past the documented bound.
//!
//! No existing schema columns are dropped or renamed. The migration
//! is `CREATE TABLE IF NOT EXISTS` plus `CREATE INDEX IF NOT EXISTS`
//! so it can run repeatedly against an existing receipt store.

use chio_settle::DeadLetterRecord;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use thiserror::Error;

/// SQL migration applied by [`SqliteDeadLetterStore::open_with_pool`]
/// to add the `settle_dead_letters` table without touching existing
/// schema.
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
    /// Backend (connection pool, SQLite, JSON) error.
    #[error("dead letter backend error: {0}")]
    Backend(String),
    /// A different dead-letter row already exists for this receipt.
    /// Operators should clear the row explicitly before replacing it.
    #[error("dead letter conflict: {0}")]
    Conflict(String),
}

/// SQLite-backed dead-letter store. Wraps an existing connection pool
/// from [`crate::SqliteReceiptStore`] so dead-letter writes share the
/// same SQLite database and journal mode.
pub struct SqliteDeadLetterStore {
    pool: Pool<SqliteConnectionManager>,
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
        Ok(Self { pool })
    }

    /// Construct the store sharing the connection pool of an existing
    /// [`crate::SqliteReceiptStore`].
    pub fn open_alongside(store: &crate::SqliteReceiptStore) -> Result<Self, DeadLetterStoreError> {
        Self::open_with_pool(store.pool.clone())
    }

    /// Persist a dead-letter record. Idempotent on byte-identical
    /// re-inserts; returns [`DeadLetterStoreError::Conflict`] if a
    /// different record already exists for the same receipt.
    pub fn insert(&self, record: &DeadLetterRecord) -> Result<bool, DeadLetterStoreError> {
        let canonical_str = serde_json::to_string(record)
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        let attempts: i64 = i64::from(record.attempts);
        let finalized_at: i64 =
            record
                .finalized_at
                .try_into()
                .map_err(|err: std::num::TryFromIntError| {
                    DeadLetterStoreError::Backend(err.to_string())
                })?;

        let mut connection = self
            .pool
            .get()
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        let tx = connection
            .transaction()
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;

        let existing = tx
            .query_row(
                "SELECT canonical_json FROM settle_dead_letters WHERE receipt_id = ?1",
                params![record.receipt_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        if let Some(existing_canonical) = existing {
            if existing_canonical == canonical_str {
                return Ok(false);
            }
            return Err(DeadLetterStoreError::Conflict(format!(
                "settle_dead_letters row for receipt_id={} already exists with different bytes",
                record.receipt_id
            )));
        }

        tx.execute(
            "INSERT INTO settle_dead_letters \
                (receipt_id, finalized_at, attempts, reason, pipeline_error, canonical_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.receipt_id.as_str(),
                finalized_at,
                attempts,
                record.reason.as_str(),
                record.pipeline_error.as_deref(),
                canonical_str.as_str(),
            ],
        )
        .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;

        tx.commit()
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        Ok(true)
    }

    /// Look up a single dead-letter record by `receipt_id`.
    pub fn get(&self, receipt_id: &str) -> Result<Option<DeadLetterRecord>, DeadLetterStoreError> {
        let connection = self
            .pool
            .get()
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        let canonical = connection
            .query_row(
                "SELECT canonical_json FROM settle_dead_letters WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        match canonical {
            Some(json) => {
                Ok(Some(serde_json::from_str(&json).map_err(|err| {
                    DeadLetterStoreError::Backend(err.to_string())
                })?))
            }
            None => Ok(None),
        }
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
                "SELECT canonical_json FROM settle_dead_letters \
                 ORDER BY finalized_at ASC, receipt_id ASC",
            )
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            let canonical = row.map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
            let record: DeadLetterRecord = serde_json::from_str(&canonical)
                .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
            out.push(record);
        }
        Ok(out)
    }

    /// Remove a dead-letter row. Returns `true` if a row was deleted.
    pub fn clear(&self, receipt_id: &str) -> Result<bool, DeadLetterStoreError> {
        let connection = self
            .pool
            .get()
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        let affected = connection
            .execute(
                "DELETE FROM settle_dead_letters WHERE receipt_id = ?1",
                params![receipt_id],
            )
            .map_err(|err| DeadLetterStoreError::Backend(err.to_string()))?;
        Ok(affected > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chio_settle::{DeadLetterRecord, SettlementError};
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    use chio_test_support::prelude::*;

    fn pool() -> Pool<SqliteConnectionManager> {
        let manager = SqliteConnectionManager::memory();
        Pool::builder()
            .max_size(2)
            .build(manager)
            .test_expect("test pool builds")
    }

    fn sample_record(receipt_id: &str, attempts: u32) -> DeadLetterRecord {
        DeadLetterRecord::new(receipt_id, 100, attempts, "rpc failure")
            .with_pipeline_error(&SettlementError::Rpc("connection refused".to_string()))
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
    fn insert_with_different_bytes_returns_conflict() {
        let store = SqliteDeadLetterStore::open_with_pool(pool()).test_expect("store opens");
        let record = sample_record("rcpt-3", 2);
        store.insert(&record).test_expect("first insert");
        let mut conflicting = record.clone();
        conflicting.reason = "different reason".to_string();
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
                .map(|r| r.receipt_id.as_str())
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
}
