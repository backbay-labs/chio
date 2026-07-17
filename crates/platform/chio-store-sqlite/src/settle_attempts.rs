//! Durable settlement-retry sink: the bounded `settle_attempts` retry
//! envelope plus the existing dead-letter store, opened alongside the receipt
//! store so `chio settle status` reads tables production code writes.

use chio_kernel::settlement_retry::{
    SettleAttemptRecord, SettlementRetryError, SettlementRetryStore,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OptionalExtension;

use crate::dead_letters::{DeadLetterStoreError, SqliteDeadLetterStore};

const SETTLE_ATTEMPTS_MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS settle_attempts (
    receipt_id      TEXT PRIMARY KEY,
    finalized_at    INTEGER NOT NULL,
    attempts        INTEGER NOT NULL,
    next_visible_at INTEGER NOT NULL,
    last_reason     TEXT,
    updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_settle_attempts_visible ON settle_attempts(next_visible_at);
"#;

/// Settlement retry sink: `settle_attempts` plus the dead-letter store, both
/// on the receipt store's connection pool.
pub struct SqliteSettlementRetryStore {
    pool: Pool<SqliteConnectionManager>,
    dead_letters: SqliteDeadLetterStore,
}

impl SqliteSettlementRetryStore {
    /// Open the retry sink in the same database as `store` (mirrors
    /// [`SqliteDeadLetterStore::open_alongside`]).
    pub fn open_alongside(store: &crate::SqliteReceiptStore) -> Result<Self, SettlementRetryError> {
        let dead_letters = SqliteDeadLetterStore::open_alongside(store).map_err(map_dl_err)?;
        let pool = store.pool.clone();
        {
            let connection = pool.get().map_err(backend_err)?;
            connection
                .execute_batch(SETTLE_ATTEMPTS_MIGRATION)
                .map_err(backend_err)?;
        }
        Ok(Self { pool, dead_letters })
    }

    fn now_unix_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

fn backend_err(error: impl std::fmt::Display) -> SettlementRetryError {
    SettlementRetryError::Backend(error.to_string())
}

fn map_dl_err(error: DeadLetterStoreError) -> SettlementRetryError {
    match error {
        DeadLetterStoreError::Conflict(message) => SettlementRetryError::Conflict(message),
        other => SettlementRetryError::Backend(other.to_string()),
    }
}

fn row_to_attempt(row: &rusqlite::Row<'_>) -> rusqlite::Result<SettleAttemptRecord> {
    Ok(SettleAttemptRecord {
        receipt_id: row.get::<_, String>(0)?,
        finalized_at: row.get::<_, i64>(1)?.max(0) as u64,
        attempts: row.get::<_, i64>(2)?.clamp(0, i64::from(u32::MAX)) as u32,
        next_visible_at: row.get::<_, i64>(3)?.max(0) as u64,
        last_reason: row.get::<_, Option<String>>(4)?,
    })
}

impl SettlementRetryStore for SqliteSettlementRetryStore {
    fn load_attempt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<SettleAttemptRecord>, SettlementRetryError> {
        let connection = self.pool.get().map_err(backend_err)?;
        connection
            .query_row(
                "SELECT receipt_id, finalized_at, attempts, next_visible_at, last_reason \
                 FROM settle_attempts WHERE receipt_id = ?1",
                rusqlite::params![receipt_id],
                row_to_attempt,
            )
            .optional()
            .map_err(backend_err)
    }

    fn upsert_attempt(&self, record: &SettleAttemptRecord) -> Result<(), SettlementRetryError> {
        let connection = self.pool.get().map_err(backend_err)?;
        connection
            .execute(
                "INSERT INTO settle_attempts \
                 (receipt_id, finalized_at, attempts, next_visible_at, last_reason, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(receipt_id) DO UPDATE SET \
                   attempts = excluded.attempts, \
                   next_visible_at = excluded.next_visible_at, \
                   last_reason = excluded.last_reason, \
                   updated_at = excluded.updated_at",
                rusqlite::params![
                    record.receipt_id,
                    record.finalized_at as i64,
                    i64::from(record.attempts),
                    record.next_visible_at as i64,
                    record.last_reason,
                    Self::now_unix_secs() as i64,
                ],
            )
            .map_err(backend_err)?;
        Ok(())
    }

    fn clear_attempt(&self, receipt_id: &str) -> Result<(), SettlementRetryError> {
        let connection = self.pool.get().map_err(backend_err)?;
        connection
            .execute(
                "DELETE FROM settle_attempts WHERE receipt_id = ?1",
                rusqlite::params![receipt_id],
            )
            .map_err(backend_err)?;
        Ok(())
    }

    fn insert_dead_letter(
        &self,
        record: &chio_settle::DeadLetterRecord,
    ) -> Result<bool, SettlementRetryError> {
        self.dead_letters.insert(record).map_err(map_dl_err)
    }

    fn due_attempts(
        &self,
        now_unix_secs: u64,
        limit: usize,
    ) -> Result<Vec<SettleAttemptRecord>, SettlementRetryError> {
        let connection = self.pool.get().map_err(backend_err)?;
        let mut statement = connection
            .prepare(
                "SELECT receipt_id, finalized_at, attempts, next_visible_at, last_reason \
                 FROM settle_attempts WHERE next_visible_at <= ?1 \
                 ORDER BY next_visible_at ASC LIMIT ?2",
            )
            .map_err(backend_err)?;
        let rows = statement
            .query_map(
                rusqlite::params![now_unix_secs as i64, limit as i64],
                row_to_attempt,
            )
            .map_err(backend_err)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(backend_err)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::settlement_retry::{SettleAttemptRecord, SettlementRetryStore};

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "chio-{prefix}-{}-{nonce}.sqlite3",
            std::process::id()
        ))
    }

    #[test]
    fn attempt_upsert_load_due_and_clear_roundtrip() {
        let path = unique_db_path("settle-attempts");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();

        assert!(store.load_attempt("r1").unwrap().is_none());
        store
            .upsert_attempt(&SettleAttemptRecord {
                receipt_id: "r1".to_string(),
                finalized_at: 100,
                attempts: 1,
                next_visible_at: 250,
                last_reason: Some("retryable".to_string()),
            })
            .unwrap();
        let loaded = store.load_attempt("r1").unwrap().expect("attempt present");
        assert_eq!(loaded.attempts, 1);
        assert_eq!(loaded.next_visible_at, 250);

        // Upsert again with a higher attempt count and a later visibility.
        store
            .upsert_attempt(&SettleAttemptRecord {
                receipt_id: "r1".to_string(),
                finalized_at: 100,
                attempts: 2,
                next_visible_at: 500,
                last_reason: Some("retryable".to_string()),
            })
            .unwrap();
        assert_eq!(store.load_attempt("r1").unwrap().unwrap().attempts, 2);

        // due_attempts respects next_visible_at.
        assert!(store.due_attempts(499, 10).unwrap().is_empty());
        assert_eq!(store.due_attempts(500, 10).unwrap().len(), 1);

        store.clear_attempt("r1").unwrap();
        assert!(store.load_attempt("r1").unwrap().is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dead_letter_insert_is_idempotent() {
        let path = unique_db_path("settle-dead-letter");
        let receipts = crate::SqliteReceiptStore::open(&path).unwrap();
        let store = SqliteSettlementRetryStore::open_alongside(&receipts).unwrap();
        let record = chio_settle::DeadLetterRecord::new("r-dl", 100, 3, "permanent");
        assert!(
            store.insert_dead_letter(&record).unwrap(),
            "first insert is new"
        );
        assert!(
            !store.insert_dead_letter(&record).unwrap(),
            "byte-identical replay returns false, not a conflict"
        );
        let _ = std::fs::remove_file(&path);
    }
}
