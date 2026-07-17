//! Durable SQLite EIP-3009 single-use nonce store. Survives a restart and
//! cannot wedge at capacity without an operator: `record_if_fresh` is an
//! atomic keyed insert that NEVER prunes, and `gc_expired` stays the sole
//! entry point that drops entries, so replay decisions remain decoupled from
//! the wall clock exactly as the trait contract requires.

use std::path::Path;

use chio_settle::{Eip3009NonceStore, NonceOutcome, SettlementError};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

const EIP3009_MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS eip3009_nonces (
    from_address TEXT NOT NULL,
    nonce_key    TEXT NOT NULL,
    retain_until INTEGER NOT NULL,
    PRIMARY KEY (from_address, nonce_key)
);
CREATE INDEX IF NOT EXISTS idx_eip3009_nonces_retain_until ON eip3009_nonces(retain_until);
"#;

/// Durable EIP-3009 nonce store over a SQLite connection pool.
pub struct SqliteEip3009NonceStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteEip3009NonceStore {
    /// Open (or create) the store at `path`, running the additive migration.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SettlementError> {
        let manager = SqliteConnectionManager::file(path.as_ref());
        let pool = Pool::new(manager)
            .map_err(|error| SettlementError::InvalidBinding(format!("eip3009 pool: {error}")))?;
        Self::open_with_pool(pool)
    }

    /// Open the store over an existing pool (for co-locating with sibling
    /// tables in one database).
    pub fn open_with_pool(pool: Pool<SqliteConnectionManager>) -> Result<Self, SettlementError> {
        {
            let connection = pool.get().map_err(|error| {
                SettlementError::InvalidBinding(format!("eip3009 connection: {error}"))
            })?;
            connection
                .execute_batch(EIP3009_MIGRATION)
                .map_err(|error| {
                    SettlementError::InvalidBinding(format!("eip3009 migration: {error}"))
                })?;
        }
        Ok(Self { pool })
    }
}

/// Normalize a key component exactly as the in-memory store does (trim,
/// strip a leading `0x`/`0X`, lowercase), so casing and prefix variants of
/// the same key map to the same row and cannot evade replay detection.
fn canonicalize(value: &str) -> String {
    let trimmed = value.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    without_prefix.to_ascii_lowercase()
}

impl Eip3009NonceStore for SqliteEip3009NonceStore {
    fn record_if_fresh(
        &self,
        from_address: &str,
        nonce: &str,
        retain_until_unix_seconds: u64,
    ) -> Result<NonceOutcome, SettlementError> {
        let from = canonicalize(from_address);
        let key = canonicalize(nonce);
        let mut connection = self.pool.get().map_err(|error| {
            SettlementError::InvalidBinding(format!("eip3009 connection: {error}"))
        })?;
        // Atomic single-use: the keyed insert ignores a present row, so two
        // parallel replays of the same pair cannot both observe Fresh. No
        // pruning happens here by contract.
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| {
                SettlementError::InvalidBinding(format!("eip3009 transaction: {error}"))
            })?;
        let changed = transaction
            .execute(
                "INSERT INTO eip3009_nonces (from_address, nonce_key, retain_until) \
                 VALUES (?1, ?2, ?3) ON CONFLICT(from_address, nonce_key) DO NOTHING",
                rusqlite::params![
                    from,
                    key,
                    retain_until_unix_seconds.min(i64::MAX as u64) as i64
                ],
            )
            .map_err(|error| SettlementError::InvalidBinding(format!("eip3009 insert: {error}")))?;
        transaction
            .commit()
            .map_err(|error| SettlementError::InvalidBinding(format!("eip3009 commit: {error}")))?;
        Ok(if changed == 1 {
            NonceOutcome::Fresh
        } else {
            NonceOutcome::Replayed
        })
    }

    fn gc_expired(&self, now_unix_seconds: u64) -> Result<usize, SettlementError> {
        let connection = self.pool.get().map_err(|error| {
            SettlementError::InvalidBinding(format!("eip3009 connection: {error}"))
        })?;
        connection
            .execute(
                "DELETE FROM eip3009_nonces WHERE retain_until < ?1",
                rusqlite::params![now_unix_seconds.min(i64::MAX as u64) as i64],
            )
            .map_err(|error| SettlementError::InvalidBinding(format!("eip3009 gc: {error}")))
    }

    fn len(&self) -> Result<usize, SettlementError> {
        let connection = self.pool.get().map_err(|error| {
            SettlementError::InvalidBinding(format!("eip3009 connection: {error}"))
        })?;
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM eip3009_nonces", [], |row| row.get(0))
            .map_err(|error| SettlementError::InvalidBinding(format!("eip3009 count: {error}")))?;
        Ok(count.max(0) as usize)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_settle::{Eip3009NonceStore, NonceOutcome};

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "chio-{prefix}-{}-{nonce}.sqlite3",
            std::process::id()
        ))
    }

    #[test]
    fn fresh_then_replayed_survives_reopen_and_normalizes_key() {
        let path = unique_db_path("eip3009");
        {
            let store = SqliteEip3009NonceStore::open(&path).unwrap();
            assert_eq!(
                store
                    .record_if_fresh("0xABCdef", "0xNonce1", 1_000)
                    .unwrap(),
                NonceOutcome::Fresh
            );
            // The same key with different casing or prefix is a replay.
            assert_eq!(
                store.record_if_fresh("abcdef", "nonce1", 1_000).unwrap(),
                NonceOutcome::Replayed
            );
        }
        // Reopen: the recorded nonce is still a replay across restart.
        let store = SqliteEip3009NonceStore::open(&path).unwrap();
        assert_eq!(
            store.record_if_fresh("0xABCDEF", "NONCE1", 1_000).unwrap(),
            NonceOutcome::Replayed
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn gc_expired_drops_only_expired_and_record_never_prunes() {
        let path = unique_db_path("eip3009-gc");
        let store = SqliteEip3009NonceStore::open(&path).unwrap();
        store.record_if_fresh("addr", "n-early", 100).unwrap();
        store.record_if_fresh("addr", "n-late", 900).unwrap();
        assert_eq!(store.len().unwrap(), 2);
        // record_if_fresh takes no clock and never prunes: recording another
        // entry does not drop the expired one.
        store.record_if_fresh("addr", "n-mid", 500).unwrap();
        assert_eq!(store.len().unwrap(), 3);
        // gc_expired(now = 500) drops retain_until < 500 (n-early only).
        assert_eq!(store.gc_expired(500).unwrap(), 1);
        assert_eq!(store.len().unwrap(), 2);
        let _ = std::fs::remove_file(&path);
    }
}
