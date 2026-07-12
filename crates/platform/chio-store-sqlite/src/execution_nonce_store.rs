//! SQLite-backed `ExecutionNonceStore`.
//!
//! Durable replay-prevention for execution nonces so a kernel that
//! crashes and restarts cannot be tricked into accepting a nonce that was
//! already consumed by the previous process. Expiry is enforced by
//! storing the nonce's `expires_at` alongside the consumed marker;
//! `reserve` refuses to recycle a slot until the nonce is past its
//! expiry.
//!
//! The schema is:
//!
//! ```sql
//! CREATE TABLE chio_execution_nonces (
//!     nonce_id    TEXT PRIMARY KEY,
//!     consumed_at INTEGER NOT NULL,
//!     expires_at  INTEGER NOT NULL
//! );
//! CREATE INDEX idx_chio_execution_nonces_expires_at
//!     ON chio_execution_nonces(expires_at);
//! ```

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::{ExecutionNonceStore, KernelError};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;

/// Default number of seconds a consumed-marker persists after its
/// `expires_at` before the garbage collector reclaims the row. Keeps the
/// table bounded without letting a replay slip through immediately after
/// the nonce would have expired anyway.
const RETENTION_GRACE_SECS: i64 = 60;

/// Opaque error type returned by the SQLite nonce store.
#[derive(Debug)]
pub struct SqliteExecutionNonceStoreError(String);

impl std::fmt::Display for SqliteExecutionNonceStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sqlite execution nonce store error: {}", self.0)
    }
}

impl std::error::Error for SqliteExecutionNonceStoreError {}

impl From<rusqlite::Error> for SqliteExecutionNonceStoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<std::io::Error> for SqliteExecutionNonceStoreError {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<r2d2::Error> for SqliteExecutionNonceStoreError {
    fn from(e: r2d2::Error) -> Self {
        Self(e.to_string())
    }
}

/// SQLite-backed replay-prevention store for execution nonces.
pub struct SqliteExecutionNonceStore {
    pool: Pool<SqliteConnectionManager>,
}

/// Execution-nonce-store schema revision. Bump on every schema-affecting change.
const EXECUTION_NONCE_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const EXECUTION_NONCE_STORE_SCHEMA_KEY: &str = "execution_nonce";
/// Tables shipped before schema stamping existed, used to adopt a pre-stamping
/// execution-nonce database rather than reject it as foreign.
const EXECUTION_NONCE_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &["chio_execution_nonces"];

impl SqliteExecutionNonceStore {
    /// Open the store at the given path. Creates the parent directory
    /// if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteExecutionNonceStoreError> {
        let path = path.as_ref();
        // Resolve any `file:` URI to its on-disk parent before creating it, so a
        // URI-configured store creates the real backing directory rather than a
        // bogus scheme-prefixed one.
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(&parent)?;
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder().max_size(8).build(manager)?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    /// Open an in-memory store for tests.
    pub fn open_in_memory() -> Result<Self, SqliteExecutionNonceStoreError> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(1).build(manager)?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), SqliteExecutionNonceStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| SqliteExecutionNonceStoreError(format!("pool acquire: {e}")))?;
        crate::check_schema_version(
            &conn,
            EXECUTION_NONCE_STORE_SCHEMA_KEY,
            EXECUTION_NONCE_STORE_SUPPORTED_SCHEMA_VERSION,
            EXECUTION_NONCE_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| SqliteExecutionNonceStoreError(error.to_string()))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_execution_nonces (
                nonce_id    TEXT PRIMARY KEY,
                consumed_at INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_execution_nonces_expires_at
                ON chio_execution_nonces(expires_at);
            "#,
        )?;
        crate::stamp_schema_version(
            &conn,
            EXECUTION_NONCE_STORE_SCHEMA_KEY,
            EXECUTION_NONCE_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| SqliteExecutionNonceStoreError(error.to_string()))?;
        Ok(())
    }

    /// Reserve a nonce id. Shared code path for the trait impl and
    /// tests -- takes an explicit `expires_at` for caller-controlled
    /// retention (the trait method uses `now + RETENTION_GRACE_SECS`).
    pub fn try_reserve(
        &self,
        nonce_id: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<bool, SqliteExecutionNonceStoreError> {
        if nonce_id.trim().is_empty() || nonce_id.trim() != nonce_id {
            return Err(SqliteExecutionNonceStoreError(
                "nonce_id must be non-empty and unpadded".to_string(),
            ));
        }
        let mut conn = self
            .pool
            .get()
            .map_err(|e| SqliteExecutionNonceStoreError(format!("pool acquire: {e}")))?;

        let tx = conn.transaction()?;

        // First, prune any rows that are past their `expires_at` so a
        // long-lived kernel doesn't accumulate garbage. Keeping the
        // prune here (rather than a background job) is safe because the
        // query is indexed on expires_at.
        tx.execute(
            "DELETE FROM chio_execution_nonces WHERE expires_at <= ?1",
            params![now],
        )?;

        // Then attempt the reservation. A conflicting row means the
        // nonce was already consumed and is still within the retention
        // window; return `false`.
        let rows = tx.execute(
            r#"
            INSERT INTO chio_execution_nonces (nonce_id, consumed_at, expires_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(nonce_id) DO NOTHING
            "#,
            params![nonce_id, now, expires_at],
        )?;
        tx.commit()?;
        Ok(rows > 0)
    }
}

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
    .unwrap_or(i64::MAX)
}

impl ExecutionNonceStore for SqliteExecutionNonceStore {
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        // Back-compat path: callers that do not know the nonce's signed
        // expiry estimate the kernel default TTL and delegate to
        // `reserve_until` so the consumed marker survives the full
        // cryptographic validity window.
        let now = now_secs();
        let estimated_nonce_expiry = now.saturating_add(
            i64::try_from(chio_kernel::DEFAULT_EXECUTION_NONCE_TTL_SECS).unwrap_or(0),
        );
        self.reserve_until(nonce_id, estimated_nonce_expiry)
    }

    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError> {
        // Retain the consumed marker for the full signed validity window
        // plus a small grace, so a pruner cannot reclaim the row while
        // the nonce is still cryptographically valid. Take the max of
        // `nonce_expires_at + RETENTION_GRACE_SECS` and
        // `now + RETENTION_GRACE_SECS`, preserving the original grace
        // for clock-skew safety.
        let now = now_secs();
        let retention = nonce_expires_at.saturating_add(RETENTION_GRACE_SECS);
        let baseline = now.saturating_add(RETENTION_GRACE_SECS);
        let expires_at = retention.max(baseline);
        self.try_reserve(nonce_id, now, expires_at)
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    #[test]
    fn fresh_nonce_is_reserved() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        assert!(<SqliteExecutionNonceStore as ExecutionNonceStore>::reserve(&store, "a").unwrap());
    }

    #[test]
    fn duplicate_nonce_is_rejected() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        assert!(store.try_reserve("a", 1_000, 1_100).unwrap());
        assert!(!store.try_reserve("a", 1_001, 1_100).unwrap());
    }

    #[test]
    fn padded_nonce_id_is_rejected() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let error = store.try_reserve(" nonce", 1_000, 1_100).unwrap_err();

        assert!(
            error.to_string().contains("nonce_id"),
            "expected nonce_id validation error, got {error}"
        );
    }

    #[test]
    fn expired_row_is_pruned_and_slot_reusable() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        assert!(store.try_reserve("a", 1_000, 1_030).unwrap());
        // "Now" after expiry + retention: prune removes the row and the
        // same id can be re-reserved (this is benign because verify_
        // execution_nonce also checks the signed expires_at).
        assert!(store.try_reserve("a", 2_000, 2_030).unwrap());
    }

    #[test]
    fn persists_across_reopen() {
        let path = unique_db_path("chio-exec-nonce");
        {
            let store = SqliteExecutionNonceStore::open(&path).unwrap();
            assert!(store
                .try_reserve("persistent-nonce", 1_000, 1_000_000_000)
                .unwrap());
        }
        let reopened = SqliteExecutionNonceStore::open(&path).unwrap();
        assert!(!reopened
            .try_reserve("persistent-nonce", 1_001, 1_000_000_000)
            .unwrap());
        let _ = fs::remove_file(path);
    }
}
