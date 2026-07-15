//! SQLite-backed `ExecutionNonceStore`.
//!
//! Durable replay-prevention for execution nonces so a kernel that
//! crashes and restarts cannot be tricked into accepting a nonce that was
//! already consumed by the previous process. Expiry is enforced by storing a
//! retention boundary derived from the nonce's signed `expires_at` alongside
//! the consumed marker; signed reservations refuse to recycle the slot before
//! that boundary.
//!
//! The schema is:
//!
//! ```sql
//! CREATE TABLE chio_execution_nonces (
//!     nonce_id    TEXT PRIMARY KEY,
//!     consumed_at INTEGER NOT NULL,
//!     expires_at  INTEGER NOT NULL,
//!     dispatch_reservation_id TEXT
//! );
//! CREATE INDEX idx_chio_execution_nonces_expires_at
//!     ON chio_execution_nonces(expires_at);
//! CREATE TABLE chio_execution_nonce_clock (
//!     singleton             INTEGER PRIMARY KEY,
//!     wall_clock_high_water INTEGER NOT NULL
//! );
//! CREATE TABLE chio_execution_nonce_limits (
//!     singleton INTEGER PRIMARY KEY,
//!     capacity  INTEGER NOT NULL
//! );
//! ```

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::{ExecutionNonceStore, KernelError, DEFAULT_EXECUTION_NONCE_STORE_CAPACITY};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, TransactionBehavior};

/// Default number of seconds a consumed marker persists after the signed
/// artifact's `expires_at` before the garbage collector reclaims the row. Keeps the
/// table bounded without letting a replay slip through immediately after
/// the nonce would have expired anyway.
const RETENTION_GRACE_SECS: i64 = 60;

fn configure_pooled_connection(connection: &mut Connection) -> rusqlite::Result<()> {
    connection.execute_batch("PRAGMA busy_timeout = 5000;")
}

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
    capacity: usize,
}

impl SqliteExecutionNonceStore {
    /// Open the store at the given path. Creates the parent directory
    /// if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteExecutionNonceStoreError> {
        Self::open_with_capacity(path, DEFAULT_EXECUTION_NONCE_STORE_CAPACITY)
    }

    /// Open the store with a hard store-wide retained-row capacity.
    ///
    /// Expired rows are pruned before the limit is checked. Live replay
    /// markers are never evicted to make room for a new reservation.
    pub fn open_with_capacity(
        path: impl AsRef<Path>,
        capacity: usize,
    ) -> Result<Self, SqliteExecutionNonceStoreError> {
        Self::validate_capacity(capacity)?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let manager = SqliteConnectionManager::file(path).with_init(configure_pooled_connection);
        let pool = Pool::builder().max_size(8).build(manager)?;
        let store = Self { pool, capacity };
        store.run_migrations()?;
        store.validate_retained_row_capacity()?;
        Ok(store)
    }

    /// Open an in-memory store for tests.
    pub fn open_in_memory() -> Result<Self, SqliteExecutionNonceStoreError> {
        Self::open_in_memory_with_capacity(DEFAULT_EXECUTION_NONCE_STORE_CAPACITY)
    }

    /// Open an in-memory store with a hard retained-row capacity.
    pub fn open_in_memory_with_capacity(
        capacity: usize,
    ) -> Result<Self, SqliteExecutionNonceStoreError> {
        Self::validate_capacity(capacity)?;
        let manager = SqliteConnectionManager::memory().with_init(configure_pooled_connection);
        let pool = Pool::builder().max_size(1).build(manager)?;
        let store = Self { pool, capacity };
        store.run_migrations()?;
        store.validate_retained_row_capacity()?;
        Ok(store)
    }

    fn validate_capacity(capacity: usize) -> Result<(), SqliteExecutionNonceStoreError> {
        if capacity == 0 {
            return Err(SqliteExecutionNonceStoreError(
                "execution nonce store capacity must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }

    fn run_migrations(&self) -> Result<(), SqliteExecutionNonceStoreError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| SqliteExecutionNonceStoreError(format!("pool acquire: {e}")))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            "#,
        )?;

        let tx = conn.transaction()?;
        tx.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS chio_execution_nonces (
                nonce_id    TEXT PRIMARY KEY,
                consumed_at INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL,
                dispatch_reservation_id TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_chio_execution_nonces_expires_at
                ON chio_execution_nonces(expires_at);

            CREATE TABLE IF NOT EXISTS chio_execution_nonce_clock (
                singleton             INTEGER PRIMARY KEY CHECK (singleton = 1),
                wall_clock_high_water INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_execution_nonce_limits (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                capacity  INTEGER NOT NULL CHECK (capacity > 0)
            );
            "#,
        )?;
        let capacity = i64::try_from(self.capacity).map_err(|_| {
            SqliteExecutionNonceStoreError(
                "execution nonce store capacity exceeds SQLite integer range".to_string(),
            )
        })?;
        tx.execute(
            "INSERT INTO chio_execution_nonce_limits (singleton, capacity) VALUES (1, ?1) ON CONFLICT(singleton) DO NOTHING",
            params![capacity],
        )?;
        tx.execute(
            r#"
            INSERT INTO chio_execution_nonce_clock (singleton, wall_clock_high_water)
            SELECT 1, MAX(?1, COALESCE(MAX(consumed_at), ?2))
            FROM chio_execution_nonces
            WHERE true
            ON CONFLICT(singleton) DO UPDATE SET
                wall_clock_high_water = MAX(
                    chio_execution_nonce_clock.wall_clock_high_water,
                    excluded.wall_clock_high_water
                )
            "#,
            params![now_secs(), i64::MIN],
        )?;
        let has_dispatch_reservation_id = {
            let mut statement = tx.prepare("PRAGMA table_info(chio_execution_nonces)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "dispatch_reservation_id" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_dispatch_reservation_id {
            tx.execute(
                "ALTER TABLE chio_execution_nonces ADD COLUMN dispatch_reservation_id TEXT",
                [],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn validate_retained_row_capacity(&self) -> Result<(), SqliteExecutionNonceStoreError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| SqliteExecutionNonceStoreError(format!("pool acquire: {e}")))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let wall_clock_high_water = tx.query_row(
            "SELECT wall_clock_high_water FROM chio_execution_nonce_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        tx.execute(
            "DELETE FROM chio_execution_nonces WHERE expires_at <= ?1",
            params![wall_clock_high_water],
        )?;
        let retained_rows =
            tx.query_row("SELECT COUNT(*) FROM chio_execution_nonces", [], |row| {
                row.get::<_, i64>(0)
            })?;
        let retained_rows = usize::try_from(retained_rows).map_err(|_| {
            SqliteExecutionNonceStoreError(
                "retained execution nonce row count cannot be represented as usize".to_string(),
            )
        })?;
        let persisted_capacity = tx.query_row(
            "SELECT capacity FROM chio_execution_nonce_limits WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        tx.commit()?;
        if retained_rows > self.capacity {
            return Err(SqliteExecutionNonceStoreError(format!(
                "configured capacity {} is below the {retained_rows} retained execution nonce rows",
                self.capacity
            )));
        }
        let requested_capacity = i64::try_from(self.capacity).map_err(|_| {
            SqliteExecutionNonceStoreError(
                "execution nonce store capacity exceeds SQLite integer range".to_string(),
            )
        })?;
        if persisted_capacity != requested_capacity {
            return Err(SqliteExecutionNonceStoreError(format!(
                "persisted execution nonce capacity {persisted_capacity} does not match requested capacity {requested_capacity}"
            )));
        }
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
        self.try_reserve_entry(nonce_id, now, expires_at, None)
    }

    fn try_reserve_entry(
        &self,
        nonce_id: &str,
        now: i64,
        expires_at: i64,
        dispatch_reservation_id: Option<&str>,
    ) -> Result<bool, SqliteExecutionNonceStoreError> {
        self.try_reserve_entry_with_clock_policy(
            nonce_id,
            now,
            expires_at,
            None,
            dispatch_reservation_id,
        )
    }

    fn try_reserve_signed_entry(
        &self,
        nonce_id: &str,
        now: i64,
        signed_expires_at: i64,
        retention_expires_at: i64,
        dispatch_reservation_id: Option<&str>,
    ) -> Result<bool, SqliteExecutionNonceStoreError> {
        self.try_reserve_entry_with_clock_policy(
            nonce_id,
            now,
            retention_expires_at.max(signed_expires_at),
            Some(signed_expires_at),
            dispatch_reservation_id,
        )
    }

    fn try_reserve_entry_with_clock_policy(
        &self,
        nonce_id: &str,
        now: i64,
        expires_at: i64,
        signed_expires_at: Option<i64>,
        dispatch_reservation_id: Option<&str>,
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

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let wall_clock_high_water = tx.query_row(
            "SELECT wall_clock_high_water FROM chio_execution_nonce_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let clock_rolled_back = now < wall_clock_high_water;
        let updated_high_water = wall_clock_high_water.max(now);
        if updated_high_water != wall_clock_high_water {
            tx.execute(
                "UPDATE chio_execution_nonce_clock SET wall_clock_high_water = ?1 WHERE singleton = 1",
                params![updated_high_water],
            )?;
        }
        if clock_rolled_back {
            tx.commit()?;
            return Ok(false);
        }

        let prune_at = if let Some(signed_expires_at) = signed_expires_at {
            if signed_expires_at <= updated_high_water {
                tx.commit()?;
                return Ok(false);
            }
            updated_high_water
        } else {
            now
        };

        // Prune local entries against the caller's clock and signed entries
        // against the persisted high-water. The latter can never move
        // backward, so reclamation cannot reopen a replay window.
        tx.execute(
            "DELETE FROM chio_execution_nonces WHERE expires_at <= ?1",
            params![prune_at],
        )?;

        let already_reserved = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM chio_execution_nonces WHERE nonce_id = ?1)",
            params![nonce_id],
            |row| row.get::<_, bool>(0),
        )?;
        if already_reserved {
            tx.commit()?;
            return Ok(false);
        }

        let retained_rows =
            tx.query_row("SELECT COUNT(*) FROM chio_execution_nonces", [], |row| {
                row.get::<_, i64>(0)
            })?;
        let capacity = tx.query_row(
            "SELECT capacity FROM chio_execution_nonce_limits WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if retained_rows >= capacity {
            tx.commit()?;
            return Err(SqliteExecutionNonceStoreError(format!(
                "execution nonce store capacity {} exhausted; denying reservation fail-closed",
                capacity
            )));
        }

        // The immediate transaction serializes the prune/count/insert sequence
        // across pooled connections, so concurrent writers cannot exceed the
        // configured live-row bound.
        let rows = tx.execute(
            r#"
            INSERT INTO chio_execution_nonces (
                nonce_id,
                consumed_at,
                expires_at,
                dispatch_reservation_id
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(nonce_id) DO NOTHING
            "#,
            params![nonce_id, now, expires_at, dispatch_reservation_id],
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
        // Compatibility path for callers without a signed expiry. Its fixed
        // grace is a local retention contract only; signed execution-nonce
        // verification uses `reserve_until` with the artifact's `expires_at`.
        let now = now_secs();
        let expires_at = now.saturating_add(RETENTION_GRACE_SECS);
        self.try_reserve(nonce_id, now, expires_at)
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))
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
        self.try_reserve_signed_entry(nonce_id, now, nonce_expires_at, expires_at, None)
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))
    }

    fn supports_dispatch_reservations(&self) -> bool {
        true
    }

    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let now = now_secs();
        let retention = nonce_expires_at.saturating_add(RETENTION_GRACE_SECS);
        let baseline = now.saturating_add(RETENTION_GRACE_SECS);
        self.try_reserve_signed_entry(
            nonce_id,
            now,
            nonce_expires_at,
            retention.max(baseline),
            Some(reservation_id),
        )
        .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))
    }

    fn rollback_dispatch_reservation(
        &self,
        nonce_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))?;
        let rows = tx
            .execute(
                "DELETE FROM chio_execution_nonces WHERE nonce_id = ?1 AND dispatch_reservation_id = ?2",
                params![nonce_id, reservation_id],
            )
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))?;
        tx.commit()
            .map_err(|e| KernelError::Internal(format!("sqlite execution nonce store: {e}")))?;
        Ok(rows > 0)
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
    fn zero_capacity_is_rejected() {
        let error = match SqliteExecutionNonceStore::open_in_memory_with_capacity(0) {
            Ok(_) => panic!("zero-capacity store must not open"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("greater than zero"));
    }

    #[test]
    fn live_capacity_pressure_fails_closed_without_evicting_markers() {
        let store = SqliteExecutionNonceStore::open_in_memory_with_capacity(2).unwrap();
        let now = now_secs();
        let expires_at = now.saturating_add(100);
        assert!(store.try_reserve("capacity-a", now, expires_at).unwrap());
        assert!(store.try_reserve("capacity-b", now, expires_at).unwrap());
        assert!(!store.try_reserve("capacity-a", now, expires_at).unwrap());

        let error = store
            .try_reserve("capacity-c", now, expires_at)
            .unwrap_err();
        assert!(error.to_string().contains("capacity 2 exhausted"));
        assert!(!store.try_reserve("capacity-a", now, expires_at).unwrap());
        assert!(!store.try_reserve("capacity-b", now, expires_at).unwrap());

        assert!(store
            .try_reserve(
                "capacity-c",
                now.saturating_add(1_000),
                now.saturating_add(1_100),
            )
            .unwrap());
    }

    #[test]
    fn concurrent_writers_cannot_exceed_capacity() {
        let path = unique_db_path("chio-exec-nonce-capacity-concurrent");
        let store =
            std::sync::Arc::new(SqliteExecutionNonceStore::open_with_capacity(&path, 1).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let now = now_secs();
        let mut writers = Vec::new();

        for nonce_id in ["concurrent-a", "concurrent-b"] {
            let store = std::sync::Arc::clone(&store);
            let barrier = std::sync::Arc::clone(&barrier);
            writers.push(std::thread::spawn(move || {
                barrier.wait();
                store.try_reserve(nonce_id, now, now.saturating_add(300))
            }));
        }

        barrier.wait();
        let outcomes: Vec<_> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Ok(true)))
                .count(),
            1
        );
        let errors: Vec<_> = outcomes
            .iter()
            .filter_map(|outcome| outcome.as_ref().err())
            .collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].to_string().contains("capacity 1 exhausted"));

        let conn = store.pool.get().unwrap();
        let retained_rows = conn
            .query_row("SELECT COUNT(*) FROM chio_execution_nonces", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(retained_rows, 1);
        drop(conn);
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn every_pooled_connection_has_busy_timeout() {
        let path = unique_db_path("chio-exec-nonce-busy-timeout");
        let store = SqliteExecutionNonceStore::open(&path).unwrap();
        let first = store.pool.get().unwrap();
        let second = store.pool.get().unwrap();

        for connection in [&first, &second] {
            let busy_timeout = connection
                .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                .unwrap();
            assert!(busy_timeout >= 5_000);
        }

        drop(second);
        drop(first);
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn owned_rollback_frees_capacity() {
        let store = SqliteExecutionNonceStore::open_in_memory_with_capacity(1).unwrap();
        let expires_at = now_secs().saturating_add(300);
        assert!(store
            .reserve_for_dispatch("rollback-a", expires_at, "owner-a")
            .unwrap());
        assert!(store
            .reserve_for_dispatch("rollback-b", expires_at, "owner-b")
            .is_err());
        assert!(!store
            .rollback_dispatch_reservation("rollback-a", "owner-b")
            .unwrap());
        assert!(store
            .reserve_for_dispatch("rollback-b", expires_at, "owner-b")
            .is_err());
        assert!(store
            .rollback_dispatch_reservation("rollback-a", "owner-a")
            .unwrap());
        assert!(store
            .reserve_for_dispatch("rollback-b", expires_at, "owner-b")
            .unwrap());
    }

    #[test]
    fn duplicate_nonce_is_rejected() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let now = now_secs();
        assert!(store
            .try_reserve("a", now, now.saturating_add(100))
            .unwrap());
        assert!(!store
            .try_reserve("a", now.saturating_add(1), now.saturating_add(100))
            .unwrap());
    }

    #[test]
    fn dispatch_reservation_rolls_back_only_for_its_owner() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let now = now_secs();
        assert!(store
            .reserve_for_dispatch("dispatch-owned", now.saturating_add(100), "owner-a")
            .unwrap());
        assert!(!store
            .rollback_dispatch_reservation("dispatch-owned", "owner-b")
            .unwrap());
        assert!(!store.reserve("dispatch-owned").unwrap());
        assert!(store
            .rollback_dispatch_reservation("dispatch-owned", "owner-a")
            .unwrap());
        assert!(store.reserve("dispatch-owned").unwrap());
    }

    #[test]
    fn padded_nonce_id_is_rejected() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let now = now_secs();
        let error = store
            .try_reserve(" nonce", now, now.saturating_add(100))
            .unwrap_err();

        assert!(
            error.to_string().contains("nonce_id"),
            "expected nonce_id validation error, got {error}"
        );
    }

    #[test]
    fn expired_row_is_pruned_and_slot_reusable() {
        let store = SqliteExecutionNonceStore::open_in_memory().unwrap();
        let now = now_secs();
        assert!(store.try_reserve("a", now, now.saturating_add(30)).unwrap());
        // The explicit local API preserves caller-controlled prune and reuse.
        assert!(store
            .try_reserve("a", now.saturating_add(1_000), now.saturating_add(1_030))
            .unwrap());
    }

    #[test]
    fn high_water_survives_reopen_and_closes_the_rollback_interval() {
        let path = unique_db_path("chio-exec-nonce-high-water");
        let base_time;
        {
            let store = SqliteExecutionNonceStore::open(&path).unwrap();
            base_time = now_secs();
            assert!(store
                .try_reserve_signed_entry(
                    "used",
                    base_time,
                    base_time.saturating_add(5),
                    base_time.saturating_add(10),
                    None,
                )
                .unwrap());
            assert!(store
                .try_reserve(
                    "forward-local",
                    base_time.saturating_add(1_000),
                    base_time.saturating_add(2_000),
                )
                .unwrap());
            let conn = store.pool.get().unwrap();
            let used_rows = conn
                .query_row(
                    "SELECT COUNT(*) FROM chio_execution_nonces WHERE nonce_id = 'used'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap();
            assert_eq!(used_rows, 0);
        }

        let reopened = SqliteExecutionNonceStore::open(&path).unwrap();
        assert!(!reopened
            .try_reserve_signed_entry(
                "used",
                base_time.saturating_add(500),
                base_time.saturating_add(3_000),
                base_time.saturating_add(3_000),
                None,
            )
            .unwrap());
        assert!(!reopened
            .try_reserve(
                "local-during-rollback",
                base_time.saturating_add(500),
                base_time.saturating_add(3_000),
            )
            .unwrap());
        assert!(reopened
            .try_reserve_signed_entry(
                "caught-up",
                base_time.saturating_add(1_000),
                base_time.saturating_add(3_000),
                base_time.saturating_add(3_000),
                None,
            )
            .unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn legacy_database_seeds_high_water_from_existing_consumption() {
        let path = unique_db_path("chio-exec-nonce-legacy-high-water");
        let now = now_secs();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE chio_execution_nonces (
                    nonce_id   TEXT PRIMARY KEY,
                    consumed_at INTEGER NOT NULL,
                    expires_at  INTEGER NOT NULL
                );
                "#,
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chio_execution_nonces (nonce_id, consumed_at, expires_at) VALUES (?1, ?2, ?3)",
                params![
                    "legacy-used",
                    now.saturating_add(1_000),
                    now.saturating_add(2_000),
                ],
            )
            .unwrap();
        }

        let store = SqliteExecutionNonceStore::open(&path).unwrap();
        let conn = store.pool.get().unwrap();
        let high_water = conn
            .query_row(
                "SELECT wall_clock_high_water FROM chio_execution_nonce_clock WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(high_water, now.saturating_add(1_000));
        drop(conn);
        assert!(!store
            .try_reserve_signed_entry(
                "new-signed",
                now.saturating_add(500),
                now.saturating_add(3_000),
                now.saturating_add(3_000),
                None,
            )
            .unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persists_across_reopen() {
        let path = unique_db_path("chio-exec-nonce");
        {
            let store = SqliteExecutionNonceStore::open(&path).unwrap();
            let now = now_secs();
            assert!(store
                .try_reserve("persistent-nonce", now, now.saturating_add(1_000_000_000),)
                .unwrap());
        }
        let reopened = SqliteExecutionNonceStore::open(&path).unwrap();
        let now = now_secs();
        assert!(!reopened
            .try_reserve("persistent-nonce", now, now.saturating_add(1_000_000_000),)
            .unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn capacity_pressure_persists_across_reopen() {
        let path = unique_db_path("chio-exec-nonce-capacity-restart");
        let now;
        {
            let store = SqliteExecutionNonceStore::open_with_capacity(&path, 1).unwrap();
            now = now_secs();
            assert!(store
                .try_reserve("restart-a", now, now.saturating_add(300))
                .unwrap());
        }

        let reopened = SqliteExecutionNonceStore::open_with_capacity(&path, 1).unwrap();
        let reopen_now = now_secs();
        assert!(!reopened
            .try_reserve("restart-a", reopen_now, now.saturating_add(300))
            .unwrap());
        let error = reopened
            .try_reserve("restart-b", reopen_now, now.saturating_add(300))
            .unwrap_err();
        assert!(error.to_string().contains("capacity 1 exhausted"));
        assert!(!reopened
            .try_reserve("restart-a", reopen_now, now.saturating_add(300))
            .unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn independently_opened_handles_cannot_change_the_persisted_capacity() {
        let path = unique_db_path("chio-exec-nonce-capacity-handle-mismatch");
        let store = SqliteExecutionNonceStore::open_with_capacity(&path, 1).unwrap();
        let error = match SqliteExecutionNonceStore::open_with_capacity(&path, 2) {
            Ok(_) => panic!("a second handle must not weaken the persisted capacity"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("does not match requested capacity"));

        let now = now_secs();
        assert!(store
            .try_reserve("persisted-limit-a", now, now.saturating_add(300))
            .unwrap());
        assert!(store
            .try_reserve("persisted-limit-b", now, now.saturating_add(300))
            .is_err());
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn reopening_below_retained_row_count_fails_without_eviction() {
        let path = unique_db_path("chio-exec-nonce-capacity-reconfigure");
        let now;
        {
            let store = SqliteExecutionNonceStore::open_with_capacity(&path, 2).unwrap();
            now = now_secs();
            assert!(store
                .try_reserve("retained-a", now, now.saturating_add(300))
                .unwrap());
            assert!(store
                .try_reserve("retained-b", now, now.saturating_add(300))
                .unwrap());
        }

        let error = match SqliteExecutionNonceStore::open_with_capacity(&path, 1) {
            Ok(_) => panic!("store must not evict retained rows to satisfy a smaller capacity"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("below the 2 retained"));

        let reopened = SqliteExecutionNonceStore::open_with_capacity(&path, 2).unwrap();
        let reopen_now = now_secs();
        assert!(!reopened
            .try_reserve("retained-a", reopen_now, now.saturating_add(300))
            .unwrap());
        assert!(!reopened
            .try_reserve("retained-b", reopen_now, now.saturating_add(300))
            .unwrap());
        let _ = fs::remove_file(path);
    }
}
