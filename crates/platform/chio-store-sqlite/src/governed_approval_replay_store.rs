//! Durable replay prevention for governed approval dispatches.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::{
    GovernedApprovalReplayStore, KernelError, ReplayClockDirection,
    DEFAULT_GOVERNED_APPROVAL_REPLAY_CAPACITY,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, TransactionBehavior};

use crate::replay_clock::{ReplayClockValidationError, StableReplayClock};

const LEGACY_UNSCOPED_SUBJECT_ID: &str = "__chio_legacy_unscoped_subject__";

/// Maximum unexplained wall-clock skew accepted by the durable approval store.
pub const MAX_GOVERNED_APPROVAL_CLOCK_SKEW_SECS: u64 = 300;

const MAX_GOVERNED_APPROVAL_CLOCK_SKEW_I64: i64 = 300;

fn configure_pooled_connection(connection: &mut Connection) -> rusqlite::Result<()> {
    connection.execute_batch("PRAGMA busy_timeout = 5000;")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SqliteGovernedApprovalReplayStoreError {
    /// SQLite, pool, filesystem, configuration, or invariant failure.
    Storage(String),
    /// Wall-clock movement that cannot safely advance replay retention.
    ClockAnomaly {
        direction: ReplayClockDirection,
        observed_unix_secs: i64,
        high_water_unix_secs: i64,
        max_tolerated_skew_secs: u64,
    },
}

impl SqliteGovernedApprovalReplayStoreError {
    fn storage(message: impl Into<String>) -> Self {
        Self::Storage(message.into())
    }

    fn clock_anomaly(
        direction: ReplayClockDirection,
        observed_unix_secs: i64,
        high_water_unix_secs: i64,
    ) -> Self {
        Self::ClockAnomaly {
            direction,
            observed_unix_secs,
            high_water_unix_secs,
            max_tolerated_skew_secs: MAX_GOVERNED_APPROVAL_CLOCK_SKEW_SECS,
        }
    }
}

impl std::fmt::Display for SqliteGovernedApprovalReplayStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(message) => write!(
                formatter,
                "sqlite governed approval replay store error: {message}"
            ),
            Self::ClockAnomaly {
                direction,
                observed_unix_secs,
                high_water_unix_secs,
                max_tolerated_skew_secs,
            } => write!(
                formatter,
                "sqlite governed approval replay clock {direction}: observed {observed_unix_secs}, high-water {high_water_unix_secs}, maximum tolerated skew {max_tolerated_skew_secs}s"
            ),
        }
    }
}

impl std::error::Error for SqliteGovernedApprovalReplayStoreError {}

impl From<rusqlite::Error> for SqliteGovernedApprovalReplayStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

impl From<std::io::Error> for SqliteGovernedApprovalReplayStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

impl From<r2d2::Error> for SqliteGovernedApprovalReplayStoreError {
    fn from(error: r2d2::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

fn map_replay_clock_error(
    error: ReplayClockValidationError,
) -> SqliteGovernedApprovalReplayStoreError {
    match error {
        ReplayClockValidationError::Poisoned => {
            SqliteGovernedApprovalReplayStoreError::storage("replay clock mutex poisoned")
        }
        ReplayClockValidationError::Anomaly {
            direction,
            observed,
            high_water,
        } => SqliteGovernedApprovalReplayStoreError::clock_anomaly(direction, observed, high_water),
    }
}

/// SQLite-backed governed approval replay store.
pub struct SqliteGovernedApprovalReplayStore {
    pool: Pool<SqliteConnectionManager>,
    capacity: usize,
    clock: StableReplayClock,
}

const GOVERNED_APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 1;
const GOVERNED_APPROVAL_STORE_SCHEMA_KEY: &str = "governed_approval_replay";
const GOVERNED_APPROVAL_STORE_LEGACY_ANCHOR_TABLES: &[&str] =
    &["chio_governed_approval_replay_entries"];

impl SqliteGovernedApprovalReplayStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteGovernedApprovalReplayStoreError> {
        Self::open_with_capacity(path, DEFAULT_GOVERNED_APPROVAL_REPLAY_CAPACITY)
    }

    pub fn open_with_capacity(
        path: impl AsRef<Path>,
        capacity: usize,
    ) -> Result<Self, SqliteGovernedApprovalReplayStoreError> {
        let path = path.as_ref();
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(parent)?;
        }
        let manager = SqliteConnectionManager::file(path).with_init(configure_pooled_connection);
        let pool = Pool::builder().max_size(8).build(manager)?;
        let store = Self {
            pool,
            capacity: validate_capacity(capacity)?,
            clock: StableReplayClock::new(now_secs(), MAX_GOVERNED_APPROVAL_CLOCK_SKEW_I64),
        };
        store.run_migrations()?;
        store.validate_retained_row_capacity()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, SqliteGovernedApprovalReplayStoreError> {
        Self::open_in_memory_with_capacity(DEFAULT_GOVERNED_APPROVAL_REPLAY_CAPACITY)
    }

    pub fn open_in_memory_with_capacity(
        capacity: usize,
    ) -> Result<Self, SqliteGovernedApprovalReplayStoreError> {
        let manager = SqliteConnectionManager::memory().with_init(configure_pooled_connection);
        let pool = Pool::builder().max_size(1).build(manager)?;
        let store = Self {
            pool,
            capacity: validate_capacity(capacity)?,
            clock: StableReplayClock::new(now_secs(), MAX_GOVERNED_APPROVAL_CLOCK_SKEW_I64),
        };
        store.run_migrations()?;
        store.validate_retained_row_capacity()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), SqliteGovernedApprovalReplayStoreError> {
        let mut conn = self.pool.get()?;
        crate::check_schema_version(
            &conn,
            GOVERNED_APPROVAL_STORE_SCHEMA_KEY,
            GOVERNED_APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION,
            GOVERNED_APPROVAL_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| SqliteGovernedApprovalReplayStoreError::storage(error.to_string()))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            "#,
        )?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let entries_exist = tx.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'chio_governed_approval_replay_entries'
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )?;
        let has_subject_id = if entries_exist {
            let mut statement =
                tx.prepare("PRAGMA table_info(chio_governed_approval_replay_entries)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "subject_id" {
                    found = true;
                    break;
                }
            }
            found
        } else {
            false
        };
        if entries_exist && !has_subject_id {
            tx.execute(
                "ALTER TABLE chio_governed_approval_replay_entries RENAME TO chio_governed_approval_replay_entries_legacy_subjectless",
                [],
            )?;
            tx.execute(
                "DROP INDEX IF EXISTS idx_chio_governed_approval_replay_expiry",
                [],
            )?;
        }
        tx.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS chio_governed_approval_replay_entries (
                subject_id              TEXT NOT NULL,
                request_id              TEXT NOT NULL,
                intent_hash             TEXT NOT NULL,
                expires_at              INTEGER NOT NULL,
                dispatch_reservation_id TEXT,
                PRIMARY KEY (subject_id, request_id, intent_hash)
            );

            CREATE INDEX IF NOT EXISTS idx_chio_governed_approval_replay_expiry
                ON chio_governed_approval_replay_entries(expires_at);

            CREATE TABLE IF NOT EXISTS chio_governed_approval_replay_clock (
                singleton             INTEGER PRIMARY KEY CHECK (singleton = 1),
                wall_clock_high_water INTEGER NOT NULL,
                pruned_through        INTEGER NOT NULL DEFAULT -9223372036854775808
            );

            CREATE TABLE IF NOT EXISTS chio_governed_approval_replay_limits (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                capacity  INTEGER NOT NULL CHECK (capacity > 0)
            );
            "#,
        )?;
        let has_pruned_through = {
            let mut statement =
                tx.prepare("PRAGMA table_info(chio_governed_approval_replay_clock)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "pruned_through" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_pruned_through {
            tx.execute(
                "ALTER TABLE chio_governed_approval_replay_clock ADD COLUMN pruned_through INTEGER NOT NULL DEFAULT -9223372036854775808",
                [],
            )?;
        }
        let capacity = i64::try_from(self.capacity).map_err(|_| {
            SqliteGovernedApprovalReplayStoreError::storage(
                "governed approval replay capacity exceeds SQLite integer range",
            )
        })?;
        tx.execute(
            "INSERT INTO chio_governed_approval_replay_limits (singleton, capacity) VALUES (1, ?1) ON CONFLICT(singleton) DO NOTHING",
            params![capacity],
        )?;
        if entries_exist && !has_subject_id {
            tx.execute(
                r#"
                INSERT INTO chio_governed_approval_replay_entries (
                    subject_id,
                    request_id,
                    intent_hash,
                    expires_at,
                    dispatch_reservation_id
                )
                SELECT ?1, request_id, intent_hash, expires_at, dispatch_reservation_id
                FROM chio_governed_approval_replay_entries_legacy_subjectless
                "#,
                params![LEGACY_UNSCOPED_SUBJECT_ID],
            )?;
            tx.execute(
                "DROP TABLE chio_governed_approval_replay_entries_legacy_subjectless",
                [],
            )?;
        }
        tx.execute(
            r#"
            INSERT INTO chio_governed_approval_replay_clock (
                singleton,
                wall_clock_high_water
            )
            VALUES (1, ?1)
            ON CONFLICT(singleton) DO NOTHING
            "#,
            params![i64::MIN],
        )?;
        tx.execute(
            r#"
            UPDATE chio_governed_approval_replay_clock
            SET wall_clock_high_water = MAX(wall_clock_high_water, ?1)
            WHERE singleton = 1
            "#,
            params![self
                .clock
                .expected_wall_now()
                .map_err(map_replay_clock_error)?],
        )?;
        tx.commit()?;
        crate::stamp_schema_version(
            &conn,
            GOVERNED_APPROVAL_STORE_SCHEMA_KEY,
            GOVERNED_APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| SqliteGovernedApprovalReplayStoreError::storage(error.to_string()))?;
        Ok(())
    }

    fn validate_retained_row_capacity(&self) -> Result<(), SqliteGovernedApprovalReplayStoreError> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let high_water = tx.query_row(
            "SELECT wall_clock_high_water FROM chio_governed_approval_replay_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        self.validate_persisted_clock(high_water)?;
        record_governed_approval_prune(&tx, high_water)?;
        let retained_rows = tx.query_row(
            "SELECT COUNT(*) FROM chio_governed_approval_replay_entries",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let retained_rows = usize::try_from(retained_rows).map_err(|_| {
            SqliteGovernedApprovalReplayStoreError::storage(
                "retained approval replay row count cannot be represented as usize",
            )
        })?;
        let persisted_capacity = tx.query_row(
            "SELECT capacity FROM chio_governed_approval_replay_limits WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let requested_capacity = i64::try_from(self.capacity).map_err(|_| {
            SqliteGovernedApprovalReplayStoreError::storage(
                "governed approval replay capacity exceeds SQLite integer range",
            )
        })?;
        if requested_capacity < persisted_capacity {
            return Err(SqliteGovernedApprovalReplayStoreError::storage(format!(
                "governed approval replay capacity cannot shrink from {persisted_capacity} to {requested_capacity}"
            )));
        }
        if retained_rows > self.capacity {
            return Err(SqliteGovernedApprovalReplayStoreError::storage(format!(
                "configured capacity {} is below the {retained_rows} retained governed approval replay rows",
                self.capacity
            )));
        }
        if requested_capacity > persisted_capacity {
            let changed = tx.execute(
                "UPDATE chio_governed_approval_replay_limits SET capacity = ?1 WHERE singleton = 1 AND capacity = ?2",
                params![requested_capacity, persisted_capacity],
            )?;
            if changed != 1 {
                return Err(SqliteGovernedApprovalReplayStoreError::storage(
                    "governed approval replay capacity changed during serialized reconfiguration",
                ));
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn validate_persisted_clock(
        &self,
        high_water: i64,
    ) -> Result<(), SqliteGovernedApprovalReplayStoreError> {
        self.clock
            .validate_persisted(high_water)
            .map_err(map_replay_clock_error)
    }

    fn validate_observed_clock(
        &self,
        observed: i64,
        high_water: i64,
    ) -> Result<(), SqliteGovernedApprovalReplayStoreError> {
        self.clock
            .validate_observed(observed, high_water)
            .map_err(map_replay_clock_error)
    }

    /// Deliberately lower a latched clock high-water after the host clock has
    /// been corrected. The exact old value is a compare-and-swap guard, and
    /// recovery never deletes retained approval markers.
    pub fn recover_clock_high_water(
        path: impl AsRef<Path>,
        expected_high_water: i64,
        corrected_high_water: i64,
    ) -> Result<(), SqliteGovernedApprovalReplayStoreError> {
        let path = path.as_ref();
        let filesystem_path = path
            .to_str()
            .map(crate::sqlite_filesystem_path)
            .unwrap_or_else(|| path.to_path_buf());
        if !filesystem_path.is_file() {
            return Err(SqliteGovernedApprovalReplayStoreError::storage(format!(
                "governed approval replay database does not exist: {}",
                filesystem_path.display()
            )));
        }

        let observed_now = now_secs();
        let minimum_corrected = observed_now.saturating_sub(MAX_GOVERNED_APPROVAL_CLOCK_SKEW_I64);
        let maximum_corrected = observed_now.saturating_add(MAX_GOVERNED_APPROVAL_CLOCK_SKEW_I64);
        if corrected_high_water < minimum_corrected || corrected_high_water > maximum_corrected {
            return Err(SqliteGovernedApprovalReplayStoreError::storage(format!(
                "corrected high-water {corrected_high_water} is not within the tolerated skew of current wall time {observed_now}"
            )));
        }
        if corrected_high_water >= expected_high_water {
            return Err(SqliteGovernedApprovalReplayStoreError::storage(
                "clock recovery must lower the expected high-water",
            ));
        }

        let mut connection = Connection::open(path)?;
        configure_pooled_connection(&mut connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual_high_water = transaction.query_row(
            "SELECT wall_clock_high_water FROM chio_governed_approval_replay_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let pruned_through = transaction.query_row(
            "SELECT pruned_through FROM chio_governed_approval_replay_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if actual_high_water != expected_high_water {
            return Err(SqliteGovernedApprovalReplayStoreError::storage(format!(
                "clock recovery compare-and-swap failed: expected {expected_high_water}, found {actual_high_water}"
            )));
        }
        if corrected_high_water < pruned_through {
            return Err(SqliteGovernedApprovalReplayStoreError::storage(format!(
                "clock recovery cannot lower the high-water below pruned-through {pruned_through}; retained replay markers may already have been deleted"
            )));
        }
        let changed = transaction.execute(
            "UPDATE chio_governed_approval_replay_clock SET wall_clock_high_water = ?1 WHERE singleton = 1 AND wall_clock_high_water = ?2",
            params![corrected_high_water, expected_high_water],
        )?;
        if changed != 1 {
            return Err(SqliteGovernedApprovalReplayStoreError::storage(
                "clock recovery compare-and-swap did not update the high-water",
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    fn try_reserve_at(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        expires_at: u64,
        reservation_id: &str,
        now: i64,
    ) -> Result<bool, SqliteGovernedApprovalReplayStoreError> {
        validate_key_part("subject_id", subject_id)?;
        if subject_id == LEGACY_UNSCOPED_SUBJECT_ID {
            return Err(SqliteGovernedApprovalReplayStoreError::storage(
                "subject_id uses a reserved legacy marker",
            ));
        }
        validate_key_part("request_id", request_id)?;
        validate_key_part("intent_hash", intent_hash)?;
        validate_key_part("reservation_id", reservation_id)?;
        let expires_at = i64::try_from(expires_at).map_err(|_| {
            SqliteGovernedApprovalReplayStoreError::storage(
                "approval expiry exceeds SQLite integer range",
            )
        })?;

        let mut conn = self.pool.get()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let high_water = tx.query_row(
            "SELECT wall_clock_high_water FROM chio_governed_approval_replay_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        self.validate_observed_clock(now, high_water)?;
        let updated_high_water = high_water.max(now);
        if updated_high_water != high_water {
            tx.execute(
                "UPDATE chio_governed_approval_replay_clock SET wall_clock_high_water = ?1 WHERE singleton = 1",
                params![updated_high_water],
            )?;
        }
        if expires_at <= updated_high_water {
            tx.commit()?;
            return Ok(false);
        }

        record_governed_approval_prune(&tx, updated_high_water)?;
        let already_reserved = tx.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM chio_governed_approval_replay_entries
                WHERE request_id = ?2
                  AND intent_hash = ?3
                  AND (subject_id = ?1 OR subject_id = ?4)
            )
            "#,
            params![
                subject_id,
                request_id,
                intent_hash,
                LEGACY_UNSCOPED_SUBJECT_ID
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if already_reserved {
            tx.commit()?;
            return Ok(false);
        }
        let live_rows = tx.query_row(
            "SELECT COUNT(*) FROM chio_governed_approval_replay_entries",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let capacity = tx.query_row(
            "SELECT capacity FROM chio_governed_approval_replay_limits WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if live_rows >= capacity {
            tx.commit()?;
            return Err(SqliteGovernedApprovalReplayStoreError::storage(format!(
                "live-row capacity {} exhausted; denying fail-closed",
                capacity
            )));
        }

        let inserted = tx.execute(
            r#"
            INSERT INTO chio_governed_approval_replay_entries (
                subject_id,
                request_id,
                intent_hash,
                expires_at,
                dispatch_reservation_id
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(subject_id, request_id, intent_hash) DO NOTHING
            "#,
            params![
                subject_id,
                request_id,
                intent_hash,
                expires_at,
                reservation_id
            ],
        )?;
        tx.commit()?;
        Ok(inserted > 0)
    }

    fn commit_owned(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, SqliteGovernedApprovalReplayStoreError> {
        validate_key_part("subject_id", subject_id)?;
        validate_key_part("request_id", request_id)?;
        validate_key_part("intent_hash", intent_hash)?;
        validate_key_part("reservation_id", reservation_id)?;
        let conn = self.pool.get()?;
        let updated = conn.execute(
            r#"
            UPDATE chio_governed_approval_replay_entries
            SET dispatch_reservation_id = NULL
            WHERE subject_id = ?1
              AND request_id = ?2
              AND intent_hash = ?3
              AND dispatch_reservation_id = ?4
            "#,
            params![subject_id, request_id, intent_hash, reservation_id],
        )?;
        Ok(updated > 0)
    }

    fn rollback_owned(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, SqliteGovernedApprovalReplayStoreError> {
        validate_key_part("subject_id", subject_id)?;
        validate_key_part("request_id", request_id)?;
        validate_key_part("intent_hash", intent_hash)?;
        validate_key_part("reservation_id", reservation_id)?;
        let conn = self.pool.get()?;
        let deleted = conn.execute(
            r#"
            DELETE FROM chio_governed_approval_replay_entries
            WHERE subject_id = ?1
              AND request_id = ?2
              AND intent_hash = ?3
              AND dispatch_reservation_id = ?4
            "#,
            params![subject_id, request_id, intent_hash, reservation_id],
        )?;
        Ok(deleted > 0)
    }
}

fn record_governed_approval_prune(
    transaction: &rusqlite::Transaction<'_>,
    horizon: i64,
) -> Result<(), rusqlite::Error> {
    transaction.execute(
        "DELETE FROM chio_governed_approval_replay_entries WHERE expires_at <= ?1",
        params![horizon],
    )?;
    transaction.execute(
        "UPDATE chio_governed_approval_replay_clock SET pruned_through = MAX(pruned_through, ?1) WHERE singleton = 1",
        params![horizon],
    )?;
    Ok(())
}

impl GovernedApprovalReplayStore for SqliteGovernedApprovalReplayStore {
    fn reserve_for_dispatch(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        expires_at: u64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.try_reserve_at(
            subject_id,
            request_id,
            intent_hash,
            expires_at,
            reservation_id,
            now_secs(),
        )
        .map_err(kernel_store_error)
    }

    fn commit_dispatch_reservation(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.commit_owned(subject_id, request_id, intent_hash, reservation_id)
            .map_err(kernel_store_error)
    }

    fn rollback_dispatch_reservation(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.rollback_owned(subject_id, request_id, intent_hash, reservation_id)
            .map_err(kernel_store_error)
    }
}

fn validate_capacity(capacity: usize) -> Result<usize, SqliteGovernedApprovalReplayStoreError> {
    if capacity == 0 {
        return Err(SqliteGovernedApprovalReplayStoreError::storage(
            "live-row capacity must be greater than zero",
        ));
    }
    Ok(capacity)
}

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
    )
    .unwrap_or(i64::MAX)
}

fn validate_key_part(
    name: &str,
    value: &str,
) -> Result<(), SqliteGovernedApprovalReplayStoreError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(SqliteGovernedApprovalReplayStoreError::storage(format!(
            "{name} must be non-empty and unpadded"
        )));
    }
    Ok(())
}

fn kernel_store_error(error: SqliteGovernedApprovalReplayStoreError) -> KernelError {
    match error {
        SqliteGovernedApprovalReplayStoreError::ClockAnomaly {
            direction,
            observed_unix_secs,
            high_water_unix_secs,
            max_tolerated_skew_secs,
        } => KernelError::ReplayClockAnomaly {
            store: "sqlite_governed_approval_replay_store",
            direction,
            observed_unix_secs,
            high_water_unix_secs,
            max_tolerated_skew_secs,
        },
        SqliteGovernedApprovalReplayStoreError::Storage(message) => {
            KernelError::GovernedTransactionDenied(format!(
                "governed approval replay store unavailable: sqlite governed approval replay store error: {message}"
            ))
        }
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
    fn committed_marker_rejects_replay_after_reopen() {
        let path = unique_db_path("chio-approval-replay-committed");
        let expires_at = u64::try_from(now_secs()).unwrap().saturating_add(60);
        {
            let store = SqliteGovernedApprovalReplayStore::open(&path).unwrap();
            assert!(store
                .reserve_for_dispatch("subject", "request", "intent", expires_at, "owner")
                .unwrap());
            assert!(store
                .commit_dispatch_reservation("subject", "request", "intent", "owner")
                .unwrap());
        }
        let reopened = SqliteGovernedApprovalReplayStore::open(&path).unwrap();
        assert!(!reopened
            .reserve_for_dispatch("subject", "request", "intent", expires_at, "other")
            .unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn uncommitted_marker_rejects_replay_after_reopen() {
        let path = unique_db_path("chio-approval-replay-reserved");
        let expires_at = u64::try_from(now_secs()).unwrap().saturating_add(60);
        {
            let store = SqliteGovernedApprovalReplayStore::open(&path).unwrap();
            assert!(store
                .reserve_for_dispatch("subject", "request", "intent", expires_at, "owner")
                .unwrap());
        }
        let reopened = SqliteGovernedApprovalReplayStore::open(&path).unwrap();
        assert!(!reopened
            .reserve_for_dispatch("subject", "request", "intent", expires_at, "other")
            .unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rollback_and_commit_require_exact_owner() {
        let store = SqliteGovernedApprovalReplayStore::open_in_memory().unwrap();
        let expires_at = u64::try_from(now_secs()).unwrap().saturating_add(60);
        assert!(store
            .reserve_for_dispatch("subject", "request-a", "intent-a", expires_at, "owner-a",)
            .unwrap());
        assert!(!store
            .rollback_dispatch_reservation("subject", "request-a", "intent-a", "owner-b")
            .unwrap());
        assert!(store
            .commit_dispatch_reservation("subject", "request-a", "intent-a", "owner-a")
            .unwrap());
        assert!(!store
            .rollback_dispatch_reservation("subject", "request-a", "intent-a", "owner-a")
            .unwrap());

        assert!(store
            .reserve_for_dispatch("subject", "request-b", "intent-b", expires_at, "owner-b",)
            .unwrap());
        assert!(store
            .rollback_dispatch_reservation("subject", "request-b", "intent-b", "owner-b")
            .unwrap());
    }

    #[test]
    fn identical_request_and_intent_are_scoped_by_subject() {
        let store = SqliteGovernedApprovalReplayStore::open_in_memory().unwrap();
        let expires_at = u64::try_from(now_secs()).unwrap().saturating_add(60);
        assert!(store
            .reserve_for_dispatch("subject-a", "request", "intent", expires_at, "owner-a",)
            .unwrap());
        assert!(store
            .reserve_for_dispatch("subject-b", "request", "intent", expires_at, "owner-b",)
            .unwrap());
    }

    #[test]
    fn bounded_stale_observation_is_accepted_without_lowering_high_water() {
        let store = SqliteGovernedApprovalReplayStore::open_in_memory().unwrap();
        let base = now_secs();
        assert!(store
            .try_reserve_at(
                "subject",
                "request-a",
                "intent-a",
                u64::try_from(base).unwrap().saturating_add(100),
                "owner-a",
                base,
            )
            .unwrap());
        assert!(store
            .try_reserve_at(
                "subject",
                "request-b",
                "intent-b",
                u64::try_from(base).unwrap().saturating_add(200),
                "owner-b",
                base.saturating_sub(1),
            )
            .unwrap());

        let high_water = store
            .pool
            .get()
            .unwrap()
            .query_row(
                "SELECT wall_clock_high_water FROM chio_governed_approval_replay_clock WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(high_water, base);

        assert!(!store
            .try_reserve_at(
                "subject",
                "request-c",
                "intent-c",
                u64::try_from(base).unwrap(),
                "owner-c",
                base,
            )
            .unwrap());

        let error = store
            .try_reserve_at(
                "subject",
                "request-d",
                "intent-d",
                u64::try_from(base).unwrap().saturating_add(200),
                "owner-d",
                base.saturating_sub(MAX_GOVERNED_APPROVAL_CLOCK_SKEW_I64 + 1),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SqliteGovernedApprovalReplayStoreError::ClockAnomaly {
                direction: ReplayClockDirection::Rollback,
                ..
            }
        ));
    }

    #[test]
    fn open_seeds_high_water_before_first_reservation() {
        let before_open = now_secs();
        let store = SqliteGovernedApprovalReplayStore::open_in_memory().unwrap();
        let expires_at = u64::try_from(before_open).unwrap().saturating_add(60);
        let error = store
            .try_reserve_at(
                "subject",
                "request",
                "intent",
                expires_at,
                "owner",
                before_open.saturating_sub(MAX_GOVERNED_APPROVAL_CLOCK_SKEW_I64 + 1),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SqliteGovernedApprovalReplayStoreError::ClockAnomaly {
                direction: ReplayClockDirection::Rollback,
                ..
            }
        ));
    }

    #[test]
    fn latched_future_high_water_is_typed_recoverable_and_retains_markers() {
        let path = unique_db_path("chio-approval-replay-high-water");
        let base = now_secs();
        let expiry = u64::try_from(base).unwrap().saturating_add(10_000);
        {
            let store = SqliteGovernedApprovalReplayStore::open(&path).unwrap();
            assert!(store
                .try_reserve_at(
                    "subject",
                    "future-request",
                    "future-intent",
                    expiry,
                    "owner",
                    base,
                )
                .unwrap());
        }

        let latched_high_water = base.saturating_add(1_000);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE chio_governed_approval_replay_clock SET wall_clock_high_water = ?1 WHERE singleton = 1",
                params![latched_high_water],
            )
            .unwrap();
        drop(connection);

        let error = match SqliteGovernedApprovalReplayStore::open(&path) {
            Ok(_) => panic!("a latched future high-water must require recovery"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SqliteGovernedApprovalReplayStoreError::ClockAnomaly {
                direction: ReplayClockDirection::Rollback,
                high_water_unix_secs,
                ..
            } if high_water_unix_secs == latched_high_water
        ));

        SqliteGovernedApprovalReplayStore::recover_clock_high_water(
            &path,
            latched_high_water,
            now_secs(),
        )
        .unwrap();
        let reopened = SqliteGovernedApprovalReplayStore::open(&path).unwrap();
        assert!(!reopened
            .try_reserve_at(
                "subject",
                "future-request",
                "future-intent",
                expiry,
                "other-owner",
                now_secs(),
            )
            .unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn recovery_refuses_to_cross_a_pruned_high_water() {
        let path = unique_db_path("chio-approval-replay-pruned-through");
        let base = now_secs();
        let expiry = base.saturating_add(100);
        {
            let store = SqliteGovernedApprovalReplayStore::open(&path).unwrap();
            assert!(store
                .try_reserve_at(
                    "subject",
                    "request",
                    "intent",
                    u64::try_from(expiry).unwrap(),
                    "owner",
                    base,
                )
                .unwrap());
            assert!(store
                .commit_owned("subject", "request", "intent", "owner")
                .unwrap());
        }

        let jumped = base.saturating_add(1_000);
        let manager = SqliteConnectionManager::file(&path).with_init(configure_pooled_connection);
        let advanced = SqliteGovernedApprovalReplayStore {
            pool: Pool::builder().max_size(1).build(manager).unwrap(),
            capacity: DEFAULT_GOVERNED_APPROVAL_REPLAY_CAPACITY,
            clock: StableReplayClock::new(jumped, MAX_GOVERNED_APPROVAL_CLOCK_SKEW_I64),
        };
        advanced.run_migrations().unwrap();
        advanced.validate_retained_row_capacity().unwrap();
        drop(advanced);

        let error =
            SqliteGovernedApprovalReplayStore::recover_clock_high_water(&path, jumped, now_secs())
                .unwrap_err();
        assert!(error.to_string().contains("below pruned-through"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn typed_clock_anomaly_maps_to_typed_kernel_error() {
        let error = SqliteGovernedApprovalReplayStoreError::clock_anomaly(
            ReplayClockDirection::Rollback,
            10,
            20,
        );
        assert!(matches!(
            kernel_store_error(error),
            KernelError::ReplayClockAnomaly {
                store: "sqlite_governed_approval_replay_store",
                direction: ReplayClockDirection::Rollback,
                observed_unix_secs: 10,
                high_water_unix_secs: 20,
                max_tolerated_skew_secs: MAX_GOVERNED_APPROVAL_CLOCK_SKEW_SECS,
            }
        ));
    }

    #[test]
    fn capacity_does_not_evict_live_markers_and_expiry_reclaims_space() {
        let store = SqliteGovernedApprovalReplayStore::open_in_memory_with_capacity(1).unwrap();
        let base = now_secs();
        let first_expiry = u64::try_from(base).unwrap().saturating_add(1);
        let second_expiry = u64::try_from(base).unwrap().saturating_add(100);
        assert!(store
            .try_reserve_at(
                "subject",
                "request-a",
                "intent-a",
                first_expiry,
                "owner-a",
                base,
            )
            .unwrap());
        assert!(!store
            .try_reserve_at(
                "subject",
                "request-a",
                "intent-a",
                first_expiry,
                "other",
                base,
            )
            .unwrap());
        assert!(store
            .commit_owned("subject", "request-a", "intent-a", "owner-a")
            .unwrap());
        assert!(store
            .try_reserve_at(
                "subject",
                "request-b",
                "intent-b",
                second_expiry,
                "owner-b",
                base,
            )
            .is_err());
        assert!(store
            .try_reserve_at(
                "subject",
                "request-b",
                "intent-b",
                second_expiry,
                "owner-b",
                base.saturating_add(1),
            )
            .unwrap());
    }

    #[test]
    fn expiry_reclaims_crash_owned_reservation_and_capacity() {
        let store = SqliteGovernedApprovalReplayStore::open_in_memory_with_capacity(1).unwrap();
        let base = now_secs();
        let first_expiry = u64::try_from(base).unwrap().saturating_add(1);
        let second_expiry = u64::try_from(base).unwrap().saturating_add(100);

        assert!(store
            .try_reserve_at(
                "subject",
                "crashed-request",
                "crashed-intent",
                first_expiry,
                "abandoned-owner",
                base,
            )
            .unwrap());
        assert!(store
            .try_reserve_at(
                "subject",
                "next-request",
                "next-intent",
                second_expiry,
                "next-owner",
                base,
            )
            .is_err());

        assert!(store
            .try_reserve_at(
                "subject",
                "next-request",
                "next-intent",
                second_expiry,
                "next-owner",
                base.saturating_add(1),
            )
            .unwrap());
        assert!(!store
            .commit_owned(
                "subject",
                "crashed-request",
                "crashed-intent",
                "abandoned-owner",
            )
            .unwrap());
    }

    #[test]
    fn reopen_rejects_capacity_below_retained_live_rows() {
        let path = unique_db_path("chio-approval-replay-capacity-reopen");
        let expires_at = u64::try_from(now_secs()).unwrap().saturating_add(60);
        {
            let store = SqliteGovernedApprovalReplayStore::open_with_capacity(&path, 2).unwrap();
            assert!(store
                .reserve_for_dispatch("subject", "request-a", "intent", expires_at, "owner-a",)
                .unwrap());
            assert!(store
                .reserve_for_dispatch("subject", "request-b", "intent", expires_at, "owner-b",)
                .unwrap());
        }
        let error = match SqliteGovernedApprovalReplayStore::open_with_capacity(&path, 1) {
            Ok(_) => panic!("open must reject a capacity below retained rows"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("cannot shrink from 2 to 1"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn independently_opened_handles_can_only_increase_persisted_capacity() {
        let path = unique_db_path("chio-approval-replay-capacity-handle-mismatch");
        let store = SqliteGovernedApprovalReplayStore::open_with_capacity(&path, 1).unwrap();
        let larger = SqliteGovernedApprovalReplayStore::open_with_capacity(&path, 2).unwrap();

        let expires_at = u64::try_from(now_secs()).unwrap().saturating_add(60);
        assert!(store
            .reserve_for_dispatch("subject", "request-a", "intent", expires_at, "owner-a")
            .unwrap());
        assert!(store
            .reserve_for_dispatch("subject", "request-b", "intent", expires_at, "owner-b")
            .unwrap());
        drop(larger);

        let error = match SqliteGovernedApprovalReplayStore::open_with_capacity(&path, 1) {
            Ok(_) => panic!("a later handle must not shrink the persisted capacity"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("cannot shrink from 2 to 1"));
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn legacy_subjectless_marker_blocks_all_subjects_until_expiry() {
        let path = unique_db_path("chio-approval-replay-legacy-subjectless");
        let expires_at = now_secs().saturating_add(60);
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    r#"
                    CREATE TABLE chio_governed_approval_replay_entries (
                        request_id              TEXT NOT NULL,
                        intent_hash             TEXT NOT NULL,
                        expires_at              INTEGER NOT NULL,
                        dispatch_reservation_id TEXT,
                        PRIMARY KEY (request_id, intent_hash)
                    );
                    "#,
                )
                .unwrap();
            connection
                .execute(
                    r#"
                    INSERT INTO chio_governed_approval_replay_entries (
                        request_id,
                        intent_hash,
                        expires_at,
                        dispatch_reservation_id
                    ) VALUES ('request', 'intent', ?1, NULL)
                    "#,
                    params![expires_at],
                )
                .unwrap();
        }
        let store = SqliteGovernedApprovalReplayStore::open(&path).unwrap();
        assert!(!store
            .reserve_for_dispatch(
                "subject-a",
                "request",
                "intent",
                u64::try_from(expires_at).unwrap(),
                "owner-a",
            )
            .unwrap());
        assert!(!store
            .reserve_for_dispatch(
                "subject-b",
                "request",
                "intent",
                u64::try_from(expires_at).unwrap(),
                "owner-b",
            )
            .unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn every_pooled_connection_has_busy_timeout() {
        let store = SqliteGovernedApprovalReplayStore::open_in_memory().unwrap();
        let connection = store.pool.get().unwrap();
        let timeout = connection
            .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
            .unwrap();
        assert_eq!(timeout, 5000);
    }

    #[test]
    fn zero_capacity_is_rejected() {
        assert!(SqliteGovernedApprovalReplayStore::open_in_memory_with_capacity(0).is_err());
    }
}
