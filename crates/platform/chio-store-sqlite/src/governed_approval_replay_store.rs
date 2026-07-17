//! Durable replay prevention for governed approval dispatches.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::{
    GovernedApprovalReplayStore, KernelError, DEFAULT_GOVERNED_APPROVAL_REPLAY_CAPACITY,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, TransactionBehavior};

const LEGACY_UNSCOPED_SUBJECT_ID: &str = "__chio_legacy_unscoped_subject__";

fn configure_pooled_connection(connection: &mut Connection) -> rusqlite::Result<()> {
    connection.execute_batch("PRAGMA busy_timeout = 5000;")
}

#[derive(Debug)]
pub struct SqliteGovernedApprovalReplayStoreError(String);

impl std::fmt::Display for SqliteGovernedApprovalReplayStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "sqlite governed approval replay store error: {}",
            self.0
        )
    }
}

impl std::error::Error for SqliteGovernedApprovalReplayStoreError {}

impl From<rusqlite::Error> for SqliteGovernedApprovalReplayStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<std::io::Error> for SqliteGovernedApprovalReplayStoreError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<r2d2::Error> for SqliteGovernedApprovalReplayStoreError {
    fn from(error: r2d2::Error) -> Self {
        Self(error.to_string())
    }
}

/// SQLite-backed governed approval replay store.
pub struct SqliteGovernedApprovalReplayStore {
    pool: Pool<SqliteConnectionManager>,
    capacity: usize,
}

impl SqliteGovernedApprovalReplayStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteGovernedApprovalReplayStoreError> {
        Self::open_with_capacity(path, DEFAULT_GOVERNED_APPROVAL_REPLAY_CAPACITY)
    }

    pub fn open_with_capacity(
        path: impl AsRef<Path>,
        capacity: usize,
    ) -> Result<Self, SqliteGovernedApprovalReplayStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let manager = SqliteConnectionManager::file(path).with_init(configure_pooled_connection);
        let pool = Pool::builder().max_size(8).build(manager)?;
        let store = Self {
            pool,
            capacity: validate_capacity(capacity)?,
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
        };
        store.run_migrations()?;
        store.validate_retained_row_capacity()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), SqliteGovernedApprovalReplayStoreError> {
        let mut conn = self.pool.get()?;
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
                wall_clock_high_water INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_governed_approval_replay_limits (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                capacity  INTEGER NOT NULL CHECK (capacity > 0)
            );
            "#,
        )?;
        let capacity = i64::try_from(self.capacity).map_err(|_| {
            SqliteGovernedApprovalReplayStoreError(
                "governed approval replay capacity exceeds SQLite integer range".to_string(),
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
            params![now_secs()],
        )?;
        tx.commit()?;
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
        tx.execute(
            "DELETE FROM chio_governed_approval_replay_entries WHERE expires_at <= ?1",
            params![high_water],
        )?;
        let retained_rows = tx.query_row(
            "SELECT COUNT(*) FROM chio_governed_approval_replay_entries",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let retained_rows = usize::try_from(retained_rows).map_err(|_| {
            SqliteGovernedApprovalReplayStoreError(
                "retained approval replay row count cannot be represented as usize".to_string(),
            )
        })?;
        let persisted_capacity = tx.query_row(
            "SELECT capacity FROM chio_governed_approval_replay_limits WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let requested_capacity = i64::try_from(self.capacity).map_err(|_| {
            SqliteGovernedApprovalReplayStoreError(
                "governed approval replay capacity exceeds SQLite integer range".to_string(),
            )
        })?;
        if requested_capacity < persisted_capacity {
            return Err(SqliteGovernedApprovalReplayStoreError(format!(
                "governed approval replay capacity cannot shrink from {persisted_capacity} to {requested_capacity}"
            )));
        }
        if retained_rows > self.capacity {
            return Err(SqliteGovernedApprovalReplayStoreError(format!(
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
                return Err(SqliteGovernedApprovalReplayStoreError(
                    "governed approval replay capacity changed during serialized reconfiguration"
                        .to_string(),
                ));
            }
        }
        tx.commit()?;
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
            return Err(SqliteGovernedApprovalReplayStoreError(
                "subject_id uses a reserved legacy marker".to_string(),
            ));
        }
        validate_key_part("request_id", request_id)?;
        validate_key_part("intent_hash", intent_hash)?;
        validate_key_part("reservation_id", reservation_id)?;
        let expires_at = i64::try_from(expires_at).map_err(|_| {
            SqliteGovernedApprovalReplayStoreError(
                "approval expiry exceeds SQLite integer range".to_string(),
            )
        })?;

        let mut conn = self.pool.get()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let high_water = tx.query_row(
            "SELECT wall_clock_high_water FROM chio_governed_approval_replay_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if now < high_water {
            tx.commit()?;
            return Ok(false);
        }
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

        tx.execute(
            "DELETE FROM chio_governed_approval_replay_entries WHERE expires_at <= ?1",
            params![updated_high_water],
        )?;
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
            return Err(SqliteGovernedApprovalReplayStoreError(format!(
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
        return Err(SqliteGovernedApprovalReplayStoreError(
            "live-row capacity must be greater than zero".to_string(),
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
        return Err(SqliteGovernedApprovalReplayStoreError(format!(
            "{name} must be non-empty and unpadded"
        )));
    }
    Ok(())
}

fn kernel_store_error(error: SqliteGovernedApprovalReplayStoreError) -> KernelError {
    KernelError::GovernedTransactionDenied(format!(
        "governed approval replay store unavailable: {error}"
    ))
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
    fn clock_rollback_and_elapsed_expiry_fail_closed() {
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
        assert!(!store
            .try_reserve_at(
                "subject",
                "request-b",
                "intent-b",
                u64::try_from(base).unwrap().saturating_add(200),
                "owner-b",
                base.saturating_sub(1),
            )
            .unwrap());
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
    }

    #[test]
    fn open_seeds_high_water_before_first_reservation() {
        let before_open = now_secs();
        let store = SqliteGovernedApprovalReplayStore::open_in_memory().unwrap();
        let expires_at = u64::try_from(before_open).unwrap().saturating_add(60);
        assert!(!store
            .try_reserve_at(
                "subject",
                "request",
                "intent",
                expires_at,
                "owner",
                before_open.saturating_sub(1),
            )
            .unwrap());
    }

    #[test]
    fn reopen_preserves_a_future_high_water_mark() {
        let path = unique_db_path("chio-approval-replay-high-water");
        let future = now_secs().saturating_add(100);
        let expiry = u64::try_from(future).unwrap().saturating_add(100);
        {
            let store = SqliteGovernedApprovalReplayStore::open(&path).unwrap();
            assert!(store
                .try_reserve_at(
                    "subject",
                    "future-request",
                    "future-intent",
                    expiry,
                    "owner",
                    future,
                )
                .unwrap());
        }

        let reopened = SqliteGovernedApprovalReplayStore::open(&path).unwrap();
        assert!(!reopened
            .try_reserve_at(
                "subject",
                "current-request",
                "current-intent",
                expiry,
                "other-owner",
                now_secs(),
            )
            .unwrap());
        let _ = fs::remove_file(path);
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
