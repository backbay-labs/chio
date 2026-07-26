//! Durable replay prevention for authenticated Agent-Web webhook deliveries.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use chio_agent_web_interop::{
    AgentWebReplayEntry, AgentWebReplayStore, AgentWebReplayStoreError,
    DEFAULT_AGENT_WEB_REPLAY_GLOBAL_CAPACITY, DEFAULT_AGENT_WEB_REPLAY_PER_SCOPE_CAPACITY,
};
use rusqlite::{params, Connection, TransactionBehavior};

const LEGACY_UNSCOPED_REPLAY_SCOPE: &str = "__chio_legacy_unscoped_replay_scope__";

#[derive(Debug, thiserror::Error)]
#[error("sqlite Agent-Web replay store error: {0}")]
pub struct SqliteAgentWebReplayStoreError(String);

impl From<std::io::Error> for SqliteAgentWebReplayStoreError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<rusqlite::Error> for SqliteAgentWebReplayStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self(error.to_string())
    }
}

#[derive(Debug)]
pub struct SqliteAgentWebReplayStore {
    path: PathBuf,
    global_capacity: usize,
    per_scope_capacity: usize,
}

impl SqliteAgentWebReplayStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteAgentWebReplayStoreError> {
        Self::open_with_capacity(
            path,
            DEFAULT_AGENT_WEB_REPLAY_GLOBAL_CAPACITY,
            DEFAULT_AGENT_WEB_REPLAY_PER_SCOPE_CAPACITY,
        )
    }

    pub fn open_with_capacity(
        path: impl AsRef<Path>,
        global_capacity: usize,
        per_scope_capacity: usize,
    ) -> Result<Self, SqliteAgentWebReplayStoreError> {
        validate_capacities(global_capacity, per_scope_capacity)?;
        let path = path.as_ref();
        let path_text = path.to_string_lossy();
        if path_text.is_empty() || path_text == ":memory:" || path_text.starts_with("file:") {
            return Err(SqliteAgentWebReplayStoreError(
                "a durable filesystem path is required".to_string(),
            ));
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let store = Self {
            path: path.to_path_buf(),
            global_capacity,
            per_scope_capacity,
        };
        store.run_migrations()?;
        store.validate_retained_capacity()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), SqliteAgentWebReplayStoreError> {
        let mut connection = self.connection()?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            "#,
        )?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let entries_exist = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table' AND name = 'chio_agent_web_replays'
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )?;
        let has_replay_scope = if entries_exist {
            let mut statement = transaction.prepare("PRAGMA table_info(chio_agent_web_replays)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "replay_scope" {
                    found = true;
                    break;
                }
            }
            found
        } else {
            false
        };
        if entries_exist && !has_replay_scope {
            transaction.execute(
                "ALTER TABLE chio_agent_web_replays RENAME TO chio_agent_web_replays_legacy_unscoped",
                [],
            )?;
            transaction.execute(
                "DROP INDEX IF EXISTS idx_chio_agent_web_replays_expires_at",
                [],
            )?;
        }
        transaction.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS chio_agent_web_replays (
                replay_scope TEXT NOT NULL,
                webhook_id  TEXT NOT NULL,
                consumed_at INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL,
                PRIMARY KEY (replay_scope, webhook_id)
            );

            CREATE INDEX IF NOT EXISTS idx_chio_agent_web_replays_expires_at
                ON chio_agent_web_replays(expires_at);

            CREATE TABLE IF NOT EXISTS chio_agent_web_replay_clock (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                wall_clock_high_water INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_agent_web_replay_limits (
                singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
                global_capacity    INTEGER NOT NULL CHECK (global_capacity > 0),
                per_scope_capacity INTEGER NOT NULL CHECK (per_scope_capacity > 0)
            );
            "#,
        )?;
        let global_capacity = i64::try_from(self.global_capacity).map_err(|_| {
            SqliteAgentWebReplayStoreError(
                "global replay capacity exceeds SQLite integer range".to_string(),
            )
        })?;
        let per_scope_capacity = i64::try_from(self.per_scope_capacity).map_err(|_| {
            SqliteAgentWebReplayStoreError(
                "per-scope replay capacity exceeds SQLite integer range".to_string(),
            )
        })?;
        transaction.execute(
            "INSERT INTO chio_agent_web_replay_limits (singleton, global_capacity, per_scope_capacity) VALUES (1, ?1, ?2) ON CONFLICT(singleton) DO NOTHING",
            params![global_capacity, per_scope_capacity],
        )?;
        if entries_exist && !has_replay_scope {
            transaction.execute(
                r#"
                INSERT INTO chio_agent_web_replays (
                    replay_scope,
                    webhook_id,
                    consumed_at,
                    expires_at
                )
                SELECT ?1, webhook_id, consumed_at, expires_at
                FROM chio_agent_web_replays_legacy_unscoped
                "#,
                params![LEGACY_UNSCOPED_REPLAY_SCOPE],
            )?;
            transaction.execute("DROP TABLE chio_agent_web_replays_legacy_unscoped", [])?;
        }
        let latest_consumed_at = transaction.query_row(
            "SELECT MAX(consumed_at) FROM chio_agent_web_replays",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        // An empty store has not observed verifier time yet. Seed it at zero so
        // the first authenticated verifier observation establishes the durable
        // high-water. Migrated rows still carry their historical consumed time,
        // which prevents reopening an already observed rollback window.
        let migration_high_water = latest_consumed_at.unwrap_or(0);
        transaction.execute(
            r#"
            INSERT INTO chio_agent_web_replay_clock (singleton, wall_clock_high_water)
            VALUES (1, ?1)
            ON CONFLICT(singleton) DO UPDATE SET
                wall_clock_high_water = MAX(
                    chio_agent_web_replay_clock.wall_clock_high_water,
                    excluded.wall_clock_high_water
                )
            "#,
            params![migration_high_water],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn validate_retained_capacity(&self) -> Result<(), SqliteAgentWebReplayStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let high_water = transaction.query_row(
            "SELECT wall_clock_high_water FROM chio_agent_web_replay_clock WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        transaction.execute(
            "DELETE FROM chio_agent_web_replays WHERE expires_at < ?1",
            params![high_water],
        )?;
        let retained_rows =
            transaction.query_row("SELECT COUNT(*) FROM chio_agent_web_replays", [], |row| {
                row.get::<_, i64>(0)
            })?;
        let largest_scope = transaction.query_row(
            r#"
            SELECT COALESCE(MAX(scope_rows), 0)
            FROM (
                SELECT COUNT(*) AS scope_rows
                FROM chio_agent_web_replays
                GROUP BY replay_scope
            )
            "#,
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let (persisted_global_capacity, persisted_per_scope_capacity) = transaction.query_row(
            "SELECT global_capacity, per_scope_capacity FROM chio_agent_web_replay_limits WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        transaction.commit()?;
        let retained_rows = count_as_usize(retained_rows, "retained replay row count")?;
        let largest_scope = count_as_usize(largest_scope, "retained per-scope replay row count")?;
        if retained_rows > self.global_capacity {
            return Err(SqliteAgentWebReplayStoreError(format!(
                "configured global capacity {} is below the {retained_rows} retained Agent-Web replay rows",
                self.global_capacity
            )));
        }
        if largest_scope > self.per_scope_capacity {
            return Err(SqliteAgentWebReplayStoreError(format!(
                "configured per-scope capacity {} is below the {largest_scope} retained Agent-Web replay rows in one scope",
                self.per_scope_capacity
            )));
        }
        let requested_global_capacity = i64::try_from(self.global_capacity).map_err(|_| {
            SqliteAgentWebReplayStoreError(
                "global replay capacity exceeds SQLite integer range".to_string(),
            )
        })?;
        let requested_per_scope_capacity =
            i64::try_from(self.per_scope_capacity).map_err(|_| {
                SqliteAgentWebReplayStoreError(
                    "per-scope replay capacity exceeds SQLite integer range".to_string(),
                )
            })?;
        if persisted_global_capacity != requested_global_capacity
            || persisted_per_scope_capacity != requested_per_scope_capacity
        {
            return Err(SqliteAgentWebReplayStoreError(format!(
                "persisted Agent-Web replay capacities ({persisted_global_capacity}, {persisted_per_scope_capacity}) do not match requested capacities ({requested_global_capacity}, {requested_per_scope_capacity})"
            )));
        }
        Ok(())
    }

    fn connection(&self) -> Result<Connection, SqliteAgentWebReplayStoreError> {
        let connection = Connection::open(&self.path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA synchronous = FULL;")?;
        Ok(connection)
    }
}

impl AgentWebReplayStore for SqliteAgentWebReplayStore {
    fn check_and_insert(
        &self,
        now_unix_seconds: u64,
        entries: &[AgentWebReplayEntry],
    ) -> Result<(), AgentWebReplayStoreError> {
        let now = i64::try_from(now_unix_seconds).map_err(|error| {
            AgentWebReplayStoreError::Unavailable(format!("invalid verifier time: {error}"))
        })?;
        let mut connection = self
            .connection()
            .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;

        let wall_clock_high_water = transaction
            .query_row(
                "SELECT wall_clock_high_water FROM chio_agent_web_replay_clock WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
        if now < wall_clock_high_water {
            return Err(AgentWebReplayStoreError::Unavailable(format!(
                "verifier clock rollback detected: {now} is before high-water {wall_clock_high_water}"
            )));
        }
        if now > wall_clock_high_water {
            transaction
                .execute(
                    "UPDATE chio_agent_web_replay_clock SET wall_clock_high_water = ?1 WHERE singleton = 1",
                    params![now],
                )
                .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
        }

        let mut expires_at_values = Vec::with_capacity(entries.len());
        for entry in entries {
            let expires_at = match i64::try_from(entry.expires_at_unix_seconds()) {
                Ok(expires_at) => expires_at,
                Err(error) => {
                    transaction.commit().map_err(|commit_error| {
                        AgentWebReplayStoreError::Unavailable(commit_error.to_string())
                    })?;
                    return Err(AgentWebReplayStoreError::Unavailable(format!(
                        "invalid replay expiry for {}: {error}",
                        entry.webhook_id()
                    )));
                }
            };
            if expires_at < now {
                transaction
                    .commit()
                    .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
                return Err(AgentWebReplayStoreError::Unavailable(format!(
                    "replay expiry for {} is before verifier time",
                    entry.webhook_id()
                )));
            }
            expires_at_values.push(expires_at);
        }

        let mut batch_keys = BTreeSet::new();
        let mut batch_scope_counts = BTreeMap::<&str, usize>::new();
        for entry in entries {
            let key = (entry.replay_scope().as_str(), entry.webhook_id());
            if !batch_keys.insert(key) {
                transaction
                    .commit()
                    .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
                return Err(AgentWebReplayStoreError::Replayed(
                    entry.webhook_id().to_string(),
                ));
            }
            *batch_scope_counts
                .entry(entry.replay_scope().as_str())
                .or_default() += 1;
        }

        for entry in entries {
            let active = transaction
                .query_row(
                    r#"
                    SELECT EXISTS(
                        SELECT 1
                        FROM chio_agent_web_replays
                        WHERE webhook_id = ?1
                          AND (replay_scope = ?2 OR replay_scope = ?3)
                          AND expires_at >= ?4
                    )
                    "#,
                    params![
                        entry.webhook_id(),
                        entry.replay_scope().as_str(),
                        LEGACY_UNSCOPED_REPLAY_SCOPE,
                        now
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
            if active {
                transaction
                    .commit()
                    .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
                return Err(AgentWebReplayStoreError::Replayed(
                    entry.webhook_id().to_string(),
                ));
            }
        }

        let (global_capacity, per_scope_capacity) = transaction
            .query_row(
                "SELECT global_capacity, per_scope_capacity FROM chio_agent_web_replay_limits WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
        let live_global = transaction
            .query_row(
                "SELECT COUNT(*) FROM chio_agent_web_replays WHERE expires_at >= ?1",
                params![now],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
        let batch_size = i64::try_from(entries.len()).map_err(|error| {
            AgentWebReplayStoreError::Unavailable(format!(
                "replay batch size exceeds SQLite integer range: {error}"
            ))
        })?;
        if live_global.saturating_add(batch_size) > global_capacity {
            transaction
                .commit()
                .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
            return Err(AgentWebReplayStoreError::Unavailable(format!(
                "global live-entry capacity {} exhausted; denying fail-closed",
                global_capacity
            )));
        }
        for (replay_scope, batch_count) in batch_scope_counts {
            let live_for_scope = transaction
                .query_row(
                    r#"
                    SELECT COUNT(*)
                    FROM chio_agent_web_replays
                    WHERE replay_scope = ?1 AND expires_at >= ?2
                    "#,
                    params![replay_scope, now],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
            let batch_count = i64::try_from(batch_count).map_err(|error| {
                AgentWebReplayStoreError::Unavailable(format!(
                    "per-scope replay batch size exceeds SQLite integer range: {error}"
                ))
            })?;
            if live_for_scope.saturating_add(batch_count) > per_scope_capacity {
                transaction
                    .commit()
                    .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
                return Err(AgentWebReplayStoreError::Unavailable(format!(
                    "per-scope live-entry capacity {} exhausted; denying fail-closed",
                    per_scope_capacity
                )));
            }
        }

        transaction
            .execute(
                "DELETE FROM chio_agent_web_replays WHERE expires_at < ?1",
                params![now],
            )
            .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;

        for (entry, expires_at) in entries.iter().zip(expires_at_values) {
            transaction
                .execute(
                    r#"
                    INSERT INTO chio_agent_web_replays (
                        replay_scope,
                        webhook_id,
                        consumed_at,
                        expires_at
                    )
                    VALUES (?1, ?2, ?3, ?4)
                    "#,
                    params![
                        entry.replay_scope().as_str(),
                        entry.webhook_id(),
                        now,
                        expires_at
                    ],
                )
                .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))?;
        }
        transaction
            .commit()
            .map_err(|error| AgentWebReplayStoreError::Unavailable(error.to_string()))
    }
}

fn validate_capacities(
    global_capacity: usize,
    per_scope_capacity: usize,
) -> Result<(), SqliteAgentWebReplayStoreError> {
    if global_capacity == 0 || per_scope_capacity == 0 {
        return Err(SqliteAgentWebReplayStoreError(
            "global and per-scope replay capacity values must be greater than zero".to_string(),
        ));
    }
    if per_scope_capacity > global_capacity {
        return Err(SqliteAgentWebReplayStoreError(
            "per-scope replay capacity cannot exceed global replay capacity".to_string(),
        ));
    }
    Ok(())
}

fn count_as_usize(count: i64, description: &str) -> Result<usize, SqliteAgentWebReplayStoreError> {
    usize::try_from(count).map_err(|_| {
        SqliteAgentWebReplayStoreError(format!("{description} cannot be represented as usize"))
    })
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use chio_agent_web_interop::{
        AgentWebReplayEntry, AgentWebReplayScope, AgentWebReplayStore, AgentWebReplayStoreError,
    };
    use chio_test_support::prelude::*;
    use rusqlite::{params, Connection};

    use super::SqliteAgentWebReplayStore;

    fn replay_entry(webhook_id: &str, expires_at_unix_seconds: u64) -> AgentWebReplayEntry {
        replay_entry_in_scope(1, webhook_id, expires_at_unix_seconds)
    }

    fn replay_entry_in_scope(
        scope_seed: u8,
        webhook_id: &str,
        expires_at_unix_seconds: u64,
    ) -> AgentWebReplayEntry {
        let replay_scope = AgentWebReplayScope::parse(format!("{scope_seed:064x}"))
            .test_expect("fixture replay scope parses");
        AgentWebReplayEntry::new(replay_scope, webhook_id, expires_at_unix_seconds)
            .test_expect("fixture replay entry validates")
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_expect("system time is after Unix epoch")
            .as_secs()
    }

    #[test]
    fn replay_marker_persists_across_reopen() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let path = tempdir.path().join("replay.sqlite");
        let store = SqliteAgentWebReplayStore::open(&path).test_expect("replay store opens");
        let now = unix_now();
        store
            .check_and_insert(now, &[replay_entry("webhook-1", now + 3_600)])
            .test_expect("first reservation succeeds");
        drop(store);

        let reopened = SqliteAgentWebReplayStore::open(&path).test_expect("replay store reopens");
        let error = reopened
            .check_and_insert(unix_now(), &[replay_entry("webhook-1", now + 3_600)])
            .test_expect_err("replayed id is durable");
        assert_eq!(
            error,
            AgentWebReplayStoreError::Replayed("webhook-1".to_string())
        );
    }

    #[test]
    fn first_verifier_observation_seeds_an_empty_store_clock() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let store = SqliteAgentWebReplayStore::open(tempdir.path().join("replay.sqlite"))
            .test_expect("replay store opens");

        store
            .check_and_insert(1, &[replay_entry("first", 20)])
            .test_expect("first verifier observation establishes high-water");
        let error = store
            .check_and_insert(0, &[])
            .test_expect_err("later rollback below verifier observation rejects");
        assert!(matches!(
            error,
            AgentWebReplayStoreError::Unavailable(message)
                if message.contains("clock rollback detected")
        ));
    }

    #[test]
    fn replay_ids_are_independent_across_authenticated_scopes() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let store = SqliteAgentWebReplayStore::open_with_capacity(
            tempdir.path().join("replay.sqlite"),
            4,
            2,
        )
        .test_expect("replay store opens");
        let now = unix_now();
        store
            .check_and_insert(now, &[replay_entry_in_scope(1, "shared", now + 20)])
            .test_expect("first scope reserves id");
        store
            .check_and_insert(now, &[replay_entry_in_scope(2, "shared", now + 20)])
            .test_expect("second authenticated scope may reuse id");
        let error = store
            .check_and_insert(now, &[replay_entry_in_scope(1, "shared", now + 20)])
            .test_expect_err("same scope rejects replay");
        assert_eq!(
            error,
            AgentWebReplayStoreError::Replayed("shared".to_string())
        );
    }

    #[test]
    fn replay_batch_rolls_back_when_later_entry_conflicts() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let store = SqliteAgentWebReplayStore::open(tempdir.path().join("replay.sqlite"))
            .test_expect("replay store opens");
        let now = unix_now();
        store
            .check_and_insert(now, &[replay_entry("conflict", now + 20)])
            .test_expect("conflict marker seeds");

        let error = store
            .check_and_insert(
                now + 1,
                &[
                    replay_entry("fresh", now + 20),
                    replay_entry("conflict", now + 20),
                ],
            )
            .test_expect_err("batch conflict rejects");
        assert_eq!(
            error,
            AgentWebReplayStoreError::Replayed("conflict".to_string())
        );
        store
            .check_and_insert(now + 1, &[replay_entry("fresh", now + 20)])
            .test_expect("earlier batch insert rolled back");
    }

    #[test]
    fn replay_expiry_equality_stays_reserved_until_next_second() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let store = SqliteAgentWebReplayStore::open(tempdir.path().join("replay.sqlite"))
            .test_expect("replay store opens");
        let now = unix_now();
        store
            .check_and_insert(now, &[replay_entry("boundary", now + 1)])
            .test_expect("boundary marker seeds");
        let error = store
            .check_and_insert(now + 1, &[replay_entry("boundary", now + 1)])
            .test_expect_err("expiry equality remains replayed");
        assert_eq!(
            error,
            AgentWebReplayStoreError::Replayed("boundary".to_string())
        );
        store
            .check_and_insert(now + 2, &[replay_entry("boundary", now + 10)])
            .test_expect("expired marker is reclaimed after boundary");
    }

    #[test]
    fn concurrent_duplicate_reservation_has_one_winner() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let store = Arc::new(
            SqliteAgentWebReplayStore::open(tempdir.path().join("replay.sqlite"))
                .test_expect("replay store opens"),
        );
        let now = unix_now();
        let handles = (0..2)
            .map(|_| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    store.check_and_insert(now, &[replay_entry("concurrent", now + 20)])
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().test_expect("reservation thread joins"))
            .collect::<Vec<_>>();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(AgentWebReplayStoreError::Replayed(_))))
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_distinct_reservations_cannot_exceed_global_capacity() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let store = Arc::new(
            SqliteAgentWebReplayStore::open_with_capacity(
                tempdir.path().join("replay.sqlite"),
                1,
                1,
            )
            .test_expect("replay store opens"),
        );
        let now = unix_now();
        let handles = (1..=2)
            .map(|scope_seed| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    store.check_and_insert(
                        now,
                        &[replay_entry_in_scope(
                            scope_seed,
                            &format!("concurrent-{scope_seed}"),
                            now + 20,
                        )],
                    )
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().test_expect("reservation thread joins"))
            .collect::<Vec<_>>();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(AgentWebReplayStoreError::Unavailable(message))
                        if message.contains("global live-entry capacity")
                ))
                .count(),
            1
        );
    }

    #[test]
    fn capacity_denials_are_atomic_and_never_evict_live_markers() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let store = SqliteAgentWebReplayStore::open_with_capacity(
            tempdir.path().join("replay.sqlite"),
            2,
            1,
        )
        .test_expect("replay store opens");
        let now = unix_now();
        store
            .check_and_insert(now, &[replay_entry_in_scope(1, "one", now + 20)])
            .test_expect("first marker reserves");
        let error = store
            .check_and_insert(now, &[replay_entry_in_scope(1, "two", now + 20)])
            .test_expect_err("per-scope capacity rejects");
        assert!(matches!(
            error,
            AgentWebReplayStoreError::Unavailable(message)
                if message.contains("per-scope live-entry capacity")
        ));
        let replay_error = store
            .check_and_insert(now, &[replay_entry_in_scope(1, "one", now + 20)])
            .test_expect_err("capacity denial retained original marker");
        assert_eq!(
            replay_error,
            AgentWebReplayStoreError::Replayed("one".to_string())
        );
        store
            .check_and_insert(now, &[replay_entry_in_scope(2, "two", now + 20)])
            .test_expect("second scope fills global capacity");
        let global_error = store
            .check_and_insert(now, &[replay_entry_in_scope(3, "three", now + 20)])
            .test_expect_err("global capacity rejects");
        assert!(matches!(
            global_error,
            AgentWebReplayStoreError::Unavailable(message)
                if message.contains("global live-entry capacity")
        ));
        store
            .check_and_insert(now + 21, &[replay_entry_in_scope(3, "three", now + 30)])
            .test_expect("expired markers free capacity");

        let atomic_path = tempdir.path().join("atomic.sqlite");
        let atomic_store = SqliteAgentWebReplayStore::open_with_capacity(&atomic_path, 1, 1)
            .test_expect("atomic replay store opens");
        let atomic_now = unix_now();
        atomic_store
            .check_and_insert(
                atomic_now,
                &[
                    replay_entry_in_scope(1, "batch-one", atomic_now + 20),
                    replay_entry_in_scope(2, "batch-two", atomic_now + 20),
                ],
            )
            .test_expect_err("oversized batch rejects atomically");
        atomic_store
            .check_and_insert(
                atomic_now,
                &[replay_entry_in_scope(1, "batch-one", atomic_now + 20)],
            )
            .test_expect("failed oversized batch reserved no prefix");
    }

    #[test]
    fn high_water_survives_reopen_and_closes_forward_prune_rollback_window() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let path = tempdir.path().join("replay.sqlite");
        let store = SqliteAgentWebReplayStore::open(&path).test_expect("replay store opens");
        let forward_now = unix_now() + 100;
        store
            .check_and_insert(forward_now, &[replay_entry("used", forward_now + 10)])
            .test_expect("initial replay marker reserves");
        store
            .check_and_insert(
                forward_now + 11,
                &[replay_entry("forward", forward_now + 20)],
            )
            .test_expect("forward observation prunes the expired marker");
        drop(store);

        let reopened = SqliteAgentWebReplayStore::open(&path).test_expect("replay store reopens");
        let error = reopened
            .check_and_insert(forward_now + 10, &[replay_entry("used", forward_now + 30)])
            .test_expect_err("rollback cannot reuse an id pruned before reopen");
        assert!(matches!(
            error,
            AgentWebReplayStoreError::Unavailable(message)
                if message.contains("clock rollback detected")
        ));
        reopened
            .check_and_insert(forward_now + 11, &[replay_entry("used", forward_now + 30)])
            .test_expect("a clock caught up to the high-water may reclaim the id");
    }

    #[test]
    fn replay_error_persists_high_water_and_keeps_batch_atomic_across_reopen() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let path = tempdir.path().join("replay.sqlite");
        let store = SqliteAgentWebReplayStore::open(&path).test_expect("replay store opens");
        let forward_now = unix_now() + 100;
        store
            .check_and_insert(forward_now, &[replay_entry("conflict", forward_now + 200)])
            .test_expect("conflict marker seeds");
        let error = store
            .check_and_insert(
                forward_now + 50,
                &[
                    replay_entry("fresh", forward_now + 200),
                    replay_entry("conflict", forward_now + 200),
                ],
            )
            .test_expect_err("later replay conflict rejects the whole batch");
        assert_eq!(
            error,
            AgentWebReplayStoreError::Replayed("conflict".to_string())
        );
        drop(store);

        let reopened = SqliteAgentWebReplayStore::open(&path).test_expect("replay store reopens");
        let rollback_error = reopened
            .check_and_insert(forward_now + 49, &[])
            .test_expect_err("empty operation fails closed during rollback after reopen");
        assert!(matches!(
            rollback_error,
            AgentWebReplayStoreError::Unavailable(message)
                if message.contains("clock rollback detected")
        ));
        reopened
            .check_and_insert(
                forward_now + 50,
                &[replay_entry("fresh", forward_now + 200)],
            )
            .test_expect("failed batch did not partially reserve its fresh id");
    }

    #[test]
    fn legacy_rows_raise_migration_high_water_on_open() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let path = tempdir.path().join("legacy-replay.sqlite");
        let legacy_consumed_at =
            i64::try_from(unix_now() + 100).test_expect("fixture timestamp fits SQLite integer");
        let connection = Connection::open(&path).test_expect("legacy database opens");
        connection
            .execute_batch(
                r#"
                CREATE TABLE chio_agent_web_replays (
                    webhook_id TEXT PRIMARY KEY,
                    consumed_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                "#,
            )
            .test_expect("legacy replay table creates");
        connection
            .execute(
                "INSERT INTO chio_agent_web_replays (webhook_id, consumed_at, expires_at) VALUES (?1, ?2, ?3)",
                params!["legacy", legacy_consumed_at, legacy_consumed_at + 100],
            )
            .test_expect("legacy replay row inserts");
        drop(connection);

        let store = SqliteAgentWebReplayStore::open(&path).test_expect("legacy store migrates");
        let rollback_time = u64::try_from(legacy_consumed_at - 1)
            .test_expect("fixture rollback timestamp is nonnegative");
        let error = store
            .check_and_insert(rollback_time, &[replay_entry("fresh", rollback_time + 200)])
            .test_expect_err("legacy consumed time prevents first-operation rollback");
        assert!(matches!(
            error,
            AgentWebReplayStoreError::Unavailable(message)
                if message.contains("clock rollback detected")
        ));
    }

    #[test]
    fn legacy_unscoped_marker_blocks_every_scope_until_expiry() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let path = tempdir.path().join("legacy-unscoped.sqlite");
        let now = unix_now();
        let expires_at = now + 3_600;
        let now_sql = i64::try_from(now).test_expect("fixture time fits SQLite integer");
        let expires_at_sql =
            i64::try_from(expires_at).test_expect("fixture expiry fits SQLite integer");
        let connection = Connection::open(&path).test_expect("legacy database opens");
        connection
            .execute_batch(
                r#"
                CREATE TABLE chio_agent_web_replays (
                    webhook_id TEXT PRIMARY KEY,
                    consumed_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                "#,
            )
            .test_expect("legacy replay table creates");
        connection
            .execute(
                "INSERT INTO chio_agent_web_replays (webhook_id, consumed_at, expires_at) VALUES (?1, ?2, ?3)",
                params!["legacy-shared", now_sql, expires_at_sql],
            )
            .test_expect("legacy replay row inserts");
        drop(connection);

        let store = SqliteAgentWebReplayStore::open(&path).test_expect("legacy store migrates");
        let check_time = unix_now();
        for scope_seed in [1, 2] {
            let error = store
                .check_and_insert(
                    check_time,
                    &[replay_entry_in_scope(
                        scope_seed,
                        "legacy-shared",
                        expires_at,
                    )],
                )
                .test_expect_err("legacy marker blocks authenticated scope");
            assert_eq!(
                error,
                AgentWebReplayStoreError::Replayed("legacy-shared".to_string())
            );
        }

        store
            .check_and_insert(
                expires_at + 1,
                &[replay_entry_in_scope(1, "legacy-shared", expires_at + 20)],
            )
            .test_expect("legacy marker becomes reclaimable after expiry");
        store
            .check_and_insert(
                expires_at + 1,
                &[replay_entry_in_scope(2, "legacy-shared", expires_at + 20)],
            )
            .test_expect("scoped ids are independent after legacy expiry");
    }

    #[test]
    fn reopening_with_lower_capacity_rejects_without_evicting_live_rows() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let path = tempdir.path().join("replay.sqlite");
        let store = SqliteAgentWebReplayStore::open_with_capacity(&path, 2, 2)
            .test_expect("replay store opens");
        let now = unix_now();
        store
            .check_and_insert(
                now,
                &[
                    replay_entry_in_scope(1, "one", now + 3_600),
                    replay_entry_in_scope(1, "two", now + 3_600),
                ],
            )
            .test_expect("live markers reserve");
        drop(store);

        let error = SqliteAgentWebReplayStore::open_with_capacity(&path, 1, 1)
            .test_expect_err("lower capacity rejects reopen");
        assert!(error.to_string().contains("below the 2 retained"));

        let per_scope_error = SqliteAgentWebReplayStore::open_with_capacity(&path, 2, 1)
            .test_expect_err("lower per-scope capacity rejects reopen");
        assert!(per_scope_error
            .to_string()
            .contains("per-scope capacity 1 is below the 2 retained"));

        let reopened = SqliteAgentWebReplayStore::open_with_capacity(&path, 2, 2)
            .test_expect("original capacity reopens");
        let replay_now = unix_now();
        let replay_error = reopened
            .check_and_insert(replay_now, &[replay_entry_in_scope(1, "one", now + 3_600)])
            .test_expect_err("failed lower-capacity open did not evict live rows");
        assert_eq!(
            replay_error,
            AgentWebReplayStoreError::Replayed("one".to_string())
        );
    }

    #[test]
    fn independently_opened_handles_cannot_change_persisted_capacities() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let path = tempdir.path().join("replay-capacity-handles.sqlite");
        let store = SqliteAgentWebReplayStore::open_with_capacity(&path, 2, 1)
            .test_expect("first handle opens");
        let error = SqliteAgentWebReplayStore::open_with_capacity(&path, 4, 2)
            .test_expect_err("second handle cannot weaken persisted capacities");
        assert!(error
            .to_string()
            .contains("do not match requested capacities"));

        let now = unix_now();
        store
            .check_and_insert(now, &[replay_entry_in_scope(1, "one", now + 100)])
            .test_expect("first marker reserves");
        let scope_error = store
            .check_and_insert(now, &[replay_entry_in_scope(1, "two", now + 100)])
            .test_expect_err("persisted per-scope capacity still applies");
        assert!(matches!(
            scope_error,
            AgentWebReplayStoreError::Unavailable(message)
                if message.contains("per-scope live-entry capacity 1")
        ));
    }

    #[test]
    fn explicit_capacities_must_be_positive_and_ordered() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        for (global_capacity, per_scope_capacity) in [(0, 1), (1, 0), (1, 2)] {
            let error = SqliteAgentWebReplayStore::open_with_capacity(
                tempdir.path().join(format!(
                    "invalid-{global_capacity}-{per_scope_capacity}.sqlite"
                )),
                global_capacity,
                per_scope_capacity,
            )
            .test_expect_err("invalid capacities reject");
            assert!(error.to_string().contains("capacity"));
        }
    }

    #[test]
    fn expired_input_rejects_atomically_while_expiry_equality_is_valid() {
        let tempdir = tempfile::tempdir().test_expect("tempdir creates");
        let store = SqliteAgentWebReplayStore::open(tempdir.path().join("replay.sqlite"))
            .test_expect("replay store opens");
        let now = unix_now() + 10;
        let error = store
            .check_and_insert(
                now,
                &[
                    replay_entry("fresh", now + 20),
                    replay_entry("expired", now - 1),
                ],
            )
            .test_expect_err("already expired input rejects the whole batch");
        assert!(matches!(
            error,
            AgentWebReplayStoreError::Unavailable(message)
                if message.contains("replay expiry")
        ));
        store
            .check_and_insert(now, &[replay_entry("fresh", now + 20)])
            .test_expect("invalid batch did not reserve its valid prefix");
        store
            .check_and_insert(now, &[replay_entry("boundary", now)])
            .test_expect("expiry equality is accepted");
        let error = store
            .check_and_insert(now, &[replay_entry("boundary", now + 20)])
            .test_expect_err("expiry equality remains reserved through the current second");
        assert_eq!(
            error,
            AgentWebReplayStoreError::Replayed("boundary".to_string())
        );
        store
            .check_and_insert(now + 1, &[replay_entry("boundary", now + 20)])
            .test_expect("marker becomes reclaimable after its exact expiry boundary");
    }

    #[test]
    fn durable_store_rejects_memory_and_temporary_sqlite_paths() {
        let invalid_paths = [
            "",
            ":memory:",
            "file::memory:?cache=shared",
            "file:temporary?mode=memory&cache=shared",
        ];
        for path in invalid_paths {
            let error =
                SqliteAgentWebReplayStore::open(path).test_expect_err("non-durable path rejects");
            assert!(error.to_string().contains("durable filesystem path"));
        }
    }
}
