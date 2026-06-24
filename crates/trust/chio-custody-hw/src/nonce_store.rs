//! Per-credential nonce store for replay-attack resistance.
//!
//! [`PasskeyNonceStore`] is the trust-boundary surface the issuer
//! consults BEFORE minting a capability. Recording a fresh
//! `(credential_id, challenge_nonce)` pair returns
//! [`RecordOutcome::Fresh`]; a duplicate returns
//! [`RecordOutcome::Replayed`] and the issuer fails the request closed
//! with [`CustodyError::ReplayDetected`].
//!
//! # Retention bound
//!
//! Replay window: nonce store retains entries for `exp + clock_skew`
//! (`clock_skew = 30s` default). Entries older than that are GC-able by a
//! background sweep. The retention bound is the capability `exp` (5 minutes
//! fixed per [`crate::capability::CAPABILITY_LIFETIME_SECONDS`]), NOT the
//! underlying credential lifetime and NOT an open-ended issuer-side
//! window. This keeps the store size bounded by the issuer mint rate
//! times the retention window.
//!
//! # Implementations
//!
//! - [`InMemoryPasskeyNonceStore`]: process-local `Mutex<HashMap<...>>`
//!   used in tests and single-process deployments.
//! - [`SqlitePasskeyNonceStore`] (gated behind `sqlite-store`): durable
//!   backing store sharing the rusqlite version pinned by
//!   chio-store-sqlite. The SQLite implementation owns its own
//!   connection pool here so consumers do not have to take a build-time
//!   dependency on the full chio-store-sqlite crate.
//!
//! # Trust contract
//!
//! - `record_if_fresh` is the only mutating entry point. Implementations
//!   MUST be atomic with respect to concurrent calls so two parallel
//!   replays of the same `(credential_id, challenge_nonce)` cannot both
//!   observe `Fresh`.
//! - `gc_expired` is advisory; failing to call it never causes the
//!   issuer to mint a duplicate capability, only causes the store to
//!   retain dead entries past the retention bound.

use std::collections::HashMap;
use std::sync::Mutex;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::CustodyError;

/// Default clock-skew tolerance for the retention bound. The nonce store
/// retains entries for `exp + clock_skew` seconds.
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 30;

/// Default hard capacity for retained passkey nonces.
///
/// Replay entries are short-lived, but a malicious issuer client can still
/// present an unbounded stream of distinct challenges. The store therefore
/// fails closed once this many entries are retained and relies on the
/// explicit GC path to reopen capacity.
pub const DEFAULT_MAX_NONCE_ENTRIES: usize = 65_536;

/// Maximum transport length for a base64url credential id or challenge
/// nonce accepted by the replay store.
pub const MAX_NONCE_KEY_BYTES: usize = 512;

/// Outcome of a [`PasskeyNonceStore::record_if_fresh`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// The `(credential_id, challenge_nonce)` pair was not present and
    /// has now been recorded with the given expiry.
    Fresh,
    /// The pair was already present with an unexpired entry. The issuer
    /// MUST fail the mint with [`CustodyError::ReplayDetected`].
    Replayed,
}

/// Trust-boundary surface for replay detection.
///
/// Implementations are `Send + Sync` so the issuer can keep them in an
/// `Arc<dyn PasskeyNonceStore>`.
pub trait PasskeyNonceStore: Send + Sync {
    /// Record `(credential_id, challenge_nonce)` keyed for replay
    /// detection. `exp_unix_seconds` is the capability `exp` time the
    /// nonce will be retained until (plus the implementation's
    /// clock-skew bound).
    ///
    /// Atomicity: implementations MUST guarantee that two concurrent
    /// calls with the same key cannot both observe `Fresh`.
    fn record_if_fresh(
        &self,
        credential_id: &str,
        challenge_nonce: &str,
        exp_unix_seconds: i64,
    ) -> Result<RecordOutcome, CustodyError>;

    /// Sweep entries whose retention bound is below `now_unix_seconds`.
    ///
    /// Returns the number of records pruned. Advisory: callers may run
    /// this on a background timer; failing to run it never causes a
    /// false `Fresh` result.
    fn gc_expired(&self, now_unix_seconds: i64) -> Result<usize, CustodyError>;

    /// Number of currently retained entries. Used by tests and metrics.
    fn len(&self) -> Result<usize, CustodyError>;

    /// True if no entries are retained.
    fn is_empty(&self) -> Result<bool, CustodyError> {
        Ok(self.len()? == 0)
    }
}

/// Internal map keyed on `(credential_id, challenge_nonce)` whose value
/// is the Unix-seconds retention bound (capability `exp` plus the
/// clock-skew tolerance) past which the entry is GC-able.
type NonceMap = HashMap<(String, String), i64>;

fn validate_nonce_key_part(label: &str, value: &str) -> Result<(), CustodyError> {
    if value.is_empty() {
        return Err(CustodyError::Encoding(format!(
            "{label} must be a non-empty base64url string"
        )));
    }
    if value.len() > MAX_NONCE_KEY_BYTES {
        return Err(CustodyError::Encoding(format!(
            "{label} length {} exceeds {MAX_NONCE_KEY_BYTES} bytes",
            value.len()
        )));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(CustodyError::Encoding(format!(
            "{label} must contain only base64url characters"
        )));
    }
    Ok(())
}

fn validate_nonce_key(credential_id: &str, challenge_nonce: &str) -> Result<(), CustodyError> {
    validate_nonce_key_part("credential_id", credential_id)?;
    validate_nonce_key_part("challenge_nonce", challenge_nonce)
}

/// Process-local replay-detection store.
///
/// Backed by `Mutex<NonceMap>`.
pub struct InMemoryPasskeyNonceStore {
    inner: Mutex<NonceMap>,
    clock_skew_seconds: i64,
    max_entries: usize,
}

impl Default for InMemoryPasskeyNonceStore {
    fn default() -> Self {
        Self::with_clock_skew(DEFAULT_CLOCK_SKEW_SECONDS)
    }
}

impl InMemoryPasskeyNonceStore {
    /// Build a fresh store with the default clock-skew tolerance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a fresh store with a custom clock-skew tolerance.
    #[must_use]
    pub fn with_clock_skew(clock_skew_seconds: i64) -> Self {
        Self::with_limits(clock_skew_seconds, DEFAULT_MAX_NONCE_ENTRIES)
    }

    /// Build a fresh store with a custom hard capacity.
    #[must_use]
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self::with_limits(DEFAULT_CLOCK_SKEW_SECONDS, max_entries)
    }

    /// Build a fresh store with custom clock-skew and capacity limits.
    #[must_use]
    pub fn with_limits(clock_skew_seconds: i64, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            clock_skew_seconds,
            max_entries,
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, NonceMap>, CustodyError> {
        self.inner
            .lock()
            .map_err(|err| CustodyError::Encoding(format!("nonce store mutex poisoned: {err}")))
    }
}

impl PasskeyNonceStore for InMemoryPasskeyNonceStore {
    fn record_if_fresh(
        &self,
        credential_id: &str,
        challenge_nonce: &str,
        exp_unix_seconds: i64,
    ) -> Result<RecordOutcome, CustodyError> {
        validate_nonce_key(credential_id, challenge_nonce)?;
        let mut guard = self.lock()?;
        let key = (credential_id.to_string(), challenge_nonce.to_string());
        let retain_until = exp_unix_seconds.saturating_add(self.clock_skew_seconds);

        // Fail-closed: any present entry, even if past its retention
        // bound, is treated as a replay. The `gc_expired` sweep is the
        // ONLY entry point that drops entries; we never prune on the
        // record path because doing so would couple replay decisions
        // to the wall clock and create a window where a slow GC sweep
        // could be observed as accepting a replay.
        if guard.contains_key(&key) {
            return Ok(RecordOutcome::Replayed);
        }
        if guard.len() >= self.max_entries {
            return Err(CustodyError::Encoding(format!(
                "nonce store capacity exceeded: {} retained entries (max {})",
                guard.len(),
                self.max_entries
            )));
        }
        guard.insert(key, retain_until);
        Ok(RecordOutcome::Fresh)
    }

    fn gc_expired(&self, now_unix_seconds: i64) -> Result<usize, CustodyError> {
        let mut guard = self.lock()?;
        let before = guard.len();
        guard.retain(|_, retain_until| *retain_until >= now_unix_seconds);
        Ok(before - guard.len())
    }

    fn len(&self) -> Result<usize, CustodyError> {
        Ok(self.lock()?.len())
    }
}

/// Resolve the current Unix time in seconds.
///
/// Used by the in-memory test fixtures and (when consumers enable
/// background GC) by the sweep loop. Failures map to `Encoding` because
/// a system clock that pre-dates the Unix epoch is a deployment-side
/// bug, not an authentication failure.
#[cfg(test)]
fn current_unix_seconds() -> Result<i64, CustodyError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| CustodyError::Encoding(format!("system clock pre-1970: {err}")))?;
    let secs = elapsed.as_secs();
    i64::try_from(secs)
        .map_err(|err| CustodyError::Encoding(format!("system clock overflow: {err}")))
}

#[cfg(feature = "sqlite-store")]
mod sqlite {
    //! SQLite-backed [`PasskeyNonceStore`].
    //!
    //! Re-uses the same rusqlite version pinned by chio-store-sqlite
    //! (workspace `rusqlite = "0.39"`). The
    //! implementation owns its own connection so callers do not need
    //! to take a build-time dependency on the full chio-store-sqlite
    //! crate just to use the durable nonce store.

    use std::sync::Mutex;

    use rusqlite::{params, Connection, OpenFlags};

    use super::{
        PasskeyNonceStore, RecordOutcome, DEFAULT_CLOCK_SKEW_SECONDS, DEFAULT_MAX_NONCE_ENTRIES,
    };
    use crate::error::CustodyError;

    /// Durable [`PasskeyNonceStore`] backed by a single SQLite
    /// connection (pooled if the caller wraps in a connection pool).
    pub struct SqlitePasskeyNonceStore {
        conn: Mutex<Connection>,
        clock_skew_seconds: i64,
        max_entries: usize,
    }

    impl SqlitePasskeyNonceStore {
        /// Open or create a SQLite-backed nonce store at `path` with
        /// the default clock-skew tolerance.
        pub fn open(path: &str) -> Result<Self, CustodyError> {
            Self::open_with_clock_skew(path, DEFAULT_CLOCK_SKEW_SECONDS)
        }

        /// Open or create a SQLite-backed nonce store at `path` with a
        /// custom clock-skew tolerance.
        pub fn open_with_clock_skew(
            path: &str,
            clock_skew_seconds: i64,
        ) -> Result<Self, CustodyError> {
            Self::open_with_limits(path, clock_skew_seconds, DEFAULT_MAX_NONCE_ENTRIES)
        }

        /// Open or create a SQLite-backed nonce store at `path` with
        /// custom clock-skew and hard-cap limits.
        pub fn open_with_limits(
            path: &str,
            clock_skew_seconds: i64,
            max_entries: usize,
        ) -> Result<Self, CustodyError> {
            let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
            let conn = Connection::open_with_flags(path, flags).map_err(|err| {
                CustodyError::Encoding(format!("sqlite open {path} failed: {err}"))
            })?;
            Self::with_connection(conn, clock_skew_seconds, max_entries)
        }

        /// Open an in-memory SQLite store. Used by tests.
        pub fn open_in_memory() -> Result<Self, CustodyError> {
            let conn = Connection::open_in_memory()
                .map_err(|err| CustodyError::Encoding(format!("sqlite mem open: {err}")))?;
            Self::with_connection(conn, DEFAULT_CLOCK_SKEW_SECONDS, DEFAULT_MAX_NONCE_ENTRIES)
        }

        fn with_connection(
            conn: Connection,
            clock_skew_seconds: i64,
            max_entries: usize,
        ) -> Result<Self, CustodyError> {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS chio_custody_nonces (
                    credential_id TEXT NOT NULL,
                    challenge_nonce TEXT NOT NULL,
                    retain_until_unix_seconds INTEGER NOT NULL,
                    PRIMARY KEY (credential_id, challenge_nonce)
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS idx_chio_custody_nonces_retain
                    ON chio_custody_nonces (retain_until_unix_seconds);",
            )
            .map_err(|err| CustodyError::Encoding(format!("sqlite schema init: {err}")))?;
            Ok(Self {
                conn: Mutex::new(conn),
                clock_skew_seconds,
                max_entries,
            })
        }

        fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, CustodyError> {
            self.conn.lock().map_err(|err| {
                CustodyError::Encoding(format!("sqlite nonce store mutex poisoned: {err}"))
            })
        }
    }

    impl PasskeyNonceStore for SqlitePasskeyNonceStore {
        fn record_if_fresh(
            &self,
            credential_id: &str,
            challenge_nonce: &str,
            exp_unix_seconds: i64,
        ) -> Result<RecordOutcome, CustodyError> {
            super::validate_nonce_key(credential_id, challenge_nonce)?;
            let retain_until = exp_unix_seconds.saturating_add(self.clock_skew_seconds);

            // INSERT OR IGNORE atomically detects the duplicate. The
            // sweeper (`gc_expired`) is the ONLY entry point that
            // drops entries; the record path never prunes so replay
            // decisions stay decoupled from the wall clock.
            let guard = self.lock()?;
            let existing: i64 = guard
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM chio_custody_nonces
                        WHERE credential_id = ?1 AND challenge_nonce = ?2
                    )",
                    params![credential_id, challenge_nonce],
                    |row| row.get(0),
                )
                .map_err(|err| CustodyError::Encoding(format!("sqlite exists: {err}")))?;
            if existing != 0 {
                return Ok(RecordOutcome::Replayed);
            }
            let retained: i64 = guard
                .query_row("SELECT COUNT(*) FROM chio_custody_nonces", [], |row| {
                    row.get(0)
                })
                .map_err(|err| CustodyError::Encoding(format!("sqlite count: {err}")))?;
            let retained = usize::try_from(retained)
                .map_err(|err| CustodyError::Encoding(format!("sqlite count overflow: {err}")))?;
            if retained >= self.max_entries {
                return Err(CustodyError::Encoding(format!(
                    "sqlite nonce store capacity exceeded: {retained} retained entries (max {})",
                    self.max_entries
                )));
            }
            let inserted = guard
                .execute(
                    "INSERT OR IGNORE INTO chio_custody_nonces
                     (credential_id, challenge_nonce, retain_until_unix_seconds)
                     VALUES (?1, ?2, ?3)",
                    params![credential_id, challenge_nonce, retain_until],
                )
                .map_err(|err| CustodyError::Encoding(format!("sqlite insert: {err}")))?;

            if inserted == 1 {
                Ok(RecordOutcome::Fresh)
            } else {
                Ok(RecordOutcome::Replayed)
            }
        }

        fn gc_expired(&self, now_unix_seconds: i64) -> Result<usize, CustodyError> {
            let guard = self.lock()?;
            let pruned = guard
                .execute(
                    "DELETE FROM chio_custody_nonces WHERE retain_until_unix_seconds < ?1",
                    params![now_unix_seconds],
                )
                .map_err(|err| CustodyError::Encoding(format!("sqlite gc: {err}")))?;
            Ok(pruned)
        }

        fn len(&self) -> Result<usize, CustodyError> {
            let guard = self.lock()?;
            let count: i64 = guard
                .query_row("SELECT COUNT(*) FROM chio_custody_nonces", [], |row| {
                    row.get(0)
                })
                .map_err(|err| CustodyError::Encoding(format!("sqlite count: {err}")))?;
            usize::try_from(count)
                .map_err(|err| CustodyError::Encoding(format!("sqlite count overflow: {err}")))
        }
    }
}

#[cfg(feature = "sqlite-store")]
pub use sqlite::SqlitePasskeyNonceStore;

#[cfg(test)]
mod tests {
    use super::*;

    fn unwrap_clock() -> i64 {
        match current_unix_seconds() {
            Ok(v) => v,
            Err(e) => panic!("clock fixture must succeed: {e}"),
        }
    }

    #[test]
    fn fresh_then_replay_in_memory() {
        let store = InMemoryPasskeyNonceStore::new();
        let now = unwrap_clock();
        let exp = now + 300;
        let first = match store.record_if_fresh("cred-1", "nonce-1", exp) {
            Ok(o) => o,
            Err(e) => panic!("fresh record must succeed: {e}"),
        };
        assert_eq!(first, RecordOutcome::Fresh);
        let second = match store.record_if_fresh("cred-1", "nonce-1", exp) {
            Ok(o) => o,
            Err(e) => panic!("second record must succeed: {e}"),
        };
        assert_eq!(second, RecordOutcome::Replayed);
    }

    #[test]
    fn distinct_credentials_share_nonce_value_safely() {
        let store = InMemoryPasskeyNonceStore::new();
        let now = unwrap_clock();
        let exp = now + 300;
        let a = match store.record_if_fresh("cred-A", "shared-nonce", exp) {
            Ok(o) => o,
            Err(e) => panic!("record A: {e}"),
        };
        assert_eq!(a, RecordOutcome::Fresh);
        let b = match store.record_if_fresh("cred-B", "shared-nonce", exp) {
            Ok(o) => o,
            Err(e) => panic!("record B: {e}"),
        };
        assert_eq!(
            b,
            RecordOutcome::Fresh,
            "nonce store keys on (credential_id, challenge_nonce); same nonce on a different credential is not a replay"
        );
    }

    #[test]
    fn gc_prunes_expired_entries_only() {
        let store = InMemoryPasskeyNonceStore::with_clock_skew(0);
        let now = unwrap_clock();
        if let Err(e) = store.record_if_fresh("cred", "old", now - 100) {
            panic!("old record: {e}");
        }
        if let Err(e) = store.record_if_fresh("cred", "new", now + 100) {
            panic!("new record: {e}");
        }
        let pruned = match store.gc_expired(now) {
            Ok(n) => n,
            Err(e) => panic!("gc: {e}"),
        };
        assert_eq!(pruned, 1, "only the expired entry must be pruned");
        let len = match store.len() {
            Ok(n) => n,
            Err(e) => panic!("len: {e}"),
        };
        assert_eq!(len, 1);
    }

    #[test]
    fn oversized_nonce_key_rejects_fail_closed() {
        let store = InMemoryPasskeyNonceStore::new();
        let too_long = "a".repeat(MAX_NONCE_KEY_BYTES + 1);
        let err = store.record_if_fresh("cred", &too_long, unwrap_clock() + 300);
        assert!(
            matches!(err, Err(CustodyError::Encoding(_))),
            "oversized nonce keys must not allocate into the replay store"
        );
    }

    #[test]
    fn hard_cap_rejects_new_keys_until_explicit_gc() {
        let store = InMemoryPasskeyNonceStore::with_limits(0, 1);
        let now = unwrap_clock();
        if let Err(e) = store.record_if_fresh("cred", "old", now - 100) {
            panic!("old record: {e}");
        }

        let replay = match store.record_if_fresh("cred", "old", now + 300) {
            Ok(outcome) => outcome,
            Err(e) => panic!("replay at cap should still classify as replay: {e}"),
        };
        assert_eq!(replay, RecordOutcome::Replayed);

        let capped = store.record_if_fresh("cred", "new", now + 300);
        assert!(
            matches!(capped, Err(CustodyError::Encoding(_))),
            "new key must fail closed while retained entries are at cap"
        );

        let pruned = match store.gc_expired(now) {
            Ok(n) => n,
            Err(e) => panic!("gc: {e}"),
        };
        assert_eq!(pruned, 1);
        let fresh = match store.record_if_fresh("cred", "new", now + 300) {
            Ok(outcome) => outcome,
            Err(e) => panic!("fresh after gc: {e}"),
        };
        assert_eq!(fresh, RecordOutcome::Fresh);
    }
}

#[cfg(all(test, feature = "sqlite-store"))]
mod sqlite_tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{PasskeyNonceStore, RecordOutcome, SqlitePasskeyNonceStore};

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_nanos(),
            Err(e) => panic!("clock before epoch: {e}"),
        };
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    #[test]
    fn sqlite_fresh_then_replay_in_memory() {
        let store = match SqlitePasskeyNonceStore::open_in_memory() {
            Ok(s) => s,
            Err(e) => panic!("open mem: {e}"),
        };
        let first = match store.record_if_fresh("cred-1", "nonce-1", 1_000) {
            Ok(o) => o,
            Err(e) => panic!("fresh record: {e}"),
        };
        assert_eq!(first, RecordOutcome::Fresh);
        let second = match store.record_if_fresh("cred-1", "nonce-1", 1_000) {
            Ok(o) => o,
            Err(e) => panic!("second record: {e}"),
        };
        assert_eq!(second, RecordOutcome::Replayed);
    }

    #[test]
    fn sqlite_nonce_single_use_survives_reopen() {
        // The durable store's single-use guarantee must hold across a
        // process restart: a nonce recorded before a reopen MUST be
        // detected as a replay after the reopen.
        let path = unique_db_path("chio-custody-nonce");
        let path_str = match path.to_str() {
            Some(s) => s.to_string(),
            None => panic!("temp path not utf-8"),
        };
        {
            let store = match SqlitePasskeyNonceStore::open(&path_str) {
                Ok(s) => s,
                Err(e) => panic!("open: {e}"),
            };
            let first = match store.record_if_fresh("cred", "n-1", 4_000) {
                Ok(o) => o,
                Err(e) => panic!("first record: {e}"),
            };
            assert_eq!(first, RecordOutcome::Fresh);
        }

        let reopened = match SqlitePasskeyNonceStore::open(&path_str) {
            Ok(s) => s,
            Err(e) => panic!("reopen: {e}"),
        };
        let replay = match reopened.record_if_fresh("cred", "n-1", 4_000) {
            Ok(o) => o,
            Err(e) => panic!("post-reopen record: {e}"),
        };
        assert_eq!(
            replay,
            RecordOutcome::Replayed,
            "a nonce recorded before a reopen must be a replay after the reopen"
        );
        // A distinct nonce on the same credential is still fresh.
        let fresh = match reopened.record_if_fresh("cred", "n-2", 4_000) {
            Ok(o) => o,
            Err(e) => panic!("distinct nonce after reopen: {e}"),
        };
        assert_eq!(fresh, RecordOutcome::Fresh);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path_str}-wal"));
        let _ = std::fs::remove_file(format!("{path_str}-shm"));
    }
}
