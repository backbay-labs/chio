use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chio_kernel::{RevocationRecord, RevocationStore, RevocationStoreError};
use rusqlite::{params, Connection, OptionalExtension};

pub struct SqliteRevocationStore {
    connection: Mutex<Connection>,
    /// Whether the backing database lives only in process memory and so loses
    /// every revocation on restart. Computed from the open path, not assumed
    /// durable: an in-memory SQLite database must not satisfy the durability
    /// gate the way a real filesystem path does.
    ephemeral: bool,
}

/// Whether a SQLite path opens a database that lives only in memory for the life
/// of the process. rusqlite enables URI filenames, so the bare `:memory:`
/// sentinel, `file::memory:`, and any `file:...?mode=memory` URI all open a
/// non-durable database that loses every revocation on restart.
fn path_opens_in_memory(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    if value.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    let Some(rest) = value.strip_prefix("file:") else {
        return false;
    };
    let (name, query) = match rest.split_once('?') {
        Some((name, query)) => (name, Some(query)),
        None => (rest, None),
    };
    if name.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    query.is_some_and(|query| {
        query
            .split('&')
            .any(|param| param.eq_ignore_ascii_case("mode=memory"))
    })
}

/// Revocation-store schema revision. Bump on every schema-affecting change.
const REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const REVOCATION_STORE_SCHEMA_KEY: &str = "revocation";
/// Tables shipped before schema stamping existed, used to adopt a pre-stamping
/// revocation database rather than reject it as foreign.
const REVOCATION_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &["revoked_capabilities"];

impl SqliteRevocationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RevocationStoreError> {
        let path = path.as_ref();
        let ephemeral = path_opens_in_memory(path);
        if !ephemeral {
            // Derive the directory from the resolved filesystem path: a `file:`
            // URI sibling (`file:/var/lib/chio/receipts.db.revocations?mode=rwc`)
            // has a query and scheme that a raw `parent()` would fold into a
            // bogus directory, leaving the real one uncreated.
            if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
                fs::create_dir_all(&parent)?;
            }
        }

        let connection = Connection::open(path)?;
        crate::check_schema_version(
            &connection,
            REVOCATION_STORE_SCHEMA_KEY,
            REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION,
            REVOCATION_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS revoked_capabilities (
                capability_id TEXT PRIMARY KEY,
                revoked_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_revoked_capabilities_revoked_at
                ON revoked_capabilities(revoked_at);
            "#,
        )?;
        crate::stamp_schema_version(
            &connection,
            REVOCATION_STORE_SCHEMA_KEY,
            REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;

        Ok(Self {
            connection: Mutex::new(connection),
            ephemeral,
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, RevocationStoreError> {
        self.connection.lock().map_err(|_| {
            RevocationStoreError::Sync("sqlite revocation store lock poisoned".to_string())
        })
    }

    pub fn list_revocations(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<RevocationRecord>, RevocationStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT capability_id, revoked_at
            FROM revoked_capabilities
            WHERE (?1 IS NULL OR capability_id = ?1)
            ORDER BY revoked_at DESC, capability_id ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![capability_id, limit as i64], |row| {
            Ok(RevocationRecord {
                capability_id: row.get(0)?,
                revoked_at: row.get(1)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_revocations_after(
        &self,
        limit: usize,
        after_revoked_at: Option<i64>,
        after_capability_id: Option<&str>,
    ) -> Result<Vec<RevocationRecord>, RevocationStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT capability_id, revoked_at
            FROM revoked_capabilities
            WHERE (
                ?1 IS NULL
                OR revoked_at > ?1
                OR (revoked_at = ?1 AND ?2 IS NOT NULL AND capability_id > ?2)
            )
            ORDER BY revoked_at ASC, capability_id ASC
            LIMIT ?3
            "#,
        )?;
        let rows = statement.query_map(
            params![after_revoked_at, after_capability_id, limit as i64],
            |row| {
                Ok(RevocationRecord {
                    capability_id: row.get(0)?,
                    revoked_at: row.get(1)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn upsert_revocation(&self, record: &RevocationRecord) -> Result<(), RevocationStoreError> {
        self.connection()?.execute(
            r#"
            INSERT INTO revoked_capabilities (capability_id, revoked_at)
            VALUES (?1, ?2)
            ON CONFLICT(capability_id) DO UPDATE SET
                revoked_at = MAX(revoked_at, excluded.revoked_at)
            "#,
            params![record.capability_id, record.revoked_at],
        )?;
        Ok(())
    }

    /// The head of the revocation stream as the pagination cursor tuple
    /// (revoked_at, capability_id), or None when empty. list_revocations_after
    /// paginates ascending, so the head is the descending row.
    pub fn latest_revocation_cursor(&self) -> Result<Option<(i64, String)>, RevocationStoreError> {
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT revoked_at, capability_id FROM revoked_capabilities \
                 ORDER BY revoked_at DESC, capability_id DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        Ok(row)
    }
}

impl RevocationStore for SqliteRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let exists = self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(exists != 0)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let revoked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        let inserted = self
            .connection()?
            .query_row(
            r#"
            INSERT INTO revoked_capabilities (capability_id, revoked_at) VALUES (?1, ?2) ON CONFLICT(capability_id) DO NOTHING RETURNING 1
            "#,
                params![capability_id, revoked_at],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        Ok(inserted.is_some())
    }

    fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    #[test]
    fn sqlite_revocation_store_persists_across_reopen() {
        let path = unique_db_path("chio-revocations");
        {
            let store = SqliteRevocationStore::open(&path).unwrap();
            assert!(!store.is_revoked("cap-1").unwrap());
            assert!(store.revoke("cap-1").unwrap());
            assert!(store.is_revoked("cap-1").unwrap());
            assert!(!store.revoke("cap-1").unwrap());
        }

        let reopened = SqliteRevocationStore::open(&path).unwrap();
        assert!(reopened.is_revoked("cap-1").unwrap());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn latest_revocation_cursor_returns_head_or_none() -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_db_path("chio-rev-head");
        let store = SqliteRevocationStore::open(&path)?;
        assert_eq!(store.latest_revocation_cursor()?, None);
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-a".to_string(),
            revoked_at: 10,
        })?;
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-b".to_string(),
            revoked_at: 25,
        })?;
        assert_eq!(
            store.latest_revocation_cursor()?,
            Some((25, "cap-b".to_string()))
        );
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn file_backed_revocation_store_reports_durable() {
        let path = unique_db_path("chio-rev-durable");
        let store = SqliteRevocationStore::open(&path).unwrap();
        assert!(
            !store.is_ephemeral(),
            "a filesystem-backed revocation store is durable"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn in_memory_revocation_store_reports_ephemeral() {
        for path in [":memory:", "file::memory:", "file:rev?mode=memory"] {
            let store = SqliteRevocationStore::open(path).unwrap();
            assert!(
                store.is_ephemeral(),
                "in-memory revocation store {path} must report ephemeral so the durability gate refuses it"
            );
        }
    }

    #[test]
    fn open_creates_parent_dirs_for_a_file_uri_with_query() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("chio-rev-uri-{nonce}"));
        let db = base.join("nested").join("receipts.db.revocations");
        let parent = db.parent().expect("db path has a parent");
        assert!(
            !parent.exists(),
            "precondition: the parent dir must not exist yet"
        );

        // A `file:` URI sibling path carrying a query. A raw `parent()` would
        // resolve to `file:.../nested`, create a bogus relative directory, and
        // leave the real parent uncreated, so SQLite would fail to open it.
        let uri = format!("file:{}?mode=rwc", db.display());
        let store = SqliteRevocationStore::open(uri.as_str()).unwrap();

        assert!(
            !store.is_ephemeral(),
            "a file: URI to a real filesystem path is durable"
        );
        assert!(
            parent.exists(),
            "the real parent directory must be created before SQLite opens the URI"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn sqlite_revocation_store_lists_filtered_entries() {
        let path = unique_db_path("chio-revocations-filtered");
        let store = SqliteRevocationStore::open(&path).unwrap();
        assert!(store.revoke("cap-1").unwrap());
        assert!(store.revoke("cap-2").unwrap());

        let all = store.list_revocations(10, None).unwrap();
        assert_eq!(all.len(), 2);

        let filtered = store.list_revocations(10, Some("cap-1")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].capability_id, "cap-1");

        let _ = fs::remove_file(path);
    }
}
