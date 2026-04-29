use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chio_kernel::{RevocationRecord, RevocationStore, RevocationStoreError};
use rusqlite::{params, Connection};

pub struct SqliteRevocationStore {
    connection: Mutex<Connection>,
}

impl SqliteRevocationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RevocationStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(path)?;
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

        Ok(Self {
            connection: Mutex::new(connection),
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
        let rows = self.connection()?.execute(
            r#"
            INSERT INTO revoked_capabilities (capability_id, revoked_at)
            VALUES (?1, ?2)
            ON CONFLICT(capability_id) DO NOTHING
            "#,
            params![capability_id, revoked_at],
        )?;
        Ok(rows > 0)
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
