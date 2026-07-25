//! SQLite-backed `MemoryProvenanceStore`.
//!
//! Durable append-only hash-chain of memory-write provenance entries.
//! Keeps the same contract as `InMemoryMemoryProvenanceStore` in
//! `chio-kernel::memory_provenance`: `append` computes the chain linkage
//! atomically, `verify_entry` checks both the stored `hash` and the
//! `prev_hash` linkage, and `chain_digest` returns the tail hash.
//!
//! Schema:
//!
//! ```sql
//! CREATE TABLE chio_memory_provenance (
//!     seq           INTEGER PRIMARY KEY AUTOINCREMENT,
//!     entry_id      TEXT NOT NULL UNIQUE,
//!     store         TEXT NOT NULL,
//!     entry_key     TEXT NOT NULL,
//!     capability_id TEXT NOT NULL,
//!     receipt_id    TEXT NOT NULL,
//!     written_at    INTEGER NOT NULL,
//!     prev_hash     TEXT NOT NULL,
//!     hash          TEXT NOT NULL
//! );
//! CREATE INDEX idx_chio_memory_provenance_key
//!     ON chio_memory_provenance(store, entry_key, seq);
//! ```
//!
//! The monotonic `seq` column is the chain position; `verify_entry`
//! looks up the preceding row by `seq` to confirm linkage.

use std::fs;
use std::path::Path;

use chio_kernel::{
    recompute_memory_provenance_entry_hash, MemoryProvenanceAppend, MemoryProvenanceEntry,
    MemoryProvenanceError, MemoryProvenanceStore, ProvenanceVerification, UnverifiedReason,
    MEMORY_PROVENANCE_GENESIS_PREV_HASH,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

/// Opaque error type for the SQLite-backed memory provenance store.
#[derive(Debug)]
pub struct SqliteMemoryProvenanceStoreError(String);

impl std::fmt::Display for SqliteMemoryProvenanceStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sqlite memory provenance store error: {}", self.0)
    }
}

impl std::error::Error for SqliteMemoryProvenanceStoreError {}

impl From<rusqlite::Error> for SqliteMemoryProvenanceStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<std::io::Error> for SqliteMemoryProvenanceStoreError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<r2d2::Error> for SqliteMemoryProvenanceStoreError {
    fn from(error: r2d2::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<SqliteMemoryProvenanceStoreError> for MemoryProvenanceError {
    fn from(error: SqliteMemoryProvenanceStoreError) -> Self {
        MemoryProvenanceError::Backend(error.0)
    }
}

/// SQLite-backed durable memory-provenance chain.
pub struct SqliteMemoryProvenanceStore {
    pool: Pool<SqliteConnectionManager>,
}

/// Memory-provenance-store schema revision. Bump on every schema-affecting change.
const MEMORY_PROVENANCE_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const MEMORY_PROVENANCE_STORE_SCHEMA_KEY: &str = "memory_provenance";
/// Tables shipped before schema stamping existed, used to adopt a pre-stamping
/// memory-provenance database rather than reject it as foreign.
const MEMORY_PROVENANCE_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &["chio_memory_provenance"];

impl SqliteMemoryProvenanceStore {
    /// Open the store at the given path, creating the parent directory
    /// if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteMemoryProvenanceStoreError> {
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
    pub fn open_in_memory() -> Result<Self, SqliteMemoryProvenanceStoreError> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(1).build(manager)?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), SqliteMemoryProvenanceStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|error| SqliteMemoryProvenanceStoreError(format!("pool acquire: {error}")))?;
        crate::check_schema_version(
            &conn,
            MEMORY_PROVENANCE_STORE_SCHEMA_KEY,
            MEMORY_PROVENANCE_STORE_SUPPORTED_SCHEMA_VERSION,
            MEMORY_PROVENANCE_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| SqliteMemoryProvenanceStoreError(error.to_string()))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_memory_provenance (
                seq           INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id      TEXT NOT NULL UNIQUE,
                store         TEXT NOT NULL,
                entry_key     TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                receipt_id    TEXT NOT NULL,
                written_at    INTEGER NOT NULL,
                prev_hash     TEXT NOT NULL,
                hash          TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_memory_provenance_key
                ON chio_memory_provenance(store, entry_key, seq);
            "#,
        )?;
        crate::stamp_schema_version(
            &conn,
            MEMORY_PROVENANCE_STORE_SCHEMA_KEY,
            MEMORY_PROVENANCE_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| SqliteMemoryProvenanceStoreError(error.to_string()))?;
        Ok(())
    }

    /// Test helper: overwrite an existing entry's `hash` column to
    /// simulate tamper. Returns `false` when the row was not found.
    pub fn tamper_entry_hash(
        &self,
        entry_id: &str,
        forged_hash: &str,
    ) -> Result<bool, SqliteMemoryProvenanceStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|error| SqliteMemoryProvenanceStoreError(format!("pool acquire: {error}")))?;
        let updated = conn.execute(
            "UPDATE chio_memory_provenance SET hash = ?1 WHERE entry_id = ?2",
            params![forged_hash, entry_id],
        )?;
        Ok(updated > 0)
    }
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryProvenanceEntry> {
    Ok(MemoryProvenanceEntry {
        entry_id: row.get("entry_id")?,
        store: row.get("store")?,
        key: row.get("entry_key")?,
        capability_id: row.get("capability_id")?,
        receipt_id: row.get("receipt_id")?,
        written_at: row.get::<_, i64>("written_at")? as u64,
        prev_hash: row.get("prev_hash")?,
        hash: row.get("hash")?,
    })
}

impl MemoryProvenanceStore for SqliteMemoryProvenanceStore {
    fn append(
        &self,
        input: MemoryProvenanceAppend,
    ) -> Result<MemoryProvenanceEntry, MemoryProvenanceError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|error| MemoryProvenanceError::Backend(format!("pool acquire: {error}")))?;
        // `IMMEDIATE` guarantees a write lock is taken before any
        // subsequent read inside the transaction -- two concurrent
        // appenders cannot both observe the same tail and fork the
        // chain.
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?;

        let existing = tx
            .query_row(
                r#"
                SELECT entry_id, store, entry_key, capability_id, receipt_id,
                       written_at, prev_hash, hash
                FROM chio_memory_provenance
                WHERE receipt_id = ?1
                LIMIT 1
                "#,
                params![input.receipt_id.as_str()],
                map_row,
            )
            .optional()
            .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?;
        if let Some(existing) = existing {
            if existing.store != input.store
                || existing.key != input.key
                || existing.capability_id != input.capability_id
                || existing.written_at != input.written_at
            {
                return Err(MemoryProvenanceError::Backend(
                    "memory provenance receipt id was reused with different fields".to_string(),
                ));
            }
            tx.commit()
                .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?;
            return Ok(existing);
        }

        let prev_hash: String = tx
            .query_row(
                "SELECT hash FROM chio_memory_provenance ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?
            .unwrap_or_else(|| MEMORY_PROVENANCE_GENESIS_PREV_HASH.to_string());

        let entry_id = format!("mem-prov-{}", Uuid::now_v7());
        let hash = recompute_memory_provenance_entry_hash(
            &entry_id,
            &input.store,
            &input.key,
            &input.capability_id,
            &input.receipt_id,
            input.written_at,
            &prev_hash,
        )?;

        let written_at_i64 = i64::try_from(input.written_at).unwrap_or(i64::MAX);
        tx.execute(
            r#"
            INSERT INTO chio_memory_provenance
                (entry_id, store, entry_key, capability_id, receipt_id, written_at, prev_hash, hash)
            VALUES
                (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                entry_id,
                input.store,
                input.key,
                input.capability_id,
                input.receipt_id,
                written_at_i64,
                prev_hash,
                hash,
            ],
        )
        .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?;

        tx.commit()
            .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?;

        Ok(MemoryProvenanceEntry {
            entry_id,
            store: input.store,
            key: input.key,
            capability_id: input.capability_id,
            receipt_id: input.receipt_id,
            written_at: input.written_at,
            prev_hash,
            hash,
        })
    }

    fn get_entry(
        &self,
        entry_id: &str,
    ) -> Result<Option<MemoryProvenanceEntry>, MemoryProvenanceError> {
        let conn = self
            .pool
            .get()
            .map_err(|error| MemoryProvenanceError::Backend(format!("pool acquire: {error}")))?;
        let row = conn
            .query_row(
                r#"
                SELECT entry_id, store, entry_key, capability_id, receipt_id,
                       written_at, prev_hash, hash
                FROM chio_memory_provenance
                WHERE entry_id = ?1
                "#,
                params![entry_id],
                map_row,
            )
            .optional()
            .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?;
        Ok(row)
    }

    fn latest_for_key(
        &self,
        store: &str,
        key: &str,
    ) -> Result<Option<MemoryProvenanceEntry>, MemoryProvenanceError> {
        let conn = self
            .pool
            .get()
            .map_err(|error| MemoryProvenanceError::Backend(format!("pool acquire: {error}")))?;
        let row = conn
            .query_row(
                r#"
                SELECT entry_id, store, entry_key, capability_id, receipt_id,
                       written_at, prev_hash, hash
                FROM chio_memory_provenance
                WHERE store = ?1 AND entry_key = ?2
                ORDER BY seq DESC
                LIMIT 1
                "#,
                params![store, key],
                map_row,
            )
            .optional()
            .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?;
        Ok(row)
    }

    fn verify_entry(
        &self,
        entry_id: &str,
    ) -> Result<ProvenanceVerification, MemoryProvenanceError> {
        let conn = self
            .pool
            .get()
            .map_err(|error| MemoryProvenanceError::Backend(format!("pool acquire: {error}")))?;

        // Fetch the candidate row plus its seq and the prev row's hash
        // in the same query so verification is a single round-trip.
        let row = conn
            .query_row(
                r#"
                SELECT seq, entry_id, store, entry_key, capability_id, receipt_id,
                       written_at, prev_hash, hash
                FROM chio_memory_provenance
                WHERE entry_id = ?1
                "#,
                params![entry_id],
                |row| {
                    let seq: i64 = row.get("seq")?;
                    let entry = map_row(row)?;
                    Ok((seq, entry))
                },
            )
            .optional()
            .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?;

        let Some((seq, entry)) = row else {
            return Ok(ProvenanceVerification::Unverified {
                reason: UnverifiedReason::NoProvenance,
            });
        };

        let expected = entry.expected_hash()?;
        if expected != entry.hash {
            return Ok(ProvenanceVerification::Unverified {
                reason: UnverifiedReason::ChainTampered,
            });
        }

        let expected_prev: String = conn
            .query_row(
                r#"
                SELECT hash
                FROM chio_memory_provenance
                WHERE seq < ?1
                ORDER BY seq DESC
                LIMIT 1
                "#,
                params![seq],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?
            .unwrap_or_else(|| MEMORY_PROVENANCE_GENESIS_PREV_HASH.to_string());

        if expected_prev != entry.prev_hash {
            return Ok(ProvenanceVerification::Unverified {
                reason: UnverifiedReason::ChainLinkBroken,
            });
        }

        let chain_digest: String = conn
            .query_row(
                "SELECT hash FROM chio_memory_provenance ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?
            .unwrap_or_else(|| MEMORY_PROVENANCE_GENESIS_PREV_HASH.to_string());

        Ok(ProvenanceVerification::Verified {
            entry,
            chain_digest,
        })
    }

    fn chain_digest(&self) -> Result<String, MemoryProvenanceError> {
        let conn = self
            .pool
            .get()
            .map_err(|error| MemoryProvenanceError::Backend(format!("pool acquire: {error}")))?;
        let digest: Option<String> = conn
            .query_row(
                "SELECT hash FROM chio_memory_provenance ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| MemoryProvenanceError::Backend(error.to_string()))?;
        Ok(digest.unwrap_or_else(|| MEMORY_PROVENANCE_GENESIS_PREV_HASH.to_string()))
    }
}
