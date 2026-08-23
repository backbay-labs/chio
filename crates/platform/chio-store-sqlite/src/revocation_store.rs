use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use chio_kernel::budget_store::{
    BudgetEventAuthority, BudgetGuaranteeLevel, RevocationCommitMetadata,
};
use chio_kernel::{RevocationObservation, RevocationRecord, RevocationStore, RevocationStoreError};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

#[derive(Clone)]
pub struct SqliteRevocationStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Option<Arc<crate::serving_owner::SqliteServingOwner>>,
    /// Whether the backing database lives only in process memory and so loses
    /// every revocation on restart. Computed from the open path, not assumed
    /// durable: an in-memory SQLite database must not satisfy the durability
    /// gate the way a real filesystem path does.
    ephemeral: bool,
}

#[derive(Debug, Clone)]
pub struct StoredRevocation {
    pub seq: u64,
    pub record: RevocationRecord,
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
pub(crate) const REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 4;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const REVOCATION_STORE_SCHEMA_KEY: &str = "revocation";
/// Tables shipped before schema stamping existed, used to adopt a pre-stamping
/// revocation database rather than reject it as foreign.
const REVOCATION_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &["revoked_capabilities"];

impl SqliteRevocationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RevocationStoreError> {
        Self::open_with_replication_epoch(path, false)
    }

    /// Open a store that will advertise its delta stream to replication peers.
    ///
    /// Every serving activation rotates the stream identity before the caller
    /// can advertise a cursor. A database restored to an earlier dense-log head
    /// therefore cannot reuse sequence numbers under an identity cached by a
    /// follower. Ordinary non-serving opens retain the stored identity.
    pub fn open_replication_source(path: impl AsRef<Path>) -> Result<Self, RevocationStoreError> {
        Self::open_with_replication_epoch(path, true)
    }

    fn open_with_replication_epoch(
        path: impl AsRef<Path>,
        rotate_replication_epoch: bool,
    ) -> Result<Self, RevocationStoreError> {
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

        let mut connection = Connection::open(path)?;
        if let Some(epoch) = crate::serving_owner::provisioned_owner_epoch(&connection)
            .map_err(|error| RevocationStoreError::Sync(error.to_string()))?
        {
            return Err(RevocationStoreError::Sync(format!(
                "provisioned sqlite authority store requires joint serving owner at epoch {epoch}"
            )));
        }
        crate::check_schema_version(
            &connection,
            REVOCATION_STORE_SCHEMA_KEY,
            REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION,
            REVOCATION_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        initialize_revocation_schema(&mut connection, false)?;
        crate::stamp_schema_version(
            &connection,
            REVOCATION_STORE_SCHEMA_KEY,
            REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        verify_revocation_foreign_keys(&connection)?;
        if rotate_replication_epoch {
            rotate_revocation_stream_identity(&mut connection)?;
        }

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            serving_owner: None,
            ephemeral,
        })
    }

    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<crate::serving_owner::SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner: Some(serving_owner),
            ephemeral: false,
        }
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, RevocationStoreError> {
        self.connection.lock().map_err(|_| {
            RevocationStoreError::Sync("sqlite revocation store lock poisoned".to_string())
        })
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, RevocationStoreError> {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::serving_owner::verify_revocation_fence(&transaction, self.serving_owner.as_deref())?;
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .verify_authority_anchor(&transaction)
                .map_err(map_serving_owner_error)?;
        }
        Ok(transaction)
    }

    fn read<T>(
        &self,
        query: impl FnOnce(&Transaction<'_>) -> Result<T, RevocationStoreError>,
    ) -> Result<T, RevocationStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        crate::serving_owner::verify_revocation_fence(&transaction, self.serving_owner.as_deref())?;
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .verify_authority_anchor(&transaction)
                .map_err(map_serving_owner_error)?;
        }
        let value = query(&transaction)?;
        transaction.rollback()?;
        Ok(value)
    }

    pub fn latest_revocation_index(&self) -> Result<u64, RevocationStoreError> {
        let sql = if self.serving_owner.is_some() {
            "SELECT head_index FROM admission_authority_meta WHERE singleton = 1"
        } else {
            "SELECT next_index FROM revocation_replication_meta WHERE singleton = 1"
        };
        let value = self.read(|transaction| {
            transaction
                .query_row(sql, [], |row| row.get::<_, i64>(0))
                .map_err(Into::into)
        })?;
        u64::try_from(value)
            .map_err(|_| RevocationStoreError::Sync("negative revocation index".to_string()))
    }

    pub fn list_revocations(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<RevocationRecord>, RevocationStoreError> {
        self.read(|transaction| {
            let mut statement = transaction.prepare(
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
        })
    }

    pub fn list_revocations_after(
        &self,
        limit: usize,
        after_revoked_at: Option<i64>,
        after_capability_id: Option<&str>,
    ) -> Result<Vec<RevocationRecord>, RevocationStoreError> {
        self.read(|transaction| {
            let mut statement = transaction.prepare(
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
        })
    }

    pub fn list_revocations_after_seq(
        &self,
        limit: usize,
        after_seq: u64,
    ) -> Result<Vec<StoredRevocation>, RevocationStoreError> {
        self.list_revocations_after_seq_with_head(limit, after_seq)
            .map(|(records, _)| records)
    }

    /// Read one delta page and the stream head from the same SQLite snapshot.
    /// This prevents an append between two separate reads from making an honest
    /// empty page appear to end below a later head.
    pub fn list_revocations_after_seq_with_head(
        &self,
        limit: usize,
        after_seq: u64,
    ) -> Result<(Vec<StoredRevocation>, u64), RevocationStoreError> {
        let after_seq = i64::try_from(after_seq).map_err(|_| {
            RevocationStoreError::Sync("revocation cursor exceeds SQLite range".to_string())
        })?;
        self.read(|transaction| {
            let records = {
                let mut statement = transaction.prepare(
                    r#"
                    SELECT seq, capability_id, revoked_at
                    FROM revocation_delta_log
                    WHERE seq > ?1
                    ORDER BY seq ASC
                    LIMIT ?2
                    "#,
                )?;
                let rows = statement.query_map(params![after_seq, limit as i64], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?;
                rows.map(|row| {
                    let (seq, capability_id, revoked_at) = row?;
                    Ok(StoredRevocation {
                        seq: stored_index(seq)?,
                        record: RevocationRecord {
                            capability_id,
                            revoked_at,
                        },
                    })
                })
                .collect::<Result<Vec<_>, RevocationStoreError>>()?
            };
            let head = transaction.query_row(
                "SELECT next_seq FROM revocation_delta_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )?;
            Ok((records, stored_index(head)?))
        })
    }

    pub fn upsert_revocation(&self, record: &RevocationRecord) -> Result<(), RevocationStoreError> {
        self.upsert_revocation_if_newer(record).map(|_| ())
    }

    /// Apply a revocation only when it advances the stored projection.
    ///
    /// The returned flag is true exactly when this call commits a projection and
    /// append-log mutation. Replication callers use it to distinguish a fresh
    /// delta from an idempotent projection replay.
    pub fn upsert_revocation_if_newer(
        &self,
        record: &RevocationRecord,
    ) -> Result<bool, RevocationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let existing = transaction
            .query_row(
                "SELECT revoked_at FROM revoked_capabilities WHERE capability_id = ?1",
                params![&record.capability_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if existing.is_some_and(|revoked_at| revoked_at >= record.revoked_at) {
            transaction.rollback()?;
            return Ok(false);
        }
        let joint = self.serving_owner.is_some();
        let revocation_index = allocate_revocation_index(&transaction, joint)?;
        if joint {
            transaction.execute(
                r#"
                INSERT INTO revoked_capabilities (
                    capability_id, revoked_at,
                    admission_authority_commit_index
                ) VALUES (?1, ?2, ?3)
                ON CONFLICT(capability_id) DO UPDATE SET
                    revoked_at = excluded.revoked_at,
                    admission_authority_commit_index =
                        excluded.admission_authority_commit_index
                "#,
                params![record.capability_id, record.revoked_at, revocation_index],
            )?;
            append_admission_revocation_commit(
                &transaction,
                revocation_index,
                &record.capability_id,
            )?;
            self.serving_owner
                .as_ref()
                .ok_or_else(|| {
                    RevocationStoreError::Sync(
                        "joint revocation mutation lost its serving owner".to_string(),
                    )
                })?
                .append_global_commit(
                    &transaction,
                    "revocation_upsert",
                    "revocation",
                    &record.capability_id,
                    stored_index(revocation_index)?,
                )
                .map_err(map_serving_owner_error)?;
        } else {
            transaction.execute(
                r#"
                INSERT INTO revoked_capabilities (
                    capability_id, revoked_at, revocation_index
                ) VALUES (?1, ?2, ?3)
                ON CONFLICT(capability_id) DO UPDATE SET
                    revoked_at = excluded.revoked_at,
                    revocation_index = excluded.revocation_index
                "#,
                params![record.capability_id, record.revoked_at, revocation_index],
            )?;
        }
        append_revocation_delta(&transaction, record)?;
        commit_mutation(self, transaction)?;
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .sync_authority_anchor(&connection)
                .map_err(map_serving_owner_error)?;
        }
        Ok(true)
    }

    /// The head of the revocation stream as the pagination cursor tuple
    /// (revoked_at, capability_id), or None when empty. list_revocations_after
    /// paginates ascending, so the head is the descending row.
    pub fn latest_revocation_cursor(&self) -> Result<Option<(i64, String)>, RevocationStoreError> {
        self.read(|transaction| {
            transaction
                .query_row(
                    "SELECT revoked_at, capability_id FROM revoked_capabilities \
                 ORDER BY revoked_at DESC, capability_id DESC LIMIT 1",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(Into::into)
        })
    }

    pub fn latest_revocation_stream_head(
        &self,
    ) -> Result<Option<StoredRevocation>, RevocationStoreError> {
        self.read(|transaction| {
            transaction
                .query_row(
                    "SELECT seq, capability_id, revoked_at \
                     FROM revocation_delta_log \
                     ORDER BY seq DESC LIMIT 1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?
                .map(|(seq, capability_id, revoked_at)| {
                    Ok(StoredRevocation {
                        seq: stored_index(seq)?,
                        record: RevocationRecord {
                            capability_id,
                            revoked_at,
                        },
                    })
                })
                .transpose()
        })
    }

    /// Identity of this append-only revocation serving epoch.
    ///
    /// Ordinary non-serving opens preserve the stored value. A trust-control
    /// replication source rotates it at activation, before advertising status,
    /// so a database rollback cannot reuse sequence numbers under an identity
    /// cached during an earlier serving epoch. A replication cursor is valid
    /// only for the identity that issued it.
    pub fn revocation_stream_id(&self) -> Result<String, RevocationStoreError> {
        self.read(|transaction| {
            transaction
                .query_row(
                    "SELECT stream_id FROM revocation_stream_meta WHERE singleton = 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .map_err(Into::into)
        })
    }

    /// Export the current revoked-capability projection and the append-only
    /// stream head from one SQLite read snapshot.
    ///
    /// Cluster snapshots transfer current state, not mutation history. Reading
    /// both values in one transaction ensures the advertised stream head never
    /// advances past a revocation omitted from the exported projection.
    pub fn export_revocation_snapshot(
        &self,
    ) -> Result<(String, Vec<RevocationRecord>, Option<StoredRevocation>), RevocationStoreError>
    {
        self.read(|transaction| {
            let stream_id = transaction.query_row(
                "SELECT stream_id FROM revocation_stream_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )?;
            let records = {
                let mut statement = transaction.prepare(
                    "SELECT capability_id, revoked_at FROM revoked_capabilities \
                     ORDER BY revoked_at ASC, capability_id ASC",
                )?;
                let records = statement
                    .query_map([], |row| {
                        Ok(RevocationRecord {
                            capability_id: row.get(0)?,
                            revoked_at: row.get(1)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                records
            };
            let head = transaction
                .query_row(
                    "SELECT seq, capability_id, revoked_at \
                     FROM revocation_delta_log ORDER BY seq DESC LIMIT 1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?
                .map(|(seq, capability_id, revoked_at)| {
                    Ok::<StoredRevocation, RevocationStoreError>(StoredRevocation {
                        seq: stored_index(seq)?,
                        record: RevocationRecord {
                            capability_id,
                            revoked_at,
                        },
                    })
                })
                .transpose()?;
            Ok((stream_id, records, head))
        })
    }
}

impl RevocationStore for SqliteRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let exists = self.read(|transaction| {
            transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
                    params![capability_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(Into::into)
        })?;
        Ok(exists != 0)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let revoked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let exists = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, bool>(0),
        )?;
        if exists {
            transaction.rollback()?;
            return Ok(false);
        }
        let joint = self.serving_owner.is_some();
        let revocation_index = allocate_revocation_index(&transaction, joint)?;
        let index_column = if joint {
            "admission_authority_commit_index"
        } else {
            "revocation_index"
        };
        let inserted = transaction
            .query_row(
                &format!(
                    r#"
            INSERT INTO revoked_capabilities (
                capability_id, revoked_at, {index_column}
            ) VALUES (?1, ?2, ?3)
            ON CONFLICT(capability_id) DO NOTHING RETURNING 1
            "#
                ),
                params![capability_id, revoked_at, revocation_index],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if inserted.is_some() {
            append_revocation_delta(
                &transaction,
                &RevocationRecord {
                    capability_id: capability_id.to_string(),
                    revoked_at,
                },
            )?;
            if joint {
                append_admission_revocation_commit(&transaction, revocation_index, capability_id)?;
                self.serving_owner
                    .as_ref()
                    .ok_or_else(|| {
                        RevocationStoreError::Sync(
                            "joint revocation mutation lost its serving owner".to_string(),
                        )
                    })?
                    .append_global_commit(
                        &transaction,
                        "revocation_revoke",
                        "revocation",
                        capability_id,
                        stored_index(revocation_index)?,
                    )
                    .map_err(map_serving_owner_error)?;
            }
            commit_mutation(self, transaction)?;
            if let Some(owner) = self.serving_owner.as_ref() {
                owner
                    .sync_authority_anchor(&connection)
                    .map_err(map_serving_owner_error)?;
            }
        } else {
            transaction.rollback()?;
        }
        Ok(inserted.is_some())
    }

    fn observe_revocation(
        &self,
        capability_id: &str,
    ) -> Result<RevocationObservation, RevocationStoreError> {
        let sql = if self.serving_owner.is_some() {
            r#"
            SELECT EXISTS(
                       SELECT 1 FROM revoked_capabilities
                       WHERE capability_id = ?1
                   ),
                   head_index
            FROM admission_authority_meta WHERE singleton = 1
            "#
        } else {
            r#"
            SELECT EXISTS(
                       SELECT 1 FROM revoked_capabilities
                       WHERE capability_id = ?1
                   ),
                   next_index
            FROM revocation_replication_meta WHERE singleton = 1
            "#
        };
        let (revoked, commit_index) = self.read(|transaction| {
            transaction
                .query_row(sql, params![capability_id], |row| {
                    Ok((row.get::<_, bool>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(Into::into)
        })?;
        Ok(RevocationObservation {
            revoked,
            commit: self
                .serving_owner
                .as_ref()
                .map(|owner| {
                    Ok::<_, RevocationStoreError>(RevocationCommitMetadata {
                        authority: BudgetEventAuthority {
                            authority_id: owner.fence.store_uuid.clone(),
                            lease_id: owner.fence.lease_id.clone(),
                            lease_epoch: owner.fence.owner_epoch,
                        },
                        guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
                        commit_index: u64::try_from(commit_index).map_err(|_| {
                            RevocationStoreError::Sync(
                                "negative revocation commit index".to_string(),
                            )
                        })?,
                    })
                })
                .transpose()?,
        })
    }

    fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }
}

pub(crate) fn initialize_revocation_schema(
    connection: &mut Connection,
    shared_authority_sequence: bool,
) -> Result<(), RevocationStoreError> {
    connection.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;
        PRAGMA busy_timeout = 5000;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS revoked_capabilities (
            capability_id TEXT PRIMARY KEY,
            revoked_at INTEGER NOT NULL,
            revocation_index INTEGER UNIQUE,
            admission_authority_commit_index INTEGER UNIQUE
        );

        CREATE INDEX IF NOT EXISTS idx_revoked_capabilities_revoked_at
            ON revoked_capabilities(revoked_at);

        CREATE TABLE IF NOT EXISTS revocation_delta_log (
            seq INTEGER PRIMARY KEY CHECK (seq > 0),
            capability_id TEXT NOT NULL,
            revoked_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_revocation_delta_log_projection
            ON revocation_delta_log(capability_id, revoked_at);

        CREATE TABLE IF NOT EXISTS revocation_delta_meta (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            next_seq INTEGER NOT NULL CHECK (next_seq >= 0)
        );

        CREATE TABLE IF NOT EXISTS revocation_stream_meta (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            stream_id TEXT NOT NULL CHECK (stream_id <> '')
        );

        "#,
    )?;
    ensure_revocation_index_column(connection)?;
    ensure_admission_authority_index_column(connection)?;

    if !shared_authority_sequence {
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS revocation_replication_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                next_index INTEGER NOT NULL CHECK (next_index >= 0)
            );
            "#,
        )?;
    } else {
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS admission_authority_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                head_index INTEGER NOT NULL CHECK (head_index > 0)
            );

            CREATE TABLE IF NOT EXISTS admission_authority_commits (
                commit_index INTEGER PRIMARY KEY CHECK (commit_index > 0),
                kind TEXT NOT NULL CHECK (kind IN ('genesis', 'revocation')),
                capability_id TEXT,
                CHECK (
                    (kind = 'genesis' AND capability_id IS NULL)
                    OR
                    (kind = 'revocation' AND capability_id IS NOT NULL)
                ),
                FOREIGN KEY (capability_id)
                    REFERENCES revoked_capabilities(capability_id)
            );

            CREATE TABLE IF NOT EXISTS chio_authority_migrations (
                migration_key TEXT PRIMARY KEY CHECK (migration_key <> ''),
                completed_index INTEGER NOT NULL CHECK (completed_index > 0)
            );
            "#,
        )?;
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO revocation_stream_meta (singleton, stream_id) VALUES (1, ?1) \
         ON CONFLICT(singleton) DO NOTHING",
        [uuid::Uuid::now_v7().to_string()],
    )?;
    initialize_revocation_delta_log(&transaction)?;
    if shared_authority_sequence {
        transaction.execute(
            r#"
            INSERT INTO admission_authority_meta (singleton, head_index)
            VALUES (1, 1)
            ON CONFLICT(singleton) DO NOTHING
            "#,
            [],
        )?;
        transaction.execute(
            r#"
            INSERT INTO admission_authority_commits (
                commit_index, kind, capability_id
            ) VALUES (1, 'genesis', NULL)
            ON CONFLICT(commit_index) DO NOTHING
            "#,
            [],
        )?;
        let converted = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM chio_authority_migrations
                WHERE migration_key = 'revocation-admission-authority-v1'
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if !converted {
            transaction.execute(
                "UPDATE revoked_capabilities SET admission_authority_commit_index = NULL",
                [],
            )?;
            transaction.execute(
                "DELETE FROM admission_authority_commits WHERE kind = 'revocation'",
                [],
            )?;
        }
        let mut next_index = if converted {
            transaction.query_row(
                r#"
                SELECT MAX(
                    (SELECT head_index FROM admission_authority_meta
                     WHERE singleton = 1),
                    COALESCE((SELECT MAX(commit_index)
                              FROM admission_authority_commits), 1)
                )
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )?
        } else {
            1
        };
        let capability_ids = {
            let mut statement = transaction.prepare(
                r#"
                SELECT capability_id FROM revoked_capabilities
                WHERE admission_authority_commit_index IS NULL
                ORDER BY revoked_at, capability_id
                "#,
            )?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        for capability_id in capability_ids {
            next_index = next_index.checked_add(1).ok_or_else(|| {
                RevocationStoreError::Sync(
                    "admission authority commit index overflowed i64".to_string(),
                )
            })?;
            transaction.execute(
                r#"
                UPDATE revoked_capabilities
                SET admission_authority_commit_index = ?2
                WHERE capability_id = ?1
                "#,
                params![&capability_id, next_index],
            )?;
            append_admission_revocation_commit(&transaction, next_index, &capability_id)?;
        }
        transaction.execute(
            "UPDATE admission_authority_meta SET head_index = ?1 WHERE singleton = 1",
            params![next_index],
        )?;
        transaction.execute(
            r#"
            INSERT INTO chio_authority_migrations (
                migration_key, completed_index
            ) VALUES ('revocation-admission-authority-v1', ?1)
            ON CONFLICT(migration_key) DO NOTHING
            "#,
            params![next_index],
        )?;
        let invalid = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM revoked_capabilities AS revoked
                WHERE admission_authority_commit_index IS NULL
                   OR NOT EXISTS (
                       SELECT 1 FROM admission_authority_commits AS committed
                       WHERE committed.commit_index =
                                 revoked.admission_authority_commit_index
                         AND committed.kind = 'revocation'
                         AND committed.capability_id = revoked.capability_id
                   )
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if invalid {
            return Err(RevocationStoreError::Sync(
                "admission authority revocation projection is incomplete".to_string(),
            ));
        }
    } else {
        let mut next_index = transaction.query_row(
            "SELECT COALESCE(MAX(revocation_index), 0) FROM revoked_capabilities",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let capability_ids = {
            let mut statement = transaction.prepare(
                r#"
                SELECT capability_id FROM revoked_capabilities
                WHERE revocation_index IS NULL
                ORDER BY revoked_at, capability_id
                "#,
            )?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        for capability_id in capability_ids {
            next_index = next_index.checked_add(1).ok_or_else(|| {
                RevocationStoreError::Sync("revocation index overflowed i64".to_string())
            })?;
            transaction.execute(
                "UPDATE revoked_capabilities SET revocation_index = ?2 WHERE capability_id = ?1",
                params![capability_id, next_index],
            )?;
        }
        transaction.execute(
            r#"
            INSERT INTO revocation_replication_meta (singleton, next_index)
            VALUES (1, ?1)
            ON CONFLICT(singleton) DO UPDATE SET
                next_index = MAX(next_index, excluded.next_index)
            "#,
            params![next_index],
        )?;
    }
    transaction.commit()?;
    verify_revocation_delta_invariants(connection)?;
    if shared_authority_sequence {
        verify_admission_authority_invariants(connection)?;
    }
    Ok(())
}

fn rotate_revocation_stream_identity(
    connection: &mut Connection,
) -> Result<(), RevocationStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let updated = transaction.execute(
        "UPDATE revocation_stream_meta SET stream_id = ?1 WHERE singleton = 1",
        [uuid::Uuid::now_v7().to_string()],
    )?;
    if updated != 1 {
        return Err(RevocationStoreError::Sync(
            "revocation stream identity row is missing".to_string(),
        ));
    }
    transaction.commit()?;
    Ok(())
}

fn ensure_revocation_index_column(connection: &Connection) -> Result<(), RevocationStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(revoked_capabilities)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|column| column == "revocation_index") {
        connection.execute(
            "ALTER TABLE revoked_capabilities ADD COLUMN revocation_index INTEGER",
            [],
        )?;
        connection.execute(
            "CREATE UNIQUE INDEX idx_revoked_capabilities_index ON revoked_capabilities(revocation_index)",
            [],
        )?;
    }
    Ok(())
}

fn ensure_admission_authority_index_column(
    connection: &Connection,
) -> Result<(), RevocationStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(revoked_capabilities)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    if !columns
        .iter()
        .any(|column| column == "admission_authority_commit_index")
    {
        connection.execute(
            "ALTER TABLE revoked_capabilities ADD COLUMN admission_authority_commit_index INTEGER",
            [],
        )?;
    }
    connection.execute(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS idx_revoked_capabilities_admission_authority
        ON revoked_capabilities(admission_authority_commit_index)
        "#,
        [],
    )?;
    Ok(())
}

fn allocate_revocation_index(
    transaction: &Transaction<'_>,
    shared_authority_sequence: bool,
) -> Result<i64, RevocationStoreError> {
    let (table, column) = if shared_authority_sequence {
        ("admission_authority_meta", "head_index")
    } else {
        ("revocation_replication_meta", "next_index")
    };
    let current = transaction.query_row(
        &format!("SELECT {column} FROM {table} WHERE singleton = 1"),
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let next = current
        .checked_add(1)
        .ok_or_else(|| RevocationStoreError::Sync("revocation index overflowed i64".to_string()))?;
    transaction.execute(
        &format!("UPDATE {table} SET {column} = ?1 WHERE singleton = 1"),
        params![next],
    )?;
    Ok(next)
}

/// Allocate and append one row to the dense, append-only revocation delta log.
///
/// The mutable `revoked_capabilities` projection cannot itself be a sound delta
/// stream: updating one capability replaces its older projection row, and the
/// joint authority commit index is not the delta log's cursor contract. This
/// independent sequence advances exactly once for every accepted revocation
/// mutation and is written in the same transaction as the projection update.
fn append_revocation_delta(
    transaction: &Transaction<'_>,
    record: &RevocationRecord,
) -> Result<(), RevocationStoreError> {
    let current = transaction.query_row(
        "SELECT next_seq FROM revocation_delta_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let next = current.checked_add(1).ok_or_else(|| {
        RevocationStoreError::Sync("revocation delta sequence overflowed i64".to_string())
    })?;
    transaction.execute(
        "INSERT INTO revocation_delta_log (seq, capability_id, revoked_at) \
         VALUES (?1, ?2, ?3)",
        params![next, record.capability_id, record.revoked_at],
    )?;
    transaction.execute(
        "UPDATE revocation_delta_meta SET next_seq = ?1 WHERE singleton = 1",
        params![next],
    )?;
    Ok(())
}

/// Seed the append-only delta log when opening a pre-v3 revocation database.
/// Existing projection rows form the complete revocation state at the migration
/// boundary. They receive a deterministic dense prefix; all later mutations are
/// appended transactionally by `append_revocation_delta`.
fn initialize_revocation_delta_log(
    transaction: &Transaction<'_>,
) -> Result<(), RevocationStoreError> {
    transaction.execute(
        "INSERT INTO revocation_delta_meta (singleton, next_seq) VALUES (1, 0) \
         ON CONFLICT(singleton) DO NOTHING",
        [],
    )?;
    let existing_count =
        transaction.query_row("SELECT COUNT(*) FROM revocation_delta_log", [], |row| {
            row.get::<_, i64>(0)
        })?;
    if existing_count == 0 {
        let records = {
            let mut statement = transaction.prepare(
                "SELECT capability_id, revoked_at FROM revoked_capabilities \
                 ORDER BY revoked_at ASC, capability_id ASC",
            )?;
            let records = statement
                .query_map([], |row| {
                    Ok(RevocationRecord {
                        capability_id: row.get(0)?,
                        revoked_at: row.get(1)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            records
        };
        for record in records {
            append_revocation_delta(transaction, &record)?;
        }
    } else {
        let max_seq = transaction.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM revocation_delta_log",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        transaction.execute(
            "UPDATE revocation_delta_meta SET next_seq = MAX(next_seq, ?1) \
             WHERE singleton = 1",
            params![max_seq],
        )?;
    }
    Ok(())
}

fn verify_revocation_delta_invariants(connection: &Connection) -> Result<(), RevocationStoreError> {
    let projection_index_columns = {
        let mut statement =
            connection.prepare("PRAGMA index_info('idx_revocation_delta_log_projection')")?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(2))?
            .collect::<Result<Vec<_>, _>>()?;
        columns
    };
    if projection_index_columns != ["capability_id", "revoked_at"] {
        return Err(RevocationStoreError::Sync(
            "revocation projection-history index has an invalid shape".to_string(),
        ));
    }
    let (next_seq, row_count, min_seq, max_seq, projection_unlogged) = connection.query_row(
        r#"
        SELECT
            (SELECT next_seq FROM revocation_delta_meta WHERE singleton = 1),
            (SELECT COUNT(*) FROM revocation_delta_log),
            (SELECT COALESCE(MIN(seq), 0) FROM revocation_delta_log),
            (SELECT COALESCE(MAX(seq), 0) FROM revocation_delta_log),
            EXISTS(
                SELECT 1 FROM revoked_capabilities AS revoked
                WHERE NOT EXISTS (
                    SELECT 1 FROM revocation_delta_log AS delta
                    WHERE delta.capability_id = revoked.capability_id
                      AND delta.revoked_at = revoked.revoked_at
                )
            )
        "#,
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, bool>(4)?,
            ))
        },
    )?;
    let dense = if row_count == 0 {
        next_seq == 0 && min_seq == 0 && max_seq == 0
    } else {
        min_seq == 1 && row_count == max_seq && next_seq == max_seq
    };
    if !dense || projection_unlogged {
        return Err(RevocationStoreError::Sync(
            "revocation delta log is not a dense complete projection history".to_string(),
        ));
    }
    let stream_id = connection.query_row(
        "SELECT stream_id FROM revocation_stream_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let parsed = uuid::Uuid::parse_str(&stream_id).map_err(|_| {
        RevocationStoreError::Sync("revocation stream identity is not a valid UUID".to_string())
    })?;
    if parsed.get_version_num() != 7 {
        return Err(RevocationStoreError::Sync(
            "revocation stream identity is not a UUIDv7".to_string(),
        ));
    }
    Ok(())
}

fn append_admission_revocation_commit(
    transaction: &Transaction<'_>,
    commit_index: i64,
    capability_id: &str,
) -> Result<(), RevocationStoreError> {
    transaction.execute(
        r#"
        INSERT INTO admission_authority_commits (
            commit_index, kind, capability_id
        ) VALUES (?1, 'revocation', ?2)
        "#,
        params![commit_index, capability_id],
    )?;
    Ok(())
}

fn stored_index(value: i64) -> Result<u64, RevocationStoreError> {
    u64::try_from(value)
        .map_err(|_| RevocationStoreError::Sync("negative revocation index".to_string()))
}

fn map_serving_owner_error(
    error: crate::serving_owner::SqliteServingOwnerError,
) -> RevocationStoreError {
    match error {
        crate::serving_owner::SqliteServingOwnerError::OutcomeUnknown(detail) => {
            RevocationStoreError::OutcomeUnknown(detail)
        }
        error => RevocationStoreError::Sync(error.to_string()),
    }
}

fn commit_mutation(
    store: &SqliteRevocationStore,
    transaction: Transaction<'_>,
) -> Result<(), RevocationStoreError> {
    transaction.commit().map_err(|error| {
        let detail = format!("sqlite revocation commit outcome is unknown: {error}");
        match store.serving_owner.as_ref() {
            Some(owner) => map_serving_owner_error(owner.outcome_unknown(detail)),
            None => RevocationStoreError::OutcomeUnknown(detail),
        }
    })
}

pub(crate) fn verify_admission_authority_invariants(
    connection: &Connection,
) -> Result<(), RevocationStoreError> {
    let (head, commit_count, max_commit, genesis_count, migration_count) = connection.query_row(
        r#"
            SELECT
                (SELECT head_index FROM admission_authority_meta
                 WHERE singleton = 1),
                (SELECT COUNT(*) FROM admission_authority_commits),
                (SELECT COALESCE(MAX(commit_index), 0)
                 FROM admission_authority_commits),
                (SELECT COUNT(*) FROM admission_authority_commits
                 WHERE commit_index = 1 AND kind = 'genesis'
                   AND capability_id IS NULL),
                (SELECT COUNT(*) FROM chio_authority_migrations
                 WHERE migration_key = 'revocation-admission-authority-v1')
            "#,
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        },
    )?;
    let invalid_projection = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM revoked_capabilities AS revoked
            WHERE admission_authority_commit_index IS NULL
               OR NOT EXISTS (
                   SELECT 1 FROM admission_authority_commits AS committed
                   WHERE committed.commit_index =
                             revoked.admission_authority_commit_index
                     AND committed.kind = 'revocation'
                     AND committed.capability_id = revoked.capability_id
               )
        )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if head <= 0
        || commit_count != head
        || max_commit != head
        || genesis_count != 1
        || migration_count != 1
        || invalid_projection
    {
        return Err(RevocationStoreError::Sync(
            "admission authority commit log is not a dense valid projection".to_string(),
        ));
    }
    Ok(())
}

fn verify_revocation_foreign_keys(connection: &Connection) -> Result<(), RevocationStoreError> {
    let violation = connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()?;
    if let Some((table, rowid)) = violation {
        return Err(RevocationStoreError::Sync(format!(
            "sqlite foreign key violation in `{table}` row {rowid}"
        )));
    }
    Ok(())
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
    fn revocation_stream_identity_is_durable_and_store_unique(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first_path = unique_db_path("chio-rev-stream-first");
        let second_path = unique_db_path("chio-rev-stream-second");
        let first_id = SqliteRevocationStore::open(&first_path)?.revocation_stream_id()?;
        let reopened_id = SqliteRevocationStore::open(&first_path)?.revocation_stream_id()?;
        let second_id = SqliteRevocationStore::open(&second_path)?.revocation_stream_id()?;

        assert_eq!(first_id, reopened_id, "an ordinary reopen keeps the epoch");
        assert_ne!(
            first_id, second_id,
            "independent stores need distinct epochs"
        );
        assert_eq!(uuid::Uuid::parse_str(&first_id)?.get_version_num(), 7);

        let _ = fs::remove_file(first_path);
        let _ = fs::remove_file(second_path);
        Ok(())
    }

    #[test]
    fn replication_source_epoch_rotates_after_restored_sequence_reuse(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_db_path("chio-rev-stream-restore");
        let restored_snapshot = unique_db_path("chio-rev-stream-snapshot");
        let store = SqliteRevocationStore::open(&path)?;
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-first".to_string(),
            revoked_at: 10,
        })?;
        drop(store);
        fs::copy(&path, &restored_snapshot)?;

        let live = SqliteRevocationStore::open_replication_source(&path)?;
        let live_stream_id = live.revocation_stream_id()?;
        live.upsert_revocation(&RevocationRecord {
            capability_id: "cap-live-second".to_string(),
            revoked_at: 20,
        })?;
        assert_eq!(
            live.latest_revocation_stream_head()?.map(|row| row.seq),
            Some(2)
        );
        drop(live);

        fs::copy(&restored_snapshot, &path)?;
        let restored = SqliteRevocationStore::open_replication_source(&path)?;
        let restored_stream_id = restored.revocation_stream_id()?;
        restored.upsert_revocation(&RevocationRecord {
            capability_id: "cap-restored-second".to_string(),
            revoked_at: 20,
        })?;
        assert_eq!(
            restored.latest_revocation_stream_head()?.map(|row| row.seq),
            Some(2)
        );
        assert_ne!(
            live_stream_id, restored_stream_id,
            "equal restored heads must belong to distinct serving epochs"
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(restored_snapshot);
        Ok(())
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
    fn revocation_sequence_does_not_skip_same_second_backfill(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_db_path("chio-rev-sequence");
        let store = SqliteRevocationStore::open(&path)?;
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-revoke-leader".to_string(),
            revoked_at: 100,
        })?;
        let first = store.list_revocations_after_seq(10, 0)?;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].seq, 1);

        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-revoke-leader".to_string(),
            revoked_at: 101,
        })?;
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-revoke-follower".to_string(),
            revoked_at: 100,
        })?;
        let after = store.list_revocations_after_seq(10, first[0].seq)?;
        assert_eq!(after.len(), 2);
        assert_eq!(after[0].seq, 2);
        assert_eq!(after[0].record.capability_id, "cap-revoke-leader");
        assert_eq!(after[1].seq, 3);
        assert_eq!(after[1].record.capability_id, "cap-revoke-follower");
        assert_eq!(
            store
                .latest_revocation_stream_head()?
                .map(|stored| stored.seq),
            Some(3)
        );

        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn v2_projection_migrates_to_a_dense_append_only_delta_log(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_db_path("chio-rev-v2-delta-migration");
        let store = SqliteRevocationStore::open(&path)?;
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-b".to_string(),
            revoked_at: 20,
        })?;
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-a".to_string(),
            revoked_at: 10,
        })?;
        drop(store);

        let connection = Connection::open(&path)?;
        connection.execute_batch(
            r#"
            DROP TABLE revocation_delta_log;
            DROP TABLE revocation_delta_meta;
            UPDATE chio_store_schema_versions
            SET version = 2
            WHERE store_key = 'revocation';
            "#,
        )?;
        drop(connection);

        let migrated = SqliteRevocationStore::open(&path)?;
        let rows = migrated.list_revocations_after_seq(10, 0)?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].seq, 1);
        assert_eq!(rows[0].record.capability_id, "cap-a");
        assert_eq!(rows[1].seq, 2);
        assert_eq!(rows[1].record.capability_id, "cap-b");

        migrated.upsert_revocation(&RevocationRecord {
            capability_id: "cap-a".to_string(),
            revoked_at: 30,
        })?;
        let appended = migrated.list_revocations_after_seq(10, 2)?;
        assert_eq!(appended.len(), 1);
        assert_eq!(appended[0].seq, 3);
        assert_eq!(appended[0].record.revoked_at, 30);

        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn v3_store_migrates_stream_identity_and_projection_history_index(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = unique_db_path("chio-rev-v3-stream-migration");
        let store = SqliteRevocationStore::open(&path)?;
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-indexed".to_string(),
            revoked_at: 44,
        })?;
        drop(store);

        let connection = Connection::open(&path)?;
        connection.execute_batch(
            r#"
            DROP INDEX idx_revocation_delta_log_projection;
            DROP TABLE revocation_stream_meta;
            UPDATE chio_store_schema_versions
            SET version = 3
            WHERE store_key = 'revocation';
            "#,
        )?;
        drop(connection);

        let migrated = SqliteRevocationStore::open(&path)?;
        assert_eq!(
            uuid::Uuid::parse_str(&migrated.revocation_stream_id()?)?.get_version_num(),
            7
        );
        drop(migrated);

        let connection = Connection::open(&path)?;
        let version: i32 = connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'revocation'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(version, REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION);
        let plan = {
            let mut statement = connection.prepare(
                r#"
                EXPLAIN QUERY PLAN
                SELECT EXISTS(
                    SELECT 1 FROM revoked_capabilities AS revoked
                    WHERE NOT EXISTS (
                        SELECT 1 FROM revocation_delta_log AS delta
                        WHERE delta.capability_id = revoked.capability_id
                          AND delta.revoked_at = revoked.revoked_at
                    )
                )
                "#,
            )?;
            let details = statement
                .query_map([], |row| row.get::<_, String>(3))?
                .collect::<Result<Vec<_>, _>>()?;
            details
        };
        assert!(
            plan.iter()
                .any(|detail| detail.contains("idx_revocation_delta_log_projection")),
            "projection-history lookup must use the composite index: {plan:?}"
        );

        let _ = fs::remove_file(path);
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
