use chio_core::capability::token::CapabilityToken;
pub use chio_kernel::capability_lineage::{
    CapabilityLineageError, CapabilitySnapshot, StoredCapabilitySnapshot,
};
use rusqlite::types::Type;
use rusqlite::{params, OptionalExtension, Row};

use crate::receipt_store::SqliteReceiptStore;

fn snapshot_from_row(row: &Row<'_>) -> rusqlite::Result<CapabilitySnapshot> {
    Ok(CapabilitySnapshot {
        capability_id: row.get::<_, String>(0)?,
        subject_key: row.get::<_, String>(1)?,
        issuer_key: row.get::<_, String>(2)?,
        issued_at: non_negative_u64_from_column(row, 3, "issued_at")?,
        expires_at: non_negative_u64_from_column(row, 4, "expires_at")?,
        grants_json: row.get::<_, String>(5)?,
        delegation_depth: non_negative_u64_from_column(row, 6, "delegation_depth")?,
        parent_capability_id: row.get::<_, Option<String>>(7)?,
    })
}

fn non_negative_u64_from_column(
    row: &Row<'_>,
    column: usize,
    field_name: &'static str,
) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(column)?;
    if value < 0 {
        return Err(negative_lineage_integer_error(column, field_name, value));
    }
    Ok(value as u64)
}

fn negative_lineage_integer_error(
    column: usize,
    field_name: &'static str,
    value: i64,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        Type::Integer,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("capability_lineage.{field_name} must be non-negative, got {value}"),
        )),
    )
}

impl SqliteReceiptStore {
    /// Record a capability snapshot at issuance time.
    ///
    /// Uses INSERT OR IGNORE for idempotency -- duplicate inserts are silently
    /// dropped, preserving the first-writer-wins record.
    ///
    /// The `parent_capability_id` argument must refer to a capability already
    /// present in the lineage table. If it is `Some` but the parent is missing,
    /// the depth defaults to 1 (the minimum delegation depth).
    pub fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), CapabilityLineageError> {
        let grants_json = serde_json::to_string(&token.scope)?;
        let subject_key = token.subject.to_hex();
        let issuer_key = token.issuer.to_hex();

        // Compute delegation depth from parent if present.
        let delegation_depth: u64 = if let Some(parent_id) = parent_capability_id {
            let parent_depth: Option<u64> = self
                .connection()?
                .query_row(
                    "SELECT delegation_depth FROM capability_lineage WHERE capability_id = ?1",
                    params![parent_id],
                    |row: &Row<'_>| non_negative_u64_from_column(row, 0, "delegation_depth"),
                )
                .optional()?;

            parent_depth.map(|d| d.saturating_add(1)).unwrap_or(1)
        } else {
            0
        };

        self.connection()?.execute(
            r#"
            INSERT OR IGNORE INTO capability_lineage (
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                token.id,
                subject_key,
                issuer_key,
                token.issued_at as i64,
                token.expires_at as i64,
                grants_json,
                delegation_depth as i64,
                parent_capability_id,
            ],
        )?;

        Ok(())
    }

    /// Upsert an already-materialized capability snapshot.
    ///
    /// This is used by cluster replication so followers can converge on the
    /// leader's lineage table without reconstructing full signed tokens.
    pub fn upsert_capability_snapshot(
        &mut self,
        snapshot: &CapabilitySnapshot,
    ) -> Result<(), CapabilityLineageError> {
        self.connection()?.execute(
            r#"
            INSERT INTO capability_lineage (
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(capability_id) DO UPDATE SET
                subject_key = excluded.subject_key,
                issuer_key = excluded.issuer_key,
                issued_at = excluded.issued_at,
                expires_at = excluded.expires_at,
                grants_json = excluded.grants_json,
                delegation_depth = excluded.delegation_depth,
                parent_capability_id = excluded.parent_capability_id
            "#,
            params![
                snapshot.capability_id,
                snapshot.subject_key,
                snapshot.issuer_key,
                snapshot.issued_at as i64,
                snapshot.expires_at as i64,
                snapshot.grants_json,
                snapshot.delegation_depth as i64,
                snapshot.parent_capability_id,
            ],
        )?;
        Ok(())
    }

    /// Retrieve a single capability snapshot by its ID.
    ///
    /// Returns `None` if no snapshot exists for the given capability_id.
    pub fn get_lineage(
        &self,
        capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, CapabilityLineageError> {
        let row = self
            .connection()?
            .query_row(
                r#"
                SELECT
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                FROM capability_lineage
                WHERE capability_id = ?1
                "#,
                params![capability_id],
                snapshot_from_row,
            )
            .optional()?;

        Ok(row)
    }

    /// Walk the delegation chain for a capability, returning root-first ordering.
    ///
    /// Uses a WITH RECURSIVE CTE that walks from the given capability up through
    /// its parent chain, tracking depth level. The ORDER BY level DESC produces
    /// root-first ordering because the root has the highest level value.
    ///
    /// A max-depth guard (level < 20) prevents infinite recursion caused by
    /// accidental cycles in the parent chain.
    pub fn get_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
        let connection = self.connection()?;
        let mut stmt = connection.prepare(
            r#"
            WITH RECURSIVE chain(
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id,
                level
            ) AS (
                SELECT
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id,
                    0 AS level
                FROM capability_lineage
                WHERE capability_id = ?1

                UNION ALL

                SELECT
                    cl.capability_id,
                    cl.subject_key,
                    cl.issuer_key,
                    cl.issued_at,
                    cl.expires_at,
                    cl.grants_json,
                    cl.delegation_depth,
                    cl.parent_capability_id,
                    chain.level + 1
                FROM capability_lineage cl
                INNER JOIN chain ON cl.capability_id = chain.parent_capability_id
                WHERE chain.level < 20
            )
            SELECT
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id
            FROM chain
            ORDER BY level DESC
            "#,
        )?;

        let rows = stmt.query_map(params![capability_id], snapshot_from_row)?;

        let mut chain = Vec::new();
        for row in rows {
            chain.push(row?);
        }

        Ok(chain)
    }

    /// List all capability snapshots for a given subject key.
    ///
    /// Returns snapshots ordered newest-first by issued_at.
    pub fn list_capabilities_for_subject(
        &self,
        subject_key: &str,
    ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
        self.list_capability_snapshots(Some(subject_key), None)
    }

    /// List capability snapshots filtered by subject and/or issuer.
    ///
    /// If both filters are present they are combined with AND semantics.
    /// Results are ordered deterministically oldest-first to keep reputation
    /// corpus construction stable across runs.
    pub fn list_capability_snapshots(
        &self,
        subject_key: Option<&str>,
        issuer_key: Option<&str>,
    ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
        let connection = self.connection()?;
        let mut stmt = connection.prepare(
            r#"
            SELECT
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id
            FROM capability_lineage
            WHERE (?1 IS NULL OR subject_key = ?1)
              AND (?2 IS NULL OR issuer_key = ?2)
            ORDER BY issued_at ASC, capability_id ASC
            "#,
        )?;

        let rows = stmt.query_map(params![subject_key, issuer_key], snapshot_from_row)?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }

        Ok(snapshots)
    }

    /// Return capability lineage snapshots added after a given local sequence.
    ///
    /// The sequence is the SQLite `rowid`, which is monotonic for this
    /// append-only table and therefore suitable as a replication cursor.
    pub fn list_capability_snapshots_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredCapabilitySnapshot>, CapabilityLineageError> {
        let connection = self.connection()?;
        let mut stmt = connection.prepare(
            r#"
            SELECT
                rowid,
                capability_id,
                subject_key,
                issuer_key,
                issued_at,
                expires_at,
                grants_json,
                delegation_depth,
                parent_capability_id
            FROM capability_lineage
            WHERE rowid > ?1
            ORDER BY rowid ASC
            LIMIT ?2
            "#,
        )?;

        let rows = stmt.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok(StoredCapabilitySnapshot {
                seq: non_negative_u64_from_column(row, 0, "rowid")?,
                snapshot: CapabilitySnapshot {
                    capability_id: row.get::<_, String>(1)?,
                    subject_key: row.get::<_, String>(2)?,
                    issuer_key: row.get::<_, String>(3)?,
                    issued_at: non_negative_u64_from_column(row, 4, "issued_at")?,
                    expires_at: non_negative_u64_from_column(row, 5, "expires_at")?,
                    grants_json: row.get::<_, String>(6)?,
                    delegation_depth: non_negative_u64_from_column(row, 7, "delegation_depth")?,
                    parent_capability_id: row.get::<_, Option<String>>(8)?,
                },
            })
        })?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }

        Ok(snapshots)
    }

    /// Highest lineage snapshot seq (capability_lineage rowid), or 0 when empty.
    /// list_capability_snapshots_after_seq paginates on rowid, so the head is
    /// MAX(rowid). Returns ReceiptStoreError so the cluster status
    /// path converts it through the same CliError variant as the receipt heads.
    pub fn max_lineage_seq(&self) -> Result<u64, chio_kernel::ReceiptStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(rowid), 0) FROM capability_lineage",
            [],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::crypto::Keypair;
    use rusqlite::params;

    use crate::receipt_store::SqliteReceiptStore;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    /// Build a test CapabilityToken with the given ID and subject/issuer keypairs.
    fn make_token(
        id: &str,
        subject_kp: &Keypair,
        issuer_kp: &Keypair,
        issued_at: u64,
        expires_at: u64,
    ) -> CapabilityToken {
        let body = CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at,
            expires_at,
            delegation_chain: vec![],
        };
        CapabilityToken::sign(body, issuer_kp).expect("sign failed")
    }

    #[test]
    fn record_and_get_lineage_returns_matching_fields() {
        let path = unique_db_path("cl-persist");
        let store = SqliteReceiptStore::open(&path).unwrap();

        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let token = make_token("cap-001", &subject_kp, &issuer_kp, 1000, 2000);

        store.record_capability_snapshot(&token, None).unwrap();

        let snap = store.get_lineage("cap-001").unwrap().unwrap();
        assert_eq!(snap.capability_id, "cap-001");
        assert_eq!(snap.subject_key, subject_kp.public_key().to_hex());
        assert_eq!(snap.issuer_key, issuer_kp.public_key().to_hex());
        assert_eq!(snap.issued_at, 1000);
        assert_eq!(snap.expires_at, 2000);
        assert_eq!(snap.delegation_depth, 0);
        assert!(snap.parent_capability_id.is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn record_capability_snapshot_is_idempotent() {
        let path = unique_db_path("cl-idempotent");
        let store = SqliteReceiptStore::open(&path).unwrap();

        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let token = make_token("cap-idem-001", &subject_kp, &issuer_kp, 1000, 2000);

        // Insert twice -- must not panic or error.
        store.record_capability_snapshot(&token, None).unwrap();
        store.record_capability_snapshot(&token, None).unwrap();

        // Only one row should exist.
        let connection = store.connection().unwrap();
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM capability_lineage WHERE capability_id = ?1",
                params!["cap-idem-001"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn grants_json_round_trips_without_field_loss() {
        let path = unique_db_path("cl-json-rt");
        let store = SqliteReceiptStore::open(&path).unwrap();

        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let token = make_token("cap-json-001", &subject_kp, &issuer_kp, 1000, 2000);

        store.record_capability_snapshot(&token, None).unwrap();

        let snap = store.get_lineage("cap-json-001").unwrap().unwrap();
        let round_tripped: ChioScope = serde_json::from_str(&snap.grants_json).unwrap();

        assert_eq!(round_tripped.grants.len(), token.scope.grants.len());
        assert_eq!(round_tripped.grants[0].server_id, "shell");
        assert_eq!(round_tripped.grants[0].tool_name, "bash");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_lineage_returns_none_for_missing_capability() {
        let path = unique_db_path("cl-missing");
        let store = SqliteReceiptStore::open(&path).unwrap();

        let result = store.get_lineage("nonexistent-cap").unwrap();
        assert!(result.is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_lineage_rejects_negative_persisted_unsigned_fields() {
        let path = unique_db_path("cl-corrupt-read");
        let store = SqliteReceiptStore::open(&path).unwrap();
        let connection = store.connection().unwrap();
        connection
            .execute(
                r#"
                INSERT INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
                "#,
                params![
                    "cap-corrupt-read",
                    "subject",
                    "issuer",
                    -1_i64,
                    2_000_i64,
                    "{}",
                    0_i64
                ],
            )
            .unwrap();
        drop(connection);

        let error = store.get_lineage("cap-corrupt-read").unwrap_err();
        assert!(error.to_string().contains("issued_at"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn record_child_snapshot_rejects_negative_parent_depth() {
        let path = unique_db_path("cl-corrupt-parent");
        let store = SqliteReceiptStore::open(&path).unwrap();
        let connection = store.connection().unwrap();
        connection
            .execute(
                r#"
                INSERT INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
                "#,
                params![
                    "cap-corrupt-parent",
                    "subject",
                    "issuer",
                    1_000_i64,
                    2_000_i64,
                    "{}",
                    -1_i64
                ],
            )
            .unwrap();
        drop(connection);

        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let child = make_token(
            "cap-child-from-corrupt",
            &subject_kp,
            &issuer_kp,
            1_100,
            1_900,
        );
        let error = store
            .record_capability_snapshot(&child, Some("cap-corrupt-parent"))
            .unwrap_err();
        assert!(error.to_string().contains("delegation_depth"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn lineage_replication_rejects_negative_snapshot_fields() {
        let path = unique_db_path("cl-corrupt-repl");
        let store = SqliteReceiptStore::open(&path).unwrap();
        let connection = store.connection().unwrap();
        connection
            .execute(
                r#"
                INSERT INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
                "#,
                params![
                    "cap-corrupt-repl",
                    "subject",
                    "issuer",
                    1_000_i64,
                    -2_000_i64,
                    "{}",
                    0_i64
                ],
            )
            .unwrap();
        drop(connection);

        let error = store
            .list_capability_snapshots_after_seq(0, 10)
            .unwrap_err();
        assert!(error.to_string().contains("expires_at"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_delegation_chain_returns_root_first_for_three_level_chain() {
        let path = unique_db_path("cl-chain-3");
        let store = SqliteReceiptStore::open(&path).unwrap();

        let kp_root = Keypair::generate();
        let kp_mid = Keypair::generate();
        let kp_leaf = Keypair::generate();

        // root -> parent -> child
        let root = make_token("cap-root", &kp_root, &kp_root, 1000, 9000);
        let parent = make_token("cap-parent", &kp_mid, &kp_root, 1100, 8000);
        let child = make_token("cap-child", &kp_leaf, &kp_mid, 1200, 7000);

        store.record_capability_snapshot(&root, None).unwrap();
        store
            .record_capability_snapshot(&parent, Some("cap-root"))
            .unwrap();
        store
            .record_capability_snapshot(&child, Some("cap-parent"))
            .unwrap();

        // Walking the chain from child should return root, parent, child (root-first).
        let chain = store.get_delegation_chain("cap-child").unwrap();
        assert_eq!(chain.len(), 3, "should have 3 entries in chain");
        assert_eq!(chain[0].capability_id, "cap-root", "root should be first");
        assert_eq!(
            chain[1].capability_id, "cap-parent",
            "parent should be second"
        );
        assert_eq!(chain[2].capability_id, "cap-child", "child should be last");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_delegation_chain_returns_single_entry_for_root_capability() {
        let path = unique_db_path("cl-chain-root");
        let store = SqliteReceiptStore::open(&path).unwrap();

        let kp = Keypair::generate();
        let root = make_token("cap-solo", &kp, &kp, 1000, 9000);

        store.record_capability_snapshot(&root, None).unwrap();

        let chain = store.get_delegation_chain("cap-solo").unwrap();
        assert_eq!(chain.len(), 1, "root has no parent -- only itself in chain");
        assert_eq!(chain[0].capability_id, "cap-solo");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn get_delegation_chain_enforces_max_depth_guard() {
        let path = unique_db_path("cl-depth-guard");
        let store = SqliteReceiptStore::open(&path).unwrap();

        // Build a chain of 25 entries (exceeds the level < 20 guard).
        let kp = Keypair::generate();
        let mut prev_id: Option<String> = None;
        for i in 0..25usize {
            let id = format!("cap-depth-{i:03}");
            let token = make_token(&id, &kp, &kp, 1000 + i as u64, 9000);
            store
                .record_capability_snapshot(&token, prev_id.as_deref())
                .unwrap();
            prev_id = Some(id);
        }

        // Walking the chain from the deepest node should be capped at 21 entries (depth guard).
        let chain = store.get_delegation_chain("cap-depth-024").unwrap();
        // With level < 20, the recursion visits at most 21 distinct rows.
        assert!(
            chain.len() <= 21,
            "chain length {} exceeds max depth guard of 21",
            chain.len()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn capability_lineage_table_created_by_open() {
        let path = unique_db_path("cl-table-exists");
        let store = SqliteReceiptStore::open(&path).unwrap();

        // Query the table to verify it exists; COUNT(*) fails if the table is absent.
        let connection = store.connection().unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM capability_lineage", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "table should exist and be empty");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn subject_key_index_exists() {
        let path = unique_db_path("cl-index-check");
        let store = SqliteReceiptStore::open(&path).unwrap();

        // PRAGMA index_list returns rows for each index on the table.
        let connection = store.connection().unwrap();
        let mut stmt = connection
            .prepare("PRAGMA index_list(capability_lineage)")
            .unwrap();
        let index_names: Vec<String> = stmt
            .query_map([], |row: &rusqlite::Row<'_>| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r: Result<String, _>| r.ok())
            .collect();

        assert!(
            index_names
                .iter()
                .any(|n| n == "idx_capability_lineage_subject"),
            "subject_key index not found; found: {index_names:?}"
        );

        let _ = fs::remove_file(path);
    }
}
