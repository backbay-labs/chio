//! SQLite-backed HITL approval store.
//!
//! Pending requests survive kernel restart because every `store_pending`
//! call persists into a WAL-journaled SQLite database. Duplicate ids are
//! idempotent only when the serialized payload matches exactly; mismatched
//! retries are rejected so in-flight HITL state cannot be silently
//! overwritten. Resolved approvals and consumed tokens live in the same
//! database so the replay registry survives alongside the pending log.
//!
//! The store is synchronous; it uses a small r2d2 pool to keep the
//! hot-path query against a cheap connection pool rather than opening a
//! new file handle per call.

use std::fs;
use std::path::Path;

use chio_kernel::{
    ApprovalDecision, ApprovalFilter, ApprovalOutcome, ApprovalRequest, ApprovalStore,
    ApprovalStoreError, ResolvedApproval, ThresholdApprovalCollectorProposal,
    ThresholdApprovalCollectorState, ThresholdApprovalCollectorStore,
    ThresholdApprovalCollectorStoreError,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};

/// SQLite-backed `ApprovalStore`.
///
/// Schema is created on `open`. Migrations are additive and idempotent
/// via `CREATE TABLE IF NOT EXISTS`.
pub struct SqliteApprovalStore {
    pool: Pool<SqliteConnectionManager>,
}

/// Approval-store schema revision. Bump on every schema-affecting change.
const APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 2;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table. Distinct from the co-located receipt store's key so the
/// two track their revisions independently in the one sidecar file.
const APPROVAL_STORE_SCHEMA_KEY: &str = "approval";
/// Tables that identify a database this standalone approval store may open, all
/// of them the store's own. `chio_hitl_pending` is the sole approval anchor.
/// Receipt tables are deliberately excluded: a standalone receipt database (whose
/// only tables are `chio_tool_receipts` or the pre-stamping `http_receipts` /
/// `tool_receipts`) must be refused here rather than adopted and written with HITL
/// tables. The sidecar co-location, where a receipt store creates the shared file
/// first, adopts a receipt-anchored file through
/// [`SqliteApprovalStore::open_colocated_with_receipt_store`] instead. A populated
/// database carrying no approval anchor is refused rather than adopted, so a path
/// mistargeted at another store's file (a receipt, revocation, budget, or
/// authority database) never has approval tables written into it. The revocation
/// store lives in a separate file, and `revoked_capabilities` is deliberately
/// absent so a standalone revocation database fails closed here too.
const APPROVAL_STORE_OWN_ANCHOR_TABLES: &[&str] = &["chio_hitl_pending"];

/// Anchor tables accepted when co-locating behind a receipt store that created
/// the shared sidecar file first. `chio api protect` keeps the receipt and
/// approval stores in one SQLite file and opens the receipt store first, so on a
/// fresh file the shared database already carries the receipt store's
/// `chio_tool_receipts` anchor and no approval table yet. Recognizing that anchor
/// lets the approval store adopt the receipt-anchored file as its sibling instead
/// of refusing it. This wider set is used only through
/// [`SqliteApprovalStore::open_colocated_with_receipt_store`]; the default
/// [`SqliteApprovalStore::open`] keeps the strict own-anchor set so a standalone
/// receipt database is never adopted as an approval store outside the sidecar.
const APPROVAL_STORE_COLOCATED_ANCHOR_TABLES: &[&str] = &[
    "chio_hitl_pending",
    "http_receipts",
    "tool_receipts",
    "chio_tool_receipts",
];

impl SqliteApprovalStore {
    /// Open the store at the given path. Creates the parent directory
    /// if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApprovalStoreError> {
        Self::open_with_anchor_tables(path, APPROVAL_STORE_OWN_ANCHOR_TABLES)
    }

    /// Open the store co-located behind a receipt store that created the shared
    /// sidecar file first. `chio api protect` keeps both stores in one SQLite
    /// file and opens the receipt store first, so the file already carries the
    /// receipt store's provenance anchor and no approval table yet; this variant
    /// adopts that receipt-anchored file as its sibling. The default [`open`]
    /// stays strict so a standalone receipt database is never mistaken for an
    /// approval store outside the sidecar.
    ///
    /// [`open`]: SqliteApprovalStore::open
    pub fn open_colocated_with_receipt_store(
        path: impl AsRef<Path>,
    ) -> Result<Self, ApprovalStoreError> {
        Self::open_with_anchor_tables(path, APPROVAL_STORE_COLOCATED_ANCHOR_TABLES)
    }

    fn open_with_anchor_tables(
        path: impl AsRef<Path>,
        anchor_tables: &[&str],
    ) -> Result<Self, ApprovalStoreError> {
        let path = path.as_ref();
        // Derive the directory from the resolved filesystem path: a co-located
        // approval store opens the same `file:` URI as the receipt store (for
        // example `file:/var/lib/chio/receipts.db?mode=rwc`), whose scheme and
        // query a raw `parent()` would fold into a bogus directory, leaving the
        // real one uncreated so SQLite fails to open the database.
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(&parent)
                .map_err(|e| ApprovalStoreError::Backend(format!("create dir: {e}")))?;
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|e| ApprovalStoreError::Backend(format!("pool build: {e}")))?;
        let store = Self { pool };
        store.run_migrations(anchor_tables)?;
        Ok(store)
    }

    /// Open an in-memory store for tests.
    pub fn open_in_memory() -> Result<Self, ApprovalStoreError> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(1)
            .build(manager)
            .map_err(|e| ApprovalStoreError::Backend(format!("pool build: {e}")))?;
        let store = Self { pool };
        store.run_migrations(APPROVAL_STORE_OWN_ANCHOR_TABLES)?;
        Ok(store)
    }

    fn run_migrations(&self, anchor_tables: &[&str]) -> Result<(), ApprovalStoreError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let on_disk = crate::check_schema_version(
            &conn,
            APPROVAL_STORE_SCHEMA_KEY,
            APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION,
            anchor_tables,
        )
        .map_err(|error| ApprovalStoreError::Backend(error.to_string()))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;
            "#,
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("migration setup: {e}")))?;
        if on_disk < 2 {
            let votes_table_exists: bool = conn
                .query_row(
                    r#"
                    SELECT EXISTS(
                        SELECT 1 FROM sqlite_master
                        WHERE type = 'table'
                          AND name = 'chio_threshold_approval_collector_votes'
                    )
                    "#,
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| ApprovalStoreError::Backend(format!("migration probe: {e}")))?;
            if votes_table_exists {
                let transaction = conn
                    .transaction()
                    .map_err(|e| ApprovalStoreError::Backend(format!("migration begin: {e}")))?;
                transaction
                    .execute_batch(
                        r#"
                        ALTER TABLE chio_threshold_approval_collector_votes
                            RENAME TO chio_threshold_approval_collector_votes_v1;
                        CREATE TABLE chio_threshold_approval_collector_votes (
                            proposal_id TEXT NOT NULL,
                            token_id TEXT NOT NULL,
                            approver_fingerprint TEXT NOT NULL,
                            canonical_token_digest TEXT NOT NULL UNIQUE,
                            token_json BLOB NOT NULL,
                            received_at INTEGER NOT NULL,
                            PRIMARY KEY (proposal_id, token_id),
                            UNIQUE (proposal_id, approver_fingerprint),
                            UNIQUE (proposal_id, canonical_token_digest),
                            FOREIGN KEY (proposal_id)
                                REFERENCES chio_threshold_approval_collectors(proposal_id)
                        );
                        INSERT INTO chio_threshold_approval_collector_votes (
                            proposal_id, token_id, approver_fingerprint,
                            canonical_token_digest, token_json, received_at
                        )
                        SELECT proposal_id, token_id, approver_fingerprint,
                               canonical_token_digest, token_json, received_at
                        FROM chio_threshold_approval_collector_votes_v1;
                        DROP TABLE chio_threshold_approval_collector_votes_v1;
                        "#,
                    )
                    .map_err(|e| {
                        ApprovalStoreError::Backend(format!(
                            "threshold vote uniqueness migration: {e}"
                        ))
                    })?;
                transaction
                    .commit()
                    .map_err(|e| ApprovalStoreError::Backend(format!("migration commit: {e}")))?;
            }
        }
        conn.execute_batch(
            r#"

            CREATE TABLE IF NOT EXISTS chio_hitl_pending (
                approval_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                parameter_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chio_hitl_pending_subject
                ON chio_hitl_pending(subject_id);
            CREATE INDEX IF NOT EXISTS idx_chio_hitl_pending_expires
                ON chio_hitl_pending(expires_at);

            CREATE TABLE IF NOT EXISTS chio_hitl_resolved (
                approval_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                outcome TEXT NOT NULL,
                resolved_at INTEGER NOT NULL,
                approver_hex TEXT NOT NULL,
                token_id TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chio_hitl_resolved_counts
                ON chio_hitl_resolved(subject_id, policy_id, outcome);

            CREATE TABLE IF NOT EXISTS chio_hitl_consumed_tokens (
                token_id TEXT NOT NULL,
                parameter_hash TEXT NOT NULL,
                consumed_at INTEGER NOT NULL,
                PRIMARY KEY (token_id, parameter_hash)
            );

            CREATE TABLE IF NOT EXISTS chio_threshold_approval_collectors (
                proposal_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                governed_intent_hash TEXT NOT NULL,
                subject_fingerprint TEXT NOT NULL,
                authorizing_capability_digest TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                threshold INTEGER NOT NULL CHECK (threshold > 0),
                eligible_set_digest TEXT NOT NULL,
                proposal_created_at INTEGER NOT NULL,
                proposal_deadline INTEGER NOT NULL,
                submitter_fingerprint TEXT,
                require_submitter_separation INTEGER NOT NULL CHECK (
                    require_submitter_separation IN (0, 1)
                ),
                state TEXT NOT NULL CHECK (
                    state IN ('collecting', 'ready', 'delivered', 'cancelled')
                ),
                version INTEGER NOT NULL CHECK (version >= 0),
                updated_at INTEGER NOT NULL,
                proposal_json BLOB NOT NULL,
                requirement_json BLOB NOT NULL,
                record_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_threshold_approval_collector_votes (
                proposal_id TEXT NOT NULL,
                token_id TEXT NOT NULL,
                approver_fingerprint TEXT NOT NULL,
                canonical_token_digest TEXT NOT NULL UNIQUE,
                token_json BLOB NOT NULL,
                received_at INTEGER NOT NULL,
                PRIMARY KEY (proposal_id, token_id),
                UNIQUE (proposal_id, approver_fingerprint),
                UNIQUE (proposal_id, canonical_token_digest),
                FOREIGN KEY (proposal_id)
                    REFERENCES chio_threshold_approval_collectors(proposal_id)
            );
            "#,
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("migration: {e}")))?;
        crate::stamp_schema_version(
            &conn,
            APPROVAL_STORE_SCHEMA_KEY,
            APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| ApprovalStoreError::Backend(error.to_string()))?;
        Ok(())
    }
}

fn collector_state_name(state: ThresholdApprovalCollectorState) -> &'static str {
    match state {
        ThresholdApprovalCollectorState::Collecting => "collecting",
        ThresholdApprovalCollectorState::Ready => "ready",
        ThresholdApprovalCollectorState::Delivered => "delivered",
        ThresholdApprovalCollectorState::Cancelled => "cancelled",
    }
}

fn collector_error(error: impl std::fmt::Display) -> ThresholdApprovalCollectorStoreError {
    ThresholdApprovalCollectorStoreError::Backend(error.to_string())
}

fn encode_collector<T: serde::Serialize>(
    value: &T,
) -> Result<Vec<u8>, ThresholdApprovalCollectorStoreError> {
    chio_core::canonical::canonical_json_bytes(value)
        .map_err(|error| ThresholdApprovalCollectorStoreError::Serialization(error.to_string()))
}

fn decode_collector(
    bytes: &[u8],
) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
    serde_json::from_slice(bytes)
        .map_err(|error| ThresholdApprovalCollectorStoreError::Serialization(error.to_string()))
}

fn serialize_payload(request: &ApprovalRequest) -> Result<String, ApprovalStoreError> {
    serde_json::to_string(request).map_err(|e| ApprovalStoreError::Serialization(e.to_string()))
}

fn deserialize_payload(raw: &str) -> Result<ApprovalRequest, ApprovalStoreError> {
    serde_json::from_str(raw).map_err(|e| ApprovalStoreError::Serialization(e.to_string()))
}

impl ApprovalStore for SqliteApprovalStore {
    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError> {
        let payload = serialize_payload(request)?;
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let returned_payload = conn
            .query_row(
                r#"
            INSERT INTO chio_hitl_pending (approval_id, policy_id, subject_id, tool_server, tool_name, parameter_hash, expires_at, created_at, payload) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT(approval_id) DO UPDATE SET payload = excluded.payload WHERE chio_hitl_pending.payload = excluded.payload RETURNING payload
            "#,
                params![
                    request.approval_id,
                    request.policy_id,
                    request.subject_id,
                    request.tool_server,
                    request.tool_name,
                    request.parameter_hash,
                    request.expires_at as i64,
                    request.created_at as i64,
                    payload,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("insert pending: {e}")))?;
        if returned_payload.is_none() {
            return Err(ApprovalStoreError::Backend(format!(
                "approval_id {} already exists with different payload",
                request.approval_id
            )));
        }
        Ok(())
    }

    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let row: Option<String> = conn
            .query_row(
                "SELECT payload FROM chio_hitl_pending WHERE approval_id = ?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("select pending: {e}")))?;
        match row {
            Some(raw) => Ok(Some(deserialize_payload(&raw)?)),
            None => Ok(None),
        }
    }

    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let mut sql = String::from("SELECT payload FROM chio_hitl_pending WHERE 1=1");
        if filter.subject_id.is_some() {
            sql.push_str(" AND subject_id = :subject_id");
        }
        if filter.tool_server.is_some() {
            sql.push_str(" AND tool_server = :tool_server");
        }
        if filter.tool_name.is_some() {
            sql.push_str(" AND tool_name = :tool_name");
        }
        if filter.not_expired_at.is_some() {
            sql.push_str(" AND expires_at > :not_expired_at");
        }
        sql.push_str(" ORDER BY created_at ASC");
        if filter.limit.is_some() {
            sql.push_str(" LIMIT :limit");
        }

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| ApprovalStoreError::Backend(format!("prepare list: {e}")))?;

        let mut params_vec: Vec<(&str, Box<dyn rusqlite::ToSql>)> = Vec::new();
        if let Some(s) = &filter.subject_id {
            params_vec.push((":subject_id", Box::new(s.clone())));
        }
        if let Some(s) = &filter.tool_server {
            params_vec.push((":tool_server", Box::new(s.clone())));
        }
        if let Some(s) = &filter.tool_name {
            params_vec.push((":tool_name", Box::new(s.clone())));
        }
        if let Some(t) = &filter.not_expired_at {
            params_vec.push((":not_expired_at", Box::new(*t as i64)));
        }
        if let Some(limit) = &filter.limit {
            params_vec.push((":limit", Box::new(*limit as i64)));
        }

        let refs: Vec<(&str, &dyn rusqlite::ToSql)> = params_vec
            .iter()
            .map(|(name, value)| (*name, value.as_ref()))
            .collect();

        let rows = stmt
            .query_map(refs.as_slice(), |row| row.get::<_, String>(0))
            .map_err(|e| ApprovalStoreError::Backend(format!("query list: {e}")))?;

        let mut out = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| ApprovalStoreError::Backend(format!("row: {e}")))?;
            out.push(deserialize_payload(&raw)?);
        }
        Ok(out)
    }

    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let tx = conn
            .transaction()
            .map_err(|e| ApprovalStoreError::Backend(format!("begin tx: {e}")))?;

        // Pull pending record inside the tx to avoid TOCTOU races.
        let pending: Option<(String, String)> = tx
            .query_row(
                "SELECT policy_id, parameter_hash FROM chio_hitl_pending WHERE approval_id = ?1",
                params![id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("select: {e}")))?;
        let (policy_id, parameter_hash) = match pending {
            Some(p) => p,
            None => return Err(ApprovalStoreError::NotFound(id.to_string())),
        };

        // Replay guard: the bound token must not already be consumed.
        let already: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM chio_hitl_consumed_tokens WHERE token_id = ?1 AND parameter_hash = ?2",
                params![decision.token.id, parameter_hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("replay check: {e}")))?;
        if already.is_some() {
            return Err(ApprovalStoreError::Replay(id.to_string()));
        }

        // Idempotency: if already resolved, treat as AlreadyResolved.
        let already_resolved: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM chio_hitl_resolved WHERE approval_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("resolved check: {e}")))?;
        if already_resolved.is_some() {
            return Err(ApprovalStoreError::AlreadyResolved(id.to_string()));
        }

        let outcome = match decision.outcome {
            ApprovalOutcome::Approved => "approved",
            ApprovalOutcome::Denied => "denied",
        };

        tx.execute(
            r#"INSERT INTO chio_hitl_resolved (
                approval_id, policy_id, subject_id, outcome, resolved_at,
                approver_hex, token_id
            ) SELECT approval_id, policy_id, subject_id, ?2, ?3, ?4, ?5
            FROM chio_hitl_pending WHERE approval_id = ?1"#,
            params![
                id,
                outcome,
                decision.received_at as i64,
                decision.approver.to_hex(),
                decision.token.id,
            ],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert resolved: {e}")))?;

        tx.execute(
            "INSERT INTO chio_hitl_consumed_tokens (token_id, parameter_hash, consumed_at) VALUES (?1, ?2, ?3)",
            params![decision.token.id, parameter_hash, decision.received_at as i64],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert consumed: {e}")))?;

        tx.execute(
            "DELETE FROM chio_hitl_pending WHERE approval_id = ?1",
            params![id],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("delete pending: {e}")))?;

        tx.commit()
            .map_err(|e| ApprovalStoreError::Backend(format!("commit: {e}")))?;

        // policy_id is part of the trait signature but unused on this path.
        let _ = policy_id;
        Ok(())
    }

    fn count_approved(&self, subject_id: &str, policy_id: &str) -> Result<u64, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chio_hitl_resolved WHERE subject_id = ?1 AND policy_id = ?2 AND outcome = 'approved'",
                params![subject_id, policy_id],
                |row| row.get(0),
            )
            .map_err(|e| ApprovalStoreError::Backend(format!("count: {e}")))?;
        Ok(count.max(0) as u64)
    }

    fn record_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
        now: u64,
    ) -> Result<(), ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let rows = conn.execute(
            "INSERT OR IGNORE INTO chio_hitl_consumed_tokens (token_id, parameter_hash, consumed_at) VALUES (?1, ?2, ?3)",
            params![token_id, parameter_hash, now as i64],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert consumed: {e}")))?;
        if rows == 0 {
            return Err(ApprovalStoreError::Replay(format!(
                "token {token_id} already consumed"
            )));
        }
        Ok(())
    }

    fn is_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
    ) -> Result<bool, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let row: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM chio_hitl_consumed_tokens WHERE token_id = ?1 AND parameter_hash = ?2",
                params![token_id, parameter_hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("is_consumed: {e}")))?;
        Ok(row.is_some())
    }

    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let row: Option<(String, String, i64, String, String)> = conn
            .query_row(
                r#"SELECT approval_id, outcome, resolved_at, approver_hex, token_id
                   FROM chio_hitl_resolved WHERE approval_id = ?1"#,
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("get_resolution: {e}")))?;
        match row {
            Some((approval_id, outcome_str, resolved_at, approver_hex, token_id)) => {
                let outcome = match outcome_str.as_str() {
                    "approved" => ApprovalOutcome::Approved,
                    "denied" => ApprovalOutcome::Denied,
                    other => {
                        return Err(ApprovalStoreError::Serialization(format!(
                            "unknown outcome: {other}"
                        )))
                    }
                };
                Ok(Some(ResolvedApproval {
                    approval_id,
                    outcome,
                    resolved_at: resolved_at.max(0) as u64,
                    approver_hex,
                    token_id,
                }))
            }
            None => Ok(None),
        }
    }
}

impl ThresholdApprovalCollectorStore for SqliteApprovalStore {
    fn create(
        &self,
        proposal: &ThresholdApprovalCollectorProposal,
    ) -> Result<(), ThresholdApprovalCollectorStoreError> {
        let proposal_json = encode_collector(&proposal.proposal)?;
        let requirement_json = encode_collector(&proposal.requirement)?;
        let record_json = encode_collector(proposal)?;
        let conn = self.pool.get().map_err(collector_error)?;
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT record_json FROM chio_threshold_approval_collectors WHERE proposal_id = ?1",
                [&proposal.proposal.body.proposal_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(collector_error)?;
        if let Some(existing) = existing {
            return if existing == record_json {
                Ok(())
            } else {
                Err(ThresholdApprovalCollectorStoreError::Conflict(
                    "proposal id already exists with different content".to_string(),
                ))
            };
        }
        let body = &proposal.proposal.body;
        conn.execute(
            r#"
            INSERT INTO chio_threshold_approval_collectors (
                proposal_id, request_id, governed_intent_hash, subject_fingerprint,
                authorizing_capability_digest, policy_hash, threshold,
                eligible_set_digest, proposal_created_at, proposal_deadline,
                submitter_fingerprint, require_submitter_separation, state,
                version, updated_at, proposal_json, requirement_json, record_json
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, ?18
            )
            "#,
            params![
                &body.proposal_id,
                &body.request_id,
                &body.governed_intent_hash,
                body.subject.to_hex(),
                &body.authorizing_capability_digest,
                &body.policy_hash,
                i64::from(body.threshold),
                &body.eligible_set_digest,
                i64::try_from(body.proposal_created_at).map_err(collector_error)?,
                i64::try_from(body.proposal_deadline).map_err(collector_error)?,
                proposal.submitter.as_ref().map(|key| key.to_hex()),
                i64::from(proposal.require_submitter_separation),
                collector_state_name(proposal.state),
                i64::try_from(proposal.version).map_err(collector_error)?,
                i64::try_from(proposal.updated_at).map_err(collector_error)?,
                proposal_json,
                requirement_json,
                record_json,
            ],
        )
        .map_err(collector_error)?;
        Ok(())
    }

    fn get(
        &self,
        proposal_id: &str,
    ) -> Result<Option<ThresholdApprovalCollectorProposal>, ThresholdApprovalCollectorStoreError>
    {
        let conn = self.pool.get().map_err(collector_error)?;
        let record: Option<Vec<u8>> = conn
            .query_row(
                "SELECT record_json FROM chio_threshold_approval_collectors WHERE proposal_id = ?1",
                [proposal_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(collector_error)?;
        record.map(|bytes| decode_collector(&bytes)).transpose()
    }

    fn append_token(
        &self,
        proposal_id: &str,
        expected_version: u64,
        token: &chio_core::capability::governance::GovernedApprovalToken,
        replaced_token_id: Option<&str>,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut conn = self.pool.get().map_err(collector_error)?;
        let transaction = conn.transaction().map_err(collector_error)?;
        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record_json FROM chio_threshold_approval_collectors WHERE proposal_id = ?1",
                [proposal_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(collector_error)?;
        let mut record = bytes
            .as_deref()
            .map(decode_collector)
            .transpose()?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if record.version != expected_version || record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        let previous_state = collector_state_name(record.state);
        let token_digest = token.artifact_digest().map_err(|error| {
            ThresholdApprovalCollectorStoreError::Serialization(error.to_string())
        })?;
        let token_json = encode_collector(token)?;
        let write_result = if let Some(replaced_token_id) = replaced_token_id {
            transaction.execute(
                r#"
                UPDATE chio_threshold_approval_collector_votes
                SET token_id = ?1, approver_fingerprint = ?2,
                    canonical_token_digest = ?3, token_json = ?4, received_at = ?5
                WHERE proposal_id = ?6 AND token_id = ?7
                "#,
                params![
                    &token.id,
                    token.approver.to_hex(),
                    token_digest,
                    token_json,
                    i64::try_from(updated_at).map_err(collector_error)?,
                    proposal_id,
                    replaced_token_id,
                ],
            )
        } else {
            transaction.execute(
                r#"
                INSERT INTO chio_threshold_approval_collector_votes (
                    proposal_id, token_id, approver_fingerprint,
                    canonical_token_digest, token_json, received_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    proposal_id,
                    &token.id,
                    token.approver.to_hex(),
                    token_digest,
                    token_json,
                    i64::try_from(updated_at).map_err(collector_error)?,
                ],
            )
        };
        let changed_vote = write_result.map_err(|error| {
            if matches!(
                &error,
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error {
                        code: rusqlite::ErrorCode::ConstraintViolation,
                        ..
                    },
                    _
                )
            ) {
                ThresholdApprovalCollectorStoreError::Conflict(
                    "threshold approval token id, digest, or signer is not unique".to_string(),
                )
            } else {
                collector_error(error)
            }
        })?;
        if changed_vote != 1 {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval replacement token disappeared".to_string(),
            ));
        }
        if let Some(replaced_token_id) = replaced_token_id {
            let existing = record
                .tokens
                .iter_mut()
                .find(|existing| existing.id == replaced_token_id)
                .ok_or_else(|| {
                    ThresholdApprovalCollectorStoreError::Conflict(
                        "threshold approval replacement token disappeared".to_string(),
                    )
                })?;
            *existing = token.clone();
        } else {
            record.tokens.push(token.clone());
        }
        record.state = next_state;
        record.version = record.version.checked_add(1).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::Conflict("proposal version overflowed".into())
        })?;
        record.updated_at = updated_at;
        let record_json = encode_collector(&record)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE chio_threshold_approval_collectors
                SET state = ?1, version = ?2, updated_at = ?3, record_json = ?4
                WHERE proposal_id = ?5 AND version = ?6 AND state = ?7
                "#,
                params![
                    collector_state_name(next_state),
                    i64::try_from(record.version).map_err(collector_error)?,
                    i64::try_from(updated_at).map_err(collector_error)?,
                    record_json,
                    proposal_id,
                    i64::try_from(expected_version).map_err(collector_error)?,
                    previous_state,
                ],
            )
            .map_err(collector_error)?;
        if changed != 1 {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        transaction.commit().map_err(collector_error)?;
        Ok(record)
    }

    fn transition(
        &self,
        proposal_id: &str,
        expected_version: u64,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut conn = self.pool.get().map_err(collector_error)?;
        let transaction = conn.transaction().map_err(collector_error)?;
        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record_json FROM chio_threshold_approval_collectors WHERE proposal_id = ?1",
                [proposal_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(collector_error)?;
        let mut record = bytes
            .as_deref()
            .map(decode_collector)
            .transpose()?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if record.version != expected_version || record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        let previous_state = collector_state_name(record.state);
        record.state = next_state;
        record.version = record.version.checked_add(1).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::Conflict("proposal version overflowed".into())
        })?;
        record.updated_at = updated_at;
        let record_json = encode_collector(&record)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE chio_threshold_approval_collectors
                SET state = ?1, version = ?2, updated_at = ?3, record_json = ?4
                WHERE proposal_id = ?5 AND version = ?6 AND state = ?7
                "#,
                params![
                    collector_state_name(next_state),
                    i64::try_from(record.version).map_err(collector_error)?,
                    i64::try_from(updated_at).map_err(collector_error)?,
                    record_json,
                    proposal_id,
                    i64::try_from(expected_version).map_err(collector_error)?,
                    previous_state,
                ],
            )
            .map_err(collector_error)?;
        if changed != 1 {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        transaction.commit().map_err(collector_error)?;
        Ok(record)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        ThresholdApprovalProposal, ThresholdApprovalProposalBody,
        THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
    };
    use chio_core::capability::threshold_approval::{
        ThresholdApprovalRequirement, ThresholdApproverIdentity,
    };
    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_kernel::ThresholdApprovalCollector;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn open_colocated_creates_parent_dirs_for_a_file_uri_with_query() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("chio-approval-uri-{nonce}"));
        let db = base.join("nested").join("receipts.db");
        let parent = db.parent().expect("db path has a parent");
        assert!(
            !parent.exists(),
            "precondition: the parent dir must not exist yet"
        );

        // The co-located approval store opens the receipt store's `file:` URI,
        // whose query and scheme a raw `parent()` would fold into a bogus
        // relative directory, leaving the real parent uncreated so SQLite would
        // fail to open the database.
        let uri = format!("file:{}?mode=rwc", db.display());
        let store = SqliteApprovalStore::open_colocated_with_receipt_store(uri.as_str())
            .expect("open colocated approval store from a file: URI");
        // The store must be usable once its real parent directory exists.
        store
            .store_pending(&sample_request("uri-1", "hash-uri"))
            .expect("store a pending approval");

        assert!(
            parent.exists(),
            "the real parent directory must be created before SQLite opens the URI"
        );

        let _ = fs::remove_dir_all(&base);
    }

    fn sample_request(id: &str, hash: &str) -> ApprovalRequest {
        let subject = Keypair::generate();
        let approver = Keypair::generate();
        ApprovalRequest {
            approval_id: id.into(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "tool".into(),
            action: "invoke".into(),
            parameter_hash: hash.into(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 42,
            summary: "unit".into(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        }
    }

    #[test]
    fn store_and_list_round_trip() {
        let store = SqliteApprovalStore::open_in_memory().unwrap();
        let r1 = sample_request("a-1", "h-1");
        let r2 = sample_request("a-2", "h-2");
        store.store_pending(&r1).unwrap();
        store.store_pending(&r2).unwrap();

        let all = store.list_pending(&ApprovalFilter::default()).unwrap();
        assert_eq!(all.len(), 2);

        let fetched = store.get_pending("a-1").unwrap().unwrap();
        assert_eq!(fetched.approval_id, "a-1");
        assert_eq!(fetched.parameter_hash, "h-1");
    }

    #[test]
    fn duplicate_pending_insert_is_idempotent_only_when_payload_matches() {
        let store = SqliteApprovalStore::open_in_memory().unwrap();
        let original = sample_request("dup-1", "hash-a");
        let identical = original.clone();
        let mut mismatched = original.clone();
        mismatched.parameter_hash = "hash-b".into();

        store.store_pending(&original).unwrap();
        store.store_pending(&identical).unwrap();

        let err = store.store_pending(&mismatched).unwrap_err();
        match err {
            ApprovalStoreError::Backend(message) => {
                assert!(message.contains("already exists with different payload"));
            }
            other => panic!("expected Backend mismatch error, got {other:?}"),
        }

        let fetched = store.get_pending("dup-1").unwrap().unwrap();
        assert_eq!(fetched.parameter_hash, "hash-a");
    }

    #[test]
    fn standalone_open_refuses_a_receipt_sidecar_that_colocated_open_adopts() {
        // `chio api protect` keeps the approval store in the same file as its
        // receipt and revocation sidecar tables, and opens the receipt store
        // first so it owns the shared file's provenance anchor; the approval store
        // then co-locates onto it. A database carrying only receipt (and
        // revocation) tables and no approval anchor therefore belongs to the
        // receipt store. The standalone approval open must refuse it rather than
        // write HITL tables into a receipt store's file, while the dedicated
        // co-located open adopts it as its sibling.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sidecar.sqlite3");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE http_receipts (id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL);
                 CREATE TABLE tool_receipts (id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL);
                 CREATE TABLE revoked_capabilities (capability_id TEXT PRIMARY KEY);",
            )
            .unwrap();
            let app_id: i32 = conn
                .query_row("PRAGMA application_id", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                app_id, 0,
                "fixture must be unstamped like a legacy database"
            );
        }

        assert!(
            SqliteApprovalStore::open(&path).is_err(),
            "standalone approval open must refuse a receipt-only sidecar file"
        );

        let store = SqliteApprovalStore::open_colocated_with_receipt_store(&path)
            .expect("co-located open must adopt the receipt sidecar file");
        store
            .store_pending(&sample_request("adopt-1", "hash-adopt"))
            .unwrap();
        assert!(store.get_pending("adopt-1").unwrap().is_some());
    }

    #[test]
    fn standalone_open_reopens_a_genuine_approval_database() {
        // A real approval database carries the approval anchor, so the standalone
        // open reopens it across restarts without co-location.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval.sqlite3");
        {
            let store = SqliteApprovalStore::open(&path).unwrap();
            store
                .store_pending(&sample_request("reopen-1", "hash-reopen"))
                .unwrap();
        }
        let store = SqliteApprovalStore::open(&path)
            .expect("a genuine approval database must reopen standalone");
        assert!(store.get_pending("reopen-1").unwrap().is_some());
    }

    #[test]
    fn open_migrates_v1_threshold_vote_ids_to_proposal_scope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval-v1.sqlite3");
        drop(SqliteApprovalStore::open(&path).unwrap());

        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                r#"
                ALTER TABLE chio_threshold_approval_collector_votes
                    RENAME TO chio_threshold_approval_collector_votes_v2;
                CREATE TABLE chio_threshold_approval_collector_votes (
                    proposal_id TEXT NOT NULL,
                    token_id TEXT NOT NULL UNIQUE,
                    approver_fingerprint TEXT NOT NULL,
                    canonical_token_digest TEXT NOT NULL UNIQUE,
                    token_json BLOB NOT NULL,
                    received_at INTEGER NOT NULL,
                    UNIQUE (proposal_id, approver_fingerprint),
                    UNIQUE (proposal_id, canonical_token_digest),
                    FOREIGN KEY (proposal_id)
                        REFERENCES chio_threshold_approval_collectors(proposal_id)
                );
                DROP TABLE chio_threshold_approval_collector_votes_v2;
                INSERT INTO chio_threshold_approval_collectors (
                    proposal_id, request_id, governed_intent_hash,
                    subject_fingerprint, authorizing_capability_digest,
                    policy_hash, threshold, eligible_set_digest,
                    proposal_created_at, proposal_deadline, submitter_fingerprint,
                    require_submitter_separation, state, version, updated_at,
                    proposal_json, requirement_json, record_json
                ) VALUES (
                    'proposal-v1', 'request-v1', 'intent-v1', 'subject-v1',
                    'capability-v1', 'policy-v1', 1, 'eligible-v1',
                    100, 200, NULL, 0, 'collecting', 1, 100,
                    X'01', X'01', X'01'
                );
                INSERT INTO chio_threshold_approval_collector_votes (
                    proposal_id, token_id, approver_fingerprint,
                    canonical_token_digest, token_json, received_at
                ) VALUES (
                    'proposal-v1', 'shared-token', 'approver-v1',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    X'01', 101
                );
                UPDATE chio_store_schema_versions
                SET version = 1
                WHERE store_key = 'approval';
                "#,
            )
            .unwrap();
        drop(connection);

        let store = SqliteApprovalStore::open(&path).unwrap();
        let connection = store.pool.get().unwrap();
        let primary_key_columns: String = connection
            .query_row(
                r#"
                SELECT group_concat(name, ',')
                FROM (
                    SELECT name
                    FROM pragma_table_info('chio_threshold_approval_collector_votes')
                    WHERE pk > 0
                    ORDER BY pk
                )
                "#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        let retained_votes: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM chio_threshold_approval_collector_votes",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(primary_key_columns, "proposal_id,token_id");
        assert_eq!(retained_votes, 1);
    }

    #[test]
    fn threshold_collector_recovers_votes_and_persists_delivery_before_return() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("threshold.sqlite3");
        let authority = Keypair::generate();
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let subject = Keypair::generate();
        let policy_hash = sha256_hex(b"threshold-policy");
        let requirement = ThresholdApprovalRequirement::new(
            policy_hash.clone(),
            2,
            vec![
                ThresholdApproverIdentity {
                    identifier: "alice".to_string(),
                    public_key: alice.public_key(),
                },
                ThresholdApproverIdentity {
                    identifier: "bob".to_string(),
                    public_key: bob.public_key(),
                },
            ],
            "directory-v1".to_string(),
            100,
        )
        .unwrap();
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
                proposal_id: "durable-proposal".to_string(),
                request_id: "durable-request".to_string(),
                governed_intent_hash: sha256_hex(b"durable-intent"),
                subject: subject.public_key(),
                authorizing_capability_digest: sha256_hex(b"durable-capability"),
                policy_hash: policy_hash.clone(),
                threshold: 2,
                eligible_set_digest: requirement.eligible_set_digest.clone(),
                proposal_created_at: 100,
                proposal_deadline: 200,
                policy_authority: authority.public_key(),
            },
            &authority,
        )
        .unwrap();
        let second_proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
                proposal_id: "durable-proposal-b".to_string(),
                request_id: "durable-request-b".to_string(),
                governed_intent_hash: sha256_hex(b"durable-intent-b"),
                subject: subject.public_key(),
                authorizing_capability_digest: sha256_hex(b"durable-capability-b"),
                policy_hash: policy_hash.clone(),
                threshold: 2,
                eligible_set_digest: requirement.eligible_set_digest.clone(),
                proposal_created_at: 100,
                proposal_deadline: 200,
                policy_authority: authority.public_key(),
            },
            &authority,
        )
        .unwrap();
        let make_token = |proposal: &ThresholdApprovalProposal,
                          approver: &Keypair,
                          id: &str,
                          expires_at: u64| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: id.to_string(),
                    approver: approver.public_key(),
                    subject: proposal.body.subject.clone(),
                    governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                    request_id: proposal.body.request_id.clone(),
                    threshold_proposal_hash: Some(proposal.artifact_digest().unwrap()),
                    issued_at: 101,
                    expires_at,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .unwrap()
        };

        {
            let store = Arc::new(SqliteApprovalStore::open(&path).unwrap());
            let collector = ThresholdApprovalCollector::new(
                store,
                policy_hash.clone(),
                vec![authority.public_key()],
            );
            collector
                .create_proposal(proposal.clone(), requirement.clone(), None, false, 100)
                .unwrap();
        }

        {
            let store = Arc::new(SqliteApprovalStore::open(&path).unwrap());
            let collector = ThresholdApprovalCollector::new(
                store,
                policy_hash.clone(),
                vec![authority.public_key()],
            );
            assert!(collector
                .get_proposal("durable-proposal")
                .unwrap()
                .is_some());
            collector
                .submit_token(
                    "durable-proposal",
                    make_token(&proposal, &alice, "token-alice", 120),
                    110,
                )
                .unwrap();
        }

        {
            let store = Arc::new(SqliteApprovalStore::open(&path).unwrap());
            let collector = ThresholdApprovalCollector::new(
                store,
                policy_hash.clone(),
                vec![authority.public_key()],
            );
            let recovered = collector.get_proposal("durable-proposal").unwrap().unwrap();
            assert_eq!(recovered.tokens.len(), 1);
            let ready = collector
                .submit_token(
                    "durable-proposal",
                    make_token(&proposal, &bob, "token-bob", 199),
                    111,
                )
                .unwrap();
            assert_eq!(ready.state, ThresholdApprovalCollectorState::Ready);
        }

        {
            let store = Arc::new(SqliteApprovalStore::open(&path).unwrap());
            let collector = ThresholdApprovalCollector::new(
                store,
                policy_hash.clone(),
                vec![authority.public_key()],
            );
            let ready = collector.get_proposal("durable-proposal").unwrap().unwrap();
            assert_eq!(ready.state, ThresholdApprovalCollectorState::Ready);
            assert!(collector.deliver("durable-proposal", 150).is_err());
            let refreshed = collector
                .submit_token(
                    "durable-proposal",
                    make_token(&proposal, &alice, "token-alice-fresh", 199),
                    150,
                )
                .unwrap();
            assert_eq!(refreshed.state, ThresholdApprovalCollectorState::Ready);
            assert_eq!(refreshed.tokens.len(), 2);
            let delivered = collector.deliver("durable-proposal", 151).unwrap();
            assert_eq!(delivered.tokens.len(), 2);
            assert!(delivered
                .tokens
                .iter()
                .any(|token| token.id == "token-alice-fresh"));
        }

        let store = Arc::new(SqliteApprovalStore::open(&path).unwrap());
        let collector =
            ThresholdApprovalCollector::new(store, policy_hash, vec![authority.public_key()]);
        assert_eq!(
            collector
                .get_proposal("durable-proposal")
                .unwrap()
                .unwrap()
                .state,
            ThresholdApprovalCollectorState::Delivered
        );
        collector
            .create_proposal(second_proposal.clone(), requirement, None, false, 100)
            .unwrap();
        collector
            .submit_token(
                "durable-proposal-b",
                make_token(&second_proposal, &alice, "token-alice-fresh", 199),
                110,
            )
            .unwrap();
        let second_ready = collector
            .submit_token(
                "durable-proposal-b",
                make_token(&second_proposal, &bob, "token-bob", 199),
                111,
            )
            .unwrap();
        assert_eq!(second_ready.state, ThresholdApprovalCollectorState::Ready);
    }
}
