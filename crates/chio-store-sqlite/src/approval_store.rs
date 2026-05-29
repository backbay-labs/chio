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
    ApprovalStoreError, ResolvedApproval,
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

impl SqliteApprovalStore {
    /// Open the store at the given path. Creates the parent directory
    /// if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApprovalStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| ApprovalStoreError::Backend(format!("create dir: {e}")))?;
            }
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|e| ApprovalStoreError::Backend(format!("pool build: {e}")))?;
        let store = Self { pool };
        store.run_migrations()?;
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
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;

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
            "#,
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("migration: {e}")))?;
        Ok(())
    }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;

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
}
