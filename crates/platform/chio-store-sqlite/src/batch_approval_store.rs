//! SQLite-backed `BatchApprovalStore`.
//!
//! Mirrors the single-request approval store: a WAL-journaled SQLite
//! database with idempotent migrations. Batch records carry their own
//! usage counters so the kernel can reconcile consumption without
//! going back to the receipt log.

use std::fs;
use std::path::Path;

use chio_core::capability::scope::MonetaryAmount;
use chio_kernel::{ApprovalStoreError, BatchApproval, BatchApprovalStore};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};

pub struct SqliteBatchApprovalStore {
    pool: Pool<SqliteConnectionManager>,
}

/// Batch-approval-store schema revision. Bump on every schema-affecting change.
const BATCH_APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const BATCH_APPROVAL_STORE_SCHEMA_KEY: &str = "batch_approval";
/// Tables shipped before schema stamping existed, used to adopt a pre-stamping
/// batch-approval database rather than reject it as foreign.
const BATCH_APPROVAL_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &["chio_hitl_batches"];

impl SqliteBatchApprovalStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApprovalStoreError> {
        let path = path.as_ref();
        // Resolve any `file:` URI to its on-disk parent before creating it, so a
        // URI-configured store creates the real backing directory rather than a
        // bogus scheme-prefixed one.
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(&parent)
                .map_err(|e| ApprovalStoreError::Backend(format!("create dir: {e}")))?;
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder()
            .max_size(4)
            .build(manager)
            .map_err(|e| ApprovalStoreError::Backend(format!("pool build: {e}")))?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

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
        crate::check_schema_version(
            &conn,
            BATCH_APPROVAL_STORE_SCHEMA_KEY,
            BATCH_APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION,
            BATCH_APPROVAL_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| ApprovalStoreError::Backend(error.to_string()))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_hitl_batches (
                batch_id TEXT PRIMARY KEY,
                approver_hex TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                server_pattern TEXT NOT NULL,
                tool_pattern TEXT NOT NULL,
                per_call_currency TEXT,
                per_call_units INTEGER,
                total_currency TEXT,
                total_units INTEGER,
                max_calls INTEGER,
                not_before INTEGER NOT NULL,
                not_after INTEGER NOT NULL,
                used_calls INTEGER NOT NULL DEFAULT 0,
                used_total_units INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_chio_hitl_batches_subject
                ON chio_hitl_batches(subject_id, revoked);
            "#,
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("migration: {e}")))?;
        crate::stamp_schema_version(
            &conn,
            BATCH_APPROVAL_STORE_SCHEMA_KEY,
            BATCH_APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| ApprovalStoreError::Backend(error.to_string()))?;
        Ok(())
    }
}

fn row_to_batch(row: &rusqlite::Row<'_>) -> rusqlite::Result<BatchApproval> {
    let per_call_currency: Option<String> = row.get(5)?;
    let per_call_units: Option<i64> = row.get(6)?;
    let total_currency: Option<String> = row.get(7)?;
    let total_units: Option<i64> = row.get(8)?;
    let max_calls: Option<i64> = row.get(9)?;
    let revoked: i64 = row.get(14)?;
    Ok(BatchApproval {
        batch_id: row.get(0)?,
        approver_hex: row.get(1)?,
        subject_id: row.get(2)?,
        server_pattern: row.get(3)?,
        tool_pattern: row.get(4)?,
        max_amount_per_call: match (per_call_currency, per_call_units) {
            (Some(currency), Some(units)) => Some(MonetaryAmount {
                currency,
                units: units.max(0) as u64,
            }),
            _ => None,
        },
        max_total_amount: match (total_currency, total_units) {
            (Some(currency), Some(units)) => Some(MonetaryAmount {
                currency,
                units: units.max(0) as u64,
            }),
            _ => None,
        },
        max_calls: max_calls.map(|v| v.max(0) as u32),
        not_before: row.get::<_, i64>(10)?.max(0) as u64,
        not_after: row.get::<_, i64>(11)?.max(0) as u64,
        used_calls: row.get::<_, i64>(12)?.max(0) as u32,
        used_total_units: row.get::<_, i64>(13)?.max(0) as u64,
        revoked: revoked != 0,
    })
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

fn amount_fits(batch: &BatchApproval, amount: Option<&MonetaryAmount>) -> bool {
    let Some(amt) = amount else {
        return batch.max_amount_per_call.is_none() && batch.max_total_amount.is_none();
    };
    if let Some(per_call) = &batch.max_amount_per_call {
        if amt.currency != per_call.currency || amt.units > per_call.units {
            return false;
        }
    }
    if let Some(total) = &batch.max_total_amount {
        if amt.currency != total.currency
            || batch.used_total_units.saturating_add(amt.units) > total.units
        {
            return false;
        }
    }
    true
}

impl BatchApprovalStore for SqliteBatchApprovalStore {
    fn store(&self, batch: &BatchApproval) -> Result<(), ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        conn.execute(
            r#"INSERT OR REPLACE INTO chio_hitl_batches (
                batch_id, approver_hex, subject_id, server_pattern, tool_pattern,
                per_call_currency, per_call_units, total_currency, total_units,
                max_calls, not_before, not_after, used_calls, used_total_units, revoked
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"#,
            params![
                batch.batch_id,
                batch.approver_hex,
                batch.subject_id,
                batch.server_pattern,
                batch.tool_pattern,
                batch
                    .max_amount_per_call
                    .as_ref()
                    .map(|a| a.currency.clone()),
                batch.max_amount_per_call.as_ref().map(|a| a.units as i64),
                batch.max_total_amount.as_ref().map(|a| a.currency.clone()),
                batch.max_total_amount.as_ref().map(|a| a.units as i64),
                batch.max_calls.map(|c| c as i64),
                batch.not_before as i64,
                batch.not_after as i64,
                batch.used_calls as i64,
                batch.used_total_units as i64,
                batch.revoked as i64,
            ],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert batch: {e}")))?;
        Ok(())
    }

    fn find_matching(
        &self,
        subject_id: &str,
        server_id: &str,
        tool_name: &str,
        amount: Option<&MonetaryAmount>,
        now: u64,
    ) -> Result<Option<BatchApproval>, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        // Pull every non-revoked candidate for this subject within the
        // time window, then apply pattern + amount filters in Rust.
        let mut stmt = conn
            .prepare(
                r#"SELECT batch_id, approver_hex, subject_id, server_pattern, tool_pattern,
                          per_call_currency, per_call_units, total_currency, total_units,
                          max_calls, not_before, not_after, used_calls, used_total_units, revoked
                   FROM chio_hitl_batches
                   WHERE subject_id = ?1 AND revoked = 0
                     AND not_before <= ?2 AND not_after > ?2"#,
            )
            .map_err(|e| ApprovalStoreError::Backend(format!("prepare: {e}")))?;
        let rows = stmt
            .query_map(params![subject_id, now as i64], row_to_batch)
            .map_err(|e| ApprovalStoreError::Backend(format!("query: {e}")))?;
        for row in rows {
            let batch = row.map_err(|e| ApprovalStoreError::Backend(format!("row: {e}")))?;
            if !pattern_matches(&batch.server_pattern, server_id) {
                continue;
            }
            if !pattern_matches(&batch.tool_pattern, tool_name) {
                continue;
            }
            if let Some(max) = batch.max_calls {
                if batch.used_calls >= max {
                    continue;
                }
            }
            if !amount_fits(&batch, amount) {
                continue;
            }
            return Ok(Some(batch));
        }
        Ok(None)
    }

    fn record_usage(
        &self,
        batch_id: &str,
        amount: Option<&MonetaryAmount>,
    ) -> Result<(), ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let added_units = amount.map(|a| a.units as i64).unwrap_or(0);
        let rows = conn.execute(
            "UPDATE chio_hitl_batches SET used_calls = used_calls + 1, used_total_units = used_total_units + ?2 WHERE batch_id = ?1",
            params![batch_id, added_units],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("update usage: {e}")))?;
        if rows == 0 {
            return Err(ApprovalStoreError::NotFound(batch_id.to_string()));
        }
        Ok(())
    }

    fn revoke(&self, batch_id: &str) -> Result<(), ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let rows = conn
            .execute(
                "UPDATE chio_hitl_batches SET revoked = 1 WHERE batch_id = ?1",
                params![batch_id],
            )
            .map_err(|e| ApprovalStoreError::Backend(format!("revoke: {e}")))?;
        if rows == 0 {
            return Err(ApprovalStoreError::NotFound(batch_id.to_string()));
        }
        Ok(())
    }

    fn get(&self, batch_id: &str) -> Result<Option<BatchApproval>, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let batch: Option<BatchApproval> = conn
            .query_row(
                r#"SELECT batch_id, approver_hex, subject_id, server_pattern, tool_pattern,
                          per_call_currency, per_call_units, total_currency, total_units,
                          max_calls, not_before, not_after, used_calls, used_total_units, revoked
                   FROM chio_hitl_batches WHERE batch_id = ?1"#,
                params![batch_id],
                row_to_batch,
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("get: {e}")))?;
        Ok(batch)
    }
}
