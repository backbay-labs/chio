//! `chio settle status` CLI surface.
//!
//! Surfaces the local settlement lifecycle for operator review. The
//! command opens an existing chio-store-sqlite database read-only and
//! reports:
//!
//! - `pending`: IOU envelopes that have no `settlement_reconciliations`
//!   row yet.
//! - `settled`: rows in `settlement_reconciliations` whose
//!   `reconciliation_state` is `settled`.
//! - `dead_lettered`: rows in `settle_dead_letters`.
//!
//! The status report is deterministic: lists are sorted by
//! `(finalized_at, receipt_id)` to match the settlement-ordering
//! invariant documented on `chio-settle::SettlementHook`.
//!
//! Output formats:
//!
//! - default (TTY): a small human table per state.
//! - `--json`: a stable JSON report suitable for tooling. The schema
//!   tag is `chio.settle.status-report.v1`.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Schema string emitted on the wire for status reports.
pub const SETTLE_STATUS_REPORT_SCHEMA: &str = "chio.settle.status-report.v1";

/// Errors surfaced by the `chio settle status` command.
#[derive(Debug, thiserror::Error)]
pub enum SettleStatusError {
    #[error("settle status backend error: {0}")]
    Backend(String),
    #[error("settle status store path does not exist: {0}")]
    NotFound(PathBuf),
}

/// One pending IOU envelope row surfaced by the status report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingRow {
    pub receipt_id: String,
    pub finalized_at: i64,
    pub amount_units: i64,
    pub currency: String,
}

/// One settled receipt row surfaced by the status report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettledRow {
    pub receipt_id: String,
    pub reconciliation_state: String,
    pub updated_at: i64,
}

/// One dead-lettered row surfaced by the status report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeadLetteredRow {
    pub receipt_id: String,
    pub finalized_at: i64,
    pub attempts: i64,
    pub reason: String,
}

/// Aggregate status report. The `schema` tag pins the wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettleStatusReport {
    pub schema: String,
    pub pending: Vec<PendingRow>,
    pub settled: Vec<SettledRow>,
    pub dead_lettered: Vec<DeadLetteredRow>,
}

impl SettleStatusReport {
    /// Build a status report from a chio-store-sqlite database file.
    /// The connection is opened read-only; tables that are absent
    /// (because the relevant migration has not run yet) yield empty
    /// vectors rather than errors.
    pub fn load(path: &Path) -> Result<Self, SettleStatusError> {
        if !path.exists() {
            return Err(SettleStatusError::NotFound(path.to_path_buf()));
        }
        // Force a read-only connection so the CLI never mutates state.
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|err| SettleStatusError::Backend(err.to_string()))?;

        let pending = if table_exists(&conn, "iou_envelope")? {
            list_pending(&conn)?
        } else {
            Vec::new()
        };
        let settled = if table_exists(&conn, "settlement_reconciliations")? {
            list_settled(&conn)?
        } else {
            Vec::new()
        };
        let dead_lettered = if table_exists(&conn, "settle_dead_letters")? {
            list_dead_lettered(&conn)?
        } else {
            Vec::new()
        };

        Ok(Self {
            schema: SETTLE_STATUS_REPORT_SCHEMA.to_string(),
            pending,
            settled,
            dead_lettered,
        })
    }

    /// Render the report as a human-readable text summary.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "settle status: pending={} settled={} dead_lettered={}\n",
            self.pending.len(),
            self.settled.len(),
            self.dead_lettered.len()
        ));
        if !self.pending.is_empty() {
            out.push_str("\npending:\n");
            for row in &self.pending {
                out.push_str(&format!(
                    "  {receipt_id} ts={finalized_at} {amount_units} {currency}\n",
                    receipt_id = row.receipt_id,
                    finalized_at = row.finalized_at,
                    amount_units = row.amount_units,
                    currency = row.currency,
                ));
            }
        }
        if !self.settled.is_empty() {
            out.push_str("\nsettled:\n");
            for row in &self.settled {
                out.push_str(&format!(
                    "  {receipt_id} state={state} updated_at={updated_at}\n",
                    receipt_id = row.receipt_id,
                    state = row.reconciliation_state,
                    updated_at = row.updated_at,
                ));
            }
        }
        if !self.dead_lettered.is_empty() {
            out.push_str("\ndead_lettered:\n");
            for row in &self.dead_lettered {
                out.push_str(&format!(
                    "  {receipt_id} ts={finalized_at} attempts={attempts} reason={reason}\n",
                    receipt_id = row.receipt_id,
                    finalized_at = row.finalized_at,
                    attempts = row.attempts,
                    reason = row.reason,
                ));
            }
        }
        out
    }

    /// Render the report as canonical JSON.
    pub fn render_json(&self) -> Result<String, SettleStatusError> {
        serde_json::to_string_pretty(self)
            .map_err(|err| SettleStatusError::Backend(err.to_string()))
    }
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool, SettleStatusError> {
    let row: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    Ok(row.is_some())
}

fn list_pending(conn: &Connection) -> Result<Vec<PendingRow>, SettleStatusError> {
    // A pending IOU is one whose receipt_id has no settlement_reconciliations
    // row at all. If settlement_reconciliations is absent, every IOU is pending.
    let reconciliations_present = table_exists(conn, "settlement_reconciliations")?;
    let sql = if reconciliations_present {
        "SELECT iou.receipt_id, iou.receipt_timestamp, iou.amount_units, iou.currency \
         FROM iou_envelope AS iou \
         LEFT JOIN settlement_reconciliations AS rec \
           ON rec.receipt_id = iou.receipt_id \
         WHERE rec.receipt_id IS NULL \
         ORDER BY iou.receipt_timestamp ASC, iou.receipt_id ASC"
    } else {
        "SELECT receipt_id, receipt_timestamp, amount_units, currency \
         FROM iou_envelope \
         ORDER BY receipt_timestamp ASC, receipt_id ASC"
    };
    let mut stmt = conn
        .prepare(sql)
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(PendingRow {
                receipt_id: row.get(0)?,
                finalized_at: row.get(1)?,
                amount_units: row.get(2)?,
                currency: row.get(3)?,
            })
        })
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|err| SettleStatusError::Backend(err.to_string()))?);
    }
    Ok(out)
}

fn list_settled(conn: &Connection) -> Result<Vec<SettledRow>, SettleStatusError> {
    // The documented CLI ordering contract is
    // `(finalized_at, receipt_id)` across all three sections of
    // `chio settle status`. The
    // `settlement_reconciliations` table only carries `updated_at`
    // (the time the reconciliation row was last modified, which can
    // drift from the receipt's finalized timestamp on retry/restage),
    // so when `chio_tool_receipts` is present we LEFT JOIN it to
    // recover the receipt finalization time and sort on it. When the
    // receipts table is absent (synthetic test fixtures, settle-only
    // databases) we fall back to `updated_at` so the function still
    // returns rows in a deterministic order.
    let receipts_present = table_exists(conn, "chio_tool_receipts")?;
    let sql = if receipts_present {
        "SELECT sr.receipt_id, sr.reconciliation_state, sr.updated_at \
         FROM settlement_reconciliations AS sr \
         LEFT JOIN chio_tool_receipts AS r ON r.receipt_id = sr.receipt_id \
         WHERE sr.reconciliation_state = 'settled' \
         ORDER BY COALESCE(r.timestamp, sr.updated_at) ASC, sr.receipt_id ASC"
    } else {
        "SELECT receipt_id, reconciliation_state, updated_at \
         FROM settlement_reconciliations \
         WHERE reconciliation_state = 'settled' \
         ORDER BY updated_at ASC, receipt_id ASC"
    };
    let mut stmt = conn
        .prepare(sql)
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(SettledRow {
                receipt_id: row.get(0)?,
                reconciliation_state: row.get(1)?,
                updated_at: row.get(2)?,
            })
        })
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|err| SettleStatusError::Backend(err.to_string()))?);
    }
    Ok(out)
}

fn list_dead_lettered(conn: &Connection) -> Result<Vec<DeadLetteredRow>, SettleStatusError> {
    let mut stmt = conn
        .prepare(
            "SELECT receipt_id, finalized_at, attempts, reason \
             FROM settle_dead_letters \
             ORDER BY finalized_at ASC, receipt_id ASC",
        )
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(DeadLetteredRow {
                receipt_id: row.get(0)?,
                finalized_at: row.get(1)?,
                attempts: row.get(2)?,
                reason: row.get(3)?,
            })
        })
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|err| SettleStatusError::Backend(err.to_string()))?);
    }
    Ok(out)
}

/// Run `chio settle status`. Wires the report into the CLI dispatch
/// surface; callers control output format via `json`.
pub fn cmd_settle_status(store_path: &Path, json: bool) -> Result<i32, SettleStatusError> {
    // Defensive: verify the file is at least readable before opening.
    let _meta =
        fs::metadata(store_path).map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let report = SettleStatusReport::load(store_path)?;
    if json {
        println!("{}", report.render_json()?);
    } else {
        print!("{}", report.render_text());
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rusqlite::params;
    use tempfile::TempDir;

    fn write_db(dir: &TempDir) -> PathBuf {
        let path = dir.path().join("settle.sqlite");
        let conn = Connection::open(&path).expect("open db");
        conn.execute_batch(
            "CREATE TABLE iou_envelope (
                receipt_id TEXT PRIMARY KEY,
                iou_id TEXT NOT NULL,
                receipt_timestamp INTEGER NOT NULL,
                tenant_id TEXT,
                amount_units INTEGER NOT NULL,
                currency TEXT NOT NULL,
                issuer_key TEXT NOT NULL,
                canonical_json TEXT NOT NULL
            );
            CREATE TABLE settlement_reconciliations (
                receipt_id TEXT PRIMARY KEY,
                reconciliation_state TEXT NOT NULL,
                note TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE settle_dead_letters (
                receipt_id TEXT PRIMARY KEY,
                finalized_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL,
                reason TEXT NOT NULL,
                pipeline_error TEXT,
                canonical_json TEXT NOT NULL,
                recorded_at INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("create tables");
        conn.execute(
            "INSERT INTO iou_envelope \
                (receipt_id, iou_id, receipt_timestamp, tenant_id, amount_units, currency, issuer_key, canonical_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params!["rcpt-1", "iou-1", 100i64, None::<&str>, 250i64, "USD", "{}", "{}"],
        )
        .expect("insert pending");
        conn.execute(
            "INSERT INTO iou_envelope \
                (receipt_id, iou_id, receipt_timestamp, tenant_id, amount_units, currency, issuer_key, canonical_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params!["rcpt-2", "iou-2", 200i64, None::<&str>, 250i64, "USD", "{}", "{}"],
        )
        .expect("insert second");
        conn.execute(
            "INSERT INTO settlement_reconciliations \
                (receipt_id, reconciliation_state, note, updated_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params!["rcpt-2", "settled", None::<&str>, 250i64],
        )
        .expect("insert settled");
        conn.execute(
            "INSERT INTO settle_dead_letters \
                (receipt_id, finalized_at, attempts, reason, pipeline_error, canonical_json, recorded_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["rcpt-3", 300i64, 5i64, "rpc lag", None::<&str>, "{}", 0i64],
        )
        .expect("insert dead letter");
        path
    }

    #[test]
    fn load_classifies_pending_settled_dead_lettered() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_db(&dir);
        let report = SettleStatusReport::load(&path).expect("load ok");
        assert_eq!(report.pending.len(), 1);
        assert_eq!(report.pending[0].receipt_id, "rcpt-1");
        assert_eq!(report.settled.len(), 1);
        assert_eq!(report.settled[0].receipt_id, "rcpt-2");
        assert_eq!(report.dead_lettered.len(), 1);
        assert_eq!(report.dead_lettered[0].receipt_id, "rcpt-3");
        assert_eq!(report.schema, SETTLE_STATUS_REPORT_SCHEMA);
    }

    #[test]
    fn render_text_summary_lists_counts_and_rows() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_db(&dir);
        let report = SettleStatusReport::load(&path).expect("load ok");
        let text = report.render_text();
        assert!(text.contains("pending=1"));
        assert!(text.contains("settled=1"));
        assert!(text.contains("dead_lettered=1"));
        assert!(text.contains("rcpt-1"));
        assert!(text.contains("rcpt-3"));
    }

    #[test]
    fn render_json_carries_schema_tag() {
        let dir = TempDir::new().expect("tempdir");
        let path = write_db(&dir);
        let report = SettleStatusReport::load(&path).expect("load ok");
        let json = report.render_json().expect("render json");
        assert!(json.contains("\"schema\": \"chio.settle.status-report.v1\""));
        assert!(json.contains("\"pending\""));
        assert!(json.contains("\"settled\""));
        assert!(json.contains("\"dead_lettered\""));
    }

    #[test]
    fn missing_db_returns_not_found() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("absent.sqlite");
        match SettleStatusReport::load(&path) {
            Err(SettleStatusError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn missing_tables_return_empty_vectors() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("empty.sqlite");
        let conn = Connection::open(&path).expect("open empty");
        // No tables created at all.
        drop(conn);
        let report = SettleStatusReport::load(&path).expect("load ok");
        assert!(report.pending.is_empty());
        assert!(report.settled.is_empty());
        assert!(report.dead_lettered.is_empty());
    }

    #[test]
    fn settled_orders_by_receipt_finalized_at_when_receipts_table_present() {
        // When `chio_tool_receipts` is present, list_settled must
        // order by the receipt's finalized timestamp (`r.timestamp`),
        // not by `settlement_reconciliations.updated_at`. This test
        // creates two settled rows whose `updated_at` ordering is the
        // OPPOSITE of their receipt-finalized ordering, then confirms
        // the report follows the receipts ordering.
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("ordered.sqlite");
        let conn = Connection::open(&path).expect("open db");
        conn.execute_batch(
            "CREATE TABLE iou_envelope (
                receipt_id TEXT PRIMARY KEY,
                iou_id TEXT NOT NULL,
                receipt_timestamp INTEGER NOT NULL,
                tenant_id TEXT,
                amount_units INTEGER NOT NULL,
                currency TEXT NOT NULL,
                issuer_key TEXT NOT NULL,
                canonical_json TEXT NOT NULL
            );
            CREATE TABLE settlement_reconciliations (
                receipt_id TEXT PRIMARY KEY,
                reconciliation_state TEXT NOT NULL,
                note TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE chio_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL
            );",
        )
        .expect("create tables");
        // rcpt-A: finalized_at=100, settled updated_at=900
        // rcpt-B: finalized_at=200, settled updated_at=500
        // Ordering by updated_at would give B,A; ordering by
        // finalized_at gives A,B.
        conn.execute(
            "INSERT INTO chio_tool_receipts (receipt_id, timestamp) VALUES ('rcpt-A', 100), ('rcpt-B', 200)",
            [],
        )
        .expect("insert receipts");
        conn.execute(
            "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
             VALUES ('rcpt-A', 'settled', NULL, 900), ('rcpt-B', 'settled', NULL, 500)",
            [],
        )
        .expect("insert reconciliations");
        drop(conn);
        let report = SettleStatusReport::load(&path).expect("load ok");
        assert_eq!(report.settled.len(), 2);
        assert_eq!(report.settled[0].receipt_id, "rcpt-A");
        assert_eq!(report.settled[1].receipt_id, "rcpt-B");
    }
}

/// Schema string emitted on the wire for drive reports.
pub const SETTLE_DRIVE_REPORT_SCHEMA: &str = "chio.settle.drive-report.v1";

/// Summary of one settlement drive pass over due `settle_attempts` rows.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettleDriveReport {
    /// Attempts that settled: a `settlement_reconciliations` row was
    /// written and the bounded envelope cleared.
    pub settled: u64,
    /// Attempts re-armed with a later visibility.
    pub retried: u64,
    /// Attempts that landed a dead-letter row.
    pub dead_lettered: u64,
    /// Attempts cleared without a settled record (skipped outcomes and
    /// receipts outside the marketplace surface).
    pub skipped: u64,
}

/// Drive due settlement attempts through the reference hook: for each due
/// `settle_attempts` row, load the finalized receipt, rebuild its
/// observation, and apply the driver step. Settled attempts write the
/// `settlement_reconciliations` row `chio settle status` reports (IOU
/// minting stays with the signing-capable credit lane); recoverable
/// failures re-arm; terminal failures dead-letter. Bounded by `batch`.
pub fn run_settlement_drive(
    store_path: &Path,
    batch: usize,
) -> Result<SettleDriveReport, SettleStatusError> {
    use chio_kernel::settlement_retry::{SettleAttemptRecord, SettlementRetryStore};

    let receipts = chio_store_sqlite::SqliteReceiptStore::open(store_path)
        .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
    let retry_store = chio_store_sqlite::SqliteSettlementRetryStore::open_alongside(&receipts)
        .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
    let runtime = chio_settle::SettlementRuntime::new(
        chio_settle::OpsSettlementHook::new(),
        chio_settle::RetryPolicy::default(),
    );
    let connection = Connection::open(store_path)
        .map_err(|error| SettleStatusError::Backend(error.to_string()))?;

    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let due = retry_store
        .due_attempts(now_unix_secs, batch)
        .map_err(|error| SettleStatusError::Backend(error.to_string()))?;

    let mut report = SettleDriveReport::default();
    for attempt in due {
        let raw_json: Option<String> = connection
            .query_row(
                "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
                rusqlite::params![attempt.receipt_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
        let Some(raw_json) = raw_json else {
            // The attempt references a receipt this store does not hold:
            // nothing can ever settle it, so it terminates as a dead letter
            // rather than spinning forever.
            dead_letter_attempt(
                &retry_store,
                &attempt,
                "finalized receipt not found in this store",
            )?;
            report.dead_lettered += 1;
            continue;
        };
        let receipt: chio_core::receipt::body::ChioReceipt = serde_json::from_str(&raw_json)
            .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
        let observation = chio_kernel::settlement_observer::build_observation(
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
        );
        let Some(observation) = observation else {
            // Unpriced or malformed for the marketplace surface: nothing is
            // owed downstream.
            retry_store
                .clear_attempt(&attempt.receipt_id)
                .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
            report.skipped += 1;
            continue;
        };
        match runtime.drive(&observation, attempt.attempts) {
            chio_settle::SettlementDriveStep::Settle { transcript_id } => {
                connection
                    .execute(
                        "INSERT INTO settlement_reconciliations \
                         (receipt_id, reconciliation_state, note, updated_at) \
                         VALUES (?1, 'settled', ?2, ?3) \
                         ON CONFLICT(receipt_id) DO UPDATE SET \
                           reconciliation_state = 'settled', \
                           note = excluded.note, \
                           updated_at = excluded.updated_at",
                        rusqlite::params![
                            attempt.receipt_id,
                            format!("transcript={transcript_id}"),
                            now_unix_secs.min(i64::MAX as u64) as i64,
                        ],
                    )
                    .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
                retry_store
                    .clear_attempt(&attempt.receipt_id)
                    .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
                report.settled += 1;
            }
            chio_settle::SettlementDriveStep::Retry {
                attempts,
                backoff,
                reason,
            } => {
                retry_store
                    .upsert_attempt(&SettleAttemptRecord {
                        receipt_id: attempt.receipt_id.clone(),
                        finalized_at: attempt.finalized_at,
                        attempts,
                        next_visible_at: now_unix_secs
                            .saturating_add(backoff.as_secs().max(1)),
                        last_reason: Some(reason),
                    })
                    .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
                report.retried += 1;
            }
            chio_settle::SettlementDriveStep::DeadLetter { reason } => {
                dead_letter_attempt(&retry_store, &attempt, &reason)?;
                report.dead_lettered += 1;
            }
            chio_settle::SettlementDriveStep::Skip { .. } => {
                retry_store
                    .clear_attempt(&attempt.receipt_id)
                    .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
                report.skipped += 1;
            }
        }
    }
    Ok(report)
}

fn dead_letter_attempt(
    retry_store: &chio_store_sqlite::SqliteSettlementRetryStore,
    attempt: &chio_kernel::settlement_retry::SettleAttemptRecord,
    reason: &str,
) -> Result<(), SettleStatusError> {
    use chio_kernel::settlement_retry::SettlementRetryStore;
    let record = chio_settle::DeadLetterRecord::new(
        attempt.receipt_id.clone(),
        attempt.finalized_at,
        attempt.attempts.saturating_add(1),
        reason,
    );
    retry_store
        .insert_dead_letter(&record)
        .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
    retry_store
        .clear_attempt(&attempt.receipt_id)
        .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
    Ok(())
}

/// `chio settle drive` entry point: run one drive pass and report.
pub fn cmd_settle_drive(
    store_path: &Path,
    batch: usize,
    json: bool,
) -> Result<i32, SettleStatusError> {
    let report = run_settlement_drive(store_path, batch)?;
    if json {
        let value = serde_json::json!({
            "schema": SETTLE_DRIVE_REPORT_SCHEMA,
            "settled": report.settled,
            "retried": report.retried,
            "deadLettered": report.dead_lettered,
            "skipped": report.skipped,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value)
                .map_err(|error| SettleStatusError::Backend(error.to_string()))?
        );
    } else {
        println!(
            "settled {}  retried {}  dead-lettered {}  skipped {}",
            report.settled, report.retried, report.dead_lettered, report.skipped
        );
    }
    Ok(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod drive_tests {
    use super::*;
    use chio_kernel::settlement_retry::{SettleAttemptRecord, SettlementRetryStore};
    use tempfile::TempDir;

    fn signed_money_receipt(receipt_id: &str) -> chio_core::receipt::body::ChioReceipt {
        let keypair = chio_core::crypto::Keypair::generate();
        let action = chio_core::receipt::decision::ToolCallAction::from_parameters(
            serde_json::json!({"k": "v"}),
        )
        .expect("hash parameters");
        chio_core::receipt::body::ChioReceipt::sign(
            chio_core::receipt::body::ChioReceiptBody {
                id: receipt_id.to_string(),
                timestamp: 100,
                capability_id: "cap-1".to_string(),
                tool_server: "srv".to_string(),
                tool_name: "tool".to_string(),
                action,
                decision: Some(chio_core::receipt::decision::Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content-1".to_string(),
                policy_hash: "policy-1".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "financial": {"cost_charged": 250, "currency": "USD"}
                })),
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .expect("sign receipt")
    }

    #[test]
    fn drive_settles_a_due_attempt_and_status_reports_it() {
        use chio_kernel::ReceiptStore;

        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("drive.sqlite3");
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open receipts");
        let receipt = signed_money_receipt("rcpt-drive-1");
        receipts
            .append_chio_receipt(&receipt)
            .expect("append receipt");

        let retry_store = chio_store_sqlite::SqliteSettlementRetryStore::open_alongside(&receipts)
            .expect("open retry store");
        retry_store
            .upsert_attempt(&SettleAttemptRecord {
                receipt_id: receipt.id.clone(),
                finalized_at: 100,
                attempts: 1,
                next_visible_at: 0,
                last_reason: Some("rail temporarily unavailable".to_string()),
            })
            .expect("seed attempt");
        drop(receipts);

        let report = run_settlement_drive(&path, 16).expect("drive");
        assert_eq!(report.settled, 1, "the due attempt settles: {report:?}");
        assert!(
            retry_store
                .load_attempt(&receipt.id)
                .expect("load attempt")
                .is_none(),
            "the bounded envelope drains"
        );

        // The settled record is exactly what chio settle status reads.
        let status = SettleStatusReport::load(&path).expect("status");
        assert!(status
            .settled
            .iter()
            .any(|row| row.receipt_id == receipt.id));

        // Idempotent: nothing is due on a second pass.
        let again = run_settlement_drive(&path, 16).expect("second drive");
        assert_eq!(again, SettleDriveReport::default());
    }
}
