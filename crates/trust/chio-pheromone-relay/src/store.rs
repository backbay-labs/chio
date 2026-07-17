use crate::{
    canonical_sha256, count_outbox_statuses, count_rows, count_stale_leases,
    oldest_pending_queued_at, push_queue_depth_sample, recent_failure_summaries,
    relay_directory_summary, relay_queue_summary, PheromoneRelayError, RelayEventReport,
    RelayMetricSample, RelayMetricsSnapshot, RelayObservabilityInput, RelayObservabilityReport,
    RelayOperatorRecommendation, PHEROMONE_RELAY_HEALTH_REPORT_SCHEMA,
    PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA, PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA,
    PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA,
};
use chio_federation::pheromone_gossip::PheromoneGossipBatch;
use chio_pheromone_runtime::PheromoneReceiveReport;
use rusqlite::params;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

pub trait RelayNonceRecorder: Send + Sync {
    fn record_relay_nonce(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
        expires_at_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError>;
}

pub trait PheromoneRelayStore: RelayNonceRecorder {
    fn enqueue_batch(
        &self,
        sender_kernel_id: &str,
        recipient_kernel_id: &str,
        treaty_id: &str,
        batch: &PheromoneGossipBatch,
        queued_at_unix_ms: u64,
    ) -> Result<String, PheromoneRelayError>;

    fn lease_due_batches(
        &self,
        now_unix_ms: u64,
        max_batches: usize,
    ) -> Result<Vec<RelayOutboxBatch>, PheromoneRelayError>;

    fn mark_delivered(&self, outbox_id: &str) -> Result<(), PheromoneRelayError>;

    fn mark_retry(
        &self,
        outbox_id: &str,
        code: &str,
        next_attempt_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError>;

    fn mark_dead_letter(&self, outbox_id: &str, code: &str) -> Result<(), PheromoneRelayError>;
}

#[derive(Debug, Default)]
pub struct RelayNonceSet {
    inner: Mutex<BTreeSet<(String, String)>>,
}

impl RelayNonceRecorder for RelayNonceSet {
    fn record_relay_nonce(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
        _expires_at_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError> {
        let mut guard = self.inner.lock()?;
        if !guard.insert((sender_kernel_id.to_string(), nonce.to_string())) {
            return Err(PheromoneRelayError::RelayNonceReplay(nonce.to_string()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatchupRequest {
    pub schema: String,
    pub requester_kernel_id: String,
    pub responder_kernel_id: String,
    pub treaty_id: String,
    pub after_cursor: String,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatchupResponse {
    pub schema: String,
    pub accepted: bool,
    pub responder_kernel_id: String,
    pub requester_kernel_id: String,
    pub treaty_id: String,
    pub frames: Vec<PheromoneGossipBatch>,
    pub next_cursor: String,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayOutboxBatch {
    pub outbox_id: String,
    pub sender_kernel_id: String,
    pub recipient_kernel_id: String,
    pub treaty_id: String,
    pub batch: PheromoneGossipBatch,
    pub attempts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxRecordResult {
    pub inserted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxReserveResult {
    /// True when THIS caller atomically claimed the in-flight receive slot and
    /// is therefore the sole receiver; false when a concurrent caller already
    /// holds it (the loser must take the dedup path, never re-receive).
    pub won: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayTickReport {
    pub schema: String,
    pub accepted: bool,
    pub delivered: u64,
    pub retried: u64,
    pub dead_lettered: u64,
    pub duplicate_idempotent: u64,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayOperatorReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayHealthCheck {
    pub code: String,
    pub accepted: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayHealthReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub peer_directory_version: Option<u64>,
    pub queue_depth: u64,
    pub oldest_pending_age_ms: Option<u64>,
    pub retry_count: u64,
    pub dead_letter_count: u64,
    pub inbox_count: u64,
    pub cursor_count: u64,
    pub stale_lease_count: u64,
    pub checks: Vec<RelayHealthCheck>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayDeliveryReport {
    pub schema: String,
    pub accepted: bool,
    pub recipient_kernel_id: String,
    pub code: String,
    pub receive_report: Option<PheromoneReceiveReport>,
}

#[derive(Debug, Clone)]
pub struct SqlitePheromoneRelayStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqlitePheromoneRelayStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PheromoneRelayError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let store = Self {
            conn: Arc::new(Mutex::new(Connection::open(path)?)),
        };
        store.run_migrations()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, PheromoneRelayError> {
        let store = Self {
            conn: Arc::new(Mutex::new(Connection::open_in_memory()?)),
        };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_nonces (
                sender_kernel_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY(sender_kernel_id, nonce)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_outbox (
                outbox_id TEXT PRIMARY KEY,
                sender_kernel_id TEXT NOT NULL,
                recipient_kernel_id TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                queued_at_unix_ms INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                next_attempt_unix_ms INTEGER NOT NULL,
                lease_expires_unix_ms INTEGER,
                last_error_code TEXT,
                batch_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_pheromone_relay_outbox_due
                ON chio_pheromone_relay_outbox(status, next_attempt_unix_ms);

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_inbox (
                sender_kernel_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                batch_sha256 TEXT NOT NULL,
                report_json TEXT NOT NULL,
                PRIMARY KEY(sender_kernel_id, nonce)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_inbox_reservations (
                sender_kernel_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                committed INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(sender_kernel_id, nonce)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                outbox_id TEXT NOT NULL,
                code TEXT NOT NULL,
                recorded_at_unix_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_cursors (
                peer_kernel_id TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                cursor TEXT NOT NULL,
                PRIMARY KEY(peer_kernel_id, treaty_id)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_kind TEXT NOT NULL,
                accepted INTEGER NOT NULL,
                code TEXT NOT NULL,
                recorded_at_unix_ms INTEGER NOT NULL,
                report_json TEXT NOT NULL
            );
            "#,
        )?;
        ensure_outbox_queued_column(&conn)?;
        ensure_inbox_reservation_committed_column(&conn)?;
        // Reclaim ONLY provably-pre-commit reservations at open (`committed = 0`).
        //
        // A won reservation is the sole guard that makes concurrent delivery of the
        // same batch receive it exactly once. Its lifecycle is reserve -> receive
        // (self-commits the runtime deposits) -> record the durable verdict. The
        // instant of commit sits BETWEEN the reservation and the durable inbox record,
        // and the receiver marks the reservation `committed = 1` at that instant, so at
        // open a row's `committed` flag distinguishes the two crash residuals:
        //
        // - `committed = 0`: the prior process crashed (or was cancelled) BEFORE the
        //   receive committed anything, so nothing was admitted. Clearing it lets a
        //   redelivery re-claim and re-receive; leaving it would permanently wedge that
        //   `(sender, nonce)` (every retry loses the stale reservation and never
        //   receives). These are safe and correct to clear.
        // - `committed = 1`: the prior process crashed AFTER the receive committed the
        //   deposits but BEFORE `record_inbox` wrote the durable verdict. Re-receiving
        //   would re-enter the runtime replay window and reject its already-accepted
        //   deposits (a spurious "rejected" verdict for a batch that was in fact
        //   admitted). We MUST NOT clear it: the row survives so a redelivery loses the
        //   reservation and takes the fail-closed loser path (it never re-runs the
        //   receiver; the peer retry fail-closes pending operational verdict recovery).
        //
        // This assumes the shipped single-writer ownership the outbox lease model
        // already relies on.
        conn.execute(
            "DELETE FROM chio_pheromone_relay_inbox_reservations WHERE committed = 0",
            [],
        )?;
        Ok(())
    }

    pub fn enqueue_batch(
        &self,
        sender_kernel_id: &str,
        recipient_kernel_id: &str,
        treaty_id: &str,
        batch: &PheromoneGossipBatch,
        queued_at_unix_ms: u64,
    ) -> Result<String, PheromoneRelayError> {
        let outbox_id = canonical_sha256(&serde_json::json!({
            "sender": sender_kernel_id,
            "recipient": recipient_kernel_id,
            "treaty": treaty_id,
            "batch": batch,
            "queuedAtUnixMs": queued_at_unix_ms
        }))?;
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            INSERT INTO chio_pheromone_relay_outbox
                (outbox_id, sender_kernel_id, recipient_kernel_id, treaty_id,
                 queued_at_unix_ms, status, attempts, next_attempt_unix_ms,
                 lease_expires_unix_ms, last_error_code, batch_json)
            VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?5, NULL, NULL, ?6)
            ON CONFLICT(outbox_id) DO NOTHING
            "#,
            params![
                outbox_id,
                sender_kernel_id,
                recipient_kernel_id,
                treaty_id,
                i64_from_u64(queued_at_unix_ms, "queued_at_unix_ms")?,
                serde_json::to_string(batch)?,
            ],
        )?;
        Ok(outbox_id)
    }

    pub fn lease_due_batches(
        &self,
        now_unix_ms: u64,
        max_batches: usize,
    ) -> Result<Vec<RelayOutboxBatch>, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            UPDATE chio_pheromone_relay_outbox
            SET status = 'retry',
                lease_expires_unix_ms = NULL,
                last_error_code = 'stale_lease_recovered'
            WHERE status = 'leased' AND lease_expires_unix_ms <= ?1
            "#,
            params![i64_from_u64(now_unix_ms, "now_unix_ms")?],
        )?;
        let mut stmt = conn.prepare(
            r#"
            SELECT outbox_id, sender_kernel_id, recipient_kernel_id, treaty_id, attempts, batch_json
            FROM chio_pheromone_relay_outbox
            WHERE status IN ('pending', 'retry') AND next_attempt_unix_ms <= ?1
            ORDER BY next_attempt_unix_ms, outbox_id
            LIMIT ?2
            "#,
        )?;
        let rows = stmt.query_map(
            params![
                i64_from_u64(now_unix_ms, "now_unix_ms")?,
                i64::try_from(max_batches).map_err(|_| PheromoneRelayError::Sqlite(
                    "max_batches too large".to_string()
                ))?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )?;
        let mut leased = Vec::new();
        for row in rows {
            let (outbox_id, sender_kernel_id, recipient_kernel_id, treaty_id, attempts, batch_json) =
                row?;
            leased.push(RelayOutboxBatch {
                outbox_id,
                sender_kernel_id,
                recipient_kernel_id,
                treaty_id,
                attempts: u64::try_from(attempts).map_err(|_| {
                    PheromoneRelayError::Sqlite("attempt count is negative".to_string())
                })?,
                batch: serde_json::from_str(&batch_json)?,
            });
        }
        drop(stmt);
        let lease_expires = now_unix_ms.saturating_add(30_000);
        for batch in &leased {
            conn.execute(
                r#"
                UPDATE chio_pheromone_relay_outbox
                SET status = 'leased', lease_expires_unix_ms = ?2
                WHERE outbox_id = ?1
                "#,
                params![
                    batch.outbox_id,
                    i64_from_u64(lease_expires, "lease_expires_unix_ms")?
                ],
            )?;
        }
        Ok(leased)
    }

    pub fn mark_delivered(&self, outbox_id: &str) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            "UPDATE chio_pheromone_relay_outbox SET status = 'delivered' WHERE outbox_id = ?1",
            params![outbox_id],
        )?;
        Ok(())
    }

    pub fn mark_retry(
        &self,
        outbox_id: &str,
        code: &str,
        next_attempt_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            UPDATE chio_pheromone_relay_outbox
            SET status = 'retry',
                attempts = attempts + 1,
                next_attempt_unix_ms = ?2,
                lease_expires_unix_ms = NULL,
                last_error_code = ?3
            WHERE outbox_id = ?1
            "#,
            params![
                outbox_id,
                i64_from_u64(next_attempt_unix_ms, "next_attempt_unix_ms")?,
                code,
            ],
        )?;
        conn.execute(
            r#"
            INSERT INTO chio_pheromone_relay_attempts
                (outbox_id, code, recorded_at_unix_ms)
            VALUES (?1, ?2, ?3)
            "#,
            params![
                outbox_id,
                code,
                i64_from_u64(next_attempt_unix_ms, "recorded_at_unix_ms")?,
            ],
        )?;
        Ok(())
    }

    pub fn mark_dead_letter(&self, outbox_id: &str, code: &str) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            UPDATE chio_pheromone_relay_outbox
            SET status = 'dead_letter', last_error_code = ?2
            WHERE outbox_id = ?1
            "#,
            params![outbox_id, code],
        )?;
        Ok(())
    }

    pub fn catchup_batches(
        &self,
        recipient_kernel_id: &str,
        treaty_id: &str,
        after_cursor: &str,
        limit: usize,
        max_bytes: usize,
    ) -> Result<(Vec<PheromoneGossipBatch>, String), PheromoneRelayError> {
        if limit == 0 {
            return Err(PheromoneRelayError::CatchupDenied(
                "catch-up limit must be positive".to_string(),
            ));
        }
        let after_rowid = parse_cursor(after_cursor)?;
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT rowid, batch_json
            FROM chio_pheromone_relay_outbox
            WHERE recipient_kernel_id = ?1 AND treaty_id = ?2 AND rowid > ?3
            ORDER BY rowid
            LIMIT ?4
            "#,
        )?;
        let rows = stmt.query_map(
            params![
                recipient_kernel_id,
                treaty_id,
                i64_from_u64(after_rowid, "after_cursor")?,
                i64::try_from(limit).map_err(|_| PheromoneRelayError::CatchupDenied(
                    "catch-up limit is too large".to_string()
                ))?
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut frames = Vec::new();
        let mut bytes = 0usize;
        let mut served_frame_count = 0usize;
        let mut next_cursor = after_rowid;
        for row in rows {
            let (rowid, batch_json) = row?;
            let batch_bytes = batch_json.len();
            if bytes.saturating_add(batch_bytes) > max_bytes {
                if frames.is_empty() {
                    return Err(PheromoneRelayError::CatchupDenied(
                        "catch-up byte limit exceeded before first frame".to_string(),
                    ));
                }
                break;
            }
            let batch: PheromoneGossipBatch = serde_json::from_str(&batch_json)?;
            let batch_frame_count = batch.frames.len();
            if served_frame_count.saturating_add(batch_frame_count) > limit {
                if frames.is_empty() {
                    return Err(PheromoneRelayError::CatchupDenied(
                        "catch-up frame limit exceeded before first batch".to_string(),
                    ));
                }
                break;
            }
            frames.push(batch);
            bytes = bytes.saturating_add(batch_bytes);
            served_frame_count = served_frame_count.saturating_add(batch_frame_count);
            next_cursor = u64::try_from(rowid)
                .map_err(|_| PheromoneRelayError::Sqlite("negative cursor rowid".to_string()))?;
        }
        Ok((frames, next_cursor.to_string()))
    }

    pub fn operator_report(
        &self,
        local_kernel_id: &str,
        generated_at_unix_ms: u64,
    ) -> Result<RelayOperatorReport, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let pending: i64 = conn.query_row(
            "SELECT COUNT(*) FROM chio_pheromone_relay_outbox WHERE status IN ('pending', 'retry', 'leased')",
            [],
            |row| row.get(0),
        )?;
        let delivered: i64 = conn.query_row(
            "SELECT COUNT(*) FROM chio_pheromone_relay_outbox WHERE status = 'delivered'",
            [],
            |row| row.get(0),
        )?;
        let inbox: i64 = conn.query_row(
            "SELECT COUNT(*) FROM chio_pheromone_relay_inbox",
            [],
            |row| row.get(0),
        )?;
        Ok(RelayOperatorReport {
            schema: PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA.to_string(),
            accepted: true,
            code: "accepted".to_string(),
            detail: format!("pending={pending}; delivered={delivered}; inbox={inbox}"),
            local_kernel_id: local_kernel_id.to_string(),
            generated_at_unix_ms,
        })
    }

    pub fn health_report(
        &self,
        local_kernel_id: &str,
        generated_at_unix_ms: u64,
        peer_directory_version: Option<u64>,
    ) -> Result<RelayHealthReport, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let queue_depth = count_outbox_statuses(&conn, &["pending", "retry", "leased"])?;
        let retry_count = count_outbox_statuses(&conn, &["retry"])?;
        let dead_letter_count = count_outbox_statuses(&conn, &["dead_letter"])?;
        let inbox_count = count_rows(&conn, "chio_pheromone_relay_inbox")?;
        let cursor_count = count_rows(&conn, "chio_pheromone_relay_cursors")?;
        let stale_lease_count = count_stale_leases(&conn, generated_at_unix_ms)?;
        let oldest_pending = oldest_pending_queued_at(&conn)?;
        let oldest_pending_age_ms =
            oldest_pending.map(|queued| generated_at_unix_ms.saturating_sub(queued));
        let mut checks = Vec::new();
        checks.push(RelayHealthCheck {
            code: "store.connected".to_string(),
            accepted: true,
            detail: "SQLite relay store is reachable".to_string(),
        });
        checks.push(RelayHealthCheck {
            code: "outbox.pressure".to_string(),
            accepted: queue_depth < 10_000,
            detail: format!("queue_depth={queue_depth}"),
        });
        checks.push(RelayHealthCheck {
            code: "leases.fresh".to_string(),
            accepted: stale_lease_count == 0,
            detail: format!("stale_lease_count={stale_lease_count}"),
        });
        let accepted = checks.iter().all(|check| check.accepted);
        Ok(RelayHealthReport {
            schema: PHEROMONE_RELAY_HEALTH_REPORT_SCHEMA.to_string(),
            accepted,
            code: if accepted { "accepted" } else { "degraded" }.to_string(),
            detail: "relay health evaluated from durable store state".to_string(),
            local_kernel_id: local_kernel_id.to_string(),
            generated_at_unix_ms,
            peer_directory_version,
            queue_depth,
            oldest_pending_age_ms,
            retry_count,
            dead_letter_count,
            inbox_count,
            cursor_count,
            stale_lease_count,
            checks,
        })
    }

    pub fn relay_observability_report(
        &self,
        input: RelayObservabilityInput<'_>,
    ) -> Result<RelayObservabilityReport, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let queue = relay_queue_summary(&conn, input.generated_at_unix_ms)?;
        let directory = relay_directory_summary(
            input.peer_directory,
            input.peer_directory_state,
            input.profile,
        );
        let recent_failures = recent_failure_summaries(&conn, input.recent_failure_limit)?;
        let mut recommendations = Vec::new();
        if directory.expires_at_unix_ms.is_none() {
            recommendations.push(RelayOperatorRecommendation {
                code: "directory_unknown".to_string(),
                severity: "warning".to_string(),
            });
        }
        if directory
            .expires_at_unix_ms
            .is_some_and(|expires| expires <= input.generated_at_unix_ms.saturating_add(300_000))
        {
            recommendations.push(RelayOperatorRecommendation {
                code: "directory_expiring".to_string(),
                severity: "warning".to_string(),
            });
        }
        if queue.dead_letter > 0 {
            recommendations.push(RelayOperatorRecommendation {
                code: "dead_letters_present".to_string(),
                severity: "warning".to_string(),
            });
        }
        if queue.stale_lease_count > 0 {
            recommendations.push(RelayOperatorRecommendation {
                code: "stale_leases_present".to_string(),
                severity: "warning".to_string(),
            });
        }
        if queue.retry > 0 {
            recommendations.push(RelayOperatorRecommendation {
                code: "retries_pending".to_string(),
                severity: "info".to_string(),
            });
        }
        let accepted = recommendations.is_empty();
        Ok(RelayObservabilityReport {
            schema: PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA.to_string(),
            accepted,
            code: if accepted { "accepted" } else { "degraded" }.to_string(),
            local_kernel_id: input.local_kernel_id.to_string(),
            generated_at_unix_ms: input.generated_at_unix_ms,
            directory,
            queue,
            recent_failures,
            recommendations,
        })
    }

    pub fn relay_metrics_snapshot(
        &self,
        local_kernel_id: &str,
        generated_at_unix_ms: u64,
    ) -> Result<RelayMetricsSnapshot, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let queue = relay_queue_summary(&conn, generated_at_unix_ms)?;
        let failures = recent_failure_summaries(&conn, 32)?;
        let mut samples = Vec::new();
        push_queue_depth_sample(&mut samples, "pending", queue.pending);
        push_queue_depth_sample(&mut samples, "retry", queue.retry);
        push_queue_depth_sample(&mut samples, "leased", queue.leased);
        push_queue_depth_sample(&mut samples, "delivered", queue.delivered);
        push_queue_depth_sample(&mut samples, "dead_letter", queue.dead_letter);
        samples.push(RelayMetricSample {
            name: "chio_pheromone_relay_oldest_pending_age_seconds".to_string(),
            value: queue.oldest_pending_age_ms.unwrap_or(0) as f64 / 1_000.0,
            labels: BTreeMap::new(),
        });
        samples.push(RelayMetricSample {
            name: "chio_pheromone_relay_stale_leases".to_string(),
            value: queue.stale_lease_count as f64,
            labels: BTreeMap::new(),
        });
        let mut dead_letter_labels = BTreeMap::new();
        dead_letter_labels.insert("reason".to_string(), "observed".to_string());
        samples.push(RelayMetricSample {
            name: "chio_pheromone_relay_dead_letters_total".to_string(),
            value: queue.dead_letter as f64,
            labels: dead_letter_labels,
        });
        for failure in failures {
            let mut labels = BTreeMap::new();
            labels.insert("reason".to_string(), failure.code);
            samples.push(RelayMetricSample {
                name: "chio_pheromone_relay_rejections_total".to_string(),
                value: failure.count as f64,
                labels,
            });
        }
        Ok(RelayMetricsSnapshot {
            schema: PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA.to_string(),
            local_kernel_id: local_kernel_id.to_string(),
            generated_at_unix_ms,
            samples,
        })
    }

    pub fn record_event_report(
        &self,
        report: &RelayEventReport,
    ) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            INSERT INTO chio_pheromone_relay_events
                (event_kind, accepted, code, recorded_at_unix_ms, report_json)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                &report.event_kind,
                if report.accepted { 1 } else { 0 },
                &report.code,
                i64_from_u64(report.generated_at_unix_ms, "recorded_at_unix_ms")?,
                serde_json::to_string(report)?,
            ],
        )?;
        Ok(())
    }

    /// Atomically claim the in-flight receive slot for `(sender_kernel_id, nonce)`.
    ///
    /// Returns `won = true` for the SINGLE caller that inserts the reservation and
    /// `won = false` for every concurrent caller that finds it already held. This
    /// closes the dedup race that a bare [`lookup_inbox_report`] -> receive ->
    /// [`record_inbox`] sequence leaves open: two connections delivering the SAME
    /// batch both read `None` and both re-run the receiver, double-mutating the
    /// runtime replay window. The winner is the sole receiver: it MUST run the
    /// receiver exactly once and then [`record_inbox`] the durable verdict, and on
    /// ANY failure MUST [`release_inbox_slot`] so a later redelivery can re-claim.
    /// A loser MUST NOT run the receiver; it reads the winner's durable
    /// [`lookup_inbox_report`] instead.
    ///
    /// [`record_inbox`]: Self::record_inbox
    /// [`release_inbox_slot`]: Self::release_inbox_slot
    /// [`lookup_inbox_report`]: Self::lookup_inbox_report
    pub fn reserve_inbox_slot(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
    ) -> Result<InboxReserveResult, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let inserted = conn.execute(
            r#"
            INSERT INTO chio_pheromone_relay_inbox_reservations
                (sender_kernel_id, nonce)
            VALUES (?1, ?2)
            ON CONFLICT(sender_kernel_id, nonce) DO NOTHING
            "#,
            params![sender_kernel_id, nonce],
        )?;
        Ok(InboxReserveResult { won: inserted > 0 })
    }

    /// Durably mark a won reservation as `committed` at the instant its receive has
    /// self-committed the runtime deposits (BEFORE [`record_inbox`] writes the verdict).
    ///
    /// This is the crash-recovery guard: a process that crashes in the
    /// committed-but-unrecorded window leaves a `committed = 1` reservation that
    /// SURVIVES the clear-at-open reclaim, so a redelivery loses the reservation and
    /// takes the fail-closed loser path instead of re-receiving an already-admitted
    /// batch (which would spuriously reject its already-accepted deposits). Idempotent:
    /// re-marking an already-committed slot is a no-op. Marking a slot that no longer
    /// exists (already released) affects no rows, which is harmless.
    ///
    /// [`record_inbox`]: Self::record_inbox
    pub fn mark_inbox_reservation_committed(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
    ) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            UPDATE chio_pheromone_relay_inbox_reservations
            SET committed = 1
            WHERE sender_kernel_id = ?1 AND nonce = ?2
            "#,
            params![sender_kernel_id, nonce],
        )?;
        Ok(())
    }

    /// Release the in-flight receive slot claimed by [`reserve_inbox_slot`].
    ///
    /// Idempotent: releasing an unheld slot is a no-op. A winner whose receive
    /// FAILED (committed nothing) releases so a redelivery can re-claim and
    /// re-receive. A winner whose receive COMMITTED but whose verdict FAILED to
    /// record must NOT release: re-receiving an admitted batch would reject its
    /// already-accepted deposits, so the slot stays held (fail-closed) and a
    /// redelivery takes the loser path. On a RECORDED success the caller releases
    /// the now-redundant reservation to bound table growth; the durable inbox
    /// record already short-circuits redelivery (via [`lookup_inbox_report`]) before
    /// it reaches the reservation, so a leftover row would also be harmless.
    ///
    /// [`reserve_inbox_slot`]: Self::reserve_inbox_slot
    /// [`lookup_inbox_report`]: Self::lookup_inbox_report
    pub fn release_inbox_slot(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
    ) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            DELETE FROM chio_pheromone_relay_inbox_reservations
            WHERE sender_kernel_id = ?1 AND nonce = ?2
            "#,
            params![sender_kernel_id, nonce],
        )?;
        Ok(())
    }

    pub fn record_inbox(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
        batch: &PheromoneGossipBatch,
        report: &PheromoneReceiveReport,
    ) -> Result<InboxRecordResult, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let inserted = conn.execute(
            r#"
            INSERT INTO chio_pheromone_relay_inbox
                (sender_kernel_id, nonce, batch_sha256, report_json)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(sender_kernel_id, nonce) DO NOTHING
            "#,
            params![
                sender_kernel_id,
                nonce,
                canonical_sha256(batch)?,
                serde_json::to_string(report)?,
            ],
        )?;
        Ok(InboxRecordResult {
            inserted: inserted > 0,
        })
    }

    /// Return the previously recorded inbox report for `(sender_kernel_id, nonce)`,
    /// or `None` if this batch has not been admitted yet.
    ///
    /// This is the read half of the idempotent inbox that [`record_inbox`] writes.
    /// A store-and-forward receiver consults it BEFORE re-running the receiver on a
    /// redelivery: an already-admitted batch returns its original verdict verbatim
    /// instead of re-entering the runtime replay window (which would otherwise
    /// reject the already-accepted deposits and fail a batch the peer already has).
    ///
    /// [`record_inbox`]: Self::record_inbox
    pub fn lookup_inbox_report(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
    ) -> Result<Option<PheromoneReceiveReport>, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let report_json: Option<String> = conn
            .query_row(
                r#"
                SELECT report_json
                FROM chio_pheromone_relay_inbox
                WHERE sender_kernel_id = ?1 AND nonce = ?2
                "#,
                params![sender_kernel_id, nonce],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match report_json {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }
}

impl PheromoneRelayStore for SqlitePheromoneRelayStore {
    fn enqueue_batch(
        &self,
        sender_kernel_id: &str,
        recipient_kernel_id: &str,
        treaty_id: &str,
        batch: &PheromoneGossipBatch,
        queued_at_unix_ms: u64,
    ) -> Result<String, PheromoneRelayError> {
        Self::enqueue_batch(
            self,
            sender_kernel_id,
            recipient_kernel_id,
            treaty_id,
            batch,
            queued_at_unix_ms,
        )
    }

    fn lease_due_batches(
        &self,
        now_unix_ms: u64,
        max_batches: usize,
    ) -> Result<Vec<RelayOutboxBatch>, PheromoneRelayError> {
        Self::lease_due_batches(self, now_unix_ms, max_batches)
    }

    fn mark_delivered(&self, outbox_id: &str) -> Result<(), PheromoneRelayError> {
        Self::mark_delivered(self, outbox_id)
    }

    fn mark_retry(
        &self,
        outbox_id: &str,
        code: &str,
        next_attempt_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError> {
        Self::mark_retry(self, outbox_id, code, next_attempt_unix_ms)
    }

    fn mark_dead_letter(&self, outbox_id: &str, code: &str) -> Result<(), PheromoneRelayError> {
        Self::mark_dead_letter(self, outbox_id, code)
    }
}

impl RelayNonceRecorder for SqlitePheromoneRelayStore {
    fn record_relay_nonce(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
        expires_at_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let inserted = conn.execute(
            r#"
            INSERT INTO chio_pheromone_relay_nonces
                (sender_kernel_id, nonce, expires_at_unix_ms)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(sender_kernel_id, nonce) DO NOTHING
            "#,
            params![
                sender_kernel_id,
                nonce,
                i64_from_u64(expires_at_unix_ms, "expires_at_unix_ms")?
            ],
        )?;
        if inserted == 0 {
            return Err(PheromoneRelayError::RelayNonceReplay(nonce.to_string()));
        }
        Ok(())
    }
}

pub(crate) fn i64_from_u64(value: u64, field: &str) -> Result<i64, PheromoneRelayError> {
    i64::try_from(value)
        .map_err(|_| PheromoneRelayError::Sqlite(format!("{field} does not fit signed integer")))
}

pub(crate) fn parse_cursor(cursor: &str) -> Result<u64, PheromoneRelayError> {
    if cursor.trim().is_empty() {
        return Ok(0);
    }
    cursor
        .parse::<u64>()
        .map_err(|_| PheromoneRelayError::CatchupDenied("catch-up cursor is invalid".to_string()))
}

pub(crate) fn ensure_outbox_queued_column(conn: &Connection) -> Result<(), PheromoneRelayError> {
    let mut stmt = conn.prepare("PRAGMA table_info(chio_pheromone_relay_outbox)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for column in columns {
        if column? == "queued_at_unix_ms" {
            return Ok(());
        }
    }
    conn.execute(
        "ALTER TABLE chio_pheromone_relay_outbox ADD COLUMN queued_at_unix_ms INTEGER NOT NULL DEFAULT 0",
        [],
    )?;
    Ok(())
}

/// Additive migration for the reservation `committed` marker (crash-recovery guard).
///
/// A store created before this column existed has reservations with no commit marker.
/// Backfilling them to `committed = 0` (the ADD COLUMN default) is the fail-closed
/// choice: a pre-existing reservation predates the commit-marker protocol, so its
/// receive either never committed or was recorded long ago, and clearing it at open
/// (as before) is correct. New reservations set the marker explicitly at commit time.
pub(crate) fn ensure_inbox_reservation_committed_column(
    conn: &Connection,
) -> Result<(), PheromoneRelayError> {
    let mut stmt = conn.prepare("PRAGMA table_info(chio_pheromone_relay_inbox_reservations)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for column in columns {
        if column? == "committed" {
            return Ok(());
        }
    }
    conn.execute(
        "ALTER TABLE chio_pheromone_relay_inbox_reservations ADD COLUMN committed INTEGER NOT NULL DEFAULT 0",
        [],
    )?;
    Ok(())
}

#[cfg(test)]
mod inbox_lookup_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA;
    use chio_pheromone_runtime::PheromoneBatchOutcome;

    fn sample_batch() -> PheromoneGossipBatch {
        PheromoneGossipBatch {
            schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
            recipient_kernel_id: "did:chio:recipient".to_string(),
            treaty_id: "treaty:inbox-lookup".to_string(),
            frames: Vec::new(),
            flushed_at_unix_ms: 4_000_000,
        }
    }

    fn sample_report() -> PheromoneReceiveReport {
        PheromoneReceiveReport {
            schema: "chio.pheromone-receive-report.v1".to_string(),
            accepted: true,
            batch_outcome: PheromoneBatchOutcome::Accepted,
            accepted_frame_count: 0,
            rejected_frame_count: 0,
            batch_sha256: "a".repeat(64),
            recipient_kernel_id: "did:chio:recipient".to_string(),
            authenticated_sender_kernel_id: "did:chio:sender".to_string(),
            received_at_unix_ms: 4_000_000,
            frames: Vec::new(),
        }
    }

    #[test]
    fn lookup_inbox_report_returns_stored_report_and_keys_by_sender_nonce() {
        let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
        let batch = sample_batch();
        let report = sample_report();

        // Absent before any record: fail-closed None (the caller then receives).
        assert!(store
            .lookup_inbox_report("did:chio:sender", "nonce-1")
            .unwrap()
            .is_none());

        let first = store
            .record_inbox("did:chio:sender", "nonce-1", &batch, &report)
            .unwrap();
        assert!(first.inserted, "first admission inserts the inbox row");

        // After record: the exact stored verdict is returned WITHOUT re-running the
        // receiver (this is the dedup-before-receive primitive).
        let stored = store
            .lookup_inbox_report("did:chio:sender", "nonce-1")
            .unwrap()
            .expect("recorded inbox report is looked up");
        assert_eq!(stored, report);

        // A different sender for the same nonce is a distinct (absent) row.
        assert!(store
            .lookup_inbox_report("did:chio:other", "nonce-1")
            .unwrap()
            .is_none());
    }

    #[test]
    fn reserve_inbox_slot_is_won_by_exactly_one_concurrent_caller() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;
        use std::sync::Arc;
        use std::sync::Barrier;

        const THREADS: usize = 8;
        let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
        let wins = Arc::new(AtomicUsize::new(0));
        // Release every thread into the reserve at once to actually contend.
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let store = store.clone();
            let wins = wins.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                if store
                    .reserve_inbox_slot("did:chio:sender", "nonce-race")
                    .unwrap()
                    .won
                {
                    wins.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(
            wins.load(Ordering::SeqCst),
            1,
            "exactly one concurrent caller may win the receive slot"
        );
    }

    #[test]
    fn release_inbox_slot_frees_the_slot_for_re_reservation() {
        let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
        assert!(
            store.reserve_inbox_slot("s", "n").unwrap().won,
            "the first reserve wins the free slot"
        );
        assert!(
            !store.reserve_inbox_slot("s", "n").unwrap().won,
            "a held slot cannot be re-won"
        );
        store.release_inbox_slot("s", "n").unwrap();
        assert!(
            store.reserve_inbox_slot("s", "n").unwrap().won,
            "after release the slot can be re-won (a failed winner lets a retry re-receive)"
        );
        // Release is idempotent: releasing an unheld slot is a no-op.
        store.release_inbox_slot("s", "n").unwrap();
        store.release_inbox_slot("s", "n").unwrap();
    }

    #[test]
    fn clear_at_open_preserves_committed_reservations_but_reclaims_pre_commit() {
        // Crash-recovery residual: the store's clear-at-open must NOT
        // wipe a reservation whose batch already committed its runtime deposits but
        // whose durable verdict was not yet recorded, or a redelivery would re-win the
        // slot and RE-RECEIVE an already-admitted batch (the runtime replay window then
        // wrongly rejects it, a spurious verdict). A provably-pre-commit reservation
        // (committed = 0) IS still reclaimed, so a crash between reserve and commit
        // never permanently wedges redelivery.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.sqlite3");

        {
            // Model a prior process. One reservation crashed AFTER commit but BEFORE
            // record (reserve + mark committed, no durable verdict); another is a plain
            // pre-commit leftover (reserve only). The process then crashes: the store is
            // dropped with no inbox verdict recorded for either.
            let store = SqlitePheromoneRelayStore::open(&path).unwrap();
            assert!(store.reserve_inbox_slot("s", "committed").unwrap().won);
            store
                .mark_inbox_reservation_committed("s", "committed")
                .unwrap();
            assert!(store.reserve_inbox_slot("s", "pre-commit").unwrap().won);
        }

        // Restart: re-opening the SAME file runs clear-at-open.
        let restarted = SqlitePheromoneRelayStore::open(&path).unwrap();

        // The committed-but-unrecorded reservation SURVIVES: a redelivery loses the
        // slot and takes the fail-closed loser path, NEVER re-receiving the admitted
        // batch.
        assert!(
            !restarted.reserve_inbox_slot("s", "committed").unwrap().won,
            "a committed-but-unrecorded reservation must survive restart (never re-receive)"
        );
        assert!(
            restarted
                .lookup_inbox_report("s", "committed")
                .unwrap()
                .is_none(),
            "no durable verdict was recorded; the loser fails closed pending recovery"
        );

        // The provably-pre-commit reservation is reclaimed: nothing committed, so a
        // redelivery may re-win and re-receive (no permanent wedge).
        assert!(
            restarted.reserve_inbox_slot("s", "pre-commit").unwrap().won,
            "a pre-commit reservation must be reclaimed at open so redelivery can re-receive"
        );
    }

    #[test]
    fn concurrent_same_batch_receives_exactly_once() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;
        use std::sync::Arc;
        use std::sync::Barrier;

        const THREADS: usize = 8;
        let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
        let batch = sample_batch();
        let report = sample_report();
        // The replay-mutating receive is modelled by this counter; the whole point
        // of the reservation is that it increments EXACTLY once.
        let receives = Arc::new(AtomicUsize::new(0));
        let dedup_hits = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let store = store.clone();
            let batch = batch.clone();
            let report = report.clone();
            let receives = receives.clone();
            let dedup_hits = dedup_hits.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                // Mirror PheromoneBatchHandler::handle's dedup path exactly.
                if store
                    .lookup_inbox_report("did:chio:sender", "nonce-race")
                    .unwrap()
                    .is_some()
                {
                    dedup_hits.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                if store
                    .reserve_inbox_slot("did:chio:sender", "nonce-race")
                    .unwrap()
                    .won
                {
                    // Sole receiver: the replay-mutating step runs here, once.
                    receives.fetch_add(1, Ordering::SeqCst);
                    store
                        .record_inbox("did:chio:sender", "nonce-race", &batch, &report)
                        .unwrap();
                } else {
                    // Loser: never receives; waits, bounded, for the winner's verdict.
                    let mut seen = false;
                    for _ in 0..500 {
                        if store
                            .lookup_inbox_report("did:chio:sender", "nonce-race")
                            .unwrap()
                            .is_some()
                        {
                            seen = true;
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    assert!(seen, "the loser observes the winner's recorded verdict");
                    dedup_hits.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(
            receives.load(Ordering::SeqCst),
            1,
            "the replay-mutating receive runs exactly once across concurrent same-batch deliveries"
        );
        assert_eq!(
            dedup_hits.load(Ordering::SeqCst),
            THREADS - 1,
            "every other concurrent delivery takes the dedup path, never re-receiving"
        );
        assert_eq!(
            store
                .lookup_inbox_report("did:chio:sender", "nonce-race")
                .unwrap()
                .expect("the durable verdict is recorded exactly once"),
            report
        );
    }
}
