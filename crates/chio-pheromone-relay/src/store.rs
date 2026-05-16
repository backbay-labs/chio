use crate::{
    canonical_sha256, count_outbox_statuses, count_rows, count_stale_leases,
    oldest_pending_queued_at, push_queue_depth_sample, recent_failure_summaries,
    relay_directory_summary, relay_queue_summary, PheromoneRelayError, RelayEventReport,
    RelayMetricSample, RelayMetricsSnapshot, RelayObservabilityInput, RelayObservabilityReport,
    RelayOperatorRecommendation, PHEROMONE_RELAY_HEALTH_REPORT_SCHEMA,
    PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA, PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA,
    PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA,
};
use chio_federation::PheromoneGossipBatch;
use chio_pheromone_runtime::PheromoneReceiveReport;
use rusqlite::params;
use rusqlite::Connection;
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
            frames.push(serde_json::from_str(&batch_json)?);
            bytes = bytes.saturating_add(batch_bytes);
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
