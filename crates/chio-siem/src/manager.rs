//! ExporterManager: cursor-pull loop that reads receipts from SQLite and fans out to exporters.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::params;
use tokio::sync::watch;

use chio_kernel::{ReceiptReadBoundary, ReceiptReadContext};

use crate::dlq::{DeadLetterQueue, FailedEvent};
use crate::event::SiemEvent;
use crate::exporter::{ExportError, Exporter};
use crate::ratelimit::{ExportRateLimiter, RateLimitConfig};
use crate::redaction::redact_for_operator_log;

const MAX_RETRY_BACKOFF_MS: u64 = 60_000;

/// Error variants for ExporterManager operations.
#[derive(Debug, thiserror::Error)]
pub enum SiemError {
    /// SQLite database error.
    #[error("database error: {0}")]
    DbError(String),

    /// Configuration error (invalid path, zero batch size, etc.).
    #[error("config error: {0}")]
    ConfigError(String),
}

/// Configuration for the ExporterManager cursor-pull loop.
#[derive(Debug, Clone)]
pub struct SiemConfig {
    /// Path to the Chio kernel receipt SQLite database.
    pub db_path: PathBuf,
    /// Interval between polls for new receipts. Default: 5 seconds.
    pub poll_interval: Duration,
    /// Maximum number of receipts to read per poll cycle. Default: 100.
    pub batch_size: usize,
    /// Maximum number of retry attempts per exporter before DLQ. Default: 3.
    pub max_retries: u32,
    /// Base backoff in milliseconds for exponential retry (actual: base * 2^attempt). Default: 500.
    pub base_backoff_ms: u64,
    /// Maximum capacity of the dead-letter queue. Default: 1000.
    pub dlq_capacity: usize,
    /// Optional per-exporter batch rate limit. None means unlimited.
    pub rate_limit: Option<RateLimitConfig>,
    /// Kernel public keys trusted to produce authoritative receipts.
    pub trusted_kernel_keys: BTreeSet<String>,
    /// Explicit read authority for local receipt polling. SIEM polling is an
    /// operator surface and must not run with tenant-scoped authority.
    pub read_context: ReceiptReadContext,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("receipts.sqlite3"),
            poll_interval: Duration::from_secs(5),
            batch_size: 100,
            max_retries: 3,
            base_backoff_ms: 500,
            dlq_capacity: DeadLetterQueue::DEFAULT_CAPACITY,
            rate_limit: None,
            trusted_kernel_keys: BTreeSet::new(),
            read_context: ReceiptReadContext::local_operator_admin_all(),
        }
    }
}

/// Manages the receipt cursor-pull loop and fans events out to registered exporters.
///
/// The manager reads receipts from the Chio kernel SQLite database using a
/// seq-based cursor, builds SiemEvents, and forwards batches to each registered
/// Exporter. Failed exports are retried with exponential backoff; events that
/// exhaust all retries are placed on the DeadLetterQueue.
///
/// The cursor is NOT persisted to disk. On restart, the manager re-exports all
/// receipts from seq=0. Both Splunk HEC (timestamp dedup) and Elasticsearch
/// (_id upsert) handle duplicate events idempotently.
///
/// A single read-only SQLite connection is opened at construction time and
/// reused across all poll cycles. This avoids the overhead of re-opening the
/// file on every tick and keeps WAL-mode shared-read semantics stable.
///
/// The connection is wrapped in `Mutex` so that `ExporterManager` remains
/// `Send + Sync` and can be moved into a `tokio::spawn` task. The mutex is
/// only locked during the synchronous DB read phase of each poll cycle; it is
/// always released before any `.await` point.
pub struct ExporterManager {
    exporters: Vec<Box<dyn Exporter>>,
    dlq: DeadLetterQueue,
    cursor: u64,
    config: SiemConfig,
    rate_limiter: Option<ExportRateLimiter>,
    /// Persistent read-only connection to the receipt database.
    conn: Mutex<rusqlite::Connection>,
}

impl ExporterManager {
    /// Create a new ExporterManager with the given configuration.
    ///
    /// Opens the SQLite database at `config.db_path` immediately and returns
    /// an error if the file cannot be opened.
    pub fn new(config: SiemConfig) -> Result<Self, SiemError> {
        if config.batch_size == 0 {
            return Err(SiemError::ConfigError(
                "batch_size must be greater than zero".to_string(),
            ));
        }
        if config.poll_interval.is_zero() {
            return Err(SiemError::ConfigError(
                "poll_interval must be greater than zero".to_string(),
            ));
        }
        validate_admin_read_context(&config.read_context)?;

        let rate_limiter = config
            .rate_limit
            .clone()
            .map(ExportRateLimiter::new)
            .transpose()
            .map_err(|error| {
                SiemError::ConfigError(format!("invalid rate-limit config: {error}"))
            })?;

        let conn = rusqlite::Connection::open_with_flags(
            &config.db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| SiemError::DbError(e.to_string()))?;

        let dlq = DeadLetterQueue::new(config.dlq_capacity);
        Ok(Self {
            exporters: Vec::new(),
            dlq,
            cursor: 0,
            config,
            rate_limiter,
            conn: Mutex::new(conn),
        })
    }

    /// Register an exporter to receive receipt batches.
    pub fn add_exporter(&mut self, exporter: Box<dyn Exporter>) {
        self.exporters.push(exporter);
    }

    /// Return the current number of entries in the dead-letter queue.
    pub fn dlq_len(&self) -> usize {
        self.dlq.len()
    }

    /// Run the cursor-pull loop until the cancellation channel signals true.
    ///
    /// On each tick, fetches the next batch of receipts after the current
    /// cursor using the persistent connection, builds SiemEvents, and fans
    /// them out to all registered exporters with exponential backoff retry.
    /// Events that exhaust all retries are placed on the DLQ. The cursor is
    /// advanced past the batch after all exporters have processed it (whether
    /// successful or DLQ'd).
    pub async fn run(&mut self, mut cancel: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(self.config.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.poll_once().await {
                        tracing::error!(error = %redact_for_operator_log(&e), "SIEM poll cycle failed");
                    }
                }
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        tracing::info!("SIEM ExporterManager received cancellation -- shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Execute one poll cycle: fetch a batch of receipts, fan out to exporters.
    ///
    /// Uses the persistent `self.conn` rather than opening a new connection
    /// on every tick.
    async fn poll_once(&mut self) -> Result<(), SiemError> {
        let cursor = self.cursor;
        let batch_size = self.config.batch_size;
        validate_admin_read_context(&self.config.read_context)?;

        // Lock the connection only for the synchronous DB read; release before any await.
        let rows: Vec<(u64, String)> = {
            let conn = self.conn.lock().map_err(|_| {
                SiemError::DbError("receipt db connection lock poisoned".to_string())
            })?;

            let mut stmt = conn
                .prepare(
                    "SELECT seq, raw_json \
                     FROM chio_tool_receipts \
                     WHERE seq > ?1 \
                     ORDER BY seq ASC \
                     LIMIT ?2",
                )
                .map_err(|e| SiemError::DbError(e.to_string()))?;

            let mapped = stmt
                .query_map(params![cursor as i64, batch_size as i64], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| SiemError::DbError(e.to_string()))?;

            let mut result = Vec::new();
            for row in mapped {
                let (seq, raw_json) = row.map_err(|e| SiemError::DbError(e.to_string()))?;
                result.push((seq.max(0) as u64, raw_json));
            }
            result
            // `conn` MutexGuard and `stmt` are dropped here -- lock released before any await.
        };

        if rows.is_empty() {
            return Ok(());
        }

        // Parse rows into SiemEvents.
        let mut events: Vec<SiemEvent> = Vec::with_capacity(rows.len());
        let mut max_seq = self.cursor;

        for (seq, raw_json) in &rows {
            match serde_json::from_str::<chio_core::receipt::ChioReceipt>(raw_json) {
                Ok(receipt) => {
                    events.push(SiemEvent::from_receipt_with_trusted_kernel_keys(
                        receipt,
                        Some(&self.config.trusted_kernel_keys),
                    ));
                    if *seq > max_seq {
                        max_seq = *seq;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        seq = seq,
                        error = %redact_for_operator_log(&e),
                        "Failed to deserialize receipt -- skipping"
                    );
                    // Still advance past malformed rows.
                    if *seq > max_seq {
                        max_seq = *seq;
                    }
                }
            }
        }

        if events.is_empty() {
            // Only malformed rows -- still advance cursor.
            self.cursor = max_seq;
            return Ok(());
        }

        let mut any_dlq = false;

        // Fan out to each registered exporter with retry.
        for index in 0..self.exporters.len() {
            let exporter = self.exporters[index].as_ref();
            let exporter_name = exporter.name().to_string();
            let result = Self::export_with_retry(
                &mut self.rate_limiter,
                self.config.max_retries,
                self.config.base_backoff_ms,
                exporter,
                &events,
            )
            .await;
            if let Err(e) = result {
                any_dlq = true;
                // Serialize failed events and push to DLQ.
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                for event in &events {
                    let event_json = serde_json::to_string(event).unwrap_or_else(|_| {
                        format!("{{\"serialize_error\": \"receipt {}\"}}", event.receipt.id)
                    });
                    self.dlq.push(FailedEvent {
                        event_json,
                        error: e.to_string(),
                        failed_at: now,
                        exporter_name: exporter_name.clone(),
                    });
                }

                tracing::warn!(
                    exporter = exporter_name,
                    error = %redact_for_operator_log(&e),
                    dlq_len = self.dlq.len(),
                    "All retries exhausted -- events pushed to DLQ"
                );
            }
        }

        // CRITICAL: advance cursor regardless of DLQ status so we do not re-poll the same range.
        if any_dlq {
            tracing::info!(
                seq_range_start = self.cursor,
                seq_range_end = max_seq,
                "Cursor advanced past batch containing DLQ'd events"
            );
        }
        self.cursor = max_seq;

        Ok(())
    }

    /// Call export_batch on an exporter with exponential backoff retry.
    ///
    /// Returns Ok(n) on success, or the last error after all retries are exhausted.
    async fn export_with_retry(
        rate_limiter: &mut Option<ExportRateLimiter>,
        max_retries: u32,
        base_backoff_ms: u64,
        exporter: &dyn Exporter,
        events: &[SiemEvent],
    ) -> Result<usize, ExportError> {
        let mut last_err: Option<ExportError> = None;

        for attempt in 0..=max_retries {
            if attempt > 0 {
                let backoff_ms = retry_backoff_ms(base_backoff_ms, attempt);
                tracing::debug!(
                    exporter = exporter.name(),
                    attempt = attempt,
                    backoff_ms = backoff_ms,
                    "Retrying export after backoff"
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }

            Self::wait_for_export_slot(rate_limiter, exporter.name()).await;

            match exporter.export_batch(events).await {
                Ok(n) => return Ok(n),
                Err(e) => {
                    tracing::warn!(
                        exporter = exporter.name(),
                        attempt = attempt,
                        error = %redact_for_operator_log(&e),
                        "Export attempt failed"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| ExportError::HttpError("unknown error".to_string())))
    }

    async fn wait_for_export_slot(
        rate_limiter: &mut Option<ExportRateLimiter>,
        exporter_name: &str,
    ) {
        let Some(rate_limiter) = rate_limiter.as_mut() else {
            return;
        };

        loop {
            let delay = rate_limiter.acquire_delay(exporter_name);
            if delay.is_zero() {
                return;
            }

            tracing::debug!(
                exporter = exporter_name,
                delay_ms = delay.as_millis() as u64,
                "Rate limiting exporter batch"
            );
            tokio::time::sleep(delay).await;
        }
    }
}

fn retry_backoff_ms(base_backoff_ms: u64, attempt: u32) -> u64 {
    let shift = attempt.saturating_sub(1).min(u64::BITS - 1);
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    base_backoff_ms
        .saturating_mul(multiplier)
        .min(MAX_RETRY_BACKOFF_MS)
}

fn validate_admin_read_context(read_context: &ReceiptReadContext) -> Result<(), SiemError> {
    if matches!(read_context.boundary, ReceiptReadBoundary::AdminAll) {
        Ok(())
    } else {
        Err(SiemError::ConfigError(
            "SIEM receipt polling requires explicit admin receipt read authority".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn retry_backoff_ms_saturates_at_configured_ceiling() {
        assert_eq!(retry_backoff_ms(500, 1), 500);
        assert_eq!(retry_backoff_ms(500, 2), 1_000);
        assert_eq!(retry_backoff_ms(500, 40), MAX_RETRY_BACKOFF_MS);
    }

    #[test]
    fn retry_backoff_ms_saturates_overflowing_base_delay() {
        assert_eq!(retry_backoff_ms(u64::MAX, 2), MAX_RETRY_BACKOFF_MS);
    }

    #[test]
    fn manager_new_rejects_zero_poll_interval_before_opening_db() {
        let error = match ExporterManager::new(SiemConfig {
            db_path: PathBuf::from("/definitely/not/a/chio/receipt/db.sqlite3"),
            poll_interval: Duration::ZERO,
            ..SiemConfig::default()
        }) {
            Ok(_) => panic!("zero poll interval should be rejected before opening db"),
            Err(error) => error,
        };

        assert!(
            matches!(error, SiemError::ConfigError(message) if message.contains("poll_interval"))
        );
    }

    #[test]
    fn manager_new_rejects_non_admin_read_context_before_opening_db() -> TestResult {
        let error = match ExporterManager::new(SiemConfig {
            db_path: PathBuf::from("/definitely/not/a/chio/receipt/db.sqlite3"),
            read_context: ReceiptReadContext::authenticated_tenant("tenant-a"),
            ..SiemConfig::default()
        }) {
            Ok(_) => {
                return Err(std::io::Error::other(
                    "tenant-scoped read context should be rejected before opening db",
                )
                .into());
            }
            Err(error) => error,
        };

        assert!(
            matches!(error, SiemError::ConfigError(message) if message.contains("admin receipt read authority"))
        );
        Ok(())
    }
}
