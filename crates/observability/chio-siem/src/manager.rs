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
    /// Optional path to the SIEM-owned RW cursor store (per-exporter high-water
    /// mark). When set, delivery is at-least-once: the read cursor resumes at
    /// min(acked_seq) so a failed exporter forces bounded redelivery instead of
    /// a silent skip. None keeps the legacy advance-regardless behavior. Distinct
    /// from the read-only receipt DB.
    pub cursor_db_path: Option<PathBuf>,
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
            cursor_db_path: None,
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
/// When `SiemConfig::cursor_db_path` is None the read cursor is NOT persisted:
/// on restart the manager re-exports all receipts from seq=0 (both Splunk HEC
/// timestamp dedup and Elasticsearch _id upsert handle duplicates idempotently).
/// When set, a per-exporter high-water mark is persisted and the cursor resumes
/// at min(acked_seq) for at-least-once delivery.
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
    // The poll loop emits export/lag/dlq metrics through this sink. Defaults to
    // no-op so chio-siem stays decoupled from the metric registry; the host
    // installs a registry-backed sink.
    metrics: std::sync::Arc<dyn crate::metrics_sink::SiemMetricsSink>,
    /// SIEM-owned RW high-water-mark store. None keeps the legacy
    /// advance-regardless behavior.
    cursor_store: Option<crate::cursor_store::SiemCursorStore>,
    /// In-memory per-exporter high-water mark, seeded from the store at open and
    /// advanced only on confirmed acceptance.
    acked: std::collections::BTreeMap<String, u64>,
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
        // Open the SIEM-owned cursor store when configured and resume the read
        // cursor at the slowest exporter's high-water mark.
        let cursor_store = match &config.cursor_db_path {
            Some(path) => Some(crate::cursor_store::SiemCursorStore::open(path)?),
            None => None,
        };
        let acked = match &cursor_store {
            Some(store) => store.acked_seqs()?,
            None => std::collections::BTreeMap::new(),
        };
        let cursor = acked.values().copied().min().unwrap_or(0);
        Ok(Self {
            exporters: Vec::new(),
            dlq,
            cursor,
            config,
            rate_limiter,
            conn: Mutex::new(conn),
            metrics: crate::metrics_sink::noop_metrics_sink(),
            cursor_store,
            acked,
        })
    }

    /// Attach a metrics sink. Defaults to no-op so headless callers
    /// are unchanged.
    #[must_use]
    pub fn with_metrics_sink(
        mut self,
        sink: std::sync::Arc<dyn crate::metrics_sink::SiemMetricsSink>,
    ) -> Self {
        self.metrics = sink;
        self
    }

    /// Register an exporter to receive receipt batches.
    ///
    /// With a configured cursor store, a registered exporter that has no
    /// persisted high-water mark row is seeded at BASELINE (0): it must receive
    /// every receipt persisted before it was registered, so it pins the resume
    /// cursor at 0 until its first ack rather than inheriting an already-advanced
    /// cursor from a faster peer and silently skipping the backlog. The read
    /// cursor is then recomputed as the
    /// minimum high-water mark across the known exporter set. In legacy None mode
    /// the cursor is not persisted and always advances past the batch, so no
    /// baseline pin is applied here.
    pub fn add_exporter(&mut self, exporter: Box<dyn Exporter>) {
        if self.cursor_store.is_some() {
            // Key by the exporter's STABLE, config-derived identity, not
            // registration index, so inserting or reordering a same-named
            // exporter cannot let a new instance inherit a previous instance's
            // high-water mark and skip receipts. A brand-new identity seeds at
            // BASELINE 0; a persisted identity keeps its mark.
            let key = exporter.cursor_identity();
            self.acked.entry(key).or_insert(0);
            self.exporters.push(exporter);
            // Recompute the resume cursor over ONLY currently-registered exporter
            // identities. Orphaned rows from a prior identity scheme (e.g. old
            // index-keyed "0:webhook" rows superseded by stable-identity keying)
            // remain in self.acked but must NOT drag the read cursor down to their
            // stale low mark: a min() over EVERY loaded row would
            // resume at an orphan's 0 even though the current exporters durably
            // acked far ahead, re-exporting history until they catch up. Every
            // registered key has an entry (or_insert above), so the baseline/
            // max_seq arguments are unused here.
            let keys: Vec<String> = self.exporters.iter().map(|e| e.cursor_identity()).collect();
            let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
            self.cursor = resume_cursor(&key_refs, &self.acked, 0, 0);
        } else {
            self.exporters.push(exporter);
        }
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

        // Parse rows into SiemEvents. `event_seqs` mirrors `events` (seq
        // ascending) so a short/partial export can ack ONLY the delivered prefix:
        // a malformed row is skipped from both, so the index into `events` maps
        // back to its DB seq via `event_seqs`.
        let mut events: Vec<SiemEvent> = Vec::with_capacity(rows.len());
        let mut event_seqs: Vec<u64> = Vec::with_capacity(rows.len());
        let mut max_seq = self.cursor;

        for (seq, raw_json) in &rows {
            match serde_json::from_str::<chio_core::receipt::body::ChioReceipt>(raw_json) {
                Ok(receipt) => {
                    events.push(SiemEvent::from_receipt_with_trusted_kernel_keys(
                        receipt,
                        Some(&self.config.trusted_kernel_keys),
                    ));
                    event_seqs.push(*seq);
                    if *seq > max_seq {
                        max_seq = *seq;
                    }
                }
                Err(error) => {
                    // Durably persist the malformed row to the SIEM cursor DB's
                    // dead_letters table BEFORE advancing past it. The in-memory
                    // DLQ is best-effort (drop-oldest, lost on restart/overflow),
                    // so advancing acked_seq past a row captured only in memory
                    // would skip the receipt permanently and break at-least-once.
                    // On a persist failure we leave the cursor BEHIND the row
                    // (return early via `?` without touching self.cursor) so the
                    // next poll re-reads and retries it.
                    let failed_at = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let redacted = redact_for_operator_log(&error).to_string();
                    // Durably capture the malformed row FIRST (fail-closed: a
                    // persist failure returns early via `?`, leaving the cursor
                    // behind the row). Only REPORT the malformed row on its first
                    // durable capture: a failing exporter holds the read cursor
                    // behind the whole batch, so the same malformed seq is parsed
                    // again on every poll. The durable insert is idempotent, but
                    // an unconditional in-memory `dlq.push` + `_deserialize`
                    // counters are not, so repeated redelivery would inflate the
                    // `_deserialize` DLQ depth and evict real exporter failures
                    // from the bounded DLQ. Legacy None mode has
                    // no durable table and advances the cursor past the row, so it
                    // never redelivers: report once.
                    let newly_captured = match &self.cursor_store {
                        Some(store) => store.persist_dead_letter(
                            *seq,
                            "_deserialize",
                            raw_json,
                            &redacted,
                            failed_at,
                        )?,
                        None => true,
                    };
                    if newly_captured {
                        self.metrics.record_export(
                            "_deserialize",
                            crate::metrics_sink::ExportOutcome::Malformed,
                        );
                        self.dlq.push(FailedEvent {
                            event_json: format!("{{\"raw_seq\":{seq}}}"),
                            error: redacted,
                            failed_at,
                            exporter_name: "_deserialize".to_string(),
                        });
                        // Report the DLQ depth for the malformed-row producer here
                        // too: a batch of only malformed rows returns before the
                        // exporter loop that refreshes dlq_depth, so without this
                        // the `_deserialize` gauge would stay absent/stale while
                        // the in-memory DLQ grows and the alert-pack backstop
                        // underreports malformed-row failures. Scope the depth to
                        // `_deserialize` entries only: the DLQ is shared, so the
                        // global length would fold a coexisting exporter backlog
                        // into the malformed-row gauge, the same cross-exporter
                        // attribution the exporter loop avoids.
                        self.metrics.set_dlq_depth(
                            "_deserialize",
                            self.dlq.depth_for_exporter("_deserialize") as u64,
                        );
                        tracing::warn!(
                            seq = seq,
                            "Failed to deserialize receipt -- captured to durable DLQ"
                        );
                    }
                    // Durably captured (or legacy None mode, which replays from
                    // seq=0 on restart), so advancing past it is now safe.
                    if *seq > max_seq {
                        max_seq = *seq;
                    }
                }
            }
        }

        if events.is_empty() {
            // Only malformed rows in this batch. Every row was durably captured
            // in siem_dead_letters (persist_dead_letter above), so no registered
            // exporter can ever consume them. Advance each registered exporter's
            // durable high-water mark past the malformed range so a restart
            // resumes AFTER them instead of re-reading and re-DLQ'ing the same
            // seqs every boot: advancing only the in-memory cursor would leave
            // siem_export_cursor behind, so a restart would re-read the range.
            // max() never regresses a peer already further ahead. In legacy None
            // mode there is no durable cursor; the in-memory advance below
            // suffices (restart replays from seq 0, dedup'd downstream).
            if let Some(store) = &self.cursor_store {
                let exporter_keys: Vec<String> =
                    self.exporters.iter().map(|e| e.cursor_identity()).collect();
                for key in exporter_keys {
                    let advanced = self.acked.get(&key).copied().unwrap_or(0).max(max_seq);
                    self.acked.insert(key.clone(), advanced);
                    store.set_acked(&key, advanced)?;
                }
            }
            self.cursor = max_seq;
            return Ok(());
        }

        // Fan out to each registered exporter with retry. The high-water mark
        // for an exporter advances only on confirmed acceptance.
        for index in 0..self.exporters.len() {
            let exporter = self.exporters[index].as_ref();
            let exporter_name = exporter.name().to_string();
            // Ack/cursor state is keyed by the exporter's STABLE, config-derived
            // identity, not registration index, so a config reorder cannot remap
            // one sink's high-water mark onto another. Metrics stay keyed by the
            // bare name to bound cardinality.
            let cursor_key = exporter.cursor_identity();
            // A notification overlay (alerting) is NOT a SOC export sink: its
            // outcomes are counted on chio_alert_dispatch_total by the exporter
            // itself, so they must not also feed chio_soc_export_total / _lag /
            // SOC DLQ depth, or a failed page would burn the SOC export SLO while
            // audit export is healthy. Cursor/ack tracking still applies so the
            // overlay does not stall the read cursor.
            let records_soc = exporter.is_soc_export_sink();
            let result = Self::export_with_retry(
                &mut self.rate_limiter,
                self.config.max_retries,
                self.config.base_backoff_ms,
                exporter,
                &events,
            )
            .await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            match result {
                Ok(exported) => {
                    // A backend may return Ok(n) after accepting only the first n
                    // events of the batch (a short/partial success distinct from
                    // ExportError::PartialFailure). Treat the un-exported tail as
                    // UNACKED: ack only through the delivered prefix so
                    // at-least-once redelivers the tail next poll.
                    // `events`/`event_seqs` are seq-ascending, so the delivered
                    // prefix is events[..delivered], acked at event_seqs[delivered-1].
                    let delivered = exported.min(events.len());
                    let delivered_events = &events[..delivered];
                    if records_soc {
                        for _ in delivered_events {
                            self.metrics.record_export(
                                &exporter_name,
                                crate::metrics_sink::ExportOutcome::Ok,
                            );
                        }
                        // Lag: persistence-to-ack for the newest DELIVERED event,
                        // tagged with the MAX severity present among the delivered
                        // events. An un-exported tail records no Ok
                        // sample and no lag: it is redelivered, not acked, so
                        // counting it as delivered would let a short success mask
                        // the tail's real export latency.
                        if let Some(persisted) =
                            delivered_events.iter().map(|e| e.receipt.timestamp).max()
                        {
                            self.metrics.observe_export_lag(
                                &exporter_name,
                                batch_max_severity_tag(delivered_events),
                                now.saturating_sub(persisted) as f64,
                            );
                        }
                    }
                    // Advance the high-water mark through the delivered prefix
                    // ONLY. A full batch acks max_seq (which also covers trailing
                    // malformed rows already durably captured); a short success
                    // acks event_seqs[delivered-1]; a zero-delivery Ok advances
                    // nothing (whole batch redelivered). Never regress the
                    // in-memory ack: the durable set_acked is already MAX-monotonic
                    // in SQLite, but a plain insert of a stale/duplicate low batch
                    // would regress the in-memory mark and re-export history.
                    let ack_target = if delivered == events.len() {
                        Some(max_seq)
                    } else if delivered > 0 {
                        event_seqs.get(delivered - 1).copied()
                    } else {
                        None
                    };
                    if let Some(target) = ack_target {
                        let advanced = self
                            .acked
                            .get(&cursor_key)
                            .copied()
                            .unwrap_or(0)
                            .max(target);
                        self.acked.insert(cursor_key.clone(), advanced);
                        if let Some(store) = &self.cursor_store {
                            store.set_acked(&cursor_key, advanced)?;
                        }
                    }
                }
                Err(e) => {
                    if records_soc {
                        for event in &events {
                            self.metrics.record_export(
                                &exporter_name,
                                crate::metrics_sink::ExportOutcome::Dlq,
                            );
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
                    }
                    tracing::warn!(
                        exporter = exporter_name,
                        error = %redact_for_operator_log(&e),
                        dlq_len = self.dlq.len(),
                        "All retries exhausted -- events pushed to DLQ; high-water mark held"
                    );
                    // acked_seq for this exporter is NOT advanced: the range is
                    // redelivered next poll (at-least-once). Idempotent ingest
                    // dedups downstream.
                }
            }
            // Report the DLQ depth attributed to THIS exporter only. Using the
            // global `self.dlq.len()` for every exporter label would report a
            // non-zero depth on a healthy exporter just because a different sink
            // failed in the same poll. A notification overlay is excluded from
            // SOC DLQ accounting.
            if records_soc {
                self.metrics.set_dlq_depth(
                    &exporter_name,
                    self.dlq.depth_for_exporter(&exporter_name) as u64,
                );
            }
        }

        // Advance the read cursor. In legacy None mode (no cursor store) the
        // cursor ALWAYS advances past the batch: delivery is not persisted and
        // downstream ingest dedups idempotently, so a failed exporter must not
        // hold the cursor or the next tick re-reads the same batch and pushes
        // duplicate DLQ entries indefinitely until it recovers (the
        // advance-regardless behavior). With a configured cursor store the cursor
        // resumes at the slowest REGISTERED exporter so nothing is skipped: a
        // registered exporter that has never acked is held at its baseline
        // (at-least-once). Zero registered exporters falls back to max_seq.
        self.cursor = if self.cursor_store.is_some() {
            let exporter_keys: Vec<String> =
                self.exporters.iter().map(|e| e.cursor_identity()).collect();
            let key_refs: Vec<&str> = exporter_keys.iter().map(String::as_str).collect();
            resume_cursor(&key_refs, &self.acked, cursor, max_seq)
        } else {
            max_seq
        };

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

/// Compute the read cursor after a poll: the minimum high-water mark across all
/// REGISTERED exporters, so the cursor never advances past receipts the slowest
/// exporter has not consumed (at-least-once).
///
/// A registered exporter absent from `acked` has never acked (it failed before
/// its first successful export); it is held at `baseline` (the pre-poll cursor)
/// so the un-acked batch is redelivered rather than skipped. With zero
/// registered exporters the cursor advances to `max_seq`,
/// matching the legacy headless / malformed-only advance-regardless behavior.
fn resume_cursor(
    exporter_names: &[&str],
    acked: &std::collections::BTreeMap<String, u64>,
    baseline: u64,
    max_seq: u64,
) -> u64 {
    exporter_names
        .iter()
        .map(|name| acked.get(*name).copied().unwrap_or(baseline))
        .min()
        .unwrap_or(max_seq)
}

/// The maximum alert severity across a batch, as a bounded metric tag
/// (info/low/medium/high/critical). Used to tag the SOC export lag sample so a
/// batch containing a high/critical denial records its lag under that severity
/// instead of always "info". An empty batch defaults to "info".
fn batch_max_severity_tag(events: &[SiemEvent]) -> &'static str {
    events
        .iter()
        .map(crate::alerting::derive_event_severity)
        .max()
        .map(|severity| severity.as_tag())
        .unwrap_or("info")
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
    fn resume_cursor_holds_at_baseline_for_a_never_acked_exporter() {
        // "webhook" is registered but has never acked (absent from `acked`).
        // Even though "splunk" acked up to seq 10, the cursor must be HELD at the
        // pre-poll baseline (3) so the batch is redelivered to "webhook"
        // (at-least-once). The old `min(acked)` logic would have advanced to 10,
        // permanently skipping [4..10] for "webhook".
        let mut acked = std::collections::BTreeMap::new();
        acked.insert("splunk".to_string(), 10u64);
        let cursor = resume_cursor(&["splunk", "webhook"], &acked, 3, 10);
        assert_eq!(
            cursor, 3,
            "a never-acked exporter holds the cursor at baseline"
        );
    }

    #[test]
    fn resume_cursor_advances_to_the_slowest_acked_exporter() {
        let mut acked = std::collections::BTreeMap::new();
        acked.insert("splunk".to_string(), 10u64);
        acked.insert("webhook".to_string(), 7u64);
        let cursor = resume_cursor(&["splunk", "webhook"], &acked, 3, 10);
        assert_eq!(
            cursor, 7,
            "the cursor resumes at the slowest acked exporter"
        );
    }

    #[test]
    fn resume_cursor_advances_to_max_seq_with_zero_exporters() {
        let acked = std::collections::BTreeMap::new();
        let cursor = resume_cursor(&[], &acked, 3, 10);
        assert_eq!(
            cursor, 10,
            "with no registered exporters the cursor advances (legacy headless behavior)"
        );
    }

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

    /// Seed a receipt DB carrying a single malformed row at seq=1.
    fn seed_malformed_receipt_db(path: &std::path::Path) -> TestResult {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE chio_tool_receipts (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 receipt_id TEXT NOT NULL UNIQUE,
                 timestamp INTEGER NOT NULL,
                 capability_id TEXT NOT NULL,
                 tool_server TEXT NOT NULL,
                 tool_name TEXT NOT NULL,
                 decision_kind TEXT NOT NULL,
                 policy_hash TEXT NOT NULL,
                 content_hash TEXT NOT NULL,
                 raw_json TEXT NOT NULL
             );",
        )?;
        conn.execute(
            "INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, \
             tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
             VALUES ('m1', 1, 'c', 's', 't', 'allow', 'p', 'h', 'not valid receipt json')",
            [],
        )?;
        Ok(())
    }

    /// A malformed row is durably persisted to the cursor DB's dead_letters
    /// table BEFORE the read cursor advances past it.
    #[tokio::test]
    async fn malformed_row_persisted_durably_before_cursor_advances() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_malformed_receipt_db(&receipt_db)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;

        // No exporters: a malformed-only batch. A healthy poll must persist the
        // malformed row durably and only then advance the read cursor.
        manager.poll_once().await?;

        assert_eq!(
            manager.cursor, 1,
            "cursor advances past a durably-persisted malformed row"
        );
        let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
        assert_eq!(
            store.dead_letter_seqs()?,
            vec![1u64],
            "the malformed row must be durably captured in dead_letters"
        );
        Ok(())
    }

    /// If the durable persist fails, the cursor is left BEHIND the malformed row
    /// (not advanced), so at-least-once is preserved and the next poll re-reads it.
    #[tokio::test]
    async fn malformed_row_persist_failure_leaves_cursor_behind() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_malformed_receipt_db(&receipt_db)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;

        // Force the durable persist to fail: drop the dead_letters table out from
        // under the manager's cursor-store connection via a second connection.
        {
            let conn = rusqlite::Connection::open(&cursor_db)?;
            conn.execute("DROP TABLE siem_dead_letters", [])?;
        }

        let result = manager.poll_once().await;
        assert!(
            result.is_err(),
            "a durable-persist failure must propagate and hold the cursor"
        );
        assert_eq!(
            manager.cursor, 0,
            "the cursor must stay behind an un-persisted malformed row (at-least-once)"
        );
        Ok(())
    }

    /// A malformed-ONLY batch is durably captured in siem_dead_letters, and its
    /// durable per-exporter mark must advance past the malformed range so a
    /// restart resumes AFTER it instead of re-reading and re-DLQ'ing the same
    /// dead-lettered seq every boot.
    #[tokio::test]
    async fn malformed_only_batch_advances_durable_cursor_across_restart() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_malformed_receipt_db(&receipt_db)?; // single malformed row at seq 1
        let cursor_db = dir.path().join("cursor.sqlite3");

        {
            let mut manager = ExporterManager::new(SiemConfig {
                db_path: receipt_db.clone(),
                cursor_db_path: Some(cursor_db.clone()),
                ..SiemConfig::default()
            })?;
            manager.add_exporter(Box::new(OkExporter {
                name: "splunk".to_string(),
            }));
            manager.poll_once().await?;
            assert_eq!(
                manager.cursor, 1,
                "the in-memory cursor advances past the malformed row"
            );
        }

        // The durable per-exporter mark must have advanced past the malformed row.
        {
            let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
            assert_eq!(
                store.acked_seqs()?.values().copied().min(),
                Some(1),
                "the durable high-water mark must advance past a malformed-only batch"
            );
        }

        // Simulated restart: a fresh manager over the same DBs must resume AFTER
        // the dead-lettered seq and not re-read it.
        {
            let mut manager = ExporterManager::new(SiemConfig {
                db_path: receipt_db.clone(),
                cursor_db_path: Some(cursor_db.clone()),
                ..SiemConfig::default()
            })?;
            manager.add_exporter(Box::new(OkExporter {
                name: "splunk".to_string(),
            }));
            assert_eq!(
                manager.cursor, 1,
                "restart resumes at the durable mark, past the malformed row"
            );
            manager.poll_once().await?;
            assert_eq!(
                manager.cursor, 1,
                "restart poll reads nothing new; the malformed seq is not re-read"
            );
        }

        // The malformed row is captured exactly once, not duplicated on restart.
        {
            let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
            assert_eq!(
                store.dead_letter_seqs()?,
                vec![1u64],
                "the malformed row is durably captured exactly once"
            );
        }
        Ok(())
    }

    /// A metrics sink that records `set_dlq_depth`, `record_export`, and
    /// `observe_export_lag` calls for assertions.
    #[derive(Default)]
    struct RecordingSink {
        dlq_depths: Mutex<Vec<(String, u64)>>,
        exports: Mutex<Vec<(String, crate::metrics_sink::ExportOutcome)>>,
        lags: Mutex<Vec<(String, String, f64)>>,
    }

    impl crate::metrics_sink::SiemMetricsSink for RecordingSink {
        fn record_export(&self, exporter: &str, outcome: crate::metrics_sink::ExportOutcome) {
            if let Ok(mut exports) = self.exports.lock() {
                exports.push((exporter.to_string(), outcome));
            }
        }
        fn observe_export_lag(&self, exporter: &str, severity: &str, lag_seconds: f64) {
            if let Ok(mut lags) = self.lags.lock() {
                lags.push((exporter.to_string(), severity.to_string(), lag_seconds));
            }
        }
        fn set_dlq_depth(&self, exporter: &str, depth: u64) {
            if let Ok(mut depths) = self.dlq_depths.lock() {
                depths.push((exporter.to_string(), depth));
            }
        }
        fn record_alert_dispatch(&self, _route: &str, _outcome: &str) {}
        fn observe_alert_dispatch_latency(&self, _route: &str, _outcome: &str, _latency: f64) {}
    }

    /// A mock exporter that always succeeds (records nothing).
    struct OkExporter {
        name: String,
    }

    impl Exporter for OkExporter {
        fn export_batch<'a>(
            &'a self,
            events: &'a [SiemEvent],
        ) -> crate::exporter::ExportFuture<'a> {
            let n = events.len();
            Box::pin(async move { Ok(n) })
        }
        fn name(&self) -> &str {
            &self.name
        }
    }

    /// A mock exporter with an explicit, config-derived cursor identity (used to
    /// prove the durable cursor is keyed by identity, not registration index).
    struct IdentityExporter {
        name: String,
        identity: String,
    }

    impl Exporter for IdentityExporter {
        fn export_batch<'a>(
            &'a self,
            events: &'a [SiemEvent],
        ) -> crate::exporter::ExportFuture<'a> {
            let n = events.len();
            Box::pin(async move { Ok(n) })
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn cursor_identity(&self) -> String {
            self.identity.clone()
        }
    }

    /// A mock NOTIFICATION overlay: succeeds like alerting but reports it is not
    /// a SOC export sink, so the manager must exclude it from SOC export metrics.
    struct NotificationOverlayExporter {
        name: String,
    }

    impl Exporter for NotificationOverlayExporter {
        fn export_batch<'a>(
            &'a self,
            events: &'a [SiemEvent],
        ) -> crate::exporter::ExportFuture<'a> {
            let n = events.len();
            Box::pin(async move { Ok(n) })
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn is_soc_export_sink(&self) -> bool {
            false
        }
    }

    /// A failing exporter with an explicit config-derived cursor identity, used
    /// to prove two distinct-identity sinks keep distinct cursor state.
    struct FailingIdentityExporter {
        name: String,
        identity: String,
    }

    impl Exporter for FailingIdentityExporter {
        fn export_batch<'a>(
            &'a self,
            _events: &'a [SiemEvent],
        ) -> crate::exporter::ExportFuture<'a> {
            Box::pin(async move { Err(ExportError::HttpError("simulated failure".to_string())) })
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn cursor_identity(&self) -> String {
            self.identity.clone()
        }
    }

    /// A mock exporter that always fails, forcing the batch into the DLQ.
    struct FailExporter {
        name: String,
    }

    impl Exporter for FailExporter {
        fn export_batch<'a>(
            &'a self,
            _events: &'a [SiemEvent],
        ) -> crate::exporter::ExportFuture<'a> {
            Box::pin(async move { Err(ExportError::HttpError("simulated failure".to_string())) })
        }
        fn name(&self) -> &str {
            &self.name
        }
    }

    /// A mock exporter that accepts only the first `accept` events of each batch
    /// and returns `Ok(accept)` (a SHORT success, distinct from a PartialFailure
    /// error). Records the receipt ids it was handed on every call so a test can
    /// prove the un-exported tail is redelivered rather than silently skipped.
    struct ShortSuccessExporter {
        name: String,
        accept: usize,
        seen: std::sync::Arc<Mutex<Vec<String>>>,
    }

    impl Exporter for ShortSuccessExporter {
        fn export_batch<'a>(
            &'a self,
            events: &'a [SiemEvent],
        ) -> crate::exporter::ExportFuture<'a> {
            let seen = self.seen.clone();
            let accept = self.accept;
            Box::pin(async move {
                if let Ok(mut guard) = seen.lock() {
                    for event in events {
                        guard.push(event.receipt.id.clone());
                    }
                }
                Ok(accept.min(events.len()))
            })
        }
        fn name(&self) -> &str {
            &self.name
        }
    }

    /// Sign a minimal-but-valid receipt so the poll loop parses it into an event.
    fn sample_receipt(id: &str) -> Result<chio_core::receipt::body::ChioReceipt, Box<dyn Error>> {
        use chio_core::crypto::Keypair;
        use chio_core::receipt::{
            body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        };
        let keypair = Keypair::generate();
        let action = ToolCallAction::from_parameters(serde_json::json!({}))
            .map_err(|error| format!("action parameters serialize in tests: {error}"))?;
        let body = ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1,
            capability_id: "cap-manager-test".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, &keypair)
            .map_err(|error| format!("ChioReceipt::sign must succeed in tests: {error}").into())
    }

    /// Sign a Deny receipt whose guard drives a chosen severity (e.g. a guard
    /// containing "secret" maps to Critical).
    fn sample_deny_receipt(
        id: &str,
        guard: &str,
    ) -> Result<chio_core::receipt::body::ChioReceipt, Box<dyn Error>> {
        use chio_core::crypto::Keypair;
        use chio_core::receipt::{
            body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        };
        let keypair = Keypair::generate();
        let action = ToolCallAction::from_parameters(serde_json::json!({}))
            .map_err(|error| format!("action parameters serialize in tests: {error}"))?;
        let body = ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1,
            capability_id: "cap-manager-test".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action,
            decision: Some(Decision::Deny {
                reason: "denied".to_string(),
                guard: guard.to_string(),
            }),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, &keypair)
            .map_err(|error| format!("ChioReceipt::sign must succeed in tests: {error}").into())
    }

    /// The SOC export lag sample must be tagged with the MAX severity present in
    /// the batch, so a batch containing a high/critical denial records its lag
    /// under that severity instead of always "info".
    #[test]
    fn batch_max_severity_tag_uses_the_highest_severity_present() -> TestResult {
        let allow = SiemEvent::from_receipt(sample_receipt("allow-1")?);
        let critical = SiemEvent::from_receipt(sample_deny_receipt("deny-1", "secret_leak")?);

        assert_eq!(
            batch_max_severity_tag(&[allow.clone(), critical]),
            "critical",
            "a batch containing a critical denial tags its lag under critical, not info"
        );
        let allow_only = batch_max_severity_tag(&[allow]);
        assert_ne!(
            allow_only, "critical",
            "an allow-only batch must not be tagged critical"
        );
        assert!(
            matches!(allow_only, "info" | "low"),
            "an allow-only batch stays at a low severity tag: {allow_only}"
        );
        Ok(())
    }

    /// A notification overlay (alerting) is NOT a SOC export sink, so the manager
    /// must not emit chio_soc_export_total / SOC DLQ depth for it even though it
    /// is registered in the exporter set.
    #[tokio::test]
    async fn notification_overlay_is_excluded_from_soc_export_metrics() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 2)?;

        let sink = std::sync::Arc::new(RecordingSink::default());
        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            ..SiemConfig::default()
        })?
        .with_metrics_sink(sink.clone());
        manager.add_exporter(Box::new(OkExporter {
            name: "webhook".to_string(),
        }));
        manager.add_exporter(Box::new(NotificationOverlayExporter {
            name: "alerting".to_string(),
        }));
        manager.poll_once().await?;

        let exports = sink
            .exports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            exports.iter().any(|(exporter, _)| exporter == "webhook"),
            "the SOC webhook sink records chio_soc_export_total: {exports:?}"
        );
        assert!(
            !exports.iter().any(|(exporter, _)| exporter == "alerting"),
            "the alerting overlay must NOT record chio_soc_export_total: {exports:?}"
        );
        let depths = sink
            .dlq_depths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !depths.iter().any(|(exporter, _)| exporter == "alerting"),
            "the alerting overlay must NOT report a SOC DLQ depth gauge: {depths:?}"
        );
        let lags = sink
            .lags
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !lags.iter().any(|(exporter, _, _)| exporter == "alerting"),
            "the alerting overlay must NOT record SOC export lag: {lags:?}"
        );
        Ok(())
    }

    /// The durable cursor must be keyed by the exporter's STABLE, config-derived
    /// identity, not its registration index, so a persisted high-water mark
    /// follows the exporter across config reorders.
    #[tokio::test]
    async fn durable_cursor_keyed_by_stable_identity_not_registration_index() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 5)?;
        let cursor_db = dir.path().join("cursor.sqlite3");
        let identity = "webhook@https://soc.example.test/ingest";
        {
            let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
            store.set_acked(identity, 100)?;
        }

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;
        // Registered at index 0, but its durable mark is looked up by its stable
        // identity, so it inherits the persisted 100. An index-keyed cursor would
        // look up "0:webhook", miss the persisted "webhook@..." row, and reset to
        // baseline 0.
        manager.add_exporter(Box::new(IdentityExporter {
            name: "webhook".to_string(),
            identity: identity.to_string(),
        }));
        assert_eq!(
            manager.cursor, 100,
            "an exporter resumes at the mark persisted under its stable identity"
        );
        Ok(())
    }

    /// Resuming exporters must IGNORE orphaned/stale cursor rows from a prior
    /// identity scheme. An old index-keyed "0:webhook" row left at 0 must not drag
    /// the
    /// read cursor down to its stale low mark when the current stable-identity
    /// exporter has durably acked far ahead; otherwise the first duplicate batch
    /// re-exports history until it catches up.
    #[tokio::test]
    async fn orphan_cursor_row_does_not_regress_the_resume_cursor() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 3)?;
        let cursor_db = dir.path().join("cursor.sqlite3");
        let current_identity = "webhook@https://soc.example.test/ingest";
        {
            let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
            // Orphan row from the OLD index-keyed scheme, still at baseline 0.
            store.set_acked("0:webhook", 0)?;
            // The CURRENT stable-identity exporter durably acked seq 1_000_000.
            store.set_acked(current_identity, 1_000_000)?;
        }

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;
        manager.add_exporter(Box::new(IdentityExporter {
            name: "webhook".to_string(),
            identity: current_identity.to_string(),
        }));
        assert_eq!(
            manager.cursor, 1_000_000,
            "an orphan cursor row must not drag the resume cursor below the current \
             exporter's durable mark"
        );
        Ok(())
    }

    /// A SHORT success (a backend returns Ok(n) after accepting only the first n
    /// of a larger batch) must advance the cursor ONLY past the delivered events;
    /// the un-exported tail stays unacked and at-least-once redelivers it rather
    /// than being permanently skipped on restart.
    #[tokio::test]
    async fn short_success_leaves_the_undelivered_tail_unacked_for_redelivery() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        // seq 1 = rcpt-0000, seq 2 = rcpt-0001 (AUTOINCREMENT in insertion order).
        seed_valid_receipt_db(&receipt_db, 2)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            max_retries: 0,
            ..SiemConfig::default()
        })?;
        manager.add_exporter(Box::new(ShortSuccessExporter {
            name: "webhook".to_string(),
            accept: 1,
            seen: seen.clone(),
        }));

        // Poll 1: batch [seq1, seq2]; the exporter accepts only seq1. The cursor
        // must advance to seq 1 (the delivered event) ONLY, not the batch max 2.
        manager.poll_once().await?;
        assert_eq!(
            manager.cursor, 1,
            "a short success advances the cursor only past the delivered event"
        );

        // Poll 2: the un-exported tail (seq 2) is redelivered and now accepted.
        manager.poll_once().await?;
        assert_eq!(
            manager.cursor, 2,
            "the redelivered tail is acked once it is actually delivered"
        );

        let seen = seen
            .lock()
            .map_err(|_| std::io::Error::other("seen lock poisoned"))?;
        // Poll 1 delivered [head(seq1), tail(seq2)]; poll 2 re-delivered the tail.
        // Receipt ids are content hashes, so identify head/tail by delivery order.
        assert_eq!(
            seen.len(),
            3,
            "expected head, tail, redelivered tail: {seen:?}"
        );
        let head = &seen[0];
        let tail = &seen[1];
        assert_ne!(
            head, tail,
            "head and tail must be distinct receipts: {seen:?}"
        );
        assert_eq!(
            &seen[2], tail,
            "the un-exported tail must be the receipt redelivered on poll 2: {seen:?}"
        );
        assert_eq!(
            seen.iter().filter(|id| *id == head).count(),
            1,
            "the delivered head must NOT be redelivered (its ack advanced): {seen:?}"
        );

        // The durable cursor persisted the tail ack (no permanent skip on restart).
        let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
        assert_eq!(store.acked_seqs()?.get("webhook").copied(), Some(2));
        Ok(())
    }

    /// Seed a receipt DB with a malformed row at seq 1 and a valid receipt at
    /// seq 2, so a batch carries both a malformed row and a real event.
    fn seed_malformed_then_valid_receipt_db(path: &std::path::Path) -> TestResult {
        seed_malformed_receipt_db(path)?;
        let receipt = sample_receipt("valid-2")?;
        let raw_json = serde_json::to_string(&receipt)?;
        let conn = rusqlite::Connection::open(path)?;
        conn.execute(
            "INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, \
             tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
             VALUES (?1, 1, 'c', 's', 't', 'allow', 'p', 'h', ?2)",
            rusqlite::params![receipt.id, raw_json],
        )?;
        Ok(())
    }

    /// When a failing exporter holds the read cursor behind a batch that contains
    /// a malformed row, the same malformed seq is re-parsed every poll. The
    /// durable insert is idempotent, so the in-memory `_deserialize` DLQ depth
    /// must NOT be re-inflated on redelivery.
    #[tokio::test]
    async fn malformed_row_not_re_reported_on_redelivery() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_malformed_then_valid_receipt_db(&receipt_db)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let sink = std::sync::Arc::new(RecordingSink::default());
        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            max_retries: 0,
            ..SiemConfig::default()
        })?
        .with_metrics_sink(sink.clone());
        // A failing exporter never acks, so the cursor is held behind the batch
        // and the malformed seq is re-read on the next poll.
        manager.add_exporter(Box::new(FailExporter {
            name: "webhook".to_string(),
        }));

        manager.poll_once().await?;
        manager.poll_once().await?;

        // The malformed row is durably captured exactly once.
        let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
        assert_eq!(store.dead_letter_seqs()?, vec![1u64]);

        // Every reported _deserialize DLQ depth stays at 1: redelivery must not
        // re-push the malformed row into the bounded in-memory DLQ.
        let depths = sink
            .dlq_depths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let deserialize_depths: Vec<u64> = depths
            .iter()
            .filter(|(exporter, _)| exporter == "_deserialize")
            .map(|(_, depth)| *depth)
            .collect();
        assert!(
            !deserialize_depths.is_empty(),
            "the malformed row is reported at least once"
        );
        assert!(
            deserialize_depths.iter().all(|depth| *depth == 1),
            "the malformed _deserialize DLQ depth must not grow on redelivery: {deserialize_depths:?}"
        );
        // The _deserialize malformed counter fires exactly once (first capture).
        let deserialize_exports = sink
            .exports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(exporter, _)| exporter == "_deserialize")
            .count();
        assert_eq!(
            deserialize_exports, 1,
            "the _deserialize malformed export outcome is recorded once, not per redelivery"
        );
        Ok(())
    }

    /// Seed a receipt DB with `count` valid receipts (seq 1..=count).
    fn seed_valid_receipt_db(path: &std::path::Path, count: usize) -> TestResult {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE chio_tool_receipts (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 receipt_id TEXT NOT NULL UNIQUE,
                 timestamp INTEGER NOT NULL,
                 capability_id TEXT NOT NULL,
                 tool_server TEXT NOT NULL,
                 tool_name TEXT NOT NULL,
                 decision_kind TEXT NOT NULL,
                 policy_hash TEXT NOT NULL,
                 content_hash TEXT NOT NULL,
                 raw_json TEXT NOT NULL
             );",
        )?;
        for i in 0..count {
            let receipt = sample_receipt(&format!("rcpt-{i:04}"))?;
            let raw_json = serde_json::to_string(&receipt)?;
            conn.execute(
                "INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, \
                 tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
                 VALUES (?1, 1, 'c', 's', 't', 'allow', 'p', 'h', ?2)",
                rusqlite::params![receipt.id, raw_json],
            )?;
        }
        Ok(())
    }

    /// On startup with a cursor store, a registered exporter that has NO
    /// persisted cursor row is treated as baseline (0), so it pins the resume
    /// cursor at 0 until it acks -- even when a peer exporter has already
    /// persisted an advanced high-water mark. Otherwise the startup cursor would
    /// resume at the persisted peer's mark and the newly registered exporter
    /// would permanently skip the earlier backlog.
    #[tokio::test]
    async fn missing_exporter_cursor_pins_resume_at_baseline_on_startup() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 3)?;
        let cursor_db = dir.path().join("cursor.sqlite3");
        {
            // "splunk" has already acked up to seq 100; "webhook" has no row. The
            // durable key is the exporter's STABLE identity; OkExporter uses the
            // default identity (its bare name), so pre-seed under "splunk".
            let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
            store.set_acked("splunk", 100)?;
        }

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;
        assert_eq!(
            manager.cursor, 100,
            "before webhook registers, the cursor resumes at the persisted mark"
        );
        manager.add_exporter(Box::new(OkExporter {
            name: "splunk".to_string(),
        }));
        manager.add_exporter(Box::new(OkExporter {
            name: "webhook".to_string(),
        }));
        assert_eq!(
            manager.cursor, 0,
            "a registered exporter with no persisted cursor row pins resume at baseline 0"
        );
        Ok(())
    }

    /// In the default None mode (no cursor store) a failed exporter must NOT hold
    /// the read cursor. The cursor advances to max_seq (legacy advance-regardless)
    /// so the next poll does not re-read and re-DLQ the same batch forever.
    #[tokio::test]
    async fn legacy_none_mode_advances_cursor_past_failed_batch() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 3)?;

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            max_retries: 0,
            cursor_db_path: None,
            ..SiemConfig::default()
        })?;
        manager.add_exporter(Box::new(FailExporter {
            name: "webhook".to_string(),
        }));

        manager.poll_once().await?;
        assert_eq!(
            manager.cursor, 3,
            "None mode advances past the DLQ'd batch (legacy behavior preserved)"
        );
        Ok(())
    }

    /// WITH a cursor store, the same failed exporter holds the cursor at its
    /// baseline so the un-acked batch is redelivered (at-least-once); this
    /// behavior is gated on a configured store.
    #[tokio::test]
    async fn configured_store_holds_cursor_for_failed_never_acked_exporter() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 3)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            max_retries: 0,
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;
        manager.add_exporter(Box::new(FailExporter {
            name: "webhook".to_string(),
        }));

        manager.poll_once().await?;
        assert_eq!(
            manager.cursor, 0,
            "with a cursor store the failed never-acked exporter holds the cursor at baseline"
        );
        Ok(())
    }

    /// A batch of only malformed rows returns before the exporter loop, so the
    /// `_deserialize` DLQ-depth gauge must be reported from the malformed-capture
    /// path itself or it stays absent while the DLQ grows.
    #[tokio::test]
    async fn malformed_row_reports_deserialize_dlq_depth() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_malformed_receipt_db(&receipt_db)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let sink = std::sync::Arc::new(RecordingSink::default());
        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?
        .with_metrics_sink(sink.clone());

        manager.poll_once().await?;

        let depths = sink
            .dlq_depths
            .lock()
            .map_err(|_| std::io::Error::other("dlq depth lock poisoned"))?;
        assert!(
            depths.contains(&("_deserialize".to_string(), 1)),
            "the deserialize DLQ depth must be reported for a malformed row: {depths:?}"
        );
        Ok(())
    }

    /// Seed a receipt DB with `valid` valid receipts (seq 1..=valid) followed by
    /// one malformed row (seq valid+1).
    fn seed_valid_then_malformed_receipt_db(path: &std::path::Path, valid: usize) -> TestResult {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE chio_tool_receipts (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT,
                 receipt_id TEXT NOT NULL UNIQUE,
                 timestamp INTEGER NOT NULL,
                 capability_id TEXT NOT NULL,
                 tool_server TEXT NOT NULL,
                 tool_name TEXT NOT NULL,
                 decision_kind TEXT NOT NULL,
                 policy_hash TEXT NOT NULL,
                 content_hash TEXT NOT NULL,
                 raw_json TEXT NOT NULL
             );",
        )?;
        for i in 0..valid {
            let receipt = sample_receipt(&format!("rcpt-{i:04}"))?;
            let raw_json = serde_json::to_string(&receipt)?;
            conn.execute(
                "INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, \
                 tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
                 VALUES (?1, 1, 'c', 's', 't', 'allow', 'p', 'h', ?2)",
                rusqlite::params![receipt.id, raw_json],
            )?;
        }
        conn.execute(
            "INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, \
             tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
             VALUES ('malformed-1', 1, 'c', 's', 't', 'allow', 'p', 'h', 'not valid receipt json')",
            [],
        )?;
        Ok(())
    }

    /// The `_deserialize` DLQ-depth gauge must count only `_deserialize` entries,
    /// never the global queue length. A coexisting exporter backlog must not
    /// inflate the malformed-row gauge, the same cross-exporter attribution the
    /// exporter path avoids.
    #[tokio::test]
    async fn deserialize_dlq_depth_excludes_other_exporter_backlog() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        // seq 1,2 valid; seq 3 malformed.
        seed_valid_then_malformed_receipt_db(&receipt_db, 2)?;

        let sink = std::sync::Arc::new(RecordingSink::default());
        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            max_retries: 0,
            // Batch of 2 so poll 1 reads only the two valid rows and poll 2 reads
            // the malformed row alone (a malformed-only batch).
            batch_size: 2,
            // Legacy None mode: the cursor advances past the failed batch so poll 2
            // reaches the malformed row.
            cursor_db_path: None,
            ..SiemConfig::default()
        })?
        .with_metrics_sink(sink.clone());
        // A failing exporter fills the SHARED DLQ with two "webhook" entries.
        manager.add_exporter(Box::new(FailExporter {
            name: "webhook".to_string(),
        }));

        // Poll 1: both valid rows fail export -> 2 "webhook" DLQ entries.
        manager.poll_once().await?;
        // Poll 2: the malformed row alone -> the _deserialize gauge must report 1,
        // not the global DLQ length of 3 (2 webhook + 1 _deserialize).
        manager.poll_once().await?;

        assert_eq!(
            manager.dlq_len(),
            3,
            "the shared DLQ holds the webhook backlog plus the malformed row"
        );
        let depths = sink
            .dlq_depths
            .lock()
            .map_err(|_| std::io::Error::other("dlq depth lock poisoned"))?;
        let deserialize_depth = depths
            .iter()
            .rev()
            .find(|(name, _)| name == "_deserialize")
            .map(|(_, depth)| *depth);
        assert_eq!(
            deserialize_depth,
            Some(1),
            "the _deserialize gauge must exclude the webhook backlog: {depths:?}"
        );
        Ok(())
    }

    /// When one exporter fails and another succeeds in the same poll, the DLQ
    /// depth must be attributed to the FAILING exporter only. A healthy exporter
    /// must report depth 0 even though a different sink filled the shared DLQ.
    #[tokio::test]
    async fn dlq_depth_is_attributed_to_the_failing_exporter_only() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 2)?;

        let sink = std::sync::Arc::new(RecordingSink::default());
        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            max_retries: 0,
            cursor_db_path: None,
            ..SiemConfig::default()
        })?
        .with_metrics_sink(sink.clone());
        // Register the failing exporter FIRST so the shared DLQ is already
        // non-empty when the succeeding exporter's depth is reported.
        manager.add_exporter(Box::new(FailExporter {
            name: "fail-sink".to_string(),
        }));
        manager.add_exporter(Box::new(OkExporter {
            name: "ok-sink".to_string(),
        }));

        manager.poll_once().await?;

        let depths = sink
            .dlq_depths
            .lock()
            .map_err(|_| std::io::Error::other("dlq depth lock poisoned"))?;
        assert!(
            depths.contains(&("ok-sink".to_string(), 0)),
            "the succeeding exporter must report DLQ depth 0: {depths:?}"
        );
        assert!(
            depths
                .iter()
                .any(|(name, depth)| name == "fail-sink" && *depth > 0),
            "the failing exporter must report its own non-zero DLQ depth: {depths:?}"
        );
        Ok(())
    }

    /// High-water marks are keyed by each exporter's STABLE, config-derived
    /// identity (its endpoint), NOT its registration index. Two webhook sinks
    /// that report the same name "webhook"
    /// but point at DIFFERENT endpoints therefore keep DISTINCT cursor state that
    /// also survives a config reorder. When one acks and the other exhausts
    /// retries, the failed sink's range is redelivered (at-least-once), not
    /// skipped because a peer advanced a shared key.
    #[tokio::test]
    async fn distinct_identity_exporters_keep_distinct_cursor_state() -> TestResult {
        let dir = tempfile::tempdir()?;
        let receipt_db = dir.path().join("receipts.sqlite3");
        seed_valid_receipt_db(&receipt_db, 3)?;
        let cursor_db = dir.path().join("cursor.sqlite3");

        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db.clone(),
            max_retries: 0,
            cursor_db_path: Some(cursor_db.clone()),
            ..SiemConfig::default()
        })?;
        // Both report the metric name "webhook" but have distinct endpoint-derived
        // identities: the first succeeds, the second fails. Their cursor state
        // must stay distinct so the failed sink's range is redelivered.
        manager.add_exporter(Box::new(IdentityExporter {
            name: "webhook".to_string(),
            identity: "webhook@https://soc.example.test/a".to_string(),
        }));
        manager.add_exporter(Box::new(FailingIdentityExporter {
            name: "webhook".to_string(),
            identity: "webhook@https://soc.example.test/b".to_string(),
        }));

        manager.poll_once().await?;

        // The failed sink never acked, so the read cursor is HELD at baseline 0
        // for redelivery. A shared key would have advanced to 3 and permanently
        // skipped [1..3] for the failed sink.
        assert_eq!(
            manager.cursor, 0,
            "the failed distinct-identity sink holds the cursor at baseline for redelivery"
        );
        // The succeeding sink still advanced its OWN durable high-water mark.
        let store = crate::cursor_store::SiemCursorStore::open(&cursor_db)?;
        assert_eq!(
            store
                .acked_seqs()?
                .get("webhook@https://soc.example.test/a")
                .copied(),
            Some(3),
            "the succeeding sink advanced its own identity-keyed high-water mark"
        );
        // The failed sink never acked durably (absent from the store) and stays
        // pinned at its in-memory baseline 0, so its range is redelivered.
        assert_eq!(
            manager
                .acked
                .get("webhook@https://soc.example.test/b")
                .copied(),
            Some(0),
            "the failed sink stays at baseline for redelivery"
        );
        Ok(())
    }
}
