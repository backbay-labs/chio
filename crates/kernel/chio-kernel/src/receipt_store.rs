use chio_core::canonical::CanonicalBytes;
use chio_core::capability::token::CapabilityToken;
use chio_core::credit::CreditBondRow;
use chio_core::crypto::Keypair;
use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};
use chio_log_redact::redacted;

use crate::capability_lineage::CapabilitySnapshot;
use crate::checkpoint::KernelCheckpoint;

/// Configuration for receipt retention and archival.
///
/// When set on `KernelConfig`, the kernel can archive aged-out or oversized
/// receipt databases to a separate read-only SQLite file while keeping archived
/// receipts verifiable against their Merkle checkpoint roots.
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// Number of days to retain receipts in the live database. Default: 90.
    pub retention_days: u64,
    /// Maximum size in bytes before the live database is rotated. Default: 10 GB.
    pub max_size_bytes: u64,
    /// Path for the archive SQLite file. Must be writable on first rotation.
    pub archive_path: String,
    /// Optional tenant scope for retention. When set, rotation only archives
    /// receipts for this tenant and leaves other tenant evidence untouched.
    pub tenant_id: Option<String>,
    /// How often the kernel maintenance task evaluates rotation, in seconds.
    /// Default: 3600 (one hour).
    pub check_interval_secs: u64,
    /// Internal: set by `archive_receipts_before` to bypass the day/size
    /// threshold and rotate at an explicit cutoff. Not part of any wire form
    /// (no serialized representation of `RetentionConfig` exists).
    pub explicit_cutoff_unix_secs: Option<u64>,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            retention_days: 90,
            max_size_bytes: 10_737_418_240,
            archive_path: "receipts-archive.sqlite3".to_string(),
            tenant_id: None,
            check_interval_secs: 3_600,
            explicit_cutoff_unix_secs: None,
        }
    }
}

/// Owns the retention maintenance worker thread; signals stop and joins on
/// drop. Spawned by [`crate::kernel::ChioKernel::try_set_receipt_store_handle`]
/// when `KernelConfig.retention_config` is `Some`, so retention rotation runs
/// on an interval without operator-driven polling.
///
/// The worker thread NEVER PANICS: a rotation call is wrapped in
/// `catch_unwind` so a panic inside the receipt store's rotation path is
/// caught, logged, and retried on the next interval rather than unwinding the
/// worker thread (which would silently and permanently stop maintenance).
pub struct RetentionMaintenanceHandle {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl RetentionMaintenanceHandle {
    /// Spawn the maintenance worker. `store` is a dedicated `Arc` clone held
    /// by the worker thread for its lifetime, independent of the kernel's own
    /// `receipt_store` handle.
    pub(crate) fn spawn(store: std::sync::Arc<dyn ReceiptStore>, config: RetentionConfig) -> Self {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_stop = std::sync::Arc::clone(&stop);
        let interval = std::time::Duration::from_secs(config.check_interval_secs.max(1));
        let join = std::thread::spawn(move || {
            while !worker_stop.load(std::sync::atomic::Ordering::SeqCst) {
                // Sleep in short slices so shutdown is responsive.
                let mut waited = std::time::Duration::ZERO;
                let slice = std::time::Duration::from_millis(200);
                while waited < interval && !worker_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(slice);
                    waited += slice;
                }
                if worker_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                // Never panic: a rotation error OR a caught panic is surfaced
                // as a warning and retried next interval, rather than
                // crashing the worker thread (and, unwrapped, the kernel).
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    store.rotate_receipts(&config)
                }));
                // Persist the outcome into health so a persistent rotation
                // failure (an unwritable archive path, a missing/replaced
                // archive that no longer backs the ledger) is observable outside
                // this log: a store serving under a retention policy that is not
                // being honored must not keep reporting healthy. A success clears
                // the prior failure.
                match outcome {
                    Ok(Ok(_archived)) => {
                        store.record_retention_rotation_outcome(None);
                    }
                    Ok(Err(error)) => {
                        store.record_retention_rotation_outcome(Some(&error.to_string()));
                        tracing::warn!(
                            target: "chio::retention",
                            error = %redacted!(&error),
                            "receipt rotation failed; will retry next interval"
                        );
                    }
                    Err(_panic) => {
                        store.record_retention_rotation_outcome(Some(
                            "receipt rotation panicked",
                        ));
                        tracing::warn!(
                            target: "chio::retention",
                            "receipt rotation panicked; will retry next interval"
                        );
                    }
                }
            }
        });
        Self {
            stop,
            join: Some(join),
        }
    }
}

impl Drop for RetentionMaintenanceHandle {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptWriterCounters {
    pub accepted_total: u64,
    pub committed_total: u64,
    pub failed_total: u64,
    pub saturated_total: u64,
    pub inflight: u64,
    /// Commands still queued in the commit-actor channel, not yet pulled for
    /// processing. Unlike `inflight`, this excludes work the actor has already
    /// drained and is committing, so it is the honest saturation signal: the
    /// channel is full only once this reaches its capacity.
    #[serde(default)]
    pub queue_depth: u64,
    #[serde(default)]
    pub last_commit_unix_ms: Option<u64>,
    /// Wall-clock (unix-ms) of the first append this writer ever accepted, set
    /// once. It anchors the stall clock before the first successful commit, so a
    /// writer that wedges before ever committing is still measured against the
    /// stall threshold instead of appearing to make progress forever.
    #[serde(default)]
    pub first_accept_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptWalCheckpointReport {
    pub busy: u64,
    pub log_frames: u64,
    pub checkpointed_frames: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptFlushReport {
    pub writer: ReceiptWriterCounters,
    pub latest_committed_entry_seq: u64,
    #[serde(default)]
    pub latest_checkpoint_seq: Option<u64>,
    pub latest_checkpointed_entry_seq: u64,
    #[serde(default)]
    pub uncheckpointed_start_seq: Option<u64>,
    #[serde(default)]
    pub uncheckpointed_end_seq: Option<u64>,
    #[serde(default)]
    pub wal_checkpoint: Option<ReceiptWalCheckpointReport>,
    #[serde(default)]
    pub db_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptCheckpointRange {
    pub start_seq: u64,
    pub end_seq: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptCheckpointStatusReport {
    pub healthy: bool,
    pub latest_committed_entry_seq: u64,
    #[serde(default)]
    pub latest_checkpoint_seq: Option<u64>,
    pub latest_checkpointed_entry_seq: u64,
    #[serde(default)]
    pub next_range: Option<ReceiptCheckpointRange>,
    #[serde(default)]
    pub checkpoint_error: Option<String>,
    /// Current receipt-retention archival high-water mark (the highest
    /// `entry_seq` archived so far), or `None` if retention has never run.
    /// Reported even when retention is disabled so unbounded growth is
    /// visible in health/status output.
    #[serde(default)]
    pub retention_watermark_entry_seq: Option<u64>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptStoreHealthReport {
    pub healthy: bool,
    pub writer: ReceiptWriterCounters,
    /// Current writer-liveness label ("healthy", "wedged", "dead", ...).
    /// Serialized so an operator health surface can distinguish a slow-but-live
    /// writer from a wedged one. Optional for backward compatibility.
    #[serde(default = "receipt_writer_liveness_unknown_label")]
    pub writer_liveness: String,
    pub latest_committed_entry_seq: u64,
    #[serde(default)]
    pub latest_checkpoint_seq: Option<u64>,
    pub latest_checkpointed_entry_seq: u64,
    #[serde(default)]
    pub uncheckpointed_start_seq: Option<u64>,
    #[serde(default)]
    pub uncheckpointed_end_seq: Option<u64>,
    #[serde(default)]
    pub checkpoint_error: Option<String>,
    #[serde(default)]
    pub db_size_bytes: Option<u64>,
    /// Current receipt-retention archival high-water mark (the highest
    /// `entry_seq` archived so far), or `None` if retention has never run.
    /// Reported even when retention is disabled so unbounded growth is
    /// visible in health output.
    #[serde(default)]
    pub retention_watermark_entry_seq: Option<u64>,
    /// Last error from the background retention maintenance worker, or `None`
    /// when the most recent rotation succeeded (or retention is not configured).
    /// A persistent value means the store is serving under a retention policy
    /// that is not being honored; `healthy` is `false` while it is set so
    /// operators and automation can alert on a silently-failing background task.
    #[serde(default)]
    pub retention_error: Option<String>,
    /// Supervised health of the commit-writer thread. A durable store reports this
    /// so a dead or degraded writer can never be masked by a last-batch success.
    #[serde(default)]
    pub writer_level: chio_supervisor::HealthLevel,
    /// Cumulative writer restarts observed by the supervisor. Non-zero after any
    /// writer fault, even once the writer recovers.
    #[serde(default)]
    pub writer_restart_total: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptCheckpointCreateReport {
    pub created: bool,
    #[serde(default)]
    pub checkpoint_seq: Option<u64>,
    #[serde(default)]
    pub batch_start_seq: Option<u64>,
    #[serde(default)]
    pub batch_end_seq: Option<u64>,
    pub latest_committed_entry_seq: u64,
    pub latest_checkpointed_entry_seq: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationReceiptConsumption {
    pub authorization_receipt_id: String,
    pub consumer_receipt_id: String,
    pub request_id: String,
    pub session_id: String,
    pub tool_call_id: String,
    /// Tenant id copied from the live authorization receipt. ACP authorization
    /// receipts may legitimately carry `tenant_id: None` for non-enterprise
    /// (single-tenant or local) deployments; the consumption record mirrors
    /// the receipt's tenant scope (including `None`) for binding integrity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub parameter_hash: String,
    pub consumed_at_unix_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiptStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("sqlite pool error: {0}")]
    Pool(String),

    #[error("{operation} timed out after {timeout_ms}ms")]
    Timeout { operation: String, timeout_ms: u64 },

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("failed to prepare receipt store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto decode error: {0}")]
    CryptoDecode(String),

    #[error("canonical json error: {0}")]
    Canonical(String),

    #[error("invalid outcome filter: {0}")]
    InvalidOutcome(String),

    #[error("receipt read boundary error: {0}")]
    ReadBoundary(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("retention co-archival incomplete for {table}: {live} live rows, {archived} archived; aborting delete to preserve inclusion-proof integrity")]
    RetentionArchiveIncomplete {
        table: &'static str,
        live: u64,
        archived: u64,
    },

    #[error(
        "retention watermark regression: attempted {attempted}, current high-water mark {current}"
    )]
    RetentionWatermarkRegression { attempted: u64, current: u64 },

    #[error("claim receipt log projection is missing over a checkpointed or archived range (watermark {watermark}); the entry ordering cannot be safely regenerated to match committed checkpoint boundaries; restore the claim_receipt_log_entries projection from a backup taken before it was lost")]
    ArchivedRangeProjection { watermark: u64 },

    #[error("tenant-scoped retention is not expressible as a prefix watermark and is unsupported; no data was modified")]
    RetentionTenantScopeUnsupported,

    #[error("receipt commit writer is not serving after {restarts} restart(s): {last_error}")]
    WriterDead { restarts: u64, last_error: String },
}

/// Point-in-time liveness of a receipt store's commit writer. `Unknown` keeps
/// stores with no async writer behaving exactly as they did before liveness
/// existed: the pre-dispatch readiness gate treats it as permissive. A store
/// that does have an async writer reports a concrete verdict, which the gate
/// samples directly even when no background watchdog is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptWriterLiveness {
    Healthy,
    Saturated,
    Wedged,
    Dead,
    Unknown,
}

impl ReceiptWriterLiveness {
    /// Whether the pre-dispatch gate may admit while the writer is in this
    /// state. Only a proven-healthy or not-yet-probed writer is permissive; a
    /// saturated, wedged, or dead writer denies.
    pub fn healthy(self) -> bool {
        matches!(self, Self::Healthy | Self::Unknown)
    }

    pub fn as_label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Saturated => "saturated",
            Self::Wedged => "wedged",
            Self::Dead => "dead",
            Self::Unknown => "unknown",
        }
    }
}

fn receipt_writer_liveness_unknown_label() -> String {
    ReceiptWriterLiveness::Unknown.as_label().to_string()
}

pub trait ReceiptStore: Send + Sync {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError>;
    /// Load a chio receipt by id. The provided default returns `None`; a store
    /// backing a store-authoritative deployment MUST override this (and
    /// `load_child_receipt`) with a real point lookup.
    ///
    /// The kernel consults this BEFORE the bounded in-memory receipt mirror and
    /// falls back to the mirror only on a genuine `Ok(None)` miss. An append-only
    /// or remote store that does NOT override this therefore relies entirely on
    /// the mirror for point lookups: once the mirror evicts a receipt (past
    /// `receipt_mirror_capacity`), governed call-chain validation of an older
    /// `parent_receipt_id` misses both the store and the mirror and fails closed
    /// (a deny of the dependent claim, never a false allow). A store-authoritative
    /// remote deployment that must resolve older parent receipts MUST implement
    /// this point load so bounded-mirror eviction does not cause false denials.
    fn load_chio_receipt(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(None)
    }
    /// Load a child-request receipt by id. Provided default returns `None`; a
    /// store used for a store-authoritative deployment must override both this
    /// and `load_chio_receipt`. A miss is a fail-closed deny
    /// of the dependent call-chain claim, never a false allow. The same
    /// bounded-mirror eviction caveat documented on `load_chio_receipt` applies.
    fn load_child_receipt(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ChildRequestReceipt>, ReceiptStoreError> {
        Ok(None)
    }
    fn append_chio_receipt_canonical(
        &self,
        receipt: &ChioReceipt,
        _canonical: &CanonicalBytes,
    ) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt(receipt)
    }
    fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.append_chio_receipt(receipt)?;
        Ok(None)
    }
    /// Append a receipt, failing closed with `ReceiptStoreError::Timeout` if the
    /// commit round trip exceeds `budget`. The default ignores the budget and
    /// keeps the unbounded behavior for stores without an async writer; a store
    /// with a commit actor overrides this so a wedged writer cannot pin the
    /// kernel-wide receipt write lock indefinitely.
    fn append_chio_receipt_with_timeout(
        &self,
        receipt: &ChioReceipt,
        _budget: std::time::Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.append_chio_receipt_returning_seq(receipt)
    }
    /// Point-in-time writer liveness, assessed against the operator-configured
    /// stall threshold. Default `Unknown` keeps stores with no async writer, or
    /// no watchdog wired, permissive at the pre-dispatch gate; such stores
    /// ignore the threshold.
    fn writer_liveness(&self, _stall_threshold: std::time::Duration) -> ReceiptWriterLiveness {
        ReceiptWriterLiveness::Unknown
    }
    fn append_chio_receipt_consuming_authorization(
        &self,
        _receipt: &ChioReceipt,
        _consumption: &AuthorizationReceiptConsumption,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "durable authorization receipt consumption is not supported by this receipt store"
                .to_string(),
        ))
    }
    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError>;
    fn append_child_receipt_returning_seq(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.append_child_receipt(receipt)?;
        Ok(None)
    }
    /// Append a child receipt, failing closed with `ReceiptStoreError::Timeout`
    /// if the commit round trip exceeds `budget`. The default ignores the budget
    /// and keeps the unbounded behavior for stores without an async writer; a
    /// store with a commit actor overrides this so a wedged writer cannot pin the
    /// kernel-wide receipt write lock while nested-flow child receipts drain.
    fn append_child_receipt_with_timeout(
        &self,
        receipt: &ChildRequestReceipt,
        _budget: std::time::Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.append_child_receipt_returning_seq(receipt)
    }

    fn receipts_canonical_bytes_range(
        &self,
        _start_seq: u64,
        _end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt canonical byte ranges are not supported by this receipt store".to_string(),
        ))
    }

    fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt writer flush is not supported by this receipt store".to_string(),
        ))
    }

    fn flush_receipt_writes_with_timeout(
        &self,
        _timeout: std::time::Duration,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.flush_receipt_writes()
    }

    fn receipt_store_health(&self) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt store health is not supported by this receipt store".to_string(),
        ))
    }

    /// Whether the store's commit writer has degraded to the point that durable
    /// persistence can no longer be trusted, so evaluations must fail closed before
    /// dispatch rather than after executing a tool with no receipt path.
    ///
    /// The default is `false`: a store with no supervised background writer has
    /// nothing to trip. Stores that supervise a writer thread override this to read
    /// the writer's health flag.
    fn writer_serving_closed(&self) -> bool {
        false
    }

    fn latest_committed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt committed sequence reporting is not supported by this receipt store"
                .to_string(),
        ))
    }

    fn latest_checkpointed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt checkpoint sequence reporting is not supported by this receipt store"
                .to_string(),
        ))
    }

    fn next_checkpoint_range(
        &self,
        _max_batch: u64,
    ) -> Result<Option<ReceiptCheckpointRange>, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt checkpoint ranges are not supported by this receipt store".to_string(),
        ))
    }

    fn receipt_checkpoint_status(
        &self,
        _max_batch: Option<u64>,
    ) -> Result<ReceiptCheckpointStatusReport, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt checkpoint status is not supported by this receipt store".to_string(),
        ))
    }

    fn store_checkpoint(&self, _checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt checkpoint storage is not supported by this receipt store".to_string(),
        ))
    }

    fn create_next_receipt_checkpoint(
        &self,
        _max_batch: u64,
        _keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt checkpoint creation is not supported by this receipt store".to_string(),
        ))
    }

    fn load_checkpoint_by_seq(
        &self,
        _checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        Ok(None)
    }

    fn load_latest_checkpoint(&self) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let mut checkpoint_seq = 1;
        let mut latest = None;
        loop {
            let Some(checkpoint) = self.load_checkpoint_by_seq(checkpoint_seq)? else {
                return Ok(latest);
            };
            if checkpoint.body.checkpoint_seq != checkpoint_seq {
                return Err(ReceiptStoreError::Conflict(format!(
                    "checkpoint loader returned checkpoint {} for requested sequence {}",
                    checkpoint.body.checkpoint_seq, checkpoint_seq
                )));
            }
            checkpoint_seq = checkpoint
                .body
                .checkpoint_seq
                .checked_add(1)
                .ok_or_else(|| {
                    ReceiptStoreError::Conflict(
                        "checkpoint_seq overflow while loading latest".to_string(),
                    )
                })?;
            latest = Some(checkpoint);
        }
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        false
    }

    /// Install a background checkpoint signer on stores that build their own
    /// checkpoints on the writer thread. Returns `Ok(false)` when
    /// the store does not support background checkpointing (default).
    fn enable_background_checkpoints(
        &self,
        _keypair: Keypair,
        _max_batch: u64,
    ) -> Result<bool, ReceiptStoreError> {
        Ok(false)
    }

    /// Whether this store actually implements retention rotation
    /// (`rotate_receipts`). Default `false`: the default `rotate_receipts` is a
    /// fail-closed stub, so a kernel configured with `retention_config` uses
    /// this to refuse attaching a store that cannot rotate, rather than serving
    /// traffic under a retention policy whose background worker would only log
    /// "not supported" on every interval and never archive.
    fn supports_retention(&self) -> bool {
        false
    }

    /// Whether this store can honor a TENANT-SCOPED retention config
    /// (`RetentionConfig.tenant_id` set). Default `false`: prefix-watermark
    /// retention archives a contiguous checkpointed prefix of the WHOLE log and
    /// cannot carve out a single tenant, so a tenant-scoped `rotate_receipts`
    /// fails closed. A kernel configured with a tenant-scoped retention policy
    /// uses this to refuse attaching a store that could never archive under it,
    /// rather than spawning a worker that only logs "unsupported" every interval.
    fn supports_tenant_scoped_retention(&self) -> bool {
        false
    }

    /// Archive receipts that have aged out under `config` (day/size
    /// threshold, or an explicit cutoff). Returns the number of archived
    /// tool-receipt rows. Default: unsupported (fail-closed) for stores that
    /// do not implement retention.
    fn rotate_receipts(&self, _config: &RetentionConfig) -> Result<u64, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt retention is not supported by this receipt store".to_string(),
        ))
    }

    /// Record the outcome of a background retention rotation so a persistent
    /// failure is observable in `receipt_store_health` (and any health/flush
    /// report) rather than living only in logs. `None` clears a prior failure
    /// after a successful rotation; `Some(message)` records a rotation error or
    /// panic so a silently-failing background retention task marks the store
    /// unhealthy and surfaces the cause to operators and automation. Default
    /// no-op for stores without a health surface.
    fn record_retention_rotation_outcome(&self, _failure: Option<&str>) {}

    fn record_capability_snapshot(
        &self,
        _token: &CapabilityToken,
        _parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    /// Record a capability snapshot, failing closed with
    /// `ReceiptStoreError::Timeout` if the writer round trip exceeds `budget`.
    /// The default ignores the budget and keeps the unbounded behavior for stores
    /// without an async writer; a store with a commit actor overrides this so a
    /// writer that stalls after the pre-dispatch liveness check cannot hang the
    /// evaluation hot path inside the snapshot write.
    fn record_capability_snapshot_with_timeout(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
        _budget: std::time::Duration,
    ) -> Result<(), ReceiptStoreError> {
        self.record_capability_snapshot(token, parent_capability_id)
    }

    fn get_capability_snapshot(
        &self,
        _capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, ReceiptStoreError> {
        Ok(None)
    }

    fn get_capability_delegation_chain(
        &self,
        _capability_id: &str,
    ) -> Result<Vec<CapabilitySnapshot>, ReceiptStoreError> {
        Ok(Vec::new())
    }

    fn resolve_credit_bond(
        &self,
        _bond_id: &str,
    ) -> Result<Option<CreditBondRow>, ReceiptStoreError> {
        Ok(None)
    }

    /// Persist a serialized `SessionAnchor` (JSON form).
    fn record_session_anchor(
        &self,
        _session_id: &str,
        _anchor_id: &str,
        _auth_context_fingerprint: &str,
        _issued_at: u64,
        _supersedes_anchor_id: Option<&str>,
        _anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    /// Persist a serialized `RequestLineageRecord` (JSON form).
    #[allow(clippy::too_many_arguments)]
    fn record_request_lineage(
        &self,
        _session_id: &str,
        _request_id: &str,
        _parent_request_id: Option<&str>,
        _session_anchor_id: Option<&str>,
        _recorded_at: u64,
        _request_fingerprint: Option<&str>,
        _lineage_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    /// Persist a serialized `ReceiptLineageStatement` (JSON form).
    #[allow(clippy::too_many_arguments)]
    fn record_receipt_lineage_statement(
        &self,
        _child_receipt_id: &str,
        _request_id: Option<&str>,
        _session_id: Option<&str>,
        _session_anchor_id: Option<&str>,
        _parent_request_id: Option<&str>,
        _parent_receipt_id: Option<&str>,
        _chain_id: Option<&str>,
        _recorded_at: u64,
        _statement_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn get_receipt_lineage_verification(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ReceiptLineageVerification>, ReceiptStoreError> {
        Ok(None)
    }

    fn list_receipt_lineage_statement_links(
        &self,
        _receipt_id: &str,
    ) -> Result<Vec<ReceiptLineageStatementLink>, ReceiptStoreError> {
        Ok(Vec::new())
    }

    fn as_any_mut(&self) -> Option<&dyn std::any::Any> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AppendOnlyStore;

    impl ReceiptStore for AppendOnlyStore {
        fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
            Ok(())
        }

        fn append_child_receipt(
            &self,
            _receipt: &ChildRequestReceipt,
        ) -> Result<(), ReceiptStoreError> {
            Ok(())
        }
    }

    #[test]
    fn unsupported_durability_surfaces_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let store = AppendOnlyStore;
        let checkpoint = crate::checkpoint::build_checkpoint(
            1,
            1,
            1,
            &[b"receipt".to_vec()],
            &Keypair::generate(),
        )?;

        assert!(matches!(
            store.receipts_canonical_bytes_range(1, 1),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt canonical byte ranges are not supported")
        ));
        assert!(matches!(
            store.flush_receipt_writes(),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt writer flush is not supported")
        ));
        assert!(matches!(
            store.flush_receipt_writes_with_timeout(std::time::Duration::from_millis(1)),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt writer flush is not supported")
        ));
        assert!(matches!(
            store.receipt_store_health(),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt store health is not supported")
        ));
        assert!(matches!(
            store.latest_committed_entry_seq(),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt committed sequence reporting is not supported")
        ));
        assert!(matches!(
            store.latest_checkpointed_entry_seq(),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt checkpoint sequence reporting is not supported")
        ));
        assert!(matches!(
            store.next_checkpoint_range(1),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt checkpoint ranges are not supported")
        ));
        assert!(matches!(
            store.receipt_checkpoint_status(Some(1)),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt checkpoint status is not supported")
        ));
        assert!(matches!(
            store.store_checkpoint(&checkpoint),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt checkpoint storage is not supported")
        ));
        assert!(matches!(
            store.rotate_receipts(&RetentionConfig::default()),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt retention is not supported")
        ));
        Ok(())
    }

    /// A store whose background rotation always fails, recording the outcome the
    /// maintenance worker hands it and reflecting it in health, so a persistent
    /// retention failure is observable rather than silently healthy.
    #[derive(Default)]
    struct FailingRetentionStore {
        retention_error: std::sync::Mutex<Option<String>>,
        rotations: std::sync::atomic::AtomicU64,
    }

    impl ReceiptStore for FailingRetentionStore {
        fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
            Ok(())
        }

        fn append_child_receipt(
            &self,
            _receipt: &ChildRequestReceipt,
        ) -> Result<(), ReceiptStoreError> {
            Ok(())
        }

        fn supports_retention(&self) -> bool {
            true
        }

        fn rotate_receipts(&self, _config: &RetentionConfig) -> Result<u64, ReceiptStoreError> {
            self.rotations
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(ReceiptStoreError::Conflict(
                "archive path is unwritable".to_string(),
            ))
        }

        fn record_retention_rotation_outcome(&self, failure: Option<&str>) {
            if let Ok(mut guard) = self.retention_error.lock() {
                *guard = failure.map(ToString::to_string);
            }
        }

        fn receipt_store_health(&self) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
            let retention_error = self.retention_error.lock().ok().and_then(|g| g.clone());
            Ok(ReceiptStoreHealthReport {
                healthy: retention_error.is_none(),
                retention_error,
                ..ReceiptStoreHealthReport::default()
            })
        }
    }

    #[test]
    fn background_retention_failure_surfaces_in_health() {
        let store = std::sync::Arc::new(FailingRetentionStore::default());
        // A store with no rotation attempt yet reports healthy.
        assert!(
            store
                .receipt_store_health()
                .expect("health report")
                .healthy
        );

        let config = RetentionConfig {
            check_interval_secs: 1,
            ..RetentionConfig::default()
        };
        let handle = RetentionMaintenanceHandle::spawn(store.clone(), config);

        // The worker sleeps one interval (in 200ms slices) before its first
        // rotation, then records the failure into health. Poll until it appears.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline
            && store
                .receipt_store_health()
                .expect("health report")
                .retention_error
                .is_none()
        {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let report = store.receipt_store_health().expect("health report");
        drop(handle);
        assert!(
            store.rotations.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "the maintenance worker never attempted a rotation"
        );
        assert!(
            !report.healthy,
            "a persistently failing background rotation must mark the store unhealthy"
        );
        let message = report
            .retention_error
            .expect("the background rotation failure must surface in health");
        assert!(
            message.contains("archive path is unwritable"),
            "unexpected retention error: {message}"
        );
    }
}

#[derive(Debug, Clone)]
pub struct StoredToolReceipt {
    pub seq: u64,
    pub receipt: ChioReceipt,
}

#[derive(Debug, Clone)]
pub struct StoredChildReceipt {
    pub seq: u64,
    pub receipt: ChildRequestReceipt,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptLineageVerification {
    pub receipt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_anchor_id: Option<String>,
    pub session_anchor_verified: bool,
    pub parent_request_verified: bool,
    pub parent_receipt_verified: bool,
    pub replay_protected: bool,
}

impl ReceiptLineageVerification {
    #[must_use]
    pub fn delegated_call_chain_bound(&self) -> bool {
        self.parent_receipt_verified
            || (self.session_anchor_verified && self.parent_request_verified)
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptLineageStatementLink {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_id: Option<String>,
    pub child_receipt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_anchor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    pub recorded_at: u64,
}

#[derive(Debug, Clone)]
pub struct FederatedEvidenceShareImport {
    pub share_id: String,
    pub manifest_hash: String,
    pub exported_at: u64,
    pub issuer: String,
    pub partner: String,
    pub signer_public_key: String,
    pub require_proofs: bool,
    pub query_json: String,
    pub tool_receipts: Vec<StoredToolReceipt>,
    pub capability_lineage: Vec<CapabilitySnapshot>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FederatedEvidenceShareSummary {
    pub share_id: String,
    pub manifest_hash: String,
    pub imported_at: u64,
    pub exported_at: u64,
    pub issuer: String,
    pub partner: String,
    pub signer_public_key: String,
    pub require_proofs: bool,
    pub tool_receipts: u64,
    pub capability_lineage: u64,
}
