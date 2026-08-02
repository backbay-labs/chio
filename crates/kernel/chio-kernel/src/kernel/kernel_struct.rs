use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use dashmap::DashMap;

use super::*;

use std::collections::BTreeMap;
use std::time::Duration;

use super::construction::KernelBuildError;

/// Wall-clock budgets for the mediation hot path. All values are milliseconds.
/// `0` means "no deadline" (unbounded) for the opt-in guard and dispatch
/// budgets, so a deployment that never sets one runs byte-for-byte as it did
/// before deadlines existed. The receipt-append budget may not be `0`: an
/// unbounded wedged-writer stall is never a valid posture, so it is rejected at
/// load time and floor-clamped at read time as defense in depth.
#[derive(Debug, Clone)]
pub struct HotPathDeadlineConfig {
    /// Budget for the whole guard pipeline, enforced around `run_guards`.
    /// `0` disables (preserves the inline path).
    pub guard_pipeline_budget_ms: u64,
    /// Per-guard overrides keyed by `Guard::name()`. A named guard is enforced
    /// against its own budget instead of the pipeline budget; `0` disables the
    /// override for that guard. Any entry forces per-guard offload. A `BTreeMap`
    /// keeps the canonical key order deterministic.
    pub per_guard_budget_ms: BTreeMap<String, u64>,
    /// Offload the guard pipeline to `spawn_blocking` even with no budget set,
    /// so a blocking guard never pins an async worker. Default `false`.
    pub always_offload_guards: bool,
    /// Default per-dispatch budget, enforced around the tool-server call.
    /// `0` disables. Default `0`.
    pub dispatch_budget_ms: u64,
    /// Per-tool-server dispatch overrides keyed by `ServerId` string.
    pub per_server_dispatch_budget_ms: BTreeMap<String, u64>,
    /// Watchdog bound on one receipt-append round trip through the commit
    /// actor. Must be `>= MIN_RECEIPT_APPEND_BUDGET_MS`. Default 5000.
    pub receipt_append_budget_ms: u64,
    /// Writer-liveness watchdog poll cadence.
    pub receipt_writer_poll_ms: u64,
    /// Staleness threshold before a stuck writer is judged wedged.
    pub receipt_writer_stall_ms: u64,
}

pub const DEFAULT_RECEIPT_APPEND_BUDGET_MS: u64 = 5_000;
pub const MIN_RECEIPT_APPEND_BUDGET_MS: u64 = 250;
pub const DEFAULT_RECEIPT_WRITER_POLL_MS: u64 = 1_000;
pub const DEFAULT_RECEIPT_WRITER_STALL_MS: u64 = 10_000;
pub const DEFAULT_RUNTIME_ADMISSION_READINESS_TIMEOUT_MS: u64 = 30_000;

impl Default for HotPathDeadlineConfig {
    fn default() -> Self {
        Self {
            guard_pipeline_budget_ms: 0,
            per_guard_budget_ms: BTreeMap::new(),
            always_offload_guards: false,
            dispatch_budget_ms: 0,
            per_server_dispatch_budget_ms: BTreeMap::new(),
            receipt_append_budget_ms: DEFAULT_RECEIPT_APPEND_BUDGET_MS,
            receipt_writer_poll_ms: DEFAULT_RECEIPT_WRITER_POLL_MS,
            receipt_writer_stall_ms: DEFAULT_RECEIPT_WRITER_STALL_MS,
        }
    }
}

impl HotPathDeadlineConfig {
    /// Fail-closed load-time validation, run before kernel construction and
    /// mirrored in the config-file validator.
    pub fn validate(&self) -> Result<(), KernelBuildError> {
        if self.receipt_append_budget_ms < MIN_RECEIPT_APPEND_BUDGET_MS {
            return Err(KernelBuildError::InvalidDeadlineConfig(format!(
                "receipt_append_budget_ms must be >= {MIN_RECEIPT_APPEND_BUDGET_MS}"
            )));
        }
        if self.receipt_writer_poll_ms == 0 || self.receipt_writer_stall_ms == 0 {
            return Err(KernelBuildError::InvalidDeadlineConfig(
                "receipt writer poll and stall thresholds must be non-zero".to_string(),
            ));
        }
        Ok(())
    }

    fn ms_to_budget(ms: u64) -> Option<Duration> {
        match ms {
            0 => None,
            v => Some(Duration::from_millis(v)),
        }
    }

    pub fn guard_pipeline_budget(&self) -> Option<Duration> {
        Self::ms_to_budget(self.guard_pipeline_budget_ms)
    }

    pub fn guard_budget_for(&self, name: &str) -> Option<Duration> {
        match self.per_guard_budget_ms.get(name) {
            // A per-guard `0` disables only this guard's override, not the
            // pipeline deadline: any per-guard entry forces the offloaded path,
            // so falling through to the pipeline budget keeps an override-of-zero
            // guard bounded instead of running unbounded.
            None | Some(0) => self.guard_pipeline_budget(),
            Some(ms) => Self::ms_to_budget(*ms),
        }
    }

    pub fn dispatch_budget_for(&self, server_id: &str) -> Option<Duration> {
        match self.per_server_dispatch_budget_ms.get(server_id) {
            Some(ms) => Self::ms_to_budget(*ms),
            None => Self::ms_to_budget(self.dispatch_budget_ms),
        }
    }

    /// Effective append bound, clamped to the floor so a host that constructs a
    /// `KernelConfig` without running validation still never gets an unbounded
    /// (or below-floor) append.
    pub fn receipt_append_budget(&self) -> Duration {
        Duration::from_millis(
            self.receipt_append_budget_ms
                .max(MIN_RECEIPT_APPEND_BUDGET_MS),
        )
    }
}

#[cfg(test)]
mod hot_path_deadline_config_tests {
    use super::*;

    #[test]
    fn default_disables_guard_and_dispatch_but_bounds_append() {
        let cfg = HotPathDeadlineConfig::default();
        assert_eq!(cfg.guard_pipeline_budget(), None);
        assert_eq!(cfg.dispatch_budget_for("any-server"), None);
        assert_eq!(
            cfg.receipt_append_budget(),
            Duration::from_millis(DEFAULT_RECEIPT_APPEND_BUDGET_MS)
        );
    }

    #[test]
    fn validate_rejects_zero_append_budget() {
        let cfg = HotPathDeadlineConfig {
            receipt_append_budget_ms: 0,
            ..HotPathDeadlineConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_below_floor_append_budget() {
        let cfg = HotPathDeadlineConfig {
            receipt_append_budget_ms: MIN_RECEIPT_APPEND_BUDGET_MS - 1,
            ..HotPathDeadlineConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_poll_or_stall() {
        let cfg = HotPathDeadlineConfig {
            receipt_writer_poll_ms: 0,
            ..HotPathDeadlineConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn append_budget_is_clamped_to_floor_even_without_validation() {
        // A host that bypasses validation still never runs an unbounded (or
        // below-floor) append.
        let cfg = HotPathDeadlineConfig {
            receipt_append_budget_ms: 1,
            ..HotPathDeadlineConfig::default()
        };
        assert_eq!(
            cfg.receipt_append_budget(),
            Duration::from_millis(MIN_RECEIPT_APPEND_BUDGET_MS)
        );
    }

    #[test]
    fn per_guard_and_per_server_overrides_resolve() {
        let mut per_guard = BTreeMap::new();
        per_guard.insert("slow-guard".to_string(), 200u64);
        let mut per_server = BTreeMap::new();
        per_server.insert("slow-srv".to_string(), 300u64);
        let cfg = HotPathDeadlineConfig {
            guard_pipeline_budget_ms: 100,
            per_guard_budget_ms: per_guard,
            dispatch_budget_ms: 150,
            per_server_dispatch_budget_ms: per_server,
            ..HotPathDeadlineConfig::default()
        };
        assert_eq!(
            cfg.guard_budget_for("slow-guard"),
            Some(Duration::from_millis(200))
        );
        assert_eq!(
            cfg.guard_budget_for("other-guard"),
            Some(Duration::from_millis(100))
        );
        assert_eq!(
            cfg.dispatch_budget_for("slow-srv"),
            Some(Duration::from_millis(300))
        );
        assert_eq!(
            cfg.dispatch_budget_for("other-srv"),
            Some(Duration::from_millis(150))
        );
    }

    #[test]
    fn per_guard_zero_override_inherits_pipeline_budget() {
        // A per-guard entry of `0` disables only that guard's own override; the
        // guard must still inherit the overall pipeline budget rather than run
        // unbounded (any per-guard entry forces the offloaded, timed path).
        let mut per_guard = BTreeMap::new();
        per_guard.insert("disabled-override".to_string(), 0u64);
        let cfg = HotPathDeadlineConfig {
            guard_pipeline_budget_ms: 1_000,
            per_guard_budget_ms: per_guard,
            ..HotPathDeadlineConfig::default()
        };
        assert_eq!(
            cfg.guard_budget_for("disabled-override"),
            Some(Duration::from_millis(1_000))
        );
    }

    #[test]
    fn per_guard_zero_override_stays_unbounded_without_pipeline_budget() {
        // With no pipeline budget configured, a `0` override genuinely means no
        // deadline for that guard.
        let mut per_guard = BTreeMap::new();
        per_guard.insert("disabled-override".to_string(), 0u64);
        let cfg = HotPathDeadlineConfig {
            guard_pipeline_budget_ms: 0,
            per_guard_budget_ms: per_guard,
            ..HotPathDeadlineConfig::default()
        };
        assert_eq!(cfg.guard_budget_for("disabled-override"), None);
    }
}

/// Configuration for the Chio Runtime Kernel.
pub struct KernelConfig {
    /// Ed25519 keypair for signing receipts and issuing capabilities.
    pub keypair: Keypair,

    /// Public keys of trusted Capability Authorities.
    pub ca_public_keys: Vec<chio_core::PublicKey>,

    /// Maximum allowed delegation depth.
    pub max_delegation_depth: u32,

    /// SHA-256 hash of the active policy (embedded in receipts).
    pub policy_hash: String,

    /// Whether nested sampling requests are allowed at all.
    pub allow_sampling: bool,

    /// Whether sampling requests may include tool-use affordances.
    pub allow_sampling_tool_use: bool,

    /// Whether nested elicitation requests are allowed.
    pub allow_elicitation: bool,

    /// Maximum total wall-clock duration permitted for one streamed tool result.
    pub max_stream_duration_secs: u64,

    /// Maximum total canonical payload size permitted for one streamed tool result.
    pub max_stream_total_bytes: u64,

    /// Whether durable receipts and kernel-signed checkpoints are mandatory
    /// prerequisites for this deployment.
    pub require_web3_evidence: bool,

    /// Allow process-local receipt logs when no durable receipt store is
    /// installed. This is for tests and local scaffolds only; protocol
    /// deployments should leave it false so successful dispatch requires
    /// durable receipt persistence before any tool side effect.
    pub allow_ephemeral_receipt_log: bool,

    /// Allow a process-local (in-memory) revocation store when no durable or
    /// remote revocation source is installed. This is for tests and local
    /// scaffolds only; deployments should leave it false so a revoked
    /// capability cannot be re-accepted after a restart drops the revocation
    /// set.
    pub allow_ephemeral_revocation_store: bool,

    /// Number of receipts between Merkle checkpoint snapshots. Default: 100.
    ///
    /// Set to 0 to disable automatic checkpointing for deployments that do not
    /// require web3 evidence.
    pub checkpoint_batch_size: u64,

    /// Optional receipt retention configuration.
    ///
    /// When `None` (default), retention is disabled and receipts accumulate
    /// indefinitely. When `Some(config)`, the kernel will archive receipts
    /// that exceed the time or size threshold.
    pub retention_config: Option<crate::receipt_store::RetentionConfig>,

    /// Per-process memory budget (bounded-structure caps + RSS soft ceiling).
    pub memory_budget: MemoryBudgetConfig,

    /// Wall-clock budgets for the mediation hot path. Construction input only,
    /// not a wire payload, so this changes no signed or transmitted bytes.
    pub deadlines: HotPathDeadlineConfig,
}

impl KernelConfig {
    pub(crate) fn memory_budget_receipt_mirror_capacity(&self) -> usize {
        self.memory_budget.receipt_mirror_capacity
    }
    pub(crate) fn memory_budget_federation_cache_capacity(&self) -> usize {
        self.memory_budget.federation_cache_capacity
    }
    pub(crate) fn memory_budget_federation_cache_idle_ttl_secs(&self) -> u64 {
        self.memory_budget.federation_cache_idle_ttl_secs
    }
}

/// Boot-time configuration for the kernel-side hybrid signing path.
///
/// Mirrors the wire form of `chio_policy::CryptoFloor` (`allow_classical`,
/// `allow_hybrid`, `pq_required`) and pairs the floor with the operator's
/// 32-byte ML-DSA-65 keygen seed. Construct one of these from a parsed
/// HushSpec policy plus the boot-loaded PQ seed and pass it to
/// [`ChioKernel::with_hybrid_signing_backend`] with a verified self-quote
/// port to obtain a `Box<dyn SigningBackend>` for hybrid receipt signing.
///
/// A separate input from [`KernelConfig`]: the hybrid fields are not folded
/// into `KernelConfig`, so its wire form is unaffected.
#[derive(Debug, Clone, Default)]
pub struct HybridSigningConfig {
    /// Minimum cryptographic posture enforced on receipts, capability
    /// tokens, and compliance certificates. Default
    /// [`KernelCryptoFloor::AllowClassical`].
    pub crypto_floor: KernelCryptoFloor,

    /// Optional 32-byte ML-DSA-65 keygen seed. Required when
    /// `crypto_floor` is [`KernelCryptoFloor::AllowHybrid`] or
    /// [`KernelCryptoFloor::PqRequired`]; ignored under
    /// [`KernelCryptoFloor::AllowClassical`].
    pub pq_signing_seed: Option<[u8; 32]>,
}

pub(crate) fn capability_crypto_floor(
    floor: KernelCryptoFloor,
) -> chio_core::capability::crypto_floor::CapabilityCryptoFloor {
    match floor {
        KernelCryptoFloor::AllowClassical => {
            chio_core::capability::crypto_floor::CapabilityCryptoFloor::AllowClassical
        }
        KernelCryptoFloor::AllowHybrid => {
            chio_core::capability::crypto_floor::CapabilityCryptoFloor::AllowHybrid
        }
        KernelCryptoFloor::PqRequired => {
            chio_core::capability::crypto_floor::CapabilityCryptoFloor::PqRequired
        }
    }
}

pub(crate) fn receipt_crypto_floor(
    floor: KernelCryptoFloor,
) -> chio_core::receipt::crypto_floor::ReceiptCryptoFloor {
    match floor {
        KernelCryptoFloor::AllowClassical => {
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowClassical
        }
        KernelCryptoFloor::AllowHybrid => {
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowHybrid
        }
        KernelCryptoFloor::PqRequired => {
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired
        }
    }
}

pub const DEFAULT_MAX_STREAM_DURATION_SECS: u64 = 300;
pub const DEFAULT_MAX_STREAM_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// Default cap on the number of chunks RETAINED from one streamed tool result.
/// Bounds the accumulator `Vec<ToolCallChunk>` length and the per-chunk
/// receipt-signing preimage even when every chunk is tiny and the byte cap is
/// never reached. Generous for legitimate streams; `0` disables the cap.
pub const DEFAULT_MAX_STREAM_CHUNKS: u64 = 1_048_576;
pub const DEFAULT_CHECKPOINT_BATCH_SIZE: u64 = 100;
pub const DEFAULT_RETENTION_DAYS: u64 = 90;
pub const DEFAULT_MAX_SIZE_BYTES: u64 = 10_737_418_240;

/// Per-process memory budget: bounded-structure capacities plus a process RSS
/// soft ceiling. The soft ceiling is the in-process analog of the cgroup hard
/// limit: the kernel sheds (Overloaded) before the OS OOM-kills it.
#[derive(Debug, Clone)]
pub struct MemoryBudgetConfig {
    pub receipt_mirror_capacity: usize,
    pub federation_cache_capacity: usize,
    pub federation_cache_idle_ttl_secs: u64,
    pub velocity_bucket_cap: usize,
    pub admission_key_cap: usize,
    pub journal_entry_cap: usize,
    /// Max number of chunks retained from one streamed tool result. Bounds the
    /// retained `Vec<ToolCallChunk>` and the per-chunk signing preimage so a flood
    /// of tiny chunks that never trips `max_stream_total_bytes` still cannot grow
    /// memory without bound. `0` disables the cap.
    pub max_stream_chunks: u64,
    /// Max number of DISTINCT tool names retained in each session journal's
    /// cumulative `tool_counts` map. Unlike the `entries` and
    /// `tool_sequence` rings, `tool_counts` is cumulative (it survives ring
    /// eviction so the behavioral-sequence guard can answer "was this tool ever
    /// invoked"), so a ring cannot bound it. Once a session reaches this many
    /// distinct tool names a previously-unseen name is dropped fail-closed: a
    /// dependent required-predecessor check then treats it as never-invoked and
    /// denies. Sized well above any legitimate (registry-bounded) tool set.
    pub journal_tool_counts_cap: usize,
    /// Process RSS soft ceiling in bytes. When set and exceeded, new admissions
    /// shed with Overloaded { Allocation }. Set to roughly 85-90% of the cgroup
    /// memory.max so the graceful stop fires before the kill. Stage A ships None.
    pub rss_soft_limit_bytes: Option<u64>,
    /// How often the RSS sampler reads /proc/self/statm.
    pub rss_sample_interval_secs: u64,
}

impl MemoryBudgetConfig {
    pub fn defaults() -> Self {
        Self {
            receipt_mirror_capacity: 4096,
            federation_cache_capacity: 8192,
            federation_cache_idle_ttl_secs: 3600,
            velocity_bucket_cap: 65_536,
            admission_key_cap: 4096,
            journal_entry_cap: 4096,
            max_stream_chunks: DEFAULT_MAX_STREAM_CHUNKS,
            journal_tool_counts_cap: 4096,
            rss_soft_limit_bytes: None,
            rss_sample_interval_secs: 30,
        }
    }
}

impl Default for MemoryBudgetConfig {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Owns the RSS sampler thread; signals stop and joins on drop. On non-Linux
/// hosts the sampler is a no-op and the soft limit is inert (cgroup and
/// try_reserve backstops still apply).
pub(crate) struct RssSamplerHandle {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl RssSamplerHandle {
    pub(crate) fn spawn(shed: Arc<AtomicBool>, soft_limit_bytes: u64, interval_secs: u64) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let interval = std::time::Duration::from_secs(interval_secs.max(1));
        let join = std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            while !worker_stop.load(Ordering::SeqCst) {
                if let Some(rss) = read_process_rss_bytes() {
                    shed.store(rss > soft_limit_bytes, Ordering::Relaxed);
                }
                let mut waited = std::time::Duration::ZERO;
                let slice = std::time::Duration::from_millis(200);
                while waited < interval && !worker_stop.load(Ordering::SeqCst) {
                    std::thread::sleep(slice);
                    waited += slice;
                }
            }
        });
        Self {
            stop,
            join: Some(join),
        }
    }
}

impl Drop for RssSamplerHandle {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[cfg(target_os = "linux")]
fn read_process_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(resident_pages.saturating_mul(linux_page_size()))
}

/// Real system page size in bytes, read once via `sysconf(_SC_PAGESIZE)` and
/// cached. Hosts with non-4-KiB pages (for example common 64-KiB-page ARM
/// deployments) would otherwise undercount RSS by the page-size ratio and shed
/// far past the configured soft ceiling. Falls back to 4096 only if the query
/// fails.
#[cfg(target_os = "linux")]
fn linux_page_size() -> u64 {
    use std::sync::OnceLock;
    static PAGE_SIZE: OnceLock<u64> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| {
        // SAFETY: `sysconf` with a compile-time constant name has no
        // preconditions; it returns the configured page size, or -1 on failure.
        let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if raw > 0 {
            raw as u64
        } else {
            4096
        }
    })
}

#[cfg(not(target_os = "linux"))]
fn read_process_rss_bytes() -> Option<u64> {
    None
}

/// The Chio Runtime Kernel.
///
/// This is the central component of the Chio protocol. It validates capabilities,
/// runs guards, dispatches tool calls, and signs receipts.
///
/// The kernel is designed to be the sole trusted mediator. It never exposes its
/// signing key, address, or internal state to the agent.
pub struct ChioKernel {
    pub(super) config: KernelConfig,
    pub(super) durable_admission_mode: crate::admission_operation::DurableAdmissionMode,
    pub(super) durable_admission_runtime: Option<DurableAdmissionRuntime>,
    /// Explicit compatibility escape for development fixtures that exercise the
    /// legacy non-durable financial lifecycle. Production construction leaves
    /// this false, so a financial hold cannot cross a connector boundary without
    /// durable recovery coverage.
    pub(super) unsafe_ephemeral_financial_dispatch: bool,
    /// Guards are stored behind `Arc` so a single guard can be cloned into a
    /// `spawn_blocking` task without moving the whole pipeline, letting the
    /// deadline wrapper bound a blocking guard off the async worker.
    pub(super) guards: Arc<Vec<Arc<dyn Guard>>>,
    pub(super) post_invocation_pipeline: crate::post_invocation::PostInvocationPipeline,
    pub(super) budget_store: Arc<dyn BudgetStore>,
    pub(super) budget_store_lock: Mutex<()>,
    pub(super) revocation_store: Arc<dyn RevocationStore>,
    pub(super) capability_authority: Box<dyn CapabilityAuthority>,
    // Held behind `Arc` so a single connection can be cloned into a
    // `spawn_blocking` task, letting the dispatch deadline drive the call off the
    // async worker (a connection that blocks before its first `.await` cannot then
    // pin the worker).
    pub(super) tool_servers: HashMap<ServerId, Arc<dyn ToolServerConnection>>,
    pub(super) resource_providers: Vec<Box<dyn ResourceProvider>>,
    pub(super) prompt_providers: Vec<Box<dyn PromptProvider>>,
    pub(super) sessions: DashMap<SessionId, Arc<Session>>,
    pub(super) receipt_log: Mutex<ReceiptLog>,
    pub(super) child_receipt_log: Mutex<ChildReceiptLog>,
    /// Live entry-count gauges for the two receipt mirrors. Cloned from the
    /// ring's gauge at construction so telemetry and the
    /// bounded-structure registry (`bounded_structure_gauges`) can read the
    /// count without locking the log.
    pub(super) receipt_mirror_gauge: chio_bounded::SizeGauge,
    pub(super) child_receipt_mirror_gauge: chio_bounded::SizeGauge,
    pub(super) receipt_store: Option<Arc<dyn ReceiptStore>>,
    pub(super) receipt_store_write_lock: Mutex<()>,
    /// Retention maintenance worker, spawned at store attach when
    /// `config.retention_config` is `Some`. Owns a dedicated OS thread that
    /// calls `ReceiptStore::rotate_receipts` on `RetentionConfig.check_interval_secs`;
    /// joined when this field is dropped (kernel drop). `None` when
    /// retention is unconfigured or before a store is attached.
    pub(super) retention_maintenance: Option<crate::receipt_store::RetentionMaintenanceHandle>,
    pub(super) payment_adapter: Option<Box<dyn PaymentAdapter>>,
    pub(super) finding_purchase_verifier:
        Option<Arc<dyn crate::finding_purchase::FindingPurchaseVerifier>>,
    pub(super) finding_recovery_verifier:
        Option<Arc<dyn crate::finding_recovery::FindingRecoveryVerifier>>,
    pub(super) finding_status_proof_verifier:
        Option<Arc<dyn crate::finding_purchase::FindingStatusProofVerifier>>,
    /// Kernel keys explicitly trusted to issue Finding delivery receipts that
    /// may parent governed buyer-memory lineage.
    pub(super) finding_delivery_receipt_authorities: Vec<chio_core::crypto::PublicKey>,
    pub(super) finding_pool_allocation_authority: Option<chio_core::crypto::PublicKey>,
    pub(super) price_oracle: Option<Box<dyn PriceOracle>>,
    pub(super) runtime_admission_hook: Option<Arc<dyn RuntimeAdmissionHook>>,
    pub(super) runtime_admission_readiness_timeout: Duration,
    pub(super) runtime_trace_observer: Option<Arc<dyn RuntimeTraceObserver>>,
    pub(super) runtime_trace_transition_lock: Mutex<()>,
    pub(super) runtime_trace_sequence: AtomicU64,
    pub(super) attestation_trust_policy: Option<AttestationTrustPolicy>,
    pub(super) capability_crypto_floor: KernelCryptoFloor,
    /// How many receipts per Merkle checkpoint batch. Default: 100.
    pub(super) checkpoint_batch_size: u64,
    /// Monotonic counter for checkpoint_seq values.
    pub(super) checkpoint_seq_counter: AtomicU64,
    /// seq of the last receipt included in the previous checkpoint batch.
    pub(super) last_checkpoint_seq: AtomicU64,
    /// Nonce replay store for DPoP proof verification. Required when any grant has dpop_required.
    pub(super) dpop_nonce_store: Option<dpop::DpopNonceStore>,
    /// Configuration for DPoP proof verification TTLs and clock skew.
    pub(super) dpop_config: Option<dpop::DpopConfig>,
    /// Execution-nonce config (TTL, capacity, strict-mode flag).
    /// When `None`, no nonce is minted on allow and strict verification is
    /// disabled (compatibility deployments keep working).
    pub(super) execution_nonce_config: Option<crate::execution_nonce::ExecutionNonceConfig>,
    /// Replay-prevention store for execution nonces. Shared with
    /// any tool server that delegates verification to the kernel. Boxed
    /// trait object so SQLite-backed stores can be plugged in.
    pub(super) execution_nonce_store: Option<Box<dyn crate::execution_nonce::ExecutionNonceStore>>,
    /// Replay store for governed approval tokens. Key:
    /// `(subject_id, request_id, governed_intent_hash)`.
    pub(super) approval_replay_store:
        Option<Box<dyn crate::governed_approval_replay::GovernedApprovalReplayStore>>,
    pub(super) threshold_approval_requirement_resolver:
        Option<Arc<dyn crate::threshold_approval::ThresholdApprovalRequirementResolver>>,
    pub(super) supplemental_quota_verifier:
        Option<crate::supplemental_quota::SupplementalQuotaVerifierRuntime>,
    /// Emergency kill switch. When `true`, every evaluate entry point returns
    /// `Verdict::Deny` without performing capability validation or guard
    /// evaluation. Flipped by `emergency_stop` / `emergency_resume`.
    ///
    /// Reads use `Ordering::SeqCst` even on the hot path. The emergency check
    /// is a single atomic load per evaluate call (negligible cost relative to
    /// the guard pipeline) and `SeqCst` is the safest default for a rarely
    /// taken control path.
    pub(super) emergency_stopped: AtomicBool,
    /// Unix timestamp (seconds) at which the kill switch was last engaged.
    /// `0` means "never engaged" or "currently resumed". Written with
    /// `SeqCst` before `emergency_stopped` is set to `true`, cleared to `0`
    /// after `emergency_stopped` is set to `false`.
    pub(super) emergency_stopped_since: AtomicU64,
    /// Operator-supplied reason for the most recent emergency stop. Set on
    /// `emergency_stop`, cleared on `emergency_resume`. Stored behind
    /// ArcSwap so health probes can read the current reason without blocking.
    pub(super) emergency_stop_reason: ArcSwap<Option<String>>,
    /// Persistent degraded flag for the trusted computing base's locks. A
    /// poisoned budget-registry or session lock means a panic unwound
    /// mid-mutation, so the state it guarded may be half-updated. Tripping this
    /// flag makes the pre-dispatch gate fail evaluations closed until an
    /// operator-visible recovery, rather than silently proceeding on the
    /// recovered `into_inner` state. It is TCB-critical: any poison denies.
    pub(super) lock_poison: chio_supervisor::HealthFlag,
    /// Memory-provenance chain. When installed, every
    /// governed `MemoryWrite` action appends an entry after the allow
    /// receipt is signed, and every `MemoryRead` attaches the latest
    /// entry (or an `Unverified` marker) to its receipt as
    /// `memory_provenance` evidence metadata. `None` keeps the kernel
    /// backward-compatible: memory-shaped tool calls behave exactly as
    /// they do without a provenance chain installed.
    pub(super) memory_provenance: Option<Arc<dyn crate::memory_provenance::MemoryProvenanceStore>>,
    /// Cross-kernel federation peer set. When a request
    /// carries a `federated_origin_kernel_id` and that peer is pinned
    /// here (fresh), the kernel invokes `federation_cosigner` after
    /// locally signing the receipt to obtain the origin kernel's
    /// co-signature. Absent in non-federated deployments.
    pub(super) federation_peers:
        ArcSwap<HashMap<String, chio_federation::trust_establishment::FederationPeer>>,
    /// `ArcSwap` so trust-root rotations can land without holding a
    /// kernel mutex. Hex-keyed because `chio_core::PublicKey` does not
    /// implement `Hash`.
    pub(super) capability_trust_roots:
        ArcSwap<HashMap<String, chio_core::capability::attenuation::ScopeHash>>,
    /// Serializes read-modify-write updates to `capability_trust_roots`.
    /// Snapshot reads remain lock-free through ArcSwap.
    pub(super) capability_trust_roots_write_lock: Mutex<()>,
    /// Bilateral co-signer. Separate from the peer set so
    /// runtime can install it independently - for instance, a deployment
    /// can declare peers while still using a mock cosigner in tests.
    pub(super) federation_cosigner:
        Option<Arc<dyn chio_federation::bilateral::BilateralCoSigningProtocol>>,
    /// Locally-signed dual receipts, indexed by ChioReceipt.id.
    /// Populated only when the post-sign hook fires successfully. Kept
    /// in-memory; persistent storage plugs in via the federation-state
    /// APIs already in chio-federation.
    /// Capped, idle-swept, gauged instead of an unbounded DashMap: federated
    /// calls no longer grow kernel RSS without bound.
    pub(super) federation_dual_receipts:
        Mutex<chio_bounded::BoundedMap<String, chio_federation::bilateral::DualSignedReceipt>>,
    pub(super) federation_dual_receipts_gauge: chio_bounded::SizeGauge,
    /// DSSE signature-slice envelopes, indexed by ChioReceipt.id.
    /// These are emitted through the federation cosigner protocol rather than
    /// by loading Org A private key material in the tool-host kernel.
    pub(super) federation_dsse_envelopes:
        Mutex<chio_bounded::BoundedMap<String, chio_federation::bilateral_dsse::DsseEnvelope>>,
    pub(super) federation_dsse_envelopes_gauge: chio_bounded::SizeGauge,
    /// Optional durable backing for bilateral co-sign artifacts. When set, the
    /// co-sign hook writes through to it before caching and the
    /// accessors fall through to it on a cache miss.
    pub(super) federation_artifact_store:
        Option<std::sync::Arc<dyn crate::federation_artifact_store::FederationArtifactStore>>,
    /// Evaluation-keyed tenant scope for receipts. Async evaluate futures
    /// can resume on a different worker after dispatch, so the scope is
    /// stored in this map and selected through a task-local evaluation key.
    /// Non-tool session operations use a namespaced request-key fallback.
    pub(super) receipt_tenant_ids: Arc<DashMap<String, String>>,
    /// Evaluation-keyed copy of the receipt-version admission snapshot.
    /// Async evaluate futures may resume on a different Tokio worker
    /// after dispatch. This map keeps the admitted version and peer state
    /// isolated until that specific evaluation future finishes.
    pub(super) receipt_federation_admissions: Arc<DashMap<String, ReceiptFederationAdmission>>,
    /// Operator-declared kernel identifier used as the
    /// `org_b_kernel_id` in bilateral co-signing. Defaults to the hex
    /// encoding of the kernel's signing public key, but operators can
    /// override it to a stable DNS name via `with_federation_peers`.
    pub(super) federation_local_kernel_id: ArcSwap<Option<String>>,
    /// Mpsc-backed signing task handle. Owns a clone of `config.keypair` and
    /// pulls signing requests from a bounded channel; producers `.await` on
    /// backpressure rather than on a mutex. Spawned at [`ChioKernel::new`] and
    /// joined by [`ChioKernel::shutdown`]. Wrapped in `Arc` so shared kernel
    /// handles can pass the signing handle to in-flight evaluators without
    /// cloning the whole kernel.
    pub(super) signing_task: std::sync::Arc<signing_task::SigningTaskHandle>,
    pub(super) settlement_observer: Option<crate::settlement_routing::SettlementObserverRuntime>,
    /// Recursive-delegation oracle handle. When `Some`, the verifier consults this
    /// arc-swap-backed snapshot on every delegated dispatch and denies
    /// the capability if any link in the chain (or the leaf) is in the
    /// revoked set. `None` falls back to the per-row
    /// `RevocationStore` lookup. Field always present so the struct
    /// shape stays feature-flag agnostic.
    pub(super) revocation_view: Option<std::sync::Arc<chio_kernel_core::RevocationView>>,
    pub(super) budget_registry: Mutex<chio_kernel_core::InMemoryBudgetRegistry>,
    /// Sibling-sum shares held open by reserve-for-caller authorizations.
    ///
    /// A mediated authorization keeps its delegated child's admitted share in
    /// `budget_registry` while the reserved hold is open, so an outstanding
    /// reservation still counts against the parent and a sibling cannot
    /// over-subscribe it. Keyed by budget hold id, each entry carries the
    /// `(parent, child, share)` needed to release that headroom when the hold
    /// closes (reconciled by nonce or forfeited by the TTL reaper).
    pub(super) reserved_sibling_shares: Mutex<HashMap<String, ReservedSiblingShare>>,
    /// Fail-closed gate over delegated reserve-for-caller holds carried across a
    /// restart. A delegated reservation keeps its child's sibling-sum share
    /// admitted in `budget_registry` while its durable hold stays open, but that
    /// admission is in-memory only: a freshly built mediation kernel over a
    /// populated budget store loses it, and the durable hold record does not
    /// carry the parent capability id or the shares needed to rebuild it. Until
    /// every such hold from a prior process closes, this kernel denies delegated
    /// admission fail-closed so a sibling cannot be admitted against the parent as
    /// if the still-open reservation consumed nothing. Armed by
    /// [`ChioKernel::arm_restart_reserved_hold_gate`] at mediation-kernel startup.
    pub(super) restart_reserved_hold_gate: Mutex<RestartReservedHoldGate>,
    /// RSS soft-ceiling shed flag. Set by the sampler when process RSS exceeds
    /// `memory_budget.rss_soft_limit_bytes`; read on the
    /// admission fast path alongside the emergency stop.
    pub(super) rss_shed: Arc<AtomicBool>,
    /// Owns the sampler thread when a soft limit is configured; joins on drop.
    pub(super) rss_sampler: Option<RssSamplerHandle>,
    /// Receipt-writer liveness watchdog. Opt-in: the hosting edge spawns the
    /// poll task, which publishes the latest verdict into an `ArcSwap` the
    /// pre-dispatch readiness gate reads. Absent watchdog leaves the verdict
    /// `Unknown` and the gate behaves as before.
    pub(super) receipt_writer_watchdog:
        std::sync::Arc<receipt_writer_watchdog::ReceiptWriterWatchdogHandle>,
}

/// The parent/child/share triple a reserve-for-caller hold keeps admitted in
/// the sibling-sum `budget_registry` while its durable hold stays open. It is
/// recorded when the reservation is stamped and consumed to release the
/// parent's headroom once the hold is reconciled or reaped.
#[derive(Debug, Clone)]
pub(crate) struct ReservedSiblingShare {
    pub(crate) parent_token_id: String,
    pub(crate) child_token_id: String,
    pub(crate) share_bps: u16,
}

/// State of the fail-closed gate over delegated reserve-for-caller holds carried
/// across a restart. See [`super::ChioKernel::restart_reserved_hold_gate`].
#[derive(Debug, Clone)]
pub(crate) enum RestartReservedHoldGate {
    /// No unaccounted reserve holds from a prior process; delegated admission
    /// proceeds. Every kernel starts here and returns here once the durable open
    /// holds observed at startup have closed.
    Clear,
    /// The listed holds were open delegated reserve-for-caller holds when this
    /// kernel started and are not tracked in its in-memory sibling-share map.
    /// Delegated admission denies until each has closed (reconciled or reaped),
    /// re-queried per admission so the gate clears exactly when they settle.
    PendingHolds(std::collections::HashSet<String>),
    /// The budget store could not enumerate its reserved holds yet reported open
    /// holds at startup. Delegated admission denies until the open-hold count
    /// drains to zero; while denied this kernel opens no new holds, so the count
    /// faithfully tracks the prior process's holds draining away.
    PendingOpaqueCount,
}

impl ChioKernel {
    /// Construct the hybrid signing backend the kernel would use under
    /// `hybrid`'s configured floor and PQ key material after the kernel
    /// self-quote gate has run.
    ///
    /// Threads the kernel's classical Ed25519 keypair into a
    /// [`chio_core::crypto::Ed25519Backend`] under
    /// [`KernelCryptoFloor::AllowClassical`], or composes it with an
    /// [`chio_core::crypto::MlDsa65Backend`] derived from `hybrid.pq_signing_seed`
    /// into a [`chio_core::crypto::HybridBackend`] under
    /// [`KernelCryptoFloor::AllowHybrid`] or [`KernelCryptoFloor::PqRequired`],
    /// but only after [`crate::boot::load_kernel_signing_backend_after_self_quote`]
    /// accepts `self_quote_bytes`.
    ///
    /// Receipt body construction continues to flow through the existing
    /// inline path (`build_and_sign_receipt`); callers that opt in to
    /// hybrid signing pass the returned backend through
    /// [`crate::sign_receipt_body_with_backend`] (along with the canonical
    /// content preimage the body's `content_hash` was derived from) before
    /// persistence, so the hybrid path recomputes `content_hash` inside the
    /// trust boundary and is WYSIWYS fail-closed just like the inline
    /// classical path.
    ///
    /// # Errors
    ///
    /// Returns [`crate::boot::KernelBootError::SelfQuoteRejected`] when the
    /// self-quote verifier rejects a non-classical floor, or
    /// [`crate::boot::KernelBootError::SigningBackend`] when the configured
    /// floor needs a PQ key but `hybrid.pq_signing_seed` is `None`. Mirrors
    /// the policy-level check in `chio_policy::CryptoFloor::validate_with_pq_key`
    /// so the boot path catches the misconfiguration even when the policy crate
    /// is bypassed.
    pub fn with_hybrid_signing_backend(
        &mut self,
        hybrid: &HybridSigningConfig,
        self_quote_bytes: &[u8],
        verifier: &dyn crate::boot::KernelSelfQuoteVerifier,
    ) -> Result<Box<dyn chio_core::crypto::SigningBackend>, crate::boot::KernelBootError> {
        let backend = crate::boot::load_kernel_signing_backend_after_self_quote(
            hybrid.crypto_floor,
            self.config.keypair.clone(),
            hybrid.pq_signing_seed.as_ref(),
            self_quote_bytes,
            verifier,
        )?;
        self.capability_crypto_floor = hybrid.crypto_floor;
        Ok(backend)
    }
}
