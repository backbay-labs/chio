use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::Keypair;
use chio_kernel::{
    ChioKernel, Guard, HotPathDeadlineConfig, KernelConfig, KernelError, NestedFlowBridge,
    ToolCallRequest, ToolServerConnection, Verdict, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::SqliteReceiptStore;
use tokio::runtime::{Builder, Runtime};

use crate::{LoadgenConfig, LoadgenError, StoreBacking};

const LOADGEN_SERVER_ID: &str = "chio-loadgen-fixture";
const LOADGEN_TOOL_NAME: &str = "loadgen_dispatch";

/// Seconds added on top of the run duration when minting the driving
/// capability, so it cannot expire during a full-length run.
const CAPABILITY_TTL_HEADROOM_SECONDS: u64 = 300;

/// Raw outcome of a single dispatch through the real kernel. Chaos scenarios
/// assert on this directly: `verdict` is the kernel's decision, `reason` carries
/// the denial reason (populated on a deny), and `elapsed` is the measured
/// end-to-end latency.
#[derive(Debug, Clone)]
pub struct DispatchOutcome {
    pub verdict: Verdict,
    pub reason: Option<String>,
    pub elapsed: Duration,
}

/// A booted real stack: a live kernel, an optional durable receipt store, the
/// driving capability, and the fixture tool server's shared latency control.
pub struct StackHarness {
    kernel: ChioKernel,
    runtime: Runtime,
    store: Option<Arc<SqliteReceiptStore>>,
    capability: CapabilityToken,
    tool_latency_nanos: Arc<AtomicU64>,
    request_counter: AtomicU64,
}

impl StackHarness {
    /// Gating entry point: rejects [`StoreBacking::Memory`] (fail-closed).
    pub fn boot(config: &LoadgenConfig) -> Result<Self, LoadgenError> {
        Self::boot_inner(config, false, HotPathDeadlineConfig::default())
    }

    /// Local smoke entry point: permits [`StoreBacking::Memory`].
    pub fn boot_smoke(config: &LoadgenConfig) -> Result<Self, LoadgenError> {
        Self::boot_inner(config, true, HotPathDeadlineConfig::default())
    }

    /// Gating boot with explicit hot-path deadline overrides. Used by chaos
    /// scenarios that drive the guard-pipeline or dispatch budget; otherwise
    /// identical to [`StackHarness::boot`] (a durable store is still required).
    pub fn boot_with_deadlines(
        config: &LoadgenConfig,
        deadlines: HotPathDeadlineConfig,
    ) -> Result<Self, LoadgenError> {
        Self::boot_inner(config, false, deadlines)
    }

    fn boot_inner(
        config: &LoadgenConfig,
        allow_memory: bool,
        deadlines: HotPathDeadlineConfig,
    ) -> Result<Self, LoadgenError> {
        // Dispatch workers call `block_on` concurrently to preserve the configured
        // open-loop arrival schedule. A multi-thread runtime is therefore part of
        // the load contract, not an optimization.
        let runtime = Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .map_err(|error| {
                LoadgenError::KernelBoot(format!("tokio runtime build failed: {error}"))
            })?;

        let mut kernel = ChioKernel::new(kernel_config(Keypair::generate(), deadlines));

        let tool_latency_nanos = Arc::new(AtomicU64::new(duration_as_nanos(config.tool_latency)));
        kernel.register_tool_server(Box::new(FixtureToolServer {
            latency_nanos: Arc::clone(&tool_latency_nanos),
        }));

        let store = match &config.store {
            StoreBacking::Memory => {
                if !allow_memory {
                    return Err(LoadgenError::MemoryStoreRejectedInGate);
                }
                None
            }
            StoreBacking::Sqlite { path } => {
                // A durable gate must not advertise persistence that a transient
                // SQLite path silently voids at exit. Reject, before opening:
                // `:memory:` / `file:...?mode=memory`, an empty filename, and a
                // `file:` URI whose main-database name is empty (e.g. `file:` or
                // `file:?mode=rwc`) - all of which SQLite opens as a private
                // temporary on-disk database deleted on close. The smoke path may
                // still use one. A non-UTF8 path cannot be a transient URI, so it
                // opens.
                let transient = path.as_os_str().is_empty()
                    || path.to_str().is_some_and(|raw| {
                        chio_store_sqlite::is_in_memory_sqlite_path(raw)
                            || sqlite_file_uri_names_empty_main_db(raw)
                    });
                if !allow_memory && transient {
                    return Err(LoadgenError::MemoryStoreRejectedInGate);
                }
                let opened = SqliteReceiptStore::open(path)
                    .map_err(|error| LoadgenError::StoreOpen(error.to_string()))?;
                let handle = Arc::new(opened);
                let kernel_handle: Arc<dyn chio_kernel::ReceiptStore> = handle.clone();
                kernel
                    .set_receipt_store_handle(kernel_handle)
                    .map_err(|error| LoadgenError::KernelBoot(error.to_string()))?;
                // Block until the async verified-head seed clears. A freshly opened
                // store serves closed (head-poisoned) until the commit writer seeds
                // the verified head on its actor thread, and the kernel's
                // pre-dispatch gate denies while the writer serves closed, so the
                // first dispatch would otherwise race the seed and fail closed
                // instead of measuring the allow path. Only the durable path has a
                // writer to seed.
                wait_for_writer_health(&handle)?;
                Some(handle)
            }
        };

        let subject = Keypair::generate();
        let ttl_seconds = config
            .duration
            .as_secs()
            .saturating_add(CAPABILITY_TTL_HEADROOM_SECONDS);
        let capability = kernel
            .issue_capability(&subject.public_key(), loadgen_scope(), ttl_seconds)
            .map_err(|error| LoadgenError::KernelBoot(error.to_string()))?;

        Ok(Self {
            kernel,
            runtime,
            store,
            capability,
            tool_latency_nanos,
            request_counter: AtomicU64::new(0),
        })
    }

    /// One allow-path dispatch through the real kernel; returns the measured
    /// end-to-end latency. A non-allow verdict or a kernel error is a
    /// mid-run dispatch failure.
    pub fn dispatch_allow_once(&self) -> Result<Duration, LoadgenError> {
        let request = self.build_request();
        let started = Instant::now();
        let response = self
            .runtime
            .block_on(self.kernel.evaluate_tool_call(&request));
        let elapsed = started.elapsed();

        match response {
            Ok(response) if response.verdict == Verdict::Allow => Ok(elapsed),
            Ok(response) => {
                Err(LoadgenError::Dispatch(response.reason.unwrap_or_else(
                    || "allow lane received a non-allow verdict".to_string(),
                )))
            }
            Err(error) => Err(LoadgenError::Dispatch(error.to_string())),
        }
    }

    /// Register a guard on the booted kernel before any dispatch. Used by chaos
    /// scenarios that inject a blocking guard to exercise the guard-pipeline
    /// deadline.
    pub fn add_guard(&mut self, guard: Box<dyn Guard>) {
        self.kernel.add_guard(guard);
    }

    /// One dispatch through the real kernel returning the raw verdict, reason,
    /// and measured latency, for chaos scenarios that assert on a fail-closed
    /// deny/timeout rather than an allow. A kernel error is surfaced as a typed
    /// dispatch failure, not a hang.
    pub fn dispatch_once_verdict(&self) -> Result<DispatchOutcome, LoadgenError> {
        let request = self.build_request();
        let started = Instant::now();
        let response = self
            .runtime
            .block_on(self.kernel.evaluate_tool_call(&request))
            .map_err(|error| LoadgenError::Dispatch(error.to_string()))?;
        Ok(DispatchOutcome {
            verdict: response.verdict,
            reason: response.reason,
            elapsed: started.elapsed(),
        })
    }

    /// Direct access to the durable store for chaos scenarios. `None` under a
    /// [`StoreBacking::Memory`] boot.
    pub fn store(&self) -> Option<&SqliteReceiptStore> {
        self.store.as_deref()
    }

    /// Force-flush pending receipt writes; returns the latest committed entry
    /// seq. A memory-backed harness has no durable log and reports 0.
    pub fn flush_durable(&self) -> Result<u64, LoadgenError> {
        match &self.store {
            Some(store) => {
                let report = store.flush_receipt_writes().map_err(|error| {
                    LoadgenError::Dispatch(format!("receipt flush failed: {error}"))
                })?;
                Ok(report.latest_committed_entry_seq)
            }
            None => Ok(0),
        }
    }

    /// Override the fixture tool server's per-invoke latency for the next
    /// dispatches; used by per-scenario fault injection. The knob is milliseconds
    /// (chaos scenarios drive whole-millisecond stalls) but is stored internally
    /// as nanoseconds so the fixture server honors sub-millisecond baselines.
    pub fn set_tool_latency_ms(&self, milliseconds: u64) {
        self.tool_latency_nanos
            .store(milliseconds.saturating_mul(1_000_000), Ordering::Relaxed);
    }

    fn build_request(&self) -> ToolCallRequest {
        let sequence = self.request_counter.fetch_add(1, Ordering::Relaxed);
        ToolCallRequest {
            request_id: format!("chio-loadgen-{sequence}"),
            capability: self.capability.clone(),
            tool_name: LOADGEN_TOOL_NAME.to_string(),
            server_id: LOADGEN_SERVER_ID.to_string(),
            agent_id: self.capability.subject.to_hex(),
            arguments: serde_json::json!({ "sequence": sequence }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }
    }
}

fn kernel_config(keypair: Keypair, deadlines: HotPathDeadlineConfig) -> KernelConfig {
    KernelConfig {
        keypair,
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "chio-loadgen-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        // Automatic checkpointing disabled: the load generator drives receipt
        // appends and durability accounting, not the Web3 checkpoint chain, so
        // the store attaches with no background signer.
        checkpoint_batch_size: 0,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines,
    }
}

fn loadgen_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: LOADGEN_SERVER_ID.to_string(),
            tool_name: LOADGEN_TOOL_NAME.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn duration_as_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Bound on how long a freshly opened durable store may take to seed its verified
/// head before boot fails closed. The commit writer seeds asynchronously and
/// serves closed until then; a store still unserved at this deadline is a boot
/// failure, not a first-dispatch flake to be exported into a measured run.
const WRITER_HEALTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval while waiting for the async verified-head seed to clear.
const WRITER_HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Poll a freshly opened durable store until its writer is serving and its health
/// report reads healthy, or fail closed at [`WRITER_HEALTH_TIMEOUT`]. This mirrors
/// the bounded wait the chaos scenarios use after a reopen, so the first sustained
/// dispatch measures the allow path instead of racing the async head seed.
fn wait_for_writer_health(store: &SqliteReceiptStore) -> Result<(), LoadgenError> {
    let deadline = Instant::now() + WRITER_HEALTH_TIMEOUT;
    loop {
        let serving = !store.writer_serving_closed();
        let healthy = store
            .receipt_store_health()
            .is_ok_and(|report| report.healthy);
        if serving && healthy {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(LoadgenError::KernelBoot(
                "receipt store writer did not become healthy before the boot deadline".to_string(),
            ));
        }
        std::thread::sleep(WRITER_HEALTH_POLL_INTERVAL);
    }
}

/// A tool server whose only behavior is to sleep for a runtime-configurable
/// latency before returning a fixed allow payload, so a dispatch measures the
/// real kernel path plus a controllable tool cost. The latency is held in
/// nanoseconds so a sub-millisecond configured cost is exercised rather than
/// truncated to a zero-latency invoke.
struct FixtureToolServer {
    latency_nanos: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for FixtureToolServer {
    fn server_id(&self) -> &str {
        LOADGEN_SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![LOADGEN_TOOL_NAME.to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let latency_nanos = self.latency_nanos.load(Ordering::Relaxed);
        if latency_nanos > 0 {
            tokio::time::sleep(Duration::from_nanos(latency_nanos)).await;
        }
        Ok(serde_json::json!({
            "tool": tool_name,
            "allowed": true,
            "echo": arguments,
        }))
    }
}

/// Whether a SQLite `file:` URI names an empty main database, which SQLite opens
/// as a private temporary on-disk database (deleted on close) rather than a
/// durable file. The main-database name is what remains after the `file:`
/// scheme and an optional `//authority`, taken before the `?query`; when it is
/// empty the database is transient. A plain filesystem path carries no `file:`
/// scheme and returns false here (it is handled by the empty and in-memory
/// checks at the call site).
fn sqlite_file_uri_names_empty_main_db(raw: &str) -> bool {
    let Some(after_scheme) = raw
        .strip_prefix("file:")
        .or_else(|| raw.strip_prefix("FILE:"))
    else {
        return false;
    };
    // Drop an optional `//authority`; the path begins at the authority's first
    // `/`, or is empty when the authority runs to the end of the string.
    let after_authority = match after_scheme.strip_prefix("//") {
        Some(rest) => rest.find('/').map_or("", |slash| &rest[slash..]),
        None => after_scheme,
    };
    // The main-database name is everything before the query string.
    after_authority.split('?').next().unwrap_or("").is_empty()
}

#[cfg(test)]
mod tests {
    use super::sqlite_file_uri_names_empty_main_db;

    #[test]
    fn empty_main_db_file_uris_are_transient() {
        for raw in ["file:", "file:?mode=rwc", "file://", "file://localhost"] {
            assert!(
                sqlite_file_uri_names_empty_main_db(raw),
                "{raw} names an empty main database and must read transient"
            );
        }
    }

    #[test]
    fn named_paths_are_not_transient() {
        for raw in [
            "file:receipts.db",
            "file:/abs/receipts.db",
            "file:///abs/receipts.db",
            "file:receipts.db?mode=rwc",
            "receipts.db",
            "/abs/receipts.db",
        ] {
            assert!(
                !sqlite_file_uri_names_empty_main_db(raw),
                "{raw} names a durable database and must not read transient"
            );
        }
    }
}
