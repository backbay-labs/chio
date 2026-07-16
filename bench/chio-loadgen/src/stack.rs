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

const LOADGEN_SERVER_ID: &str = "chio-loadgen-stub";
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
/// driving capability, and the stub tool server's shared latency control.
pub struct StackHarness {
    kernel: ChioKernel,
    runtime: Runtime,
    store: Option<Arc<SqliteReceiptStore>>,
    capability: CapabilityToken,
    tool_latency_ms: Arc<AtomicU64>,
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
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                LoadgenError::KernelBoot(format!("tokio runtime build failed: {error}"))
            })?;

        let mut kernel = ChioKernel::new(kernel_config(Keypair::generate(), deadlines));

        let tool_latency_ms = Arc::new(AtomicU64::new(duration_as_millis(config.tool_latency)));
        kernel.register_tool_server(Box::new(StubToolServer {
            latency_ms: Arc::clone(&tool_latency_ms),
        }));

        let store = match &config.store {
            StoreBacking::Memory => {
                if !allow_memory {
                    return Err(LoadgenError::MemoryStoreRejectedInGate);
                }
                None
            }
            StoreBacking::Sqlite { path } => {
                let opened = SqliteReceiptStore::open(path)
                    .map_err(|error| LoadgenError::StoreOpen(error.to_string()))?;
                let handle = Arc::new(opened);
                let kernel_handle: Arc<dyn chio_kernel::ReceiptStore> = handle.clone();
                kernel
                    .set_receipt_store_handle(kernel_handle)
                    .map_err(|error| LoadgenError::KernelBoot(error.to_string()))?;
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
            tool_latency_ms,
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

    /// Override the stub tool server's per-invoke latency for the next
    /// dispatches; used by per-scenario fault injection.
    pub fn set_tool_latency_ms(&self, milliseconds: u64) {
        self.tool_latency_ms.store(milliseconds, Ordering::Relaxed);
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
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
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

fn duration_as_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// A tool server whose only behavior is to sleep for a runtime-configurable
/// latency before returning a fixed allow payload, so a dispatch measures the
/// real kernel path plus a controllable tool cost.
struct StubToolServer {
    latency_ms: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for StubToolServer {
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
        let latency_ms = self.latency_ms.load(Ordering::Relaxed);
        if latency_ms > 0 {
            tokio::time::sleep(Duration::from_millis(latency_ms)).await;
        }
        Ok(serde_json::json!({
            "tool": tool_name,
            "allowed": true,
            "echo": arguments,
        }))
    }
}
