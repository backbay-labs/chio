use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityToken,
};
use chio_core::crypto::Keypair;
use chio_core::receipt::body::ChioReceipt;
use chio_kernel::admission_operation::DurableAdmissionMode;
use chio_kernel::settlement_observer::{run_observer, SettlementObserverStatus};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ReceiptStore, ToolCallRequest,
    ToolServerConnection, Verdict, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_settle::{
    RetryPolicy, SettlementAttemptClaim, SettlementHook, SettlementHookError,
    SettlementObservation, SettlementOutcome, SettlementOutcomeStore, SettlementRoute,
    SettlementRouteError, SettlementRoutingInput, SettlementStoreBinding,
};
use chio_store_sqlite::{SqliteReceiptStore, SqliteSettlementOutcomeStore};

struct EchoServer;

#[async_trait::async_trait]
impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        "settlement"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["charge".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(arguments)
    }
}

#[derive(Clone, Copy)]
enum CrashMode {
    BeforeClaim,
    AfterClaim,
    AfterHook,
}

struct CrashOutcomeStore {
    inner: Arc<SqliteSettlementOutcomeStore>,
    mode: CrashMode,
    claimed: Mutex<Option<SettlementAttemptClaim>>,
}

impl CrashOutcomeStore {
    fn new(inner: Arc<SqliteSettlementOutcomeStore>, mode: CrashMode) -> Arc<Self> {
        Arc::new(Self {
            inner,
            mode,
            claimed: Mutex::new(None),
        })
    }

    fn captured_claim(&self) -> Result<SettlementAttemptClaim, Box<dyn Error>> {
        self.claimed
            .lock()
            .map_err(|_| std::io::Error::other("claim lock poisoned"))?
            .clone()
            .ok_or_else(|| std::io::Error::other("claim was not captured").into())
    }
}

impl SettlementOutcomeStore for CrashOutcomeStore {
    fn settlement_store_binding(&self) -> SettlementStoreBinding {
        self.inner.settlement_store_binding()
    }

    fn claim_receipt(
        &self,
        receipt_id: &str,
        worker_id: &str,
        now_ms: u64,
        lease_ms: u64,
    ) -> Result<Option<SettlementAttemptClaim>, SettlementRouteError> {
        if matches!(self.mode, CrashMode::BeforeClaim) {
            return Err(SettlementRouteError::Backend {
                detail: "simulated crash before claim".to_string(),
            });
        }
        let claim = self
            .inner
            .claim_receipt(receipt_id, worker_id, now_ms, lease_ms)?;
        if let Some(claim) = claim.as_ref() {
            *self
                .claimed
                .lock()
                .map_err(|_| SettlementRouteError::Backend {
                    detail: "claim lock poisoned".to_string(),
                })? = Some(claim.clone());
        }
        if matches!(self.mode, CrashMode::AfterClaim) {
            return Ok(None);
        }
        Ok(claim)
    }

    fn claim_due(
        &self,
        worker_id: &str,
        now_ms: u64,
        lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<SettlementAttemptClaim>, SettlementRouteError> {
        self.inner.claim_due(worker_id, now_ms, lease_ms, limit)
    }

    fn record_claimed_outcome(
        &self,
        _claim: &SettlementAttemptClaim,
        _outcome: &SettlementRoutingInput,
        _policy: RetryPolicy,
        _observed_at_ms: u64,
    ) -> Result<SettlementRoute, SettlementRouteError> {
        Err(SettlementRouteError::Backend {
            detail: "simulated crash after hook".to_string(),
        })
    }
}

#[derive(Default)]
struct AcceptingHook {
    calls: AtomicUsize,
}

impl SettlementHook for AcceptingHook {
    fn observe(
        &self,
        _observation: &SettlementObservation,
        _idempotency_key: &chio_settle::SettlementIdempotencyKey,
    ) -> Result<SettlementOutcome, SettlementHookError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(SettlementOutcome::accepted("accepted"))
    }
}

fn kernel_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "test-policy-hash".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: 0,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

fn scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "settlement".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn request(request_id: &str, capability: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: "charge".to_string(),
        server_id: "settlement".to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({ "units": 100 }),
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

fn kernel(
    receipts: &Arc<SqliteReceiptStore>,
    outcomes: Arc<dyn SettlementOutcomeStore>,
    hook: Arc<dyn SettlementHook>,
) -> Result<(ChioKernel, CapabilityToken), KernelError> {
    let mut kernel = ChioKernel::new(kernel_config());
    kernel
        .configure_durable_admission(DurableAdmissionMode::Monetary, false)
        .map_err(KernelError::from)?;
    kernel.register_tool_server(Box::new(EchoServer));
    let capability = kernel.issue_capability(&Keypair::generate().public_key(), scope(), 300)?;
    let receipt_store: Arc<dyn ReceiptStore> = receipts.clone();
    kernel.set_receipt_store_handle(receipt_store)?;
    kernel.set_settlement_observer_runtime(hook, outcomes, RetryPolicy::default())?;
    Ok((kernel, capability))
}

fn execute(
    kernel: &ChioKernel,
    capability: &CapabilityToken,
    request_id: &str,
) -> Result<ChioReceipt, KernelError> {
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &request(request_id, capability),
        Some(serde_json::json!({
            "financial": {
                "grant_index": 0,
                "cost_charged": 100,
                "currency": "USD",
                "budget_remaining": 900,
                "budget_total": 1000,
                "delegation_depth": 0,
                "root_budget_holder": capability.subject.to_hex(),
                "settlement_status": "pending"
            }
        })),
    )?;
    assert_eq!(response.verdict, Verdict::Allow);
    Ok(response.receipt)
}

fn recover_accepted(
    outcomes: &SqliteSettlementOutcomeStore,
    hook: &Arc<AcceptingHook>,
    receipt: &ChioReceipt,
    claim: &SettlementAttemptClaim,
    observed_at_ms: u64,
) -> Result<SettlementRoute, Box<dyn Error>> {
    let hook_handle: Arc<dyn SettlementHook> = hook.clone();
    let status = run_observer(
        Some(&hook_handle),
        receipt,
        std::slice::from_ref(&receipt.kernel_key),
        &chio_settle::SettlementIdempotencyKey {
            receipt_id: claim.receipt_id.clone(),
            row_version: claim.row_version,
        },
    );
    assert!(matches!(
        status,
        SettlementObserverStatus::Observed {
            outcome: SettlementOutcome::Accepted { .. }
        }
    ));
    Ok(outcomes.record_claimed_outcome(
        claim,
        &SettlementRoutingInput::Accepted,
        RetryPolicy::default(),
        observed_at_ms,
    )?)
}

fn exercise_crash_mode(
    receipts: &Arc<SqliteReceiptStore>,
    outcomes: &Arc<SqliteSettlementOutcomeStore>,
    mode: CrashMode,
    label: &str,
    initial_hook_calls: usize,
) -> Result<(), Box<dyn Error>> {
    const RECOVERY_NOW_MS: u64 = 4_000_000_000_000;

    let crash_store = CrashOutcomeStore::new(Arc::clone(outcomes), mode);
    let hook = Arc::new(AcceptingHook::default());
    let outcome_handle: Arc<dyn SettlementOutcomeStore> = crash_store.clone();
    let hook_handle: Arc<dyn SettlementHook> = hook.clone();
    let (kernel, capability) = kernel(receipts, outcome_handle, hook_handle)?;
    let receipt = execute(&kernel, &capability, label)?;

    assert_eq!(hook.calls.load(Ordering::SeqCst), initial_hook_calls);
    assert!(receipts.load_chio_receipt(&receipt.id)?.is_some());
    let stale = if matches!(mode, CrashMode::BeforeClaim) {
        None
    } else {
        Some(crash_store.captured_claim()?)
    };
    let recovery_now_ms = stale
        .as_ref()
        .map_or(RECOVERY_NOW_MS, |claim| claim.lease_until_ms);
    let recovered = outcomes
        .claim_receipt(
            &receipt.id,
            &format!("recovery-{label}"),
            recovery_now_ms,
            1_000,
        )?
        .ok_or_else(|| std::io::Error::other("settlement work was not reclaimable"))?;
    if let Some(stale) = stale.as_ref() {
        assert!(matches!(
            outcomes.record_claimed_outcome(
                stale,
                &SettlementRoutingInput::Accepted,
                RetryPolicy::default(),
                recovery_now_ms,
            ),
            Err(SettlementRouteError::Conflict { .. })
        ));
    }
    assert_eq!(
        recover_accepted(outcomes, &hook, &receipt, &recovered, recovery_now_ms)?,
        SettlementRoute::NoAction
    );
    assert_eq!(hook.calls.load(Ordering::SeqCst), initial_hook_calls + 1);
    Ok(())
}

#[test]
fn settlement_routing_sqlite_recovery_reclaims_work_and_rejects_stale_claims(
) -> Result<(), Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!(
        "chio-settlement-recovery-{}-{}.sqlite3",
        std::process::id(),
        uuid::Uuid::now_v7()
    ));
    let receipts = Arc::new(SqliteReceiptStore::open(&path)?);
    let outcomes = Arc::new(SqliteSettlementOutcomeStore::open_alongside(&receipts)?);

    exercise_crash_mode(
        &receipts,
        &outcomes,
        CrashMode::BeforeClaim,
        "before-claim",
        0,
    )?;
    exercise_crash_mode(
        &receipts,
        &outcomes,
        CrashMode::AfterClaim,
        "after-claim",
        0,
    )?;
    exercise_crash_mode(&receipts, &outcomes, CrashMode::AfterHook, "after-hook", 1)?;

    drop(outcomes);
    drop(receipts);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    Ok(())
}
