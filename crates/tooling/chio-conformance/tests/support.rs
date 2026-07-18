#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use chio_core::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::{Keypair, PublicKey};
use chio_core::receipt::authoritative_spend::PresentedNonceView;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::ToolCallAction;
use chio_core::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::sha256_hex;
use chio_kernel::budget_store::BudgetStore;
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolInvocationCost,
    ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use std::sync::Arc;

pub struct MonetaryCostServer {
    id: String,
    reported_cost: Option<ToolInvocationCost>,
}

impl MonetaryCostServer {
    pub fn new(id: &str, cost_units: u64, currency: &str) -> Self {
        Self {
            id: id.to_string(),
            reported_cost: Some(ToolInvocationCost {
                units: cost_units,
                currency: currency.to_string(),
                breakdown: None,
            }),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for MonetaryCostServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, self.reported_cost.clone()))
    }
}

pub fn mediation_kernel(
    signer: &Keypair,
    budget: Arc<dyn BudgetStore>,
    require_nonce: bool,
) -> ChioKernel {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: signer.clone(),
        ca_public_keys: vec![signer.public_key()],
        max_delegation_depth: 5,
        policy_hash: "chio_api_protect_mediation_v1".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        // Reserve-only mediation kernel: money-path durability is the reserved-hold
        // reaper plus reconcile-by-nonce, so the in-process payment journal is off,
        // matching `build_mediation_kernel`.
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    });
    kernel.set_budget_store_handle(budget);
    let nonce_cfg = ExecutionNonceConfig {
        require_nonce,
        ..ExecutionNonceConfig::default()
    };
    kernel.set_execution_nonce_store(
        nonce_cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_cfg)),
    );
    kernel
}

pub fn issue_cost_bearing_capability(
    kernel: &ChioKernel,
    agent: &Keypair,
    server: &str,
    tool: &str,
    max_per: u64,
    max_total: u64,
    currency: &str,
) -> CapabilityToken {
    let grant = ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: max_per,
            currency: currency.to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: max_total,
            currency: currency.to_string(),
        }),
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    };
    kernel
        .issue_capability(&agent.public_key(), scope, 3600)
        .unwrap()
}

/// Build a sidecar-style advisory receipt from the fields of a mediated receipt.
/// The returned receipt carries `AdvisoryEvaluation` / `AdvisoryOnly` / `Advisory`
/// markers so `is_authoritative_spend_receipt` rejects it (mirroring
/// sidecar.rs:1091-1123 `ReceiptKind::AdvisoryEvaluation` path).
pub fn advisory_receipt(signer: &Keypair, mediated: &ChioReceipt) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: String::new(),
        timestamp: mediated.timestamp,
        capability_id: mediated.capability_id.clone(),
        tool_server: mediated.tool_server.clone(),
        tool_name: mediated.tool_name.clone(),
        action: mediated.action.clone(),
        decision: None,
        receipt_kind: ReceiptKind::AdvisoryEvaluation,
        boundary_class: BoundaryClass::AdvisoryOnly,
        observation_outcome: Some(ObservationOutcome::Evaluated),
        tool_origin: ToolOrigin::HostExecutedUnmediated,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: mediated.content_hash.clone(),
        policy_hash: mediated.policy_hash.clone(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Advisory,
        tenant_id: None,
        kernel_key: signer.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, signer).unwrap()
}

/// Minimal `PresentedNonceView` test double for standalone conformance tests
/// that need a nonce binding without a live kernel invocation.
pub struct FakePresentedNonce {
    nonce_id: String,
    capability_id: String,
    tool_server: String,
    tool_name: String,
    parameter_hash: String,
    reserved_hold_id: Option<String>,
    signer: PublicKey,
}

impl PresentedNonceView for FakePresentedNonce {
    fn nonce_id(&self) -> &str {
        &self.nonce_id
    }

    fn bound_capability_id(&self) -> &str {
        &self.capability_id
    }

    fn bound_tool_server(&self) -> &str {
        &self.tool_server
    }

    fn bound_tool_name(&self) -> &str {
        &self.tool_name
    }

    fn bound_parameter_hash(&self) -> &str {
        &self.parameter_hash
    }

    fn bound_reserved_hold_id(&self) -> Option<&str> {
        self.reserved_hold_id.as_deref()
    }

    fn verify_signed_by(&self, key: &PublicKey) -> bool {
        &self.signer == key
    }
}

/// Build a standalone advisory receipt without an existing mediated receipt to
/// copy fields from. All advisory markers are set exactly as in `advisory_receipt`.
pub fn standalone_advisory_receipt(
    signer: &Keypair,
    cap_id: &str,
    server: &str,
    tool: &str,
) -> ChioReceipt {
    let action = ToolCallAction::from_parameters(serde_json::json!({})).unwrap();
    let body = ChioReceiptBody {
        id: String::new(),
        timestamp: 0,
        capability_id: cap_id.to_string(),
        tool_server: server.to_string(),
        tool_name: tool.to_string(),
        action,
        decision: None,
        receipt_kind: ReceiptKind::AdvisoryEvaluation,
        boundary_class: BoundaryClass::AdvisoryOnly,
        observation_outcome: Some(ObservationOutcome::Evaluated),
        tool_origin: ToolOrigin::HostExecutedUnmediated,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: sha256_hex(b"content"),
        policy_hash: sha256_hex(b"policy"),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Advisory,
        tenant_id: None,
        kernel_key: signer.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, signer).unwrap()
}

/// Re-sign a receipt whose body has been mutated for an adversarial test case.
///
/// Calls [`ChioReceipt::sign`] when the body remains semantically valid; falls
/// back to returning the mutated receipt when semantics are intentionally
/// broken (e.g. `trust_level` flipped to `Advisory` while `receipt_kind` stays
/// `MediatedDecision`). [`is_authoritative_spend_receipt`] checks field values
/// and the admission check only, not the raw Ed25519 signature.
pub fn resign(signer: &Keypair, receipt: ChioReceipt) -> ChioReceipt {
    let body = receipt.body();
    ChioReceipt::sign(body, signer).unwrap_or(receipt)
}

/// Construct a `FakePresentedNonce` bound to the given fields.
///
/// The returned value implements `PresentedNonceView` so it can be passed to
/// `is_authoritative_spend_receipt` as a `&dyn PresentedNonceView` reference.
pub fn fake_bound_nonce(
    signer: &Keypair,
    cap_id: &str,
    server: &str,
    tool: &str,
    parameter_hash: &str,
) -> FakePresentedNonce {
    FakePresentedNonce {
        nonce_id: "fake-nonce".to_string(),
        capability_id: cap_id.to_string(),
        tool_server: server.to_string(),
        tool_name: tool.to_string(),
        parameter_hash: parameter_hash.to_string(),
        reserved_hold_id: None,
        signer: signer.public_key(),
    }
}

/// Construct a `FakePresentedNonce` with a caller-specified `nonce_id`.
///
/// Enables isolation of individual predicate fragments against a real receipt:
/// passing a wrong `nonce_id` isolates (d), a wrong binding field isolates (c),
/// and a `signer` key that differs from the receipt's `kernel_key` isolates (f).
pub fn fake_nonce_with_id(
    signer: &Keypair,
    nonce_id: &str,
    cap_id: &str,
    server: &str,
    tool: &str,
    parameter_hash: &str,
) -> FakePresentedNonce {
    FakePresentedNonce {
        nonce_id: nonce_id.to_string(),
        capability_id: cap_id.to_string(),
        tool_server: server.to_string(),
        tool_name: tool.to_string(),
        parameter_hash: parameter_hash.to_string(),
        reserved_hold_id: None,
        signer: signer.public_key(),
    }
}
