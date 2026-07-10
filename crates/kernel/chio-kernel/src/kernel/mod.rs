use std::sync::Arc;

use chio_appraisal::VerifiedRuntimeAttestationRecord;
use chio_core::receipt::metadata::GuardEvidence;
use dashmap::DashMap;

use crate::budget_store::BudgetCommitMetadata;
use crate::*;

mod error;
mod kernel_drop_guard;
mod kernel_scopes;
mod kernel_struct;

pub use error::{KernelError, StructuredErrorReport};
pub use kernel_struct::{
    ChioKernel, HybridSigningConfig, KernelConfig, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_SIZE_BYTES, DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
    DEFAULT_RETENTION_DAYS,
};

pub(crate) use kernel_drop_guard::{
    dispatch_error_precedes_tool_side_effect, reserved_runtime_admission_ids,
    PostAdmissionDropGuard, PostAdmissionReceiptContext,
};
pub(crate) use kernel_scopes::{
    current_scoped_receipt_federation_admission, current_scoped_receipt_tenant_id,
    extract_tenant_id_from_auth_context, scope_receipt_federation_admission,
    scope_receipt_tenant_id, ReceiptFederationAdmission, ScopedKernelReceiptFederationAdmission,
    ScopedKernelReceiptTenantId,
};
pub(crate) use kernel_struct::{capability_crypto_floor, receipt_crypto_floor};

pub type AgentId = String;

/// A string-typed capability identifier.
pub type CapabilityId = String;

/// A string-typed server identifier.
pub type ServerId = String;

/// Deny reason surfaced by every evaluate path when the emergency kill
/// switch is engaged. Exposed as `pub` so HTTP adapters and SDKs can
/// pattern-match on the exact string without drifting.
pub const EMERGENCY_STOP_DENY_REASON: &str = "kernel emergency stop active";

/// Context passed to optional runtime admission hooks after capability,
/// request matching, governed-admission, and guard checks pass, but before
/// dispatch and federation co-signing side effects.
pub struct RuntimeAdmissionContext<'a> {
    pub request: &'a ToolCallRequest,
    pub extra_metadata: Option<&'a serde_json::Value>,
    pub now_unix_secs: u64,
    pub now_unix_ms: u64,
    pub matched_grant_index: Option<usize>,
    pub local_kernel_id: String,
}

/// Decision returned by a runtime admission hook.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeAdmissionDecision {
    pub allowed: bool,
    pub reason: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl RuntimeAdmissionDecision {
    #[must_use]
    pub fn allow(metadata: Option<serde_json::Value>) -> Self {
        Self {
            allowed: true,
            reason: None,
            metadata,
        }
    }

    #[must_use]
    pub fn deny(reason: impl Into<String>, metadata: Option<serde_json::Value>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
            metadata,
        }
    }
}

/// Optional pre-dispatch admission hook for product-specific runtime gates.
pub trait RuntimeAdmissionHook: Send + Sync {
    fn name(&self) -> &str;

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError>;

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        Ok(())
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelFederationTreatyDsseMetadata {
    capability_lease_ref: chio_federation::bilateral_dsse::CapabilityLeaseRef,
    policy_evaluation_summary: chio_federation::bilateral_dsse::PolicyEvaluationSummary,
    #[serde(default)]
    governance_receipt_ref: Option<chio_federation::bilateral_dsse::GovernanceReceiptRef>,
    #[serde(default)]
    consistency_anchor: Option<String>,
    #[serde(default)]
    consistency_model: Option<String>,
    #[serde(default)]
    cross_org_visibility: Option<String>,
    treaty_binding_ref: chio_federation::bilateral_dsse::TreatyBindingRef,
}

#[derive(Debug)]
pub(crate) struct ReceiptContent {
    pub(crate) content_hash: String,
    pub(crate) metadata: Option<serde_json::Value>,
    /// The exact byte preimage `content_hash` was computed over, carried so the
    /// signing boundary can independently recompute the hash and refuse to sign
    /// on mismatch (WYSIWYS). For value outputs this is the RFC 8785
    /// canonical JSON; for streams the concatenated per-chunk digest preimage;
    /// for the empty output the literal `null` canonicalization.
    pub(crate) canonical_content: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ValidatedGovernedCallChainProof {
    upstream_proof: Option<chio_core::capability::governance::GovernedUpstreamCallChainProof>,
    continuation_token_id: Option<String>,
    session_anchor_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ValidatedGovernedAdmission {
    call_chain_proof: Option<ValidatedGovernedCallChainProof>,
    verified_runtime_attestation: Option<VerifiedRuntimeAttestationRecord>,
}

#[derive(Debug, Clone)]
pub(crate) enum LocalReceiptArtifact {
    Tool(Box<chio_core::receipt::body::ChioReceipt>),
    Child(Box<chio_core::receipt::lineage::ChildRequestReceipt>),
}

impl LocalReceiptArtifact {
    fn verify_signature_with_floor(
        &self,
        floor: chio_core::receipt::crypto_floor::ReceiptCryptoFloor,
    ) -> Result<bool, KernelError> {
        match self {
            Self::Tool(receipt) => receipt.verify_signature_with_floor(floor).map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "governed call_chain parent receipt failed signature verification: {error}"
                ))
            }),
            Self::Child(receipt) => receipt.verify_signature_with_floor(floor).map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "governed call_chain parent receipt failed signature verification: {error}"
                ))
            }),
        }
    }

    fn artifact_hash(&self) -> Result<String, KernelError> {
        let canonical = match self {
            Self::Tool(receipt) => canonical_json_bytes(receipt),
            Self::Child(receipt) => canonical_json_bytes(receipt),
        }
        .map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "failed to hash governed call_chain parent receipt: {error}"
            ))
        })?;
        Ok(sha256_hex(&canonical))
    }

    fn session_anchor_reference(&self) -> Option<chio_core::session::SessionAnchorReference> {
        let metadata = match self {
            Self::Tool(receipt) => receipt.metadata.as_ref(),
            Self::Child(receipt) => receipt.metadata.as_ref(),
        };
        extract_session_anchor_reference_from_metadata(metadata)
    }
}

/// Bridge a sync caller to the async tool-server dispatch path.
///
/// Calling `futures::executor::block_on` from inside a current-thread
/// Tokio runtime parks the very thread that the runtime needs to drive
/// its reactor / timer wheel, and any tool-server future that awaits
/// Tokio I/O deadlocks silently. Tokio refuses
/// to nest `block_on` calls precisely because of this, but
/// `futures::executor::block_on` is a different executor that does not
/// see the surrounding runtime, so the deadlock manifests as a hung
/// tool call rather than a typed error.
///
/// Three cases are distinguished:
///   1. Multi-thread runtime active: use `block_in_place` so Tokio can
///      move the blocking work off the runtime threads. This is the
///      supported path.
///   2. Current-thread runtime active: refuse fail-closed with
///      [`KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime`].
///      Sync callers are expected to move the host to a multi-thread runtime
///      or call an async-native kernel entrypoint instead of this bridge.
///   3. No runtime active: drive the future with a non-tokio executor.
///      No surrounding runtime exists to deadlock; tool-server impls
///      that need Tokio I/O fail when they try to spawn
///      tasks, which is the correct, observable failure mode.
fn block_on_async_tool_dispatch<F, T>(future: F) -> Result<T, KernelError>
where
    F: std::future::Future<Output = Result<T, KernelError>>,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| handle.block_on(future))
        }
        Ok(_handle) => {
            // Current-thread runtime active. Bridging here would deadlock
            // any tool-server future that awaits Tokio I/O because we
            // would park the runtime's only worker thread. Surface a
            // typed error so the caller sees the architectural
            // incompatibility instead of a silent hang.
            Err(KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime)
        }
        Err(_) => {
            // No Tokio runtime active. The future cannot collide with a
            // surrounding reactor; the non-tokio executor is the safe
            // bridge. This is the path the in-process, compute-only
            // tool servers used in unit tests rely on.
            futures::executor::block_on(future)
        }
    }
}

fn extract_session_anchor_reference_from_metadata(
    metadata: Option<&serde_json::Value>,
) -> Option<chio_core::session::SessionAnchorReference> {
    let metadata = metadata?;
    let candidates = [
        metadata
            .get("governed_transaction")
            .and_then(|value| value.get("call_chain")),
        metadata.get("lineageReferences"),
    ];

    for candidate in candidates.into_iter().flatten() {
        let Some(session_anchor_id) = candidate
            .get("sessionAnchorId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        let Some(session_anchor_hash) = candidate
            .get("sessionAnchorHash")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        return Some(chio_core::session::SessionAnchorReference::new(
            session_anchor_id,
            session_anchor_hash,
        ));
    }

    None
}

/// A policy guard that the kernel evaluates before forwarding a tool call.
///
/// A guard is a pluggable policy check, adapted for the Chio tool-call
/// context. Each guard inspects the request and returns a verdict.
#[derive(Debug, Clone)]
pub struct GuardDecision {
    pub verdict: Verdict,
    pub evidence: Vec<GuardEvidence>,
}

impl GuardDecision {
    #[must_use]
    pub fn allow() -> Self {
        Self {
            verdict: Verdict::Allow,
            evidence: Vec::new(),
        }
    }

    #[must_use]
    pub fn allow_with_evidence(evidence: Vec<GuardEvidence>) -> Self {
        Self {
            verdict: Verdict::Allow,
            evidence,
        }
    }

    #[must_use]
    pub fn deny(evidence: Vec<GuardEvidence>) -> Self {
        Self {
            verdict: Verdict::Deny,
            evidence,
        }
    }

    #[must_use]
    pub fn pending_approval(evidence: Vec<GuardEvidence>) -> Self {
        Self {
            verdict: Verdict::PendingApproval,
            evidence,
        }
    }

    #[must_use]
    pub fn from_verdict(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self::allow(),
            Verdict::Deny => Self::deny(Vec::new()),
            Verdict::PendingApproval => Self::pending_approval(Vec::new()),
        }
    }
}

impl PartialEq<Verdict> for GuardDecision {
    fn eq(&self, other: &Verdict) -> bool {
        self.verdict == *other
    }
}

impl PartialEq<GuardDecision> for Verdict {
    fn eq(&self, other: &GuardDecision) -> bool {
        *self == other.verdict
    }
}

pub trait Guard: Send + Sync {
    /// Human-readable guard name (e.g., "forbidden-path").
    fn name(&self) -> &str;

    /// Evaluate the guard against a tool call request.
    ///
    /// Returns an allow or deny decision with optional evidence, or `Err` on
    /// internal failure (which the kernel treats as deny).
    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError>;
}

/// Context passed to guards during evaluation.
pub struct GuardContext<'a> {
    /// The tool call request being evaluated.
    pub request: &'a ToolCallRequest,
    /// The verified capability scope.
    pub scope: &'a ChioScope,
    /// The agent making the request.
    pub agent_id: &'a AgentId,
    /// The target server.
    pub server_id: &'a ServerId,
    /// Session-scoped enforceable filesystem roots, when the request is being
    /// evaluated through the supported session-backed runtime path.
    pub session_filesystem_roots: Option<&'a [String]>,
    /// Index of the matched grant in the capability's scope, populated by
    /// check_and_increment_budget before guards run.
    pub matched_grant_index: Option<usize>,
}

/// Trait representing a resource provider.
pub trait ResourceProvider: Send + Sync {
    /// List the resources this provider exposes.
    fn list_resources(&self) -> Vec<ResourceDefinition>;

    /// List parameterized resource templates.
    fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
        vec![]
    }

    /// Read a resource by URI. Returns `Ok(None)` when the provider does not own the URI.
    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError>;

    /// Return completions for a resource template or URI reference.
    fn complete_resource_argument(
        &self,
        _uri: &str,
        _argument_name: &str,
        _value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        Ok(None)
    }
}

/// Trait representing a prompt provider.
pub trait PromptProvider: Send + Sync {
    /// List available prompts.
    fn list_prompts(&self) -> Vec<PromptDefinition>;

    /// Retrieve a prompt by name. Returns `Ok(None)` when the provider does not own the prompt.
    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, KernelError>;

    /// Return completions for a prompt argument.
    fn complete_prompt_argument(
        &self,
        _name: &str,
        _argument_name: &str,
        _value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        Ok(None)
    }
}

/// In-memory append-only log of signed receipts.
///
/// This remains useful for process-local inspection even when a durable
/// backend is configured.
#[derive(Clone, Default)]
pub struct ReceiptLog {
    receipts: Vec<ChioReceipt>,
}

impl ReceiptLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, receipt: ChioReceipt) {
        self.receipts.push(receipt);
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn receipts(&self) -> &[ChioReceipt] {
        &self.receipts
    }

    pub fn get(&self, index: usize) -> Option<&ChioReceipt> {
        self.receipts.get(index)
    }
}

/// In-memory append-only log of signed child-request receipts.
#[derive(Clone, Default)]
pub struct ChildReceiptLog {
    receipts: Vec<ChildRequestReceipt>,
}

impl ChildReceiptLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, receipt: ChildRequestReceipt) {
        self.receipts.push(receipt);
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn receipts(&self) -> &[ChildRequestReceipt] {
        &self.receipts
    }

    pub fn get(&self, index: usize) -> Option<&ChildRequestReceipt> {
        self.receipts.get(index)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MatchingGrant<'a> {
    pub(crate) index: usize,
    pub(crate) grant: &'a ToolGrant,
    pub(crate) specificity: (u8, u8, usize),
}

/// Result of a monetary budget charge attempt.
///
/// Carries the accounting info needed to populate FinancialReceiptMetadata.
pub(crate) struct BudgetChargeResult {
    grant_index: usize,
    cost_charged: u64,
    currency: String,
    budget_total: u64,
    /// Running committed cost after this charge (used to compute budget_remaining).
    new_committed_cost_units: u64,
    budget_hold_id: String,
    authorize_metadata: BudgetCommitMetadata,
}

impl BudgetChargeResult {
    /// The rail/store hold id for the monetary budget charge, so a cleanup
    /// fault can name the stuck budget hold that needs manual recovery.
    pub(crate) fn budget_hold_id(&self) -> &str {
        &self.budget_hold_id
    }

    fn reverse_event_id(&self) -> String {
        format!("{}:reverse", self.budget_hold_id)
    }

    fn reconcile_event_id(&self) -> String {
        format!("{}:reconcile", self.budget_hold_id)
    }
}

pub(crate) enum PreExecutionBudgetMutation {
    None,
    Invocation { grant_index: usize },
    Charge(BudgetChargeResult),
}

impl PreExecutionBudgetMutation {
    fn charge_result(&self) -> Option<&BudgetChargeResult> {
        match self {
            Self::Charge(charge) => Some(charge),
            Self::None | Self::Invocation { .. } => None,
        }
    }

    fn into_charge_result(self) -> Option<BudgetChargeResult> {
        match self {
            Self::Charge(charge) => Some(charge),
            Self::None | Self::Invocation { .. } => None,
        }
    }
}

struct SessionNestedFlowBridge<'a, C> {
    sessions: &'a DashMap<SessionId, Arc<Session>>,
    child_receipts: &'a mut Vec<ChildRequestReceipt>,
    parent_context: &'a OperationContext,
    allow_sampling: bool,
    allow_sampling_tool_use: bool,
    allow_elicitation: bool,
    policy_hash: &'a str,
    kernel_keypair: &'a Keypair,
    client: &'a mut C,
}

impl<C> SessionNestedFlowBridge<'_, C> {
    fn complete_child_request_with_receipt<T: serde::Serialize>(
        &mut self,
        child_context: &OperationContext,
        operation_kind: OperationKind,
        result: &Result<T, KernelError>,
    ) -> Result<(), KernelError> {
        let terminal_state = child_terminal_state(&child_context.request_id, result);
        complete_session_request_with_terminal_state_in_sessions(
            self.sessions,
            &child_context.session_id,
            &child_context.request_id,
            terminal_state.clone(),
        )?;

        let receipt = build_child_request_receipt(
            self.policy_hash,
            self.kernel_keypair,
            child_context,
            operation_kind,
            terminal_state,
            child_outcome_payload(result)?,
        )?;
        self.child_receipts.push(receipt);
        Ok(())
    }
}

impl<C: NestedFlowClient> NestedFlowBridge for SessionNestedFlowBridge<'_, C> {
    fn parent_request_id(&self) -> &RequestId {
        &self.parent_context.request_id
    }

    fn poll_parent_cancellation(&mut self) -> Result<(), KernelError> {
        self.client.poll_parent_cancellation(self.parent_context)
    }

    fn list_roots(&mut self) -> Result<Vec<RootDefinition>, KernelError> {
        let (child_context, _start) = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "roots"),
            OperationKind::ListRoots,
            None,
            false,
        )?;

        let result = (|| {
            let session = session_from_map(self.sessions, &child_context.session_id)?;
            session.validate_context(&child_context)?;
            session.ensure_operation_allowed(OperationKind::ListRoots)?;
            if !session.peer_capabilities().supports_roots {
                return Err(KernelError::RootsNotNegotiated);
            }

            let roots = self
                .client
                .list_roots(self.parent_context, &child_context)?;
            session_from_map(self.sessions, &child_context.session_id)?
                .replace_roots(roots.clone());
            Ok(roots)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::ListRoots,
            &result,
        )?;

        result
    }

    fn create_message(
        &mut self,
        operation: CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        let (child_context, _start) = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "sample"),
            OperationKind::CreateMessage,
            None,
            true,
        )?;

        let result = (|| {
            validate_sampling_request_in_sessions(
                self.sessions,
                self.allow_sampling,
                self.allow_sampling_tool_use,
                &child_context,
                &operation,
            )?;
            self.client
                .create_message(self.parent_context, &child_context, &operation)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::CreateMessage,
            &result,
        )?;

        result
    }

    fn create_elicitation(
        &mut self,
        operation: CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        let (child_context, _start) = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "elicit"),
            OperationKind::CreateElicitation,
            None,
            true,
        )?;

        let result = (|| {
            validate_elicitation_request_in_sessions(
                self.sessions,
                self.allow_elicitation,
                &child_context,
                &operation,
            )?;
            self.client
                .create_elicitation(self.parent_context, &child_context, &operation)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::CreateElicitation,
            &result,
        )?;

        result
    }

    fn notify_elicitation_completed(&mut self, elicitation_id: &str) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.client
            .notify_elicitation_completed(self.parent_context, elicitation_id)
    }

    fn notify_resource_updated(&mut self, uri: &str) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        if !session.is_resource_subscribed(uri) {
            return Ok(());
        }

        self.client
            .notify_resource_updated(self.parent_context, uri)
    }

    fn notify_resources_list_changed(&mut self) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.client
            .notify_resources_list_changed(self.parent_context)
    }
}

/// Extract a guard name from a `GuardDenied` error message shaped like
/// `guard "<name>" denied the request` or `guard "<name>" error ...`.
///
/// Plan evaluation surfaces the offending guard in the per-step verdict
/// so callers can target a specific guard when replanning. Parsing the
/// name out of the canonical string is sufficient here; the structured
/// denial payload is a tool-call response type and
/// is not shared with plan evaluation.
fn extract_guard_name(message: &str) -> Option<String> {
    let start_marker = "guard \"";
    let start = message.find(start_marker)? + start_marker.len();
    let rest = &message[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn scope_from_capability_snapshot(
    snapshot: &crate::capability_lineage::CapabilitySnapshot,
) -> Result<ChioScope, KernelError> {
    serde_json::from_str(&snapshot.grants_json).map_err(|error| {
        KernelError::Internal(format!(
            "invalid capability snapshot scope for {}: {error}",
            snapshot.capability_id
        ))
    })
}

fn validate_delegation_scope_step(
    parent_capability_id: &str,
    child_capability_id: &str,
    parent_scope: &ChioScope,
    child_scope: &ChioScope,
    child_expires_at: u64,
    link: &chio_core::capability::attenuation::DelegationLink,
) -> Result<(), KernelError> {
    validate_delegatable_subset(
        parent_capability_id,
        child_capability_id,
        parent_scope,
        child_scope,
    )?;
    validate_declared_attenuations(child_capability_id, child_scope, child_expires_at, link)?;
    Ok(())
}

fn validate_delegatable_subset(
    parent_capability_id: &str,
    child_capability_id: &str,
    parent_scope: &ChioScope,
    child_scope: &ChioScope,
) -> Result<(), KernelError> {
    for child_grant in &child_scope.grants {
        let allowed = parent_scope.grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !allowed {
            return Err(KernelError::DelegationInvalid(format!(
                "parent capability {} does not authorize delegated tool grant {}/{} on child capability {}",
                parent_capability_id,
                child_grant.server_id,
                child_grant.tool_name,
                child_capability_id
            )));
        }
    }

    for child_grant in &child_scope.resource_grants {
        let allowed = parent_scope.resource_grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !allowed {
            return Err(KernelError::DelegationInvalid(format!(
                "parent capability {} does not authorize delegated resource grant {} on child capability {}",
                parent_capability_id, child_grant.uri_pattern, child_capability_id
            )));
        }
    }

    for child_grant in &child_scope.prompt_grants {
        let allowed = parent_scope.prompt_grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !allowed {
            return Err(KernelError::DelegationInvalid(format!(
                "parent capability {} does not authorize delegated prompt grant {} on child capability {}",
                parent_capability_id, child_grant.prompt_name, child_capability_id
            )));
        }
    }

    Ok(())
}

fn validate_declared_attenuations(
    child_capability_id: &str,
    child_scope: &ChioScope,
    child_expires_at: u64,
    link: &chio_core::capability::attenuation::DelegationLink,
) -> Result<(), KernelError> {
    for attenuation in &link.attenuations {
        match attenuation {
            chio_core::capability::attenuation::Attenuation::RemoveTool {
                server_id,
                tool_name,
            } => {
                if child_scope
                    .grants
                    .iter()
                    .any(|grant| tool_grant_covers_target(grant, server_id, tool_name))
                {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} still grants removed tool {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::RemoveOperation {
                server_id,
                tool_name,
                operation,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant.operations.contains(operation)
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} still grants removed operation {:?} on {}/{}",
                        child_capability_id, operation, server_id, tool_name
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::AddConstraint {
                server_id,
                tool_name,
                constraint,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && !grant.constraints.contains(constraint)
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} is missing declared constraint on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::ReduceBudget {
                server_id,
                tool_name,
                max_invocations,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant
                            .max_invocations
                            .is_none_or(|value| value > *max_invocations)
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} exceeds declared invocation budget on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::ShortenExpiry { new_expires_at } => {
                if child_expires_at > *new_expires_at {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} expires after declared shortened expiry {}",
                        child_capability_id, new_expires_at
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::ReduceCostPerInvocation {
                server_id,
                tool_name,
                max_cost_per_invocation,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant.max_cost_per_invocation.as_ref().is_none_or(|value| {
                            value.currency != max_cost_per_invocation.currency
                                || value.units > max_cost_per_invocation.units
                        })
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} exceeds declared per-invocation cost ceiling on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
            chio_core::capability::attenuation::Attenuation::ReduceTotalCost {
                server_id,
                tool_name,
                max_total_cost,
            } => {
                if child_scope.grants.iter().any(|grant| {
                    tool_grant_covers_target(grant, server_id, tool_name)
                        && grant.max_total_cost.as_ref().is_none_or(|value| {
                            value.currency != max_total_cost.currency
                                || value.units > max_total_cost.units
                        })
                }) {
                    return Err(KernelError::DelegationInvalid(format!(
                        "child capability {} exceeds declared total-cost ceiling on {}/{}",
                        child_capability_id, server_id, tool_name
                    )));
                }
            }
        }
    }

    Ok(())
}

fn tool_grant_covers_target(grant: &ToolGrant, server_id: &str, tool_name: &str) -> bool {
    (grant.server_id == "*" || grant.server_id == server_id)
        && (grant.tool_name == "*" || grant.tool_name == tool_name)
}

/// Parameters for building a receipt.
pub(crate) struct ReceiptParams<'a> {
    request_id: Option<&'a str>,
    capability_id: &'a str,
    tool_name: &'a str,
    server_id: &'a str,
    decision: Decision,
    action: ToolCallAction,
    content_hash: String,
    /// Byte preimage `content_hash` was computed over. The signing boundary
    /// recomputes `sha256_hex(canonical_content)` and refuses to sign when it
    /// disagrees with `content_hash` (WYSIWYS). Always sourced from
    /// the matching [`ReceiptContent::canonical_content`].
    canonical_content: Vec<u8>,
    metadata: Option<serde_json::Value>,
    timestamp: u64,
    /// Strength of kernel mediation for this evaluation. Defaults to
    /// `Mediated` (the safest baseline) when integration adapters do not
    /// override it.
    trust_level: chio_core::receipt::kinds::TrustLevel,
    /// Multi-tenant receipt isolation: explicit tenant tag for
    /// this receipt. `None` in virtually every call site -- the evaluate
    /// path plumbs the resolved tenant through
    /// [`scope_receipt_tenant_id`] so `build_and_sign_receipt` can pick it
    /// up without adding a parameter to every builder signature.
    ///
    /// MUST be derived from session / auth context, not caller-provided
    /// request fields (see `STRUCTURAL-SECURITY-FIXES.md` section 6).
    tenant_id: Option<String>,
}

pub(crate) fn current_unix_timestamp() -> u64 {
    if let Some(now) = fixed_runtime_unix_secs_for_current_thread() {
        return now;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn current_unix_timestamp_ms() -> u64 {
    if let Some(now) = fixed_runtime_unix_secs_for_current_thread() {
        return now.saturating_mul(1000);
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(feature = "delegation")]
#[path = "delegation.rs"]
pub(crate) mod delegation;
// Kernel construction and configuration surface. Holds the constructor,
// session/store accessors, and the `set_*` / `with_*` / `register_*`
// configuration setters.
#[path = "construction.rs"]
mod construction;
// Tool-call and plan evaluation path, including the long-form evaluation
// cores.
mod evaluation;
// Capability and budget validation.
#[path = "validation.rs"]
mod validation;
// Governed-admission validation and call-chain receipt evidence.
#[path = "governed_validation.rs"]
mod governed_validation;
// Guard evaluation, runtime admission, and tool dispatch.
#[path = "dispatch.rs"]
mod dispatch;
#[path = "evaluator.rs"]
pub mod evaluator;
mod responses;
#[path = "session_ops.rs"]
mod session_ops;
// Settlement observer slot. Wires `chio-settle::SettlementHook` into
// the post-dispatch surface so finalized receipts can be routed through
// the existing `chio-settle/ops.rs` pipeline. The observer is strictly
// post-signing: hook failures never block the dispatch path.
#[path = "settlement_observer.rs"]
pub mod settlement_observer;
// Mpsc-backed signing task. Owns a clone of the kernel signing keypair and
// pulls signing requests from a bounded `tokio::sync::mpsc` channel so receipt
// signing leaves the synchronous critical path.
#[path = "signing_task.rs"]
pub(crate) mod signing_task;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
