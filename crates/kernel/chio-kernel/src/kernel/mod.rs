use std::sync::Arc;

use chio_appraisal::VerifiedRuntimeAttestationRecord;
use chio_core::receipt::metadata::GuardEvidence;
use dashmap::DashMap;

use crate::budget_store::BudgetCommitMetadata;
use crate::*;

#[path = "admission_coordinator.rs"]
mod admission_coordinator;
mod credential_reservation;
mod error;
mod kernel_drop_guard;
mod kernel_scopes;
mod kernel_struct;
mod output_guard;
mod verified_treaty;

pub use construction::KernelBuildError;
pub use error::{
    HotPathStage, KernelError, OverloadResource, ReplayClockDirection,
    SettlementRuntimeConfigError, StructuredErrorReport,
};
pub use kernel_struct::{
    ChioKernel, HotPathDeadlineConfig, HybridSigningConfig, KernelConfig, MemoryBudgetConfig,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_SIZE_BYTES, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES, DEFAULT_RECEIPT_APPEND_BUDGET_MS,
    DEFAULT_RECEIPT_WRITER_POLL_MS, DEFAULT_RECEIPT_WRITER_STALL_MS, DEFAULT_RETENTION_DAYS,
    DEFAULT_RUNTIME_ADMISSION_READINESS_TIMEOUT_MS, MIN_RECEIPT_APPEND_BUDGET_MS,
};
pub use verified_treaty::{
    FederationTreatyAdmissionBinding, FederationTreatyVerification,
    VerifiedFederationTreatyMaterial,
};

pub(crate) use admission_coordinator::{
    DurableAdmissionRuntime, DurableToolAdmission, DurableToolReturnInput,
};
pub(crate) use kernel_drop_guard::{PostAdmissionDropGuard, PostAdmissionReceiptContext};
pub(crate) use kernel_scopes::{
    current_receipt_evaluation_scope_key, current_scoped_receipt_federation_admission,
    current_scoped_receipt_tenant_id, extract_tenant_id_from_auth_context,
    scope_receipt_federation_admission, scope_receipt_tenant_id, ReceiptFederationAdmission,
    ScopedKernelReceiptFederationAdmission, ScopedKernelReceiptTenantId,
    RECEIPT_EVALUATION_SCOPE_KEY,
};
pub(crate) use kernel_struct::{
    capability_crypto_floor, receipt_crypto_floor, ReservedSiblingShare, RestartReservedHoldGate,
};

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

/// Non-consuming context for the final runtime-admission check immediately
/// before payment authorization, nonce consumption, and tool dispatch.
pub struct RuntimeAdmissionRevalidationContext<'a> {
    pub request: &'a ToolCallRequest,
    pub admission_metadata: Option<&'a serde_json::Value>,
    pub now_unix_secs: u64,
    pub now_unix_ms: u64,
    pub matched_grant_index: Option<usize>,
    pub local_kernel_id: String,
}

/// Opaque identifier for one in-flight runtime-admission readiness poll.
/// Concurrent evaluations receive distinct tokens even when request IDs are
/// equal, so unregistering one wait cannot remove another wait's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuntimeAdmissionReadinessToken(u64);

impl RuntimeAdmissionReadinessToken {
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Decision returned by a runtime admission hook.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeAdmissionDecision {
    pub allowed: bool,
    pub reason: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub(crate) verified_treaty_material: Option<VerifiedFederationTreatyMaterial>,
}

impl RuntimeAdmissionDecision {
    #[must_use]
    pub fn has_verified_treaty_material(&self) -> bool {
        self.verified_treaty_material.is_some()
    }

    #[must_use]
    pub fn allow(metadata: Option<serde_json::Value>) -> Self {
        Self {
            allowed: true,
            reason: None,
            metadata,
            verified_treaty_material: None,
        }
    }

    #[must_use]
    pub fn allow_with_verified_treaty_material(
        metadata: Option<serde_json::Value>,
        verified_treaty_material: VerifiedFederationTreatyMaterial,
    ) -> Self {
        Self {
            allowed: true,
            reason: None,
            metadata,
            verified_treaty_material: Some(verified_treaty_material),
        }
    }

    #[must_use]
    pub fn deny(reason: impl Into<String>, metadata: Option<serde_json::Value>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
            metadata,
            verified_treaty_material: None,
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

    /// Poll readiness after admission state has been reserved but before tool
    /// dispatch is marked as started. The default is immediately ready.
    fn poll_ready_before_dispatch(
        &self,
        _request: &ToolCallRequest,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        std::task::Poll::Ready(())
    }

    /// Token-aware readiness poll. Hooks retaining per-wait state should
    /// override this method; the default preserves the original readiness API.
    fn poll_ready_before_dispatch_with_token(
        &self,
        request: &ToolCallRequest,
        _token: RuntimeAdmissionReadinessToken,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        self.poll_ready_before_dispatch(request, cx)
    }

    /// Return true when mutable admission state must be checked even if the
    /// readiness poll completes immediately.
    fn requires_dispatch_revalidation(&self) -> bool {
        false
    }

    /// Revalidate mutable admission state without acquiring another
    /// reservation. Mutable hooks opt in through
    /// [`Self::requires_dispatch_revalidation`].
    fn revalidate_before_dispatch(
        &self,
        _context: &RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    /// Remove request-scoped readiness state, including any retained waker.
    fn unregister_ready_before_dispatch(
        &self,
        _request: &ToolCallRequest,
        _token: RuntimeAdmissionReadinessToken,
    ) {
    }

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        Ok(())
    }
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
    verified_payee_binding: Option<VerifiedGovernedPayeeBinding>,
    approval_reservation: Option<VerifiedApprovalReservation>,
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedApprovalReservation {
    pub(crate) threshold_proposal_hash: String,
    pub(crate) approval_set_hash: String,
    pub(crate) threshold_replay: Option<ThresholdApprovalReplayReservationV1>,
}

#[derive(Debug)]
pub(crate) struct VerifiedThresholdApprovalSet {
    pub(crate) requirement: chio_core::capability::threshold_approval::ThresholdApprovalRequirement,
    pub(crate) body: chio_core::capability::governance::VerifiedApprovalSetBody,
    pub(crate) replay: ThresholdApprovalReplayReservationV1,
}

pub(crate) fn run_payment_adapter_operation<T>(
    operation_name: &'static str,
    operation: impl FnOnce() -> Result<T, PaymentError>,
) -> Result<T, PaymentError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => Err(PaymentError::RailError(format!(
            "payment adapter {operation_name} panicked; outcome unknown"
        ))),
    }
}

pub(crate) fn validate_payment_adapter_identifier(
    identifier: &str,
    field_name: &'static str,
) -> Result<(), PaymentError> {
    if identifier.is_empty() || identifier.trim() != identifier {
        return Err(PaymentError::RailError(format!(
            "payment adapter returned an invalid {field_name}; outcome unknown"
        )));
    }
    Ok(())
}

pub(crate) enum BudgetAdmissionOutcome {
    Authorized {
        grant_index: usize,
        mutation: Box<PreExecutionBudgetMutation>,
    },
    PendingApproval {
        grant_index: usize,
        proposal: Box<chio_core::capability::governance::ThresholdApprovalProposal>,
    },
}

#[cfg(test)]
impl BudgetAdmissionOutcome {
    pub(crate) fn into_authorized(
        self,
    ) -> Result<(usize, PreExecutionBudgetMutation), KernelError> {
        match self {
            Self::Authorized {
                grant_index,
                mutation,
            } => Ok((grant_index, *mutation)),
            Self::PendingApproval { .. } => Err(KernelError::Internal(
                "budget admission remained pending approval".to_owned(),
            )),
        }
    }
}

pub(crate) struct GovernedValidationContext<'a> {
    parent_context: Option<&'a OperationContext>,
    now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedGovernedPayeeBinding {
    beneficiary_id: String,
    settlement_destination_ref: String,
    payee_binding_digest: String,
    economic_intent_digest: String,
    pre_action_authority_digest: String,
}

impl VerifiedGovernedPayeeBinding {
    pub(in crate::kernel) fn new(
        beneficiary_id: String,
        settlement_destination_ref: String,
        economic_intent_digest: String,
        pre_action_authority_digest: String,
    ) -> Result<Self, chio_credit::obligation::ObligationError> {
        let payee_binding_digest = chio_credit::obligation::derive_obligation_payee_binding_digest(
            &beneficiary_id,
            &settlement_destination_ref,
        )?;
        Ok(Self {
            beneficiary_id,
            settlement_destination_ref,
            payee_binding_digest,
            economic_intent_digest,
            pre_action_authority_digest,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        beneficiary_id: &str,
        settlement_destination_ref: &str,
        economic_intent_digest: &str,
        pre_action_authority_digest: &str,
    ) -> Result<Self, chio_credit::obligation::ObligationError> {
        Self::new(
            beneficiary_id.to_owned(),
            settlement_destination_ref.to_owned(),
            economic_intent_digest.to_owned(),
            pre_action_authority_digest.to_owned(),
        )
    }

    #[must_use]
    pub(crate) fn beneficiary_id(&self) -> &str {
        &self.beneficiary_id
    }

    #[must_use]
    pub(crate) fn settlement_destination_ref(&self) -> &str {
        &self.settlement_destination_ref
    }

    #[must_use]
    pub(crate) fn payee_binding_digest(&self) -> &str {
        &self.payee_binding_digest
    }

    #[must_use]
    pub(crate) fn economic_intent_digest(&self) -> &str {
        &self.economic_intent_digest
    }

    #[must_use]
    pub(crate) fn pre_action_authority_digest(&self) -> &str {
        &self.pre_action_authority_digest
    }
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

    /// Return true when mutable guard state must be checked immediately before
    /// dispatch even if runtime readiness never suspended.
    fn requires_dispatch_revalidation(&self) -> bool {
        false
    }

    /// Run the opt-in immediate dispatch check. Composite guards should
    /// override this method and apply it recursively to their children.
    fn revalidate_required_before_dispatch(&self, ctx: &GuardContext) -> Result<(), KernelError> {
        if self.requires_dispatch_revalidation() {
            self.revalidate_before_dispatch(ctx)
        } else {
            Ok(())
        }
    }

    /// Revalidate mutable guard state without consuming a second quota,
    /// approval, or rate-limit token.
    fn revalidate_before_dispatch(&self, _ctx: &GuardContext) -> Result<(), KernelError> {
        Ok(())
    }

    /// Name the authenticated Finding status feed that must authorize a
    /// governed memory write. The kernel checks this against the delivery
    /// receipt before invoking the tool so a write cannot enter a quarantine
    /// domain whose resolver will later reject it.
    fn required_finding_status_feed_id(
        &self,
        _ctx: &GuardContext,
    ) -> Result<Option<String>, KernelError> {
        Ok(None)
    }

    /// Validate the exact output after the tool returns and before it can be
    /// released or committed as a durable tool return. Stateful guards use
    /// this seam to bind an admission decision to the value actually read.
    fn validate_output_before_release(
        &self,
        _ctx: &GuardContext,
        _output: &ToolServerOutput,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    /// Return true when output validation binds the exact released value and
    /// therefore must run after every configured output transform.
    fn requires_exact_released_output(&self, _ctx: &GuardContext) -> bool {
        false
    }
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

/// Default capacity for a process-local receipt mirror when constructed without
/// an explicit budget (tests / benches). The kernel construction path threads
/// the configured `MemoryBudgetConfig::receipt_mirror_capacity` instead.
const DEFAULT_RECEIPT_MIRROR_CAPACITY: usize = 4096;

/// In-memory bounded ring of signed receipts. Process-local inspection mirror;
/// a durable receipt store is authoritative for id lookups.
///
/// `Clone` yields a read-only snapshot (used by the `receipt_log()` accessor).
#[derive(Clone)]
pub struct ReceiptLog {
    ring: chio_bounded::Ring<ChioReceipt>,
}

impl ReceiptLog {
    pub fn new() -> Self {
        Self::with_capacity(
            DEFAULT_RECEIPT_MIRROR_CAPACITY,
            chio_bounded::SizeGauge::new(),
        )
    }

    pub fn with_capacity(capacity: usize, gauge: chio_bounded::SizeGauge) -> Self {
        Self {
            ring: chio_bounded::Ring::with_capacity(capacity, gauge),
        }
    }

    pub fn append(&mut self, receipt: ChioReceipt) {
        // Evicted receipts are already durably persisted (the store write in
        // record_chio_receipt precedes this mirror append) or ephemeral by
        // policy, so dropping the evicted item is safe. Caveat: for an
        // append-only/remote store that does NOT implement point lookups, this
        // mirror is the only lookup source, so eviction here
        // makes an older receipt unresolvable and parent-receipt call-chain
        // validation fails closed. Such deployments must implement
        // ReceiptStore::load_chio_receipt (see has_local_receipt_id).
        let _evicted = self.ring.push(receipt);
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ChioReceipt> {
        self.ring.iter()
    }

    /// Cloned snapshot of the mirror (process-local inspection). Bounded by the
    /// ring capacity.
    pub fn receipts(&self) -> Vec<ChioReceipt> {
        self.ring.iter().cloned().collect()
    }

    pub fn get(&self, index: usize) -> Option<&ChioReceipt> {
        self.ring.iter().nth(index)
    }
}

impl Default for ReceiptLog {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory bounded ring of signed child-request receipts.
#[derive(Clone)]
pub struct ChildReceiptLog {
    ring: chio_bounded::Ring<ChildRequestReceipt>,
}

impl ChildReceiptLog {
    pub fn new() -> Self {
        Self::with_capacity(
            DEFAULT_RECEIPT_MIRROR_CAPACITY,
            chio_bounded::SizeGauge::new(),
        )
    }

    pub fn with_capacity(capacity: usize, gauge: chio_bounded::SizeGauge) -> Self {
        Self {
            ring: chio_bounded::Ring::with_capacity(capacity, gauge),
        }
    }

    pub fn append(&mut self, receipt: ChildRequestReceipt) {
        let _evicted = self.ring.push(receipt);
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ChildRequestReceipt> {
        self.ring.iter()
    }

    /// Cloned snapshot of the mirror (process-local inspection). Bounded by the
    /// ring capacity.
    pub fn receipts(&self) -> Vec<ChildRequestReceipt> {
        self.ring.iter().cloned().collect()
    }

    pub fn get(&self, index: usize) -> Option<&ChildRequestReceipt> {
        self.ring.iter().nth(index)
    }
}

impl Default for ChildReceiptLog {
    fn default() -> Self {
        Self::new()
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
    invocation_capture: Option<Box<crate::budget_store::BudgetHoldMutationDecision>>,
}

impl BudgetChargeResult {
    /// The rail/store hold id for the monetary budget charge, so a cleanup
    /// fault can name the stuck budget hold that needs manual recovery.
    fn reverse_event_id(&self) -> String {
        let authorize_event_id = self
            .authorize_metadata
            .event_id
            .as_deref()
            .unwrap_or(&self.budget_hold_id);
        let authorize_commit_index = self.authorize_metadata.budget_commit_index.unwrap_or(0);
        format!("{authorize_event_id}:rollback:{authorize_commit_index}")
    }

    fn capture_invocation_event_id(&self) -> String {
        let authorize_commit_index = self.authorize_metadata.budget_commit_index.unwrap_or(0);
        format!(
            "{}:capture-invocation:{authorize_commit_index}",
            self.budget_hold_id
        )
    }

    fn cancel_captured_before_dispatch_event_id(&self) -> String {
        self.reverse_event_id()
    }

    fn reconcile_event_id(&self) -> String {
        format!("{}:reconcile", self.budget_hold_id)
    }
}

pub(crate) enum PreExecutionBudgetMutation {
    None,
    Invocation { grant_index: usize },
    InvocationHold(BudgetChargeResult),
    Charge(BudgetChargeResult),
}

impl PreExecutionBudgetMutation {
    fn charge_result(&self) -> Option<&BudgetChargeResult> {
        match self {
            Self::Charge(charge) => Some(charge),
            Self::None | Self::Invocation { .. } | Self::InvocationHold(_) => None,
        }
    }

    fn durable_hold_result(&self) -> Option<&BudgetChargeResult> {
        match self {
            Self::Charge(charge) | Self::InvocationHold(charge) => Some(charge),
            Self::None | Self::Invocation { .. } => None,
        }
    }

    fn durable_hold_result_mut(&mut self) -> Option<&mut BudgetChargeResult> {
        match self {
            Self::Charge(charge) | Self::InvocationHold(charge) => Some(charge),
            Self::Invocation { .. } | Self::None => None,
        }
    }

    fn into_charge_result(self) -> Option<BudgetChargeResult> {
        match self {
            Self::Charge(charge) => Some(charge),
            Self::None | Self::Invocation { .. } | Self::InvocationHold(_) => None,
        }
    }
}

struct SessionNestedFlowBridge<'a, C> {
    sessions: &'a DashMap<SessionId, Arc<Session>>,
    child_receipts: &'a mut Vec<ChildRequestReceipt>,
    nested_interaction_observed: &'a std::sync::atomic::AtomicBool,
    parent_context: &'a OperationContext,
    allow_sampling: bool,
    allow_sampling_tool_use: bool,
    allow_elicitation: bool,
    policy_hash: &'a str,
    kernel_keypair: &'a Keypair,
    client: &'a mut C,
}

impl<C> SessionNestedFlowBridge<'_, C> {
    fn mark_nested_interaction_observed(&self) {
        self.nested_interaction_observed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn ensure_parent_not_cancelled(&self) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        let request_id = &self.parent_context.request_id;
        let Some(parent) = session.inflight().get(request_id) else {
            return Err(KernelError::RequestCancelled {
                request_id: request_id.clone(),
                reason: "parent session request completed during nested dispatch".to_string(),
            });
        };
        if parent.cancellation_requested {
            return Err(KernelError::RequestCancelled {
                request_id: request_id.clone(),
                reason: parent.cancellation_reason.unwrap_or_else(|| {
                    "parent session request cancelled during nested dispatch".to_string()
                }),
            });
        }
        Ok(())
    }

    fn latch_matching_cancellation<T>(
        &mut self,
        result: &Result<T, KernelError>,
        child_request_id: Option<&RequestId>,
    ) -> Result<(), KernelError> {
        let Err(KernelError::RequestCancelled { request_id, reason }) = result else {
            return Ok(());
        };
        if request_id != &self.parent_context.request_id
            && child_request_id.is_none_or(|child_request_id| request_id != child_request_id)
        {
            return Ok(());
        }
        session_from_map(self.sessions, &self.parent_context.session_id)?
            .request_cancellation_with_reason(request_id, reason)?;
        Ok(())
    }

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

impl<C> Drop for SessionNestedFlowBridge<'_, C> {
    fn drop(&mut self) {
        if let Some(session) = self.sessions.get(&self.parent_context.session_id) {
            session.mark_request_dispatch_finished(&self.parent_context.request_id);
        }
    }
}

impl<C: NestedFlowClient> NestedFlowBridge for SessionNestedFlowBridge<'_, C> {
    fn parent_request_id(&self) -> &RequestId {
        &self.parent_context.request_id
    }

    fn poll_parent_cancellation(&mut self) -> Result<(), KernelError> {
        self.ensure_parent_not_cancelled()?;
        let result = self.client.poll_parent_cancellation(self.parent_context);
        self.latch_matching_cancellation(&result, None)?;
        result
    }

    fn list_roots(&mut self) -> Result<Vec<RootDefinition>, KernelError> {
        self.ensure_parent_not_cancelled()?;
        self.mark_nested_interaction_observed();
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
        self.ensure_parent_not_cancelled()?;
        self.mark_nested_interaction_observed();
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
        self.ensure_parent_not_cancelled()?;
        self.mark_nested_interaction_observed();
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
        self.ensure_parent_not_cancelled()?;
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.mark_nested_interaction_observed();
        let result = self
            .client
            .notify_elicitation_completed(self.parent_context, elicitation_id);
        self.latch_matching_cancellation(&result, None)?;
        result
    }

    fn notify_resource_updated(&mut self, uri: &str) -> Result<(), KernelError> {
        self.ensure_parent_not_cancelled()?;
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        if !session.is_resource_subscribed(uri) {
            return Ok(());
        }

        self.mark_nested_interaction_observed();
        let result = self
            .client
            .notify_resource_updated(self.parent_context, uri);
        self.latch_matching_cancellation(&result, None)?;
        result
    }

    fn notify_resources_list_changed(&mut self) -> Result<(), KernelError> {
        self.ensure_parent_not_cancelled()?;
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.mark_nested_interaction_observed();
        let result = self
            .client
            .notify_resources_list_changed(self.parent_context);
        self.latch_matching_cancellation(&result, None)?;
        result
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
// Reconcile-by-nonce and reserved-hold TTL primitives (mediated spend path).
#[path = "reconciliation.rs"]
mod reconciliation;
// Governed-admission validation and call-chain receipt evidence.
#[path = "governed_validation.rs"]
mod governed_validation;
// Guard evaluation, runtime admission, and tool dispatch.
#[path = "dispatch.rs"]
mod dispatch;
// Purchase-marked admission checks for delivery-committed reveals.
#[path = "delivery_contract.rs"]
pub(crate) mod delivery_contract;
#[path = "evaluator.rs"]
pub mod evaluator;
#[cfg(not(feature = "finding-market"))]
#[path = "market_disabled.rs"]
mod market_disabled;
#[cfg(feature = "finding-market")]
#[path = "purchase_gate.rs"]
mod purchase_gate;
#[cfg(all(test, feature = "finding-market"))]
pub(crate) use purchase_gate::validate_finding_pool_receipt_authority;
#[cfg(feature = "finding-market")]
mod recovery_gate;
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
// Receipt-writer liveness watchdog. Publishes the latest verdict the
// pre-dispatch readiness gate reads.
#[path = "receipt_writer_watchdog.rs"]
mod receipt_writer_watchdog;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
