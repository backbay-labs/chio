use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chio_core_types::capability::{
    scope::{ChioScope, ModelMetadata, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::decision::Decision;
use chio_core_types::receipt::metadata::GuardEvidence;
use chio_cross_protocol::discovery::{DiscoveryProtocol, TargetProtocolRegistry};
use chio_cross_protocol::routing::{plan_authoritative_route, route_selection_metadata};
use chio_kernel::{
    ApprovalStore, ChioKernel, ExecutionNonceConfig, ExecutionNonceStore, Guard, GuardContext,
    GuardDecision, InMemoryApprovalStore, KernelConfig, KernelError, ReceiptStore, RevocationStore,
    SignedExecutionNonce, ToolCallRequest, ToolCallResponse, ToolServerConnection,
    Verdict as KernelVerdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    authority_projection::{
        capability_binding, HttpKernelAuthorizationRequest, HttpKernelCapabilityState,
    },
    http_status_metadata_decision, http_status_metadata_final, CallerIdentity, ChioHttpRequest,
    HttpMethod, HttpReceipt, HttpReceiptBody, Verdict, CHIO_KERNEL_RECEIPT_ID_KEY,
};

/// Tool server id for HTTP-sidecar capability grants.
pub const HTTP_AUTHORITY_SERVER_ID: &str = "chio_http_authority";
/// Tool name for HTTP-sidecar capability grants.
pub const HTTP_AUTHORITY_TOOL_NAME: &str = "authorize_http_request";
const HTTP_AUTHORITY_TTL_SECS: u64 = 60;

/// Guard label the embedded kernel stamps on a deny receipt when it fails a
/// mediated call closed for missing durable persistence (no receipt store or no
/// durable revocation state). Kept in step with the kernel's fail-closed deny
/// builder so the authority can surface a durability failure as an error rather
/// than fold it into a routine deny receipt.
const KERNEL_DURABILITY_FAILCLOSED_GUARD: &str = "kernel.receipt_persistence";

/// Whether a kernel response is a fail-closed denial for missing durable
/// persistence, as opposed to a routine policy or capability denial. The kernel
/// runs its durability gate ahead of the HTTP projection guard, so this can fire
/// for a request that is independently projected as denied.
fn is_durability_failclosed_denial(response: &ToolCallResponse) -> bool {
    matches!(
        response.receipt.decision.as_ref(),
        Some(Decision::Deny { guard, .. }) if guard == KERNEL_DURABILITY_FAILCLOSED_GUARD
    )
}

#[must_use]
pub fn http_authority_tool_grant() -> ToolGrant {
    ToolGrant {
        server_id: HTTP_AUTHORITY_SERVER_ID.to_string(),
        tool_name: HTTP_AUTHORITY_TOOL_NAME.to_string(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpAuthorityPolicy {
    SessionAllow,
    DenyByDefault,
}

#[derive(Clone)]
pub struct HttpAuthority {
    keypair: Arc<Keypair>,
    policy_hash: String,
    kernel: Arc<ChioKernel>,
    kernel_subject: PublicKey,
    kernel_agent_id: String,
    approval_store: Arc<dyn ApprovalStore>,
    trusted_capability_issuers: Vec<PublicKey>,
}

impl std::fmt::Debug for HttpAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAuthority")
            .field("policy_hash", &self.policy_hash)
            .field("kernel_agent_id", &self.kernel_agent_id)
            .finish_non_exhaustive()
    }
}

pub struct HttpAuthorityInput<'a> {
    pub request_id: String,
    pub method: HttpMethod,
    pub route_pattern: String,
    pub path: &'a str,
    pub query: &'a HashMap<String, String>,
    pub caller: CallerIdentity,
    pub body_hash: Option<String>,
    pub body_length: u64,
    pub session_id: Option<String>,
    pub capability_id_hint: Option<&'a str>,
    pub presented_capability: Option<&'a str>,
    pub requested_tool_server: Option<&'a str>,
    pub requested_tool_name: Option<&'a str>,
    pub requested_arguments: Option<&'a Value>,
    pub model_metadata: Option<&'a ModelMetadata>,
    pub unsupported_authorization_extension: Option<&'a str>,
    pub execution_nonce: Option<&'a SignedExecutionNonce>,
    pub policy: HttpAuthorityPolicy,
}

/// Input for [`HttpAuthority::sign_transport_deny_receipt`]: a deny verdict
/// emitted by the transport layer (for example, a body-size guard) before
/// the kernel evaluation pipeline has run.
pub struct TransportDenyInput<'a> {
    pub request_id: &'a str,
    pub route_pattern: &'a str,
    pub method: HttpMethod,
    pub caller_identity_hash: &'a str,
    pub content_hash: Option<&'a str>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone)]
pub struct PreparedHttpEvaluation {
    pub verdict: Verdict,
    pub evidence: Vec<GuardEvidence>,
    pub request_id: String,
    pub route_pattern: String,
    pub http_method: HttpMethod,
    pub caller_identity_hash: String,
    pub content_hash: String,
    pub session_id: Option<String>,
    pub capability_id: Option<String>,
    pub kernel_receipt_id: String,
    pub route_selection_metadata: Option<Value>,
    pub execution_nonce: Option<SignedExecutionNonce>,
}

#[derive(Debug, Clone)]
pub struct HttpAuthorityEvaluation {
    pub verdict: Verdict,
    pub receipt: HttpReceipt,
    pub evidence: Vec<GuardEvidence>,
    pub execution_nonce: Option<SignedExecutionNonce>,
}

#[derive(Debug, Error)]
pub enum HttpAuthorityError {
    #[error("failed to hash caller identity: {0}")]
    CallerIdentity(String),

    #[error("failed to compute content hash: {0}")]
    ContentHash(String),

    #[error("kernel-backed authorization failed: {0}")]
    Kernel(String),

    #[error("kernel-backed authorization requires approval")]
    PendingApproval {
        approval_id: Option<String>,
        kernel_receipt_id: String,
    },

    #[error("failed to sign receipt: {0}")]
    ReceiptSign(String),
}

/// Whether an evaluation error is a genuine mediation-edge dispatch failure that
/// must feed `chio_dispatch_failure_total` and the error-outcome latency/guard
/// evaluation series. A [`HttpAuthorityError::PendingApproval`] is NOT a dispatch
/// failure: it is the normal HITL approval-required flow (surfaced as a 409),
/// so it is excluded from the paging metric and the error series. Every other
/// error is a real evaluation failure.
fn is_dispatch_failure(error: &HttpAuthorityError) -> bool {
    !matches!(error, HttpAuthorityError::PendingApproval { .. })
}

#[derive(Debug, Clone)]
struct PresentedCapabilityState {
    capability_id: Option<String>,
    invalid_reason: Option<String>,
}

#[derive(Clone, Copy)]
struct RequestedToolInvocation<'a> {
    server_id: &'a str,
    tool_name: &'a str,
    arguments: &'a Value,
}

struct HttpAuthorizationServer;

#[async_trait::async_trait]
impl ToolServerConnection for HttpAuthorizationServer {
    fn server_id(&self) -> &str {
        HTTP_AUTHORITY_SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![HTTP_AUTHORITY_TOOL_NAME.to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if tool_name != HTTP_AUTHORITY_TOOL_NAME {
            return Err(KernelError::Internal(format!(
                "unsupported HTTP authority tool: {tool_name}"
            )));
        }
        Ok(serde_json::json!({ "authorized": true }))
    }
}

struct HttpProjectionGuard;

impl Guard for HttpProjectionGuard {
    fn name(&self) -> &str {
        "http_projection_policy"
    }

    fn evaluate(&self, ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        let projected: HttpKernelAuthorizationRequest =
            serde_json::from_value(ctx.request.arguments.clone()).map_err(|error| {
                KernelError::Internal(format!(
                    "failed to decode projected HTTP authorization request: {error}"
                ))
            })?;

        if let Some(reason) = projected.capability.invalid_reason {
            return Err(KernelError::GuardDenied(reason));
        }

        match projected.policy {
            HttpAuthorityPolicy::SessionAllow => Ok(GuardDecision::allow()),
            HttpAuthorityPolicy::DenyByDefault => {
                if projected.capability.id.is_some() {
                    Ok(GuardDecision::allow())
                } else {
                    Err(KernelError::GuardDenied(
                        "side-effect route requires a capability token".to_string(),
                    ))
                }
            }
        }
    }
}

/// Builder for an [`HttpAuthority`] whose embedded kernel is backed by durable
/// stores. Unlike the `-> Self` constructors, `build` attaches the receipt and
/// revocation stores before the kernel is Arc-wrapped, and it is fallible
/// because attaching a receipt store hydrates checkpoint counters and can fail.
/// Both ephemeral opt-ins default to `false` (fail-closed).
struct DurableAdmissionStores {
    store: Arc<dyn chio_kernel::QualifiedAdmissionProjectionStore>,
    outcome_store: Arc<dyn chio_kernel::tool_outcome::QualifiedToolOutcomeStore>,
    fence: chio_kernel::admission_operation::StoreMutationFence,
}

#[derive(Default)]
pub struct HttpAuthorityBuilder {
    approval_store: Option<Arc<dyn ApprovalStore>>,
    receipt_store: Option<Arc<dyn ReceiptStore>>,
    revocation_store: Option<Arc<dyn RevocationStore>>,
    durable_admission: Option<DurableAdmissionStores>,
    trusted_capability_issuers: Vec<PublicKey>,
    allow_ephemeral_receipt_log: bool,
    allow_ephemeral_revocation_store: bool,
}

impl HttpAuthorityBuilder {
    #[must_use]
    pub fn receipt_store(mut self, store: Arc<dyn ReceiptStore>) -> Self {
        self.receipt_store = Some(store);
        self
    }

    #[must_use]
    pub fn revocation_store(mut self, store: Arc<dyn RevocationStore>) -> Self {
        self.revocation_store = Some(store);
        self
    }

    #[must_use]
    pub fn durable_admission_stores(
        mut self,
        store: Arc<dyn chio_kernel::QualifiedAdmissionProjectionStore>,
        outcome_store: Arc<dyn chio_kernel::tool_outcome::QualifiedToolOutcomeStore>,
        fence: chio_kernel::admission_operation::StoreMutationFence,
    ) -> Self {
        self.durable_admission = Some(DurableAdmissionStores {
            store,
            outcome_store,
            fence,
        });
        self
    }

    #[must_use]
    pub fn approval_store(mut self, store: Arc<dyn ApprovalStore>) -> Self {
        self.approval_store = Some(store);
        self
    }

    #[must_use]
    pub fn trusted_capability_issuers(mut self, issuers: Vec<PublicKey>) -> Self {
        self.trusted_capability_issuers = issuers;
        self
    }

    #[must_use]
    pub fn allow_ephemeral_receipt_log(mut self, allow: bool) -> Self {
        self.allow_ephemeral_receipt_log = allow;
        self
    }

    #[must_use]
    pub fn allow_ephemeral_revocation_store(mut self, allow: bool) -> Self {
        self.allow_ephemeral_revocation_store = allow;
        self
    }

    pub fn build(
        self,
        keypair: Keypair,
        policy_hash: String,
    ) -> Result<HttpAuthority, HttpAuthorityError> {
        let approval_store = self
            .approval_store
            .unwrap_or_else(|| Arc::new(InMemoryApprovalStore::new()));
        let keypair = Arc::new(keypair);
        let signer_public_key = keypair.public_key();
        let mut trusted = self.trusted_capability_issuers;
        if !trusted.contains(&signer_public_key) {
            trusted.push(signer_public_key.clone());
        }
        let kernel_subject = Keypair::generate().public_key();
        let kernel_agent_id = kernel_subject.to_hex();

        let mut kernel = ChioKernel::new(HttpAuthority::kernel_config(
            keypair.as_ref().clone(),
            trusted.clone(),
            policy_hash.clone(),
            self.allow_ephemeral_receipt_log,
            self.allow_ephemeral_revocation_store,
        ));
        if let Some(store) = self.receipt_store {
            kernel
                .set_receipt_store_handle(store)
                .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?;
        }
        if let Some(store) = self.revocation_store {
            kernel.set_revocation_store_handle(store);
        }
        if let Some(durable) = self.durable_admission {
            kernel
                .set_durable_admission_store(durable.store, durable.outcome_store, durable.fence)
                .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?;
        }
        kernel.register_tool_server(Box::new(HttpAuthorizationServer));
        kernel.add_guard(Box::new(HttpProjectionGuard));

        Ok(HttpAuthority {
            keypair,
            policy_hash,
            kernel: Arc::new(kernel),
            kernel_subject,
            kernel_agent_id,
            approval_store,
            trusted_capability_issuers: trusted,
        })
    }
}

impl HttpAuthority {
    /// Start building an authority whose embedded kernel is backed by durable
    /// receipt and revocation stores. Stores must be attached before the kernel
    /// is wrapped in an [`Arc`], which is what this builder does.
    #[must_use]
    pub fn builder() -> HttpAuthorityBuilder {
        HttpAuthorityBuilder::default()
    }

    /// Fail-closed constructor: no receipt or revocation store is attached and
    /// both ephemeral opt-ins are off. Existing callers compile unchanged, but
    /// the first mediated call now denies with a durable-persistence error
    /// until a durable store is wired through [`HttpAuthority::builder`]. This
    /// matches the kernel-backed lanes, which already deny when durable
    /// persistence is missing.
    #[must_use]
    pub fn new(keypair: Keypair, policy_hash: String) -> Self {
        Self::assemble(
            keypair,
            policy_hash,
            Arc::new(InMemoryApprovalStore::new()),
            Vec::new(),
            false,
            false,
        )
    }

    /// Explicitly ephemeral constructor (in-memory receipt log and revocation
    /// store) for local scaffolds and tests that intend ephemerality.
    #[must_use]
    pub fn new_ephemeral(keypair: Keypair, policy_hash: String) -> Self {
        Self::assemble(
            keypair,
            policy_hash,
            Arc::new(InMemoryApprovalStore::new()),
            Vec::new(),
            true,
            true,
        )
    }

    /// Fail-closed constructor with a caller-provided approval store. Like
    /// [`HttpAuthority::new`], no receipt or revocation store is attached and both
    /// ephemeral opt-ins stay off, so a mediated side-effect call denies with a
    /// durable-persistence error until durable stores are wired through
    /// [`HttpAuthority::builder`]. Reach for
    /// [`HttpAuthority::new_ephemeral_with_approval_store_and_trusted_issuers`]
    /// when in-memory receipts and revocations are intended.
    #[must_use]
    pub fn new_with_approval_store(
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
    ) -> Self {
        Self::assemble(
            keypair,
            policy_hash,
            approval_store,
            Vec::new(),
            false,
            false,
        )
    }

    /// Fail-closed constructor with a caller-provided approval store and trusted
    /// issuers. Side-effect calls deny until durable stores are attached; see
    /// [`HttpAuthority::new_with_approval_store`].
    #[must_use]
    pub fn new_with_approval_store_and_trusted_issuers(
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Self {
        Self::assemble(
            keypair,
            policy_hash,
            approval_store,
            trusted_capability_issuers,
            false,
            false,
        )
    }

    /// Explicitly ephemeral constructor with a caller-provided approval store and
    /// trusted issuers: the embedded kernel keeps its receipt log and revocation
    /// state in memory, and both are lost on restart. Ephemerality is opted into
    /// through the constructor name (unlike the fail-closed
    /// [`HttpAuthority::new_with_approval_store_and_trusted_issuers`]) for local
    /// scaffolds and tests that intend it.
    #[must_use]
    pub fn new_ephemeral_with_approval_store_and_trusted_issuers(
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Self {
        Self::assemble(
            keypair,
            policy_hash,
            approval_store,
            trusted_capability_issuers,
            true,
            true,
        )
    }

    /// Infallible assembly shared by every `-> Self` constructor: build the
    /// kernel config, register the tool server and projection guard, and
    /// Arc-wrap. No receipt store is attached here (attaching one is fallible
    /// and lives in the builder), so these constructors keep their signatures.
    fn assemble(
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
        mut trusted_capability_issuers: Vec<PublicKey>,
        allow_ephemeral_receipt_log: bool,
        allow_ephemeral_revocation_store: bool,
    ) -> Self {
        let keypair = Arc::new(keypair);
        let signer_public_key = keypair.public_key();
        if !trusted_capability_issuers.contains(&signer_public_key) {
            trusted_capability_issuers.push(signer_public_key.clone());
        }
        let kernel_subject = Keypair::generate().public_key();
        let kernel_agent_id = kernel_subject.to_hex();

        let mut kernel = ChioKernel::new(Self::kernel_config(
            keypair.as_ref().clone(),
            trusted_capability_issuers.clone(),
            policy_hash.clone(),
            allow_ephemeral_receipt_log,
            allow_ephemeral_revocation_store,
        ));
        kernel.register_tool_server(Box::new(HttpAuthorizationServer));
        kernel.add_guard(Box::new(HttpProjectionGuard));

        Self {
            keypair,
            policy_hash,
            kernel: Arc::new(kernel),
            kernel_subject,
            kernel_agent_id,
            approval_store,
            trusted_capability_issuers,
        }
    }

    /// The embedded kernel configuration for the HTTP mediation lane. The two
    /// ephemeral flags are the only durability knobs a caller varies; every
    /// other field is fixed for this lane.
    fn kernel_config(
        keypair: Keypair,
        ca_public_keys: Vec<PublicKey>,
        policy_hash: String,
        allow_ephemeral_receipt_log: bool,
        allow_ephemeral_revocation_store: bool,
    ) -> KernelConfig {
        KernelConfig {
            keypair,
            ca_public_keys,
            max_delegation_depth: 8,
            policy_hash,
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log,
            allow_ephemeral_revocation_store,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        }
    }

    #[must_use]
    pub fn approval_store(&self) -> Arc<dyn ApprovalStore> {
        Arc::clone(&self.approval_store)
    }

    pub fn set_execution_nonce_store(
        &mut self,
        config: ExecutionNonceConfig,
        store: Box<dyn ExecutionNonceStore>,
    ) -> Result<(), HttpAuthorityError> {
        let Some(kernel) = Arc::get_mut(&mut self.kernel) else {
            return Err(HttpAuthorityError::Kernel(
                "execution nonce store cannot be configured after HTTP authority is cloned"
                    .to_string(),
            ));
        };
        kernel.set_execution_nonce_store(config, store);
        Ok(())
    }

    fn trusted_capability_issuers(&self) -> &[PublicKey] {
        &self.trusted_capability_issuers
    }

    pub fn evaluate(
        &self,
        input: HttpAuthorityInput<'_>,
    ) -> Result<HttpAuthorityEvaluation, HttpAuthorityError> {
        let started_at = std::time::Instant::now();
        let result = self.prepare(input).and_then(|prepared| {
            let receipt = self.sign_decision_receipt(&prepared)?;
            Ok((prepared, receipt))
        });
        let elapsed_nanos = u64::try_from(started_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
        match result {
            Ok((prepared, receipt)) => {
                // A policy/capability deny is an expected fail-closed decision,
                // NOT a dispatch failure: it is tracked by the guard-verdict
                // metrics only, never on chio_dispatch_failure_total, so a normal
                // rejected request cannot page the P0 fail-open/dispatch-failure
                // alert. Only a genuine evaluation error (the Err arm below) feeds
                // the paging metric.
                let outcome = if prepared.verdict.is_allowed() {
                    crate::metrics::GUARD_OUTCOME_ALLOW
                } else {
                    crate::metrics::GUARD_OUTCOME_DENY
                };
                crate::metrics::observe_decision_latency_nanos_for_outcome(outcome, elapsed_nanos);
                crate::metrics::record_guard_evaluation(outcome);
                Ok(HttpAuthorityEvaluation {
                    verdict: prepared.verdict.clone(),
                    receipt,
                    evidence: prepared.evidence.clone(),
                    execution_nonce: prepared.execution_nonce.clone(),
                })
            }
            Err(error) => {
                // A HITL PendingApproval is the normal approval-required control
                // flow (the caller turns it into a 409 approval response), NOT a
                // mediation-edge dispatch failure. Recording it as an error would
                // feed chio_dispatch_failure_total (paging the P0 fail-open alert
                // on every governed approval prompt) and skew the error-outcome
                // latency/guard-eval series, which fold every unknown outcome into
                // the error bucket. Only a genuine evaluation error feeds these
                // instruments.
                if is_dispatch_failure(&error) {
                    crate::metrics::observe_decision_latency_nanos_for_outcome(
                        crate::metrics::GUARD_OUTCOME_ERROR,
                        elapsed_nanos,
                    );
                    crate::metrics::record_guard_evaluation(crate::metrics::GUARD_OUTCOME_ERROR);
                    crate::metrics::record_dispatch_failure(
                        crate::metrics::GUARD_LABEL_HTTP_AUTHORITY,
                        "error",
                    );
                }
                Err(error)
            }
        }
    }

    pub fn prepare(
        &self,
        input: HttpAuthorityInput<'_>,
    ) -> Result<PreparedHttpEvaluation, HttpAuthorityError> {
        let caller_identity_hash = input
            .caller
            .identity_hash()
            .map_err(|e| HttpAuthorityError::CallerIdentity(e.to_string()))?;
        let binding = capability_binding(&input, &caller_identity_hash);
        let unsupported_reason = input.unsupported_authorization_extension.map(|field| {
            format!("HTTP authority projection does not support authorization field {field}")
        });
        let presented_capability =
            if let Some(reason) = unsupported_reason.or_else(|| binding.invalid_reason.clone()) {
                PresentedCapabilityState {
                    capability_id: None,
                    invalid_reason: Some(reason),
                }
            } else {
                validate_presented_capability(
                    input.capability_id_hint,
                    input.presented_capability,
                    self.trusted_capability_issuers(),
                    binding.requested_tool_server.as_deref(),
                    binding.requested_tool_name.as_deref(),
                    binding.requested_arguments.as_ref(),
                    input.model_metadata,
                    &|capability_id| {
                        self.kernel
                            .is_capability_revoked(capability_id)
                            .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))
                    },
                )
            };

        let chio_request = ChioHttpRequest {
            request_id: input.request_id.clone(),
            method: input.method,
            route_pattern: input.route_pattern.clone(),
            path: input.path.to_string(),
            query: input.query.clone(),
            headers: HashMap::new(),
            caller: input.caller,
            body_hash: input.body_hash,
            body_length: input.body_length,
            session_id: input.session_id.clone(),
            capability_id: presented_capability.capability_id.clone(),
            tool_server: binding.requested_tool_server.clone(),
            tool_name: binding.requested_tool_name.clone(),
            arguments: binding.requested_arguments.clone(),
            model_metadata: input.model_metadata.cloned(),
            governed_intent: None,
            approval_token: None,
            approval_tokens: None,
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: input.execution_nonce.cloned(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let content_hash = chio_request
            .content_hash()
            .map_err(|e| HttpAuthorityError::ContentHash(e.to_string()))?;

        let kernel_response = self.authorize_via_kernel(
            &input.request_id,
            input.method,
            &input.route_pattern,
            input.path,
            &content_hash,
            &caller_identity_hash,
            input.session_id.as_deref(),
            binding.policy,
            &presented_capability,
            input.execution_nonce,
        )?;

        // A fail-closed durability denial (missing durable receipt store or
        // revocation state) must surface as an error for every projection, not
        // only allowed ones. The kernel runs its durability gate before the HTTP
        // projection guard, so a request independently projected as denied would
        // otherwise return a signed deny receipt while the misconfigured
        // authority silently drops the denial audit record. Denial evidence must
        // be as durable as allow evidence, so propagate it regardless of verdict.
        if is_durability_failclosed_denial(&kernel_response) {
            let reason = kernel_response
                .reason
                .clone()
                .unwrap_or_else(|| "kernel denied for missing durable persistence".to_string());
            return Err(HttpAuthorityError::Kernel(reason));
        }

        let verdict = projected_verdict(binding.policy, &presented_capability);
        let expected_allowed = verdict.is_allowed();
        match (kernel_response.verdict, expected_allowed) {
            (KernelVerdict::Allow, true) | (KernelVerdict::Deny, false) => {}
            (KernelVerdict::Allow, false) => {
                return Err(HttpAuthorityError::Kernel(
                    "kernel allowed an HTTP projection that should have been denied".to_string(),
                ));
            }
            (KernelVerdict::Deny, true) => {
                let reason = kernel_response
                    .reason
                    .unwrap_or_else(|| "kernel denied an allowed HTTP projection".to_string());
                return Err(HttpAuthorityError::Kernel(reason));
            }
            (KernelVerdict::PendingApproval, _) => {
                return Err(HttpAuthorityError::PendingApproval {
                    approval_id: pending_approval_id(
                        kernel_response.receipt.metadata.as_ref(),
                        kernel_response.reason.as_deref(),
                    ),
                    kernel_receipt_id: kernel_response.receipt.id,
                });
            }
        }
        if is_execution_nonce_preflight(&kernel_response) {
            let evidence = projected_evidence(binding.policy, &presented_capability);
            return Ok(PreparedHttpEvaluation {
                verdict: Verdict::Incomplete {
                    reason: "execution nonce preflight requires retry with presented nonce"
                        .to_string(),
                },
                evidence,
                request_id: input.request_id,
                route_pattern: input.route_pattern,
                http_method: input.method,
                caller_identity_hash,
                content_hash,
                session_id: input.session_id,
                capability_id: presented_capability.capability_id,
                kernel_receipt_id: kernel_response.receipt.id,
                route_selection_metadata: metadata_value(
                    kernel_response.receipt.metadata.as_ref(),
                    "route_selection",
                )
                .cloned(),
                execution_nonce: kernel_response.execution_nonce.as_deref().cloned(),
            });
        }

        let evidence = projected_evidence(binding.policy, &presented_capability);

        Ok(PreparedHttpEvaluation {
            verdict,
            evidence,
            request_id: input.request_id,
            route_pattern: input.route_pattern,
            http_method: input.method,
            caller_identity_hash,
            content_hash,
            session_id: input.session_id,
            capability_id: presented_capability.capability_id,
            kernel_receipt_id: kernel_response.receipt.id,
            route_selection_metadata: metadata_value(
                kernel_response.receipt.metadata.as_ref(),
                "route_selection",
            )
            .cloned(),
            execution_nonce: kernel_response.execution_nonce.as_deref().cloned(),
        })
    }

    pub fn sign_decision_receipt(
        &self,
        prepared: &PreparedHttpEvaluation,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        self.sign_receipt(
            prepared,
            decision_status(&prepared.verdict),
            decision_metadata(
                Some(&prepared.kernel_receipt_id),
                prepared.route_selection_metadata.as_ref(),
            ),
        )
    }

    pub fn finalize_receipt(
        &self,
        prepared: &PreparedHttpEvaluation,
        response_status: u16,
        decision_receipt_id: Option<&str>,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        self.sign_receipt(
            prepared,
            response_status,
            final_metadata(
                decision_receipt_id,
                Some(&prepared.kernel_receipt_id),
                prepared.route_selection_metadata.as_ref(),
            ),
        )
    }

    /// Sign a deny receipt for a request that was rejected before the kernel
    /// ever evaluated it (for example, an oversized HTTP body that the
    /// transport layer refused to buffer). The caller supplies the verdict and
    /// the surface-level identification fields directly because no kernel
    /// receipt id, content hash, or capability id exists yet. The receipt
    /// carries `final` HTTP status scope metadata so downstream auditors can
    /// distinguish it from in-band kernel decisions.
    pub fn sign_transport_deny_receipt(
        &self,
        input: TransportDenyInput<'_>,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        if !input.verdict.is_denied() {
            return Err(HttpAuthorityError::Kernel(
                "sign_transport_deny_receipt requires a Deny verdict".to_string(),
            ));
        }
        let response_status = decision_status(&input.verdict);
        let body = HttpReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            request_id: input.request_id.to_string(),
            route_pattern: input.route_pattern.to_string(),
            method: input.method,
            caller_identity_hash: input.caller_identity_hash.to_string(),
            session_id: None,
            verdict: input.verdict,
            receipt_kind: chio_core_types::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core_types::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core_types::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core_types::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            evidence: Vec::new(),
            response_status,
            timestamp: chrono::Utc::now().timestamp() as u64,
            content_hash: input.content_hash.unwrap_or_default().to_string(),
            policy_hash: self.policy_hash.clone(),
            trust_level: chio_core_types::receipt::kinds::TrustLevel::Mediated,
            capability_id: None,
            metadata: Some(http_status_metadata_final(None)),
            kernel_key: self.keypair.public_key(),
        };
        HttpReceipt::sign(body, self.keypair.as_ref())
            .map_err(|e| HttpAuthorityError::ReceiptSign(e.to_string()))
    }

    pub fn finalize_decision_receipt(
        &self,
        decision_receipt: &HttpReceipt,
        response_status: u16,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        let mut body = decision_receipt.body();
        let decision_receipt_id = body.id.clone();
        let kernel_receipt_id = metadata_string(body.metadata.as_ref(), CHIO_KERNEL_RECEIPT_ID_KEY)
            .map(ToOwned::to_owned);
        let route_selection = metadata_value(body.metadata.as_ref(), "route_selection").cloned();
        body.id = uuid::Uuid::now_v7().to_string();
        body.response_status = response_status;
        body.timestamp = chrono::Utc::now().timestamp() as u64;
        body.metadata = final_metadata(
            Some(&decision_receipt_id),
            kernel_receipt_id.as_deref(),
            route_selection.as_ref(),
        );
        HttpReceipt::sign(body, self.keypair.as_ref())
            .map_err(|e| HttpAuthorityError::ReceiptSign(e.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_via_kernel(
        &self,
        request_id: &str,
        method: HttpMethod,
        route_pattern: &str,
        path: &str,
        content_hash: &str,
        caller_identity_hash: &str,
        session_id: Option<&str>,
        policy: HttpAuthorityPolicy,
        presented_capability: &PresentedCapabilityState,
        execution_nonce: Option<&SignedExecutionNonce>,
    ) -> Result<chio_kernel::ToolCallResponse, HttpAuthorityError> {
        let capability = match execution_nonce {
            Some(nonce) => self.kernel_capability_for_nonce_retry(nonce)?,
            None => self
                .kernel
                .issue_capability(
                    &self.kernel_subject,
                    kernel_scope(),
                    HTTP_AUTHORITY_TTL_SECS,
                )
                .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?,
        };

        let projected = HttpKernelAuthorizationRequest {
            method,
            route_pattern: route_pattern.to_string(),
            path: path.to_string(),
            content_hash: content_hash.to_string(),
            caller_identity_hash: caller_identity_hash.to_string(),
            session_id: session_id.map(ToOwned::to_owned),
            policy,
            capability: HttpKernelCapabilityState {
                id: presented_capability.capability_id.clone(),
                invalid_reason: presented_capability.invalid_reason.clone(),
            },
        };

        let request = ToolCallRequest {
            request_id: request_id.to_string(),
            capability,
            tool_name: HTTP_AUTHORITY_TOOL_NAME.to_string(),
            server_id: HTTP_AUTHORITY_SERVER_ID.to_string(),
            agent_id: self.kernel_agent_id.clone(),
            arguments: serde_json::to_value(projected)
                .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?,
            dpop_proof: None,
            execution_nonce: execution_nonce.cloned(),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let route_plan = plan_authoritative_route(
            request_id,
            DiscoveryProtocol::Http,
            DiscoveryProtocol::Native,
            None,
            &TargetProtocolRegistry::new(DiscoveryProtocol::Native),
            &BTreeMap::new(),
        )
        .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?;
        let route_metadata = route_selection_metadata(&route_plan.evidence)
            .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?;

        self.kernel
            .evaluate_tool_call_blocking_with_metadata(&request, Some(route_metadata))
            .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))
    }

    fn kernel_capability_for_nonce_retry(
        &self,
        nonce: &SignedExecutionNonce,
    ) -> Result<CapabilityToken, HttpAuthorityError> {
        let now = chrono::Utc::now().timestamp();
        let issued_at = u64::try_from(now.max(0))
            .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?;
        let body = CapabilityTokenBody {
            id: nonce.nonce.bound_to.capability_id.clone(),
            issuer: self.keypair.public_key(),
            subject: self.kernel_subject.clone(),
            scope: kernel_scope(),
            issued_at,
            expires_at: issued_at.saturating_add(HTTP_AUTHORITY_TTL_SECS),
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        CapabilityToken::sign(body, self.keypair.as_ref())
            .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))
    }

    fn sign_receipt(
        &self,
        prepared: &PreparedHttpEvaluation,
        response_status: u16,
        metadata: Option<Value>,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        let body = HttpReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            request_id: prepared.request_id.clone(),
            route_pattern: prepared.route_pattern.clone(),
            method: prepared.http_method,
            caller_identity_hash: prepared.caller_identity_hash.clone(),
            session_id: prepared.session_id.clone(),
            verdict: prepared.verdict.clone(),
            receipt_kind: chio_core_types::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core_types::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core_types::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core_types::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            evidence: prepared.evidence.clone(),
            response_status,
            timestamp: chrono::Utc::now().timestamp() as u64,
            content_hash: prepared.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            trust_level: chio_core_types::receipt::kinds::TrustLevel::Mediated,
            capability_id: prepared.capability_id.clone(),
            metadata,
            kernel_key: self.keypair.public_key(),
        };

        HttpReceipt::sign(body, self.keypair.as_ref())
            .map_err(|e| HttpAuthorityError::ReceiptSign(e.to_string()))
    }
}

fn kernel_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: HTTP_AUTHORITY_SERVER_ID.to_string(),
            tool_name: HTTP_AUTHORITY_TOOL_NAME.to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    }
}

fn decision_status(verdict: &Verdict) -> u16 {
    match verdict {
        Verdict::Allow => 200,
        Verdict::Deny { http_status, .. } => *http_status,
        Verdict::Cancel { .. } | Verdict::Incomplete { .. } => 500,
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_presented_capability(
    capability_id_hint: Option<&str>,
    presented_capability: Option<&str>,
    trusted_issuers: &[PublicKey],
    requested_tool_server: Option<&str>,
    requested_tool_name: Option<&str>,
    requested_arguments: Option<&Value>,
    model_metadata: Option<&ModelMetadata>,
    is_revoked: &dyn Fn(&str) -> Result<bool, HttpAuthorityError>,
) -> PresentedCapabilityState {
    let requested_tool = match (requested_tool_server, requested_tool_name) {
        (Some(server_id), Some(tool_name)) => Some(RequestedToolInvocation {
            server_id,
            tool_name,
            arguments: requested_arguments.unwrap_or(&Value::Null),
        }),
        (None, None) => None,
        _ => {
            return PresentedCapabilityState {
                capability_id: None,
                invalid_reason: Some(
                    "tool-call evaluation requires both tool_server and tool_name".to_string(),
                ),
            };
        }
    };
    let Some(raw_capability) = presented_capability else {
        return PresentedCapabilityState {
            capability_id: None,
            invalid_reason: None,
        };
    };

    match validate_capability_token(
        raw_capability,
        trusted_issuers,
        requested_tool,
        model_metadata,
    ) {
        Ok(token) => {
            if let Some(hint) = capability_id_hint {
                if hint != token.id {
                    return PresentedCapabilityState {
                        capability_id: None,
                        invalid_reason: Some(
                            "capability_id does not match the presented capability token"
                                .to_string(),
                        ),
                    };
                }
            }
            // The kernel's revocation check runs against the internal authority
            // capability minted per request, never against the caller's token,
            // so a presented capability that has been revoked (directly or via a
            // revoked delegation ancestor) must be rejected here before it is
            // projected as authorized.
            match presented_capability_revocation(&token, is_revoked) {
                Ok(None) => PresentedCapabilityState {
                    capability_id: Some(token.id),
                    invalid_reason: None,
                },
                Ok(Some(reason)) | Err(reason) => PresentedCapabilityState {
                    capability_id: None,
                    invalid_reason: Some(reason),
                },
            }
        }
        Err(reason) => PresentedCapabilityState {
            capability_id: None,
            invalid_reason: Some(reason),
        },
    }
}

/// Reject a presented capability whose id, or any id in its delegation chain,
/// is revoked. Returns `Ok(None)` when nothing is revoked, `Ok(Some(reason))`
/// when a revoked id is found, and `Err(reason)` when the revocation store
/// cannot be consulted, so an unavailable revocation store denies (fail-closed)
/// rather than silently projecting the capability as valid.
fn presented_capability_revocation(
    token: &CapabilityToken,
    is_revoked: &dyn Fn(&str) -> Result<bool, HttpAuthorityError>,
) -> Result<Option<String>, String> {
    let chain_ids = token
        .delegation_chain
        .iter()
        .map(|link| link.capability_id.as_str());
    for capability_id in std::iter::once(token.id.as_str()).chain(chain_ids) {
        match is_revoked(capability_id) {
            Ok(false) => {}
            Ok(true) => {
                return Ok(Some(format!(
                    "presented capability {capability_id} has been revoked"
                )))
            }
            Err(error) => return Err(format!("capability revocation status unavailable: {error}")),
        }
    }
    Ok(None)
}

fn projected_verdict(
    policy: HttpAuthorityPolicy,
    presented_capability: &PresentedCapabilityState,
) -> Verdict {
    if let Some(reason) = &presented_capability.invalid_reason {
        return Verdict::deny(reason, "CapabilityGuard");
    }

    match policy {
        HttpAuthorityPolicy::SessionAllow => Verdict::Allow,
        HttpAuthorityPolicy::DenyByDefault => match &presented_capability.capability_id {
            Some(_) => Verdict::Allow,
            None => Verdict::deny(
                "side-effect route requires a capability token",
                "CapabilityGuard",
            ),
        },
    }
}

fn is_execution_nonce_preflight(response: &chio_kernel::ToolCallResponse) -> bool {
    response.verdict == KernelVerdict::Allow
        && response.execution_nonce.is_some()
        && response.output.is_none()
}

fn projected_evidence(
    policy: HttpAuthorityPolicy,
    presented_capability: &PresentedCapabilityState,
) -> Vec<GuardEvidence> {
    if let Some(reason) = &presented_capability.invalid_reason {
        return vec![GuardEvidence {
            guard_name: "CapabilityGuard".to_string(),
            verdict: false,
            details: Some(reason.clone()),
        }];
    }

    match policy {
        HttpAuthorityPolicy::SessionAllow => vec![GuardEvidence {
            guard_name: "DefaultPolicyGuard".to_string(),
            verdict: true,
            details: Some("safe method, session-scoped allow".to_string()),
        }],
        HttpAuthorityPolicy::DenyByDefault => match &presented_capability.capability_id {
            Some(_) => vec![GuardEvidence {
                guard_name: "CapabilityGuard".to_string(),
                verdict: true,
                details: Some("valid capability token presented".to_string()),
            }],
            None => vec![GuardEvidence {
                guard_name: "CapabilityGuard".to_string(),
                verdict: false,
                details: Some("side-effect route requires a valid capability token".to_string()),
            }],
        },
    }
}

fn validate_capability_token(
    raw: &str,
    trusted_issuers: &[PublicKey],
    requested_tool: Option<RequestedToolInvocation<'_>>,
    model_metadata: Option<&ModelMetadata>,
) -> Result<CapabilityToken, String> {
    let token: CapabilityToken =
        serde_json::from_str(raw).map_err(|e| format!("invalid capability token: {e}"))?;
    if !trusted_issuers.contains(&token.issuer) {
        return Err("capability issuer is not trusted".to_string());
    }
    let signature_valid = token
        .verify_signature()
        .map_err(|e| format!("capability signature verification failed: {e}"))?;
    if !signature_valid {
        return Err("capability signature verification failed".to_string());
    }
    if token.attenuation_proof.is_some() {
        return Err(
            "chain-binding requires a trust-root resolver on the HTTP authority path".to_string(),
        );
    }
    token
        .validate_time(chrono::Utc::now().timestamp() as u64)
        .map_err(|e| format!("invalid capability token: {e}"))?;

    if let Some(requested_tool) = requested_tool {
        let matches = chio_kernel::capability_matches_request_with_model_metadata(
            &token,
            requested_tool.tool_name,
            requested_tool.server_id,
            requested_tool.arguments,
            model_metadata,
        )
        .map_err(|e| format!("failed to evaluate capability scope: {e}"))?;
        if !matches {
            return Err(format!(
                "capability does not authorize tool {} on server {}",
                requested_tool.tool_name, requested_tool.server_id
            ));
        }
    }
    Ok(token)
}

fn decision_metadata(
    kernel_receipt_id: Option<&str>,
    route_selection: Option<&Value>,
) -> Option<Value> {
    let mut metadata = http_status_metadata_decision();
    insert_metadata_string(&mut metadata, CHIO_KERNEL_RECEIPT_ID_KEY, kernel_receipt_id);
    insert_metadata_value(&mut metadata, "route_selection", route_selection);
    Some(metadata)
}

fn final_metadata(
    decision_receipt_id: Option<&str>,
    kernel_receipt_id: Option<&str>,
    route_selection: Option<&Value>,
) -> Option<Value> {
    let mut metadata = http_status_metadata_final(decision_receipt_id);
    insert_metadata_string(&mut metadata, CHIO_KERNEL_RECEIPT_ID_KEY, kernel_receipt_id);
    insert_metadata_value(&mut metadata, "route_selection", route_selection);
    Some(metadata)
}

fn insert_metadata_string(metadata: &mut Value, key: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };
    if let Value::Object(map) = metadata {
        map.insert(key.to_string(), Value::String(value.to_string()));
    } else {
        let mut map = Map::new();
        map.insert(key.to_string(), Value::String(value.to_string()));
        *metadata = Value::Object(map);
    }
}

fn insert_metadata_value(metadata: &mut Value, key: &str, value: Option<&Value>) {
    let Some(value) = value else {
        return;
    };
    if let Value::Object(map) = metadata {
        map.insert(key.to_string(), value.clone());
    } else {
        let mut map = Map::new();
        map.insert(key.to_string(), value.clone());
        *metadata = Value::Object(map);
    }
}

fn metadata_string<'a>(metadata: Option<&'a Value>, key: &str) -> Option<&'a str> {
    metadata
        .and_then(Value::as_object)
        .and_then(|map| map.get(key))
        .and_then(Value::as_str)
}

fn metadata_value<'a>(metadata: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    metadata
        .and_then(Value::as_object)
        .and_then(|map| map.get(key))
}

fn pending_approval_id(metadata: Option<&Value>, reason: Option<&str>) -> Option<String> {
    metadata_string(metadata, "approval_id")
        .or_else(|| {
            metadata_value(metadata, "pending_approval")
                .and_then(Value::as_object)
                .and_then(|pending| pending.get("approval_id"))
                .and_then(Value::as_str)
        })
        .map(ToOwned::to_owned)
        .or_else(|| extract_approval_id(reason))
}

fn extract_approval_id(reason: Option<&str>) -> Option<String> {
    let reason = reason?;
    for marker in ["/approvals/", "approval_id=", "approval_id:"] {
        if let Some(start) = reason.find(marker) {
            let suffix = reason[start + marker.len()..].trim_start();
            let approval_id = suffix
                .split(|character: char| {
                    character == '/'
                        || character == ','
                        || character == ';'
                        || character.is_whitespace()
                })
                .next()?;
            if !approval_id.is_empty() {
                return Some(approval_id.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests;
