use super::*;

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct StructuredErrorReport {
    pub code: String,
    pub message: String,
    pub context: serde_json::Value,
    pub suggested_fix: String,
}

impl StructuredErrorReport {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        context: serde_json::Value,
        suggested_fix: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            context,
            suggested_fix: suggested_fix.into(),
        }
    }
}

/// Which bounded resource shed. Included in the receipt deny reason and the
/// structured error report so operators can see which policy fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverloadResource {
    ReceiptMirror,
    FederationCache,
    VelocityBuckets,
    AdmissionKeys,
    ConcurrencyBuckets,
    SessionJournal,
    StreamBytes,
    StreamChunks,
    Allocation,
}

/// Errors that can occur during kernel operations.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("unknown session: {0}")]
    UnknownSession(SessionId),

    #[error("session already exists: {0}")]
    SessionAlreadyExists(SessionId),

    #[error("session error: {0}")]
    Session(#[from] SessionError),

    #[error("capability has expired")]
    CapabilityExpired,

    #[error("capability not yet valid")]
    CapabilityNotYetValid,

    #[error("capability has been revoked: {0}")]
    CapabilityRevoked(CapabilityId),

    #[error("capability signature is invalid")]
    InvalidSignature,

    #[error("capability issuer is not a trusted CA")]
    UntrustedIssuer,

    #[error("capability issuance failed: {0}")]
    CapabilityIssuanceFailed(String),

    #[error("capability issuance denied: {0}")]
    CapabilityIssuanceDenied(String),

    #[error("requested tool {tool} on server {server} is not in capability scope")]
    OutOfScope { tool: String, server: String },

    #[error("requested resource {uri} is not in capability scope")]
    OutOfScopeResource { uri: String },

    #[error("requested prompt {prompt} is not in capability scope")]
    OutOfScopePrompt { prompt: String },

    #[error("invocation budget exhausted for capability {0}")]
    BudgetExhausted(CapabilityId),

    #[error("request agent {actual} does not match capability subject {expected}")]
    SubjectMismatch { expected: String, actual: String },

    #[error("delegation chain revoked at ancestor {0}")]
    DelegationChainRevoked(CapabilityId),

    #[error("delegation admission failed: {0}")]
    DelegationInvalid(String),

    #[error("invalid capability constraint: {0}")]
    InvalidConstraint(String),

    #[error("governed transaction denied: {0}")]
    GovernedTransactionDenied(String),

    #[error("guard denied the request: {0}")]
    GuardDenied(String),

    #[error("tool server error: {0}")]
    ToolServerError(String),

    #[error("request stream incomplete: {0}")]
    RequestIncomplete(String),

    #[error("tool not registered: {0}")]
    ToolNotRegistered(String),

    #[error("resource not registered: {0}")]
    ResourceNotRegistered(String),

    #[error("resource read denied by session roots for {uri}: {reason}")]
    ResourceRootDenied { uri: String, reason: String },

    #[error("prompt not registered: {0}")]
    PromptNotRegistered(String),

    #[error("sampling is disabled by policy")]
    SamplingNotAllowedByPolicy,

    #[error("sampling was not negotiated with the client")]
    SamplingNotNegotiated,

    #[error("sampling context inclusion is not supported by the client")]
    SamplingContextNotSupported,

    #[error("sampling tool use is disabled by policy")]
    SamplingToolUseNotAllowedByPolicy,

    #[error("sampling tool use was not negotiated with the client")]
    SamplingToolUseNotNegotiated,

    #[error("elicitation is disabled by policy")]
    ElicitationNotAllowedByPolicy,

    #[error("elicitation was not negotiated with the client")]
    ElicitationNotNegotiated,

    #[error("elicitation form mode is not supported by the client")]
    ElicitationFormNotSupported,

    #[error("elicitation URL mode was not negotiated with the client")]
    ElicitationUrlNotSupported,

    #[error("{message}")]
    UrlElicitationsRequired {
        message: String,
        elicitations: Vec<CreateElicitationOperation>,
    },

    #[error("roots/list was not negotiated with the client")]
    RootsNotNegotiated,

    #[error("sampling child requests require a ready session-bound parent request")]
    InvalidChildRequestParent,

    #[error("request {request_id} was cancelled: {reason}")]
    RequestCancelled {
        request_id: RequestId,
        reason: String,
    },

    #[error("receipt signing failed: {0}")]
    ReceiptSigningFailed(String),

    #[error("receipt persistence failed: {0}")]
    ReceiptPersistence(#[from] ReceiptStoreError),

    #[error("revocation store error: {0}")]
    RevocationStore(#[from] RevocationStoreError),

    #[error("budget store error: {0}")]
    BudgetStore(#[from] BudgetStoreError),

    #[error(
        "cross-currency budget enforcement failed: no price oracle configured for {base}/{quote}"
    )]
    NoCrossCurrencyOracle { base: String, quote: String },

    #[error("cross-currency budget enforcement failed: {0}")]
    CrossCurrencyOracle(String),

    #[error("web3 evidence prerequisites unavailable: {0}")]
    Web3EvidenceUnavailable(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("DPoP proof verification failed: {0}")]
    DpopVerificationFailed(String),

    /// A human-in-the-loop approval token failed to satisfy
    /// the pending approval contract (bad binding, bad signature,
    /// expired, or replayed).
    #[error("approval rejected: {0}")]
    ApprovalRejected(String),

    /// The sync `evaluate_tool_call` path was invoked from a context
    /// where the only available Tokio runtime is a current-thread
    /// runtime. The async tool-dispatch path cannot be safely driven
    /// on a current-thread runtime: bridging via
    /// `futures::executor::block_on` parks the caller's thread, and
    /// Tokio I/O timers / reactor wakers cannot progress on the same
    /// parked thread. Returning a typed error rather than deadlocking
    /// lets callers move the dispatch onto a multi-thread runtime.
    /// The public async `evaluate_tool_call` path is still backed by the
    /// blocking evaluator on this branch, so it is not a current-thread
    /// escape hatch.
    #[error(
        "sync tool-dispatch bridge cannot drive an async tool server on a current-thread \
         Tokio runtime; switch the host to a multi-thread Tokio runtime"
    )]
    SyncBridgeIncompatibleWithCurrentThreadRuntime,

    /// The kernel shed load to stay within its memory budget. Always a deny;
    /// never admits a call and never grows a collection.
    #[error("kernel overloaded: {resource:?} at capacity")]
    Overloaded { resource: OverloadResource },
}

impl KernelError {
    fn report_with_context(
        &self,
        code: &str,
        context: serde_json::Value,
        suggested_fix: impl Into<String>,
    ) -> StructuredErrorReport {
        StructuredErrorReport::new(code, self.to_string(), context, suggested_fix)
    }

    pub fn report(&self) -> StructuredErrorReport {
        match self {
            Self::Overloaded { resource } => self.report_with_context(
                "CHIO-KERNEL-OVERLOADED",
                serde_json::json!({ "resource": format!("{resource:?}") }),
                "The kernel shed load to stay within its memory budget. Retry with backoff; \
                 if sustained, raise the process memory budget or scale out.",
            ),
            Self::UnknownSession(session_id) => self.report_with_context(
                "CHIO-KERNEL-UNKNOWN-SESSION",
                serde_json::json!({ "session_id": session_id.to_string() }),
                "Create the session first or reuse a session ID returned by the kernel before issuing follow-up operations.",
            ),
            Self::SessionAlreadyExists(session_id) => self.report_with_context(
                "CHIO-KERNEL-SESSION-ALREADY-EXISTS",
                serde_json::json!({ "session_id": session_id.to_string() }),
                "Use a fresh session ID or drop the duplicate restored record before opening the session.",
            ),
            Self::Session(error) => self.report_with_context(
                "CHIO-KERNEL-SESSION",
                serde_json::json!({ "session_error": error.to_string() }),
                "Inspect the session lifecycle and ordering of operations, then recreate the session if it is no longer valid.",
            ),
            Self::CapabilityExpired => self.report_with_context(
                "CHIO-KERNEL-CAPABILITY-EXPIRED",
                serde_json::json!({}),
                "Refresh or reissue the capability so its validity window includes the current time.",
            ),
            Self::CapabilityNotYetValid => self.report_with_context(
                "CHIO-KERNEL-CAPABILITY-NOT-YET-VALID",
                serde_json::json!({}),
                "Use a capability whose validity window has started, or correct the issuer clock skew if timestamps are wrong.",
            ),
            Self::CapabilityRevoked(capability_id) => self.report_with_context(
                "CHIO-KERNEL-CAPABILITY-REVOKED",
                serde_json::json!({ "capability_id": capability_id }),
                "Request a new non-revoked capability or inspect the revocation record for this capability lineage.",
            ),
            Self::InvalidSignature => self.report_with_context(
                "CHIO-KERNEL-INVALID-SIGNATURE",
                serde_json::json!({}),
                "Reissue the capability or receipt with the correct signing key and verify the payload was not mutated in transit.",
            ),
            Self::UntrustedIssuer => self.report_with_context(
                "CHIO-KERNEL-UNTRUSTED-ISSUER",
                serde_json::json!({}),
                "Configure the issuing CA public key in the kernel trust set or use a capability issued by a trusted authority.",
            ),
            Self::CapabilityIssuanceFailed(reason) => self.report_with_context(
                "CHIO-KERNEL-CAPABILITY-ISSUANCE-FAILED",
                serde_json::json!({ "reason": reason }),
                "Inspect the issuance pipeline inputs and upstream stores, then retry once the issuing dependency is healthy.",
            ),
            Self::CapabilityIssuanceDenied(reason) => self.report_with_context(
                "CHIO-KERNEL-CAPABILITY-ISSUANCE-DENIED",
                serde_json::json!({ "reason": reason }),
                "Adjust the issuance request so it satisfies the policy, score, or trust requirements enforced by the authority.",
            ),
            Self::OutOfScope { tool, server } => self.report_with_context(
                "CHIO-KERNEL-OUT-OF-SCOPE-TOOL",
                serde_json::json!({ "tool": tool, "server": server }),
                "Issue a capability that grants this tool on this server, or call a tool already inside the granted scope.",
            ),
            Self::OutOfScopeResource { uri } => self.report_with_context(
                "CHIO-KERNEL-OUT-OF-SCOPE-RESOURCE",
                serde_json::json!({ "uri": uri }),
                "Issue a capability/resource grant that matches this URI, or request a resource already inside scope.",
            ),
            Self::OutOfScopePrompt { prompt } => self.report_with_context(
                "CHIO-KERNEL-OUT-OF-SCOPE-PROMPT",
                serde_json::json!({ "prompt": prompt }),
                "Issue a capability/prompt grant that matches this prompt, or request a prompt already inside scope.",
            ),
            Self::BudgetExhausted(capability_id) => self.report_with_context(
                "CHIO-KERNEL-BUDGET-EXHAUSTED",
                serde_json::json!({ "capability_id": capability_id }),
                "Increase the capability budget, wait for the budget window to reset, or lower the cost of the requested operation.",
            ),
            Self::SubjectMismatch { expected, actual } => self.report_with_context(
                "CHIO-KERNEL-SUBJECT-MISMATCH",
                serde_json::json!({ "expected": expected, "actual": actual }),
                "Use a capability issued to the requesting subject, or correct the agent identity bound to the request.",
            ),
            Self::DelegationChainRevoked(capability_id) => self.report_with_context(
                "CHIO-KERNEL-DELEGATION-CHAIN-REVOKED",
                serde_json::json!({ "capability_id": capability_id }),
                "Inspect the capability lineage and reissue the chain from a non-revoked ancestor.",
            ),
            Self::DelegationInvalid(reason) => self.report_with_context(
                "CHIO-KERNEL-DELEGATION-INVALID",
                serde_json::json!({ "reason": reason }),
                "Reissue the delegated capability with a valid ancestor snapshot chain, delegator binding, attenuation proof, and delegated scope ceiling.",
            ),
            Self::InvalidConstraint(reason) => self.report_with_context(
                "CHIO-KERNEL-INVALID-CONSTRAINT",
                serde_json::json!({ "reason": reason }),
                "Fix the capability constraint payload so it matches the kernel's supported schema and value rules.",
            ),
            Self::GovernedTransactionDenied(reason) => self.report_with_context(
                "CHIO-KERNEL-GOVERNED-TRANSACTION-DENIED",
                serde_json::json!({ "reason": reason }),
                "Adjust the governed transaction intent so it satisfies the configured approval and policy requirements.",
            ),
            Self::GuardDenied(reason) => self.report_with_context(
                "CHIO-KERNEL-GUARD-DENIED",
                serde_json::json!({ "reason": reason }),
                "Adjust the request or policy/guard configuration so the request satisfies the active guard pipeline.",
            ),
            Self::ToolServerError(reason) => self.report_with_context(
                "CHIO-KERNEL-TOOL-SERVER",
                serde_json::json!({ "reason": reason }),
                "Inspect the wrapped tool server logs and protocol compatibility, then retry once the server is healthy.",
            ),
            Self::RequestIncomplete(reason) => self.report_with_context(
                "CHIO-KERNEL-REQUEST-INCOMPLETE",
                serde_json::json!({ "reason": reason }),
                "Resubmit the request with all required fields and protocol state transitions present.",
            ),
            Self::ToolNotRegistered(tool) => self.report_with_context(
                "CHIO-KERNEL-TOOL-NOT-REGISTERED",
                serde_json::json!({ "tool": tool }),
                "Register the tool on the target server or update the request to reference an exposed tool.",
            ),
            Self::ResourceNotRegistered(uri) => self.report_with_context(
                "CHIO-KERNEL-RESOURCE-NOT-REGISTERED",
                serde_json::json!({ "uri": uri }),
                "Register the resource provider for this URI or request a resource that is actually exposed by the runtime.",
            ),
            Self::ResourceRootDenied { uri, reason } => self.report_with_context(
                "CHIO-KERNEL-RESOURCE-ROOT-DENIED",
                serde_json::json!({ "uri": uri, "reason": reason }),
                "Expand the session filesystem roots if the access is intentional, or request a resource inside the approved root set.",
            ),
            Self::PromptNotRegistered(prompt) => self.report_with_context(
                "CHIO-KERNEL-PROMPT-NOT-REGISTERED",
                serde_json::json!({ "prompt": prompt }),
                "Register the prompt provider for this prompt name or request a prompt that is actually exposed.",
            ),
            Self::SamplingNotAllowedByPolicy => self.report_with_context(
                "CHIO-KERNEL-SAMPLING-NOT-ALLOWED",
                serde_json::json!({}),
                "Enable sampling in policy if this workflow requires it, or retry without a sampling request.",
            ),
            Self::SamplingNotNegotiated => self.report_with_context(
                "CHIO-KERNEL-SAMPLING-NOT-NEGOTIATED",
                serde_json::json!({}),
                "Negotiate sampling support with the client before issuing sampling operations.",
            ),
            Self::SamplingContextNotSupported => self.report_with_context(
                "CHIO-KERNEL-SAMPLING-CONTEXT-NOT-SUPPORTED",
                serde_json::json!({}),
                "Disable sampling context inclusion or upgrade the client to one that supports the negotiated feature.",
            ),
            Self::SamplingToolUseNotAllowedByPolicy => self.report_with_context(
                "CHIO-KERNEL-SAMPLING-TOOL-USE-NOT-ALLOWED",
                serde_json::json!({}),
                "Enable sampling tool use in policy or retry without delegated tool execution inside the sampling branch.",
            ),
            Self::SamplingToolUseNotNegotiated => self.report_with_context(
                "CHIO-KERNEL-SAMPLING-TOOL-USE-NOT-NEGOTIATED",
                serde_json::json!({}),
                "Negotiate sampling tool-use support with the client before attempting tool execution inside sampling.",
            ),
            Self::ElicitationNotAllowedByPolicy => self.report_with_context(
                "CHIO-KERNEL-ELICITATION-NOT-ALLOWED",
                serde_json::json!({}),
                "Enable elicitation in policy or retry without requesting user input through the kernel.",
            ),
            Self::ElicitationNotNegotiated => self.report_with_context(
                "CHIO-KERNEL-ELICITATION-NOT-NEGOTIATED",
                serde_json::json!({}),
                "Negotiate elicitation support with the client before attempting elicitation operations.",
            ),
            Self::ElicitationFormNotSupported => self.report_with_context(
                "CHIO-KERNEL-ELICITATION-FORM-NOT-SUPPORTED",
                serde_json::json!({}),
                "Switch to a supported elicitation mode or upgrade the client to one that supports form-mode elicitation.",
            ),
            Self::ElicitationUrlNotSupported => self.report_with_context(
                "CHIO-KERNEL-ELICITATION-URL-NOT-SUPPORTED",
                serde_json::json!({}),
                "Switch to a supported elicitation mode or negotiate URL-based elicitation support with the client.",
            ),
            Self::UrlElicitationsRequired {
                message,
                elicitations,
            } => self.report_with_context(
                "CHIO-KERNEL-URL-ELICITATIONS-REQUIRED",
                serde_json::json!({
                    "message": message,
                    "elicitation_count": elicitations.len()
                }),
                "Complete the required URL-based elicitation flow and resubmit the request afterward.",
            ),
            Self::RootsNotNegotiated => self.report_with_context(
                "CHIO-KERNEL-ROOTS-NOT-NEGOTIATED",
                serde_json::json!({}),
                "Negotiate roots/list support with the client before using root-scoped resource protections.",
            ),
            Self::InvalidChildRequestParent => self.report_with_context(
                "CHIO-KERNEL-INVALID-CHILD-REQUEST-PARENT",
                serde_json::json!({}),
                "Create the child request from a ready session-bound parent request that is currently in flight.",
            ),
            Self::RequestCancelled { request_id, reason } => self.report_with_context(
                "CHIO-KERNEL-REQUEST-CANCELLED",
                serde_json::json!({ "request_id": request_id.to_string(), "reason": reason }),
                "Stop using the cancelled request ID and restart the operation if the workflow still needs to continue.",
            ),
            Self::ReceiptSigningFailed(reason) => self.report_with_context(
                "CHIO-KERNEL-RECEIPT-SIGNING-FAILED",
                serde_json::json!({ "reason": reason }),
                "Inspect the kernel signing key configuration and signing payload integrity, then retry receipt generation.",
            ),
            Self::ReceiptPersistence(error) => self.report_with_context(
                "CHIO-KERNEL-RECEIPT-PERSISTENCE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured receipt store connectivity, permissions, and schema health before retrying.",
            ),
            Self::RevocationStore(error) => self.report_with_context(
                "CHIO-KERNEL-REVOCATION-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured revocation store connectivity, permissions, and schema health before retrying.",
            ),
            Self::BudgetStore(error) => self.report_with_context(
                "CHIO-KERNEL-BUDGET-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured budget store connectivity, permissions, and schema health before retrying.",
            ),
            Self::NoCrossCurrencyOracle { base, quote } => self.report_with_context(
                "CHIO-KERNEL-NO-CROSS-CURRENCY-ORACLE",
                serde_json::json!({ "base": base, "quote": quote }),
                "Configure a price oracle for this currency pair or avoid a cross-currency budget path for this request.",
            ),
            Self::CrossCurrencyOracle(reason) => self.report_with_context(
                "CHIO-KERNEL-CROSS-CURRENCY-ORACLE",
                serde_json::json!({ "reason": reason }),
                "Inspect the price-oracle configuration and upstream quote availability for the requested currency conversion.",
            ),
            Self::Web3EvidenceUnavailable(reason) => self.report_with_context(
                "CHIO-KERNEL-WEB3-EVIDENCE-UNAVAILABLE",
                serde_json::json!({ "reason": reason }),
                "Enable the required receipt-store, checkpoint, and oracle prerequisites before running the web3 evidence path.",
            ),
            Self::Internal(reason) => self.report_with_context(
                "CHIO-KERNEL-INTERNAL",
                serde_json::json!({ "reason": reason }),
                "Capture the error report and kernel logs, then treat this as a reproducible kernel bug if it persists.",
            ),
            Self::DpopVerificationFailed(reason) => self.report_with_context(
                "CHIO-KERNEL-DPOP-VERIFICATION-FAILED",
                serde_json::json!({ "reason": reason }),
                "Attach a valid DPoP proof bound to the current capability, request, server, and tool before retrying.",
            ),
            Self::ApprovalRejected(reason) => self.report_with_context(
                "CHIO-KERNEL-APPROVAL-REJECTED",
                serde_json::json!({ "reason": reason }),
                "Obtain a fresh approval token bound to this exact request and retry once a human approver has signed it.",
            ),
            Self::SyncBridgeIncompatibleWithCurrentThreadRuntime => self.report_with_context(
                "CHIO-KERNEL-SYNC-BRIDGE-INCOMPATIBLE",
                serde_json::json!({}),
                "Move the host process to a multi-thread Tokio runtime so block_in_place can drive async tool dispatch. The public async evaluate_tool_call path is still backed by the blocking evaluator on this branch and is not a current-thread runtime workaround.",
            ),
        }
    }
}

#[cfg(test)]
mod overload_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn overloaded_reports_resource_and_fail_closed_code() {
        let err = KernelError::Overloaded {
            resource: OverloadResource::AdmissionKeys,
        };
        let report = err.report();
        assert_eq!(report.code, "CHIO-KERNEL-OVERLOADED");
        assert!(
            err.to_string().contains("AdmissionKeys"),
            "display must name the shed resource: {err}"
        );
        assert_eq!(
            report.context.get("resource").and_then(|v| v.as_str()),
            Some("AdmissionKeys")
        );
    }
}
