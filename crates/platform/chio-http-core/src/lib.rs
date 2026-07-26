//! Protocol-agnostic HTTP security types for the Chio kernel.
//!
//! This crate defines the shared types that every HTTP substrate adapter uses:
//! request model, caller identity, session context, HTTP receipts, and verdicts.
//! It is the foundation for `chio-openapi`, `chio-config`, `chio api protect`,
//! and all language-specific middleware crates.

#![forbid(unsafe_code)]

pub mod approvals;
mod authority;
mod authority_projection;
pub mod compliance;
mod egress;
pub mod emergency;
mod evaluation;
mod identity;
mod method;
pub mod metrics;
pub mod plan;
mod receipt;
pub mod regulatory_api;
mod request;
pub mod routes;
mod session;
mod verdict;

pub use metrics::{
    decision_latency_count, guard_evaluations_total, observe_decision_latency_nanos,
    record_guard_evaluation, render_http_core_metrics_prometheus, CHIO_GUARD_EVALUATIONS_TOTAL,
    CHIO_KERNEL_DECISION_LATENCY_SECONDS, GUARD_LABEL_HTTP_AUTHORITY, GUARD_OUTCOME_ALLOW,
    GUARD_OUTCOME_DENY, GUARD_OUTCOME_ERROR,
};

pub use approvals::{
    handle_batch_respond, handle_create_threshold_proposal, handle_deliver_threshold_approval,
    handle_get_approval, handle_get_threshold_proposal, handle_list_pending, handle_respond,
    handle_submit_threshold_approval, ApprovalAdmin, ApprovalHandlerError, BatchDecisionEntry,
    BatchRespondRequest, BatchRespondResponse, BatchRespondResult, BatchRespondSummary,
    CreateThresholdProposalRequest, GetApprovalResponse, PendingListResponse, PendingQuery,
    RespondRequest, RespondResponse, SubmitThresholdApprovalRequest,
};
pub use authority::{
    http_authority_tool_grant, HttpAuthority, HttpAuthorityBuilder, HttpAuthorityError,
    HttpAuthorityEvaluation, HttpAuthorityInput, HttpAuthorityPolicy, PreparedHttpEvaluation,
    TransportDenyInput, HTTP_AUTHORITY_SERVER_ID, HTTP_AUTHORITY_TOOL_NAME,
};
pub use compliance::{
    handle_compliance_score, ComplianceScoreError, ComplianceScoreRequest, ComplianceScoreResponse,
    ComplianceScoreWindow, ComplianceSource, ComplianceSourceResult,
};
#[cfg(feature = "reqwest-egress")]
pub use egress::{client_builder_with_contract, send_with_contract};
pub use egress::{HttpEgressContract, HttpEgressError, ValidatedHttpEgressTarget};
pub use emergency::{
    handle_emergency_resume, handle_emergency_status, handle_emergency_stop, EmergencyAdmin,
    EmergencyHandlerError, EmergencyResumeResponse, EmergencyStatusResponse, EmergencyStopRequest,
    EmergencyStopResponse,
};
pub use evaluation::{EvaluateResponse, HealthResponse, SidecarStatus, VerifyReceiptResponse};
pub use identity::{AuthMethod, CallerIdentity};
pub use method::HttpMethod;
pub use plan::{handle_evaluate_plan, PlanHandlerError};
pub use receipt::{
    http_status_metadata_decision, http_status_metadata_final, http_status_scope, HttpReceipt,
    HttpReceiptBody, CHIO_DECISION_RECEIPT_ID_KEY, CHIO_HTTP_STATUS_SCOPE_DECISION,
    CHIO_HTTP_STATUS_SCOPE_FINAL, CHIO_HTTP_STATUS_SCOPE_KEY, CHIO_KERNEL_RECEIPT_ID_KEY,
};
pub use regulatory_api::{
    handle_regulatory_receipts_signed, sign_regulatory_export, verify_regulatory_export,
    RegulatorIdentity, RegulatoryApiError, RegulatoryReceiptExport, RegulatoryReceiptQueryResult,
    RegulatoryReceiptSource, RegulatoryReceiptsQuery, SignedRegulatoryReceiptExport,
    MAX_REGULATORY_EXPORT_LIMIT, REGULATORY_RECEIPT_EXPORT_SCHEMA,
};
pub use request::ChioHttpRequest;
pub use routes::{
    approval_route_registrations, emergency_route_registrations, regulatory_route_registrations,
    EmergencyRouteRegistration, APPROVALS_BATCH_RESPOND_PATH, APPROVALS_GET_PATH,
    APPROVALS_PENDING_PATH, APPROVALS_RESPOND_PATH, COMPLIANCE_SCORE_PATH,
    EMERGENCY_ADMIN_TOKEN_HEADER, EMERGENCY_RESUME_PATH, EMERGENCY_STATUS_PATH,
    EMERGENCY_STOP_PATH, EVALUATE_PLAN_PATH, REGULATORY_RECEIPTS_PATH, REGULATORY_TOKEN_HEADER,
};
pub use session::SessionContext;
pub use verdict::{DenyDetails, Verdict};

// Re-export execution-nonce types so HTTP SDKs don't need to depend on
// chio-kernel directly just to read the nonce off the response.
pub use chio_kernel::{
    ExecutionNonce, ExecutionNonceConfig, ExecutionNonceError, ExecutionNonceStore,
    InMemoryExecutionNonceStore, NonceBinding, SignedExecutionNonce, EXECUTION_NONCE_SCHEMA,
};

// Re-export types from chio-core-types that HTTP adapters commonly need.
pub use chio_core_types::canonical::{canonical_json_bytes, canonical_json_string};
pub use chio_core_types::crypto::{Keypair, PublicKey, Signature};
pub use chio_core_types::plan::{
    PlanEvaluationRequest, PlanEvaluationResponse, PlanVerdict, PlannedToolCall, PlannedToolCallId,
    StepVerdict, StepVerdictKind,
};
pub use chio_core_types::receipt::metadata::GuardEvidence;
pub use chio_core_types::{sha256_hex, Error, Result};
