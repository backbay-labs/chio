//! Protocol-agnostic HTTP security types for the Chio kernel.
//!
//! This crate defines the shared types that every HTTP substrate adapter uses:
//! request model, caller identity, session context, HTTP receipts, and verdicts.
//! It is the foundation for `chio-openapi`, `chio-config`, `chio api protect`,
//! and all language-specific middleware crates.

pub mod approvals;
mod authority;
pub mod compliance;
mod egress;
pub mod emergency;
mod evaluation;
mod identity;
mod method;
pub mod plan;
mod receipt;
pub mod regulatory_api;
mod request;
pub mod routes;
mod session;
mod verdict;

pub use approvals::{
    handle_batch_respond, handle_get_approval, handle_list_pending, handle_respond, ApprovalAdmin,
    ApprovalHandlerError, BatchDecisionEntry, BatchRespondRequest, BatchRespondResponse,
    BatchRespondResult, BatchRespondSummary, GetApprovalResponse, PendingListResponse,
    PendingQuery, RespondRequest, RespondResponse,
};
pub use authority::{
    HttpAuthority, HttpAuthorityError, HttpAuthorityEvaluation, HttpAuthorityInput,
    HttpAuthorityPolicy, PreparedHttpEvaluation, TransportDenyInput,
};
pub use compliance::{
    handle_compliance_score, ComplianceScoreError, ComplianceScoreRequest, ComplianceScoreResponse,
    ComplianceScoreWindow, ComplianceSource, ComplianceSourceResult,
};
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
pub use chio_core_types::receipt::GuardEvidence;
pub use chio_core_types::{sha256_hex, Error, Result};
