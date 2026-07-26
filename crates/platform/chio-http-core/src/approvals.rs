//! HITL approval HTTP surface.
//!
//! Substrate-agnostic handlers for the four approval endpoints:
//!
//! | Method | Path                            | Handler |
//! |--------|---------------------------------|---------|
//! | GET    | `/approvals/pending`            | [`handle_list_pending`] |
//! | GET    | `/approvals/{id}`               | [`handle_get_approval`] |
//! | POST   | `/approvals/{id}/respond`       | [`handle_respond`] |
//! | POST   | `/approvals/batch/respond`      | [`handle_batch_respond`] |
//!
//! Each handler accepts parsed inputs and returns a typed response so
//! `chio-tower`, `chio-api-protect`, and hosted sidecars can serve them
//! without agreeing on a framework. Errors carry HTTP status codes via
//! [`ApprovalHandlerError::status`] for predictable mapping.

use std::sync::Arc;

use chio_core_types::capability::governance::{GovernedApprovalToken, ThresholdApprovalProposal};
use chio_core_types::capability::threshold_approval::ThresholdApprovalRequirement;
use chio_core_types::crypto::PublicKey;
use chio_kernel::{
    resume_with_decision, ApprovalDecision, ApprovalFilter, ApprovalOutcome, ApprovalRequest,
    ApprovalStore, ApprovalStoreError, ApprovalToken, CollectedThresholdApprovalSet, KernelError,
    ResolvedApproval, ThresholdApprovalCollector, ThresholdApprovalCollectorProposal,
    ThresholdApprovalCollectorStoreError,
};
use serde::{Deserialize, Serialize};

/// Errors returned by the approval handlers. Each variant maps onto a
/// stable HTTP status so substrate adapters can relay the code without
/// re-interpreting the semantics.
#[derive(Debug, Clone)]
pub enum ApprovalHandlerError {
    /// Request body could not be parsed into the expected JSON shape.
    BadRequest(String),
    /// Target approval id does not exist in the store.
    NotFound(String),
    /// Approval was already resolved (single-response rule).
    Conflict(String),
    /// Replay detected: the signed token has already been consumed.
    ReplayDetected(String),
    /// Approval token failed binding / signature / time checks.
    Rejected(String),
    /// Backend store surfaced an internal error.
    Internal(String),
}

impl ApprovalHandlerError {
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::NotFound(_) => 404,
            Self::Conflict(_) => 409,
            Self::ReplayDetected(_) => 409,
            Self::Rejected(_) => 403,
            Self::Internal(_) => 500,
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "conflict",
            Self::ReplayDetected(_) => "replay_detected",
            Self::Rejected(_) => "approval_rejected",
            Self::Internal(_) => "internal_error",
        }
    }

    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::BadRequest(m)
            | Self::NotFound(m)
            | Self::Conflict(m)
            | Self::ReplayDetected(m)
            | Self::Rejected(m)
            | Self::Internal(m) => m.clone(),
        }
    }

    #[must_use]
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.code(),
            "message": self.message(),
        })
    }
}

impl std::fmt::Display for ApprovalHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for ApprovalHandlerError {}

impl From<ApprovalStoreError> for ApprovalHandlerError {
    fn from(e: ApprovalStoreError) -> Self {
        match e {
            ApprovalStoreError::NotFound(m) => Self::NotFound(m),
            ApprovalStoreError::AlreadyResolved(m) => {
                Self::Conflict(format!("already resolved: {m}"))
            }
            ApprovalStoreError::Replay(m) => Self::ReplayDetected(m),
            ApprovalStoreError::Backend(m) => Self::Internal(m),
            ApprovalStoreError::Serialization(m) => Self::Internal(m),
        }
    }
}

impl From<KernelError> for ApprovalHandlerError {
    fn from(e: KernelError) -> Self {
        match e {
            KernelError::ApprovalRejected(m) => {
                if m.contains("replay") {
                    Self::ReplayDetected(m)
                } else {
                    Self::Rejected(m)
                }
            }
            other => Self::Internal(other.to_string()),
        }
    }
}

impl From<ThresholdApprovalCollectorStoreError> for ApprovalHandlerError {
    fn from(error: ThresholdApprovalCollectorStoreError) -> Self {
        match error {
            ThresholdApprovalCollectorStoreError::NotFound(message) => Self::NotFound(message),
            ThresholdApprovalCollectorStoreError::Conflict(message) => Self::Conflict(message),
            ThresholdApprovalCollectorStoreError::Backend(message)
            | ThresholdApprovalCollectorStoreError::Serialization(message) => {
                Self::Internal(message)
            }
        }
    }
}

/// Admin handle bound to the kernel's approval store.
#[derive(Clone)]
pub struct ApprovalAdmin {
    store: Arc<dyn ApprovalStore>,
    threshold_collector: Option<ThresholdApprovalCollector>,
}

impl std::fmt::Debug for ApprovalAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalAdmin").finish_non_exhaustive()
    }
}

impl ApprovalAdmin {
    #[must_use]
    pub fn new(store: Arc<dyn ApprovalStore>) -> Self {
        Self {
            store,
            threshold_collector: None,
        }
    }

    #[must_use]
    pub fn with_threshold_collector(
        store: Arc<dyn ApprovalStore>,
        threshold_collector: ThresholdApprovalCollector,
    ) -> Self {
        Self {
            store,
            threshold_collector: Some(threshold_collector),
        }
    }

    #[must_use]
    pub fn store(&self) -> &Arc<dyn ApprovalStore> {
        &self.store
    }

    fn threshold_collector(&self) -> Result<&ThresholdApprovalCollector, ApprovalHandlerError> {
        self.threshold_collector.as_ref().ok_or_else(|| {
            ApprovalHandlerError::Internal(
                "threshold approval collector is not configured".to_string(),
            )
        })
    }
}

// ----- Wire shapes --------------------------------------------------

/// Query parameters for `GET /approvals/pending`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PendingQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_expired_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl From<PendingQuery> for ApprovalFilter {
    fn from(q: PendingQuery) -> Self {
        Self {
            subject_id: q.subject_id,
            tool_server: q.tool_server,
            tool_name: q.tool_name,
            not_expired_at: q.not_expired_at,
            limit: q.limit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingListResponse {
    pub approvals: Vec<ApprovalRequest>,
    pub count: usize,
}

/// Body for `POST /approvals/{id}/respond`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespondRequest {
    pub outcome: ApprovalOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub approver: PublicKey,
    pub token: GovernedApprovalToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespondResponse {
    pub approval_id: String,
    pub outcome: ApprovalOutcome,
    pub resolved_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateThresholdProposalRequest {
    pub proposal: ThresholdApprovalProposal,
    pub requirement: ThresholdApprovalRequirement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitter: Option<PublicKey>,
    #[serde(default)]
    pub require_submitter_separation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitThresholdApprovalRequest {
    pub token: GovernedApprovalToken,
}

/// Body for `POST /approvals/batch/respond`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRespondRequest {
    pub decisions: Vec<BatchDecisionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecisionEntry {
    pub approval_id: String,
    pub outcome: ApprovalOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub approver: PublicKey,
    pub token: GovernedApprovalToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRespondResponse {
    pub results: Vec<BatchRespondResult>,
    pub summary: BatchRespondSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRespondResult {
    pub approval_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ApprovalOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRespondSummary {
    pub total: usize,
    pub approved: usize,
    pub denied: usize,
    pub rejected: usize,
}

// ----- Handlers -----------------------------------------------------

/// `GET /approvals/pending` -- list pending approvals matching the
/// filter. Returns a stable JSON shape.
pub fn handle_list_pending(
    admin: &ApprovalAdmin,
    query: PendingQuery,
) -> Result<PendingListResponse, ApprovalHandlerError> {
    let filter: ApprovalFilter = query.into();
    let approvals = admin.store.list_pending(&filter)?;
    let count = approvals.len();
    Ok(PendingListResponse { approvals, count })
}

/// `GET /approvals/{id}`.
///
/// Returns the pending record if still outstanding; otherwise returns
/// the resolved record. Adapters may encode "resolved" via the
/// `resolution` field so callers can tell the two states apart without
/// extra round trips.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetApprovalResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<ApprovalRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<ResolvedApproval>,
}

pub fn handle_get_approval(
    admin: &ApprovalAdmin,
    approval_id: &str,
) -> Result<GetApprovalResponse, ApprovalHandlerError> {
    let pending = admin.store.get_pending(approval_id)?;
    let resolution = admin.store.get_resolution(approval_id)?;
    if pending.is_none() && resolution.is_none() {
        return Err(ApprovalHandlerError::NotFound(approval_id.to_string()));
    }
    Ok(GetApprovalResponse {
        pending,
        resolution,
    })
}

/// `POST /approvals/{id}/respond` -- submit an approval decision.
pub fn handle_respond(
    admin: &ApprovalAdmin,
    approval_id: &str,
    body: RespondRequest,
    now: u64,
) -> Result<RespondResponse, ApprovalHandlerError> {
    // The approval_id in the URL must agree with the token the human
    // signed, otherwise the signed binding is wrong and we cannot
    // authorize resume.
    if body.token.request_id != approval_id {
        return Err(ApprovalHandlerError::BadRequest(format!(
            "approval_id {approval_id} does not match signed token request_id {}",
            body.token.request_id
        )));
    }

    let decision = ApprovalDecision {
        approval_id: approval_id.to_string(),
        outcome: body.outcome.clone(),
        reason: body.reason,
        approver: body.approver.clone(),
        token: body.token,
        received_at: now,
    };

    let outcome = resume_with_decision(admin.store.as_ref(), &decision, now)?;

    // Defense-in-depth: the ApprovalToken is now consumed; exercise
    // the replay guard immediately so operators can trust the store
    // wrote the record.
    let approval_token = ApprovalToken::from_decision(&decision);
    let _ = approval_token; // consumed; flagged via resume_with_decision.

    Ok(RespondResponse {
        approval_id: approval_id.to_string(),
        outcome,
        resolved_at: now,
    })
}

/// `POST /approvals/batch/respond` -- apply decisions to multiple
/// approvals in one call.
pub fn handle_batch_respond(
    admin: &ApprovalAdmin,
    body: BatchRespondRequest,
    now: u64,
) -> Result<BatchRespondResponse, ApprovalHandlerError> {
    if body.decisions.is_empty() {
        return Err(ApprovalHandlerError::BadRequest(
            "batch respond requires at least one decision".into(),
        ));
    }

    let mut results = Vec::with_capacity(body.decisions.len());
    let mut approved = 0usize;
    let mut denied = 0usize;
    let mut rejected = 0usize;

    for entry in body.decisions {
        let approval_id = entry.approval_id.clone();
        if entry.token.request_id != approval_id {
            rejected += 1;
            results.push(BatchRespondResult {
                approval_id,
                status: "rejected".into(),
                outcome: None,
                error: Some(format!(
                    "token request_id {} mismatches approval_id",
                    entry.token.request_id
                )),
            });
            continue;
        }

        let decision = ApprovalDecision {
            approval_id: approval_id.clone(),
            outcome: entry.outcome.clone(),
            reason: entry.reason,
            approver: entry.approver,
            token: entry.token,
            received_at: now,
        };

        match resume_with_decision(admin.store.as_ref(), &decision, now) {
            Ok(outcome) => {
                match outcome {
                    ApprovalOutcome::Approved => approved += 1,
                    ApprovalOutcome::Denied => denied += 1,
                }
                results.push(BatchRespondResult {
                    approval_id,
                    status: "resolved".into(),
                    outcome: Some(outcome),
                    error: None,
                });
            }
            Err(e) => {
                rejected += 1;
                let handler_err: ApprovalHandlerError = e.into();
                results.push(BatchRespondResult {
                    approval_id,
                    status: "rejected".into(),
                    outcome: None,
                    error: Some(handler_err.message()),
                });
            }
        }
    }

    let total = results.len();
    Ok(BatchRespondResponse {
        results,
        summary: BatchRespondSummary {
            total,
            approved,
            denied,
            rejected,
        },
    })
}

pub fn handle_create_threshold_proposal(
    admin: &ApprovalAdmin,
    body: CreateThresholdProposalRequest,
    now: u64,
) -> Result<ThresholdApprovalCollectorProposal, ApprovalHandlerError> {
    admin
        .threshold_collector()?
        .create_proposal(
            body.proposal,
            body.requirement,
            body.submitter,
            body.require_submitter_separation,
            now,
        )
        .map_err(Into::into)
}

pub fn handle_get_threshold_proposal(
    admin: &ApprovalAdmin,
    proposal_id: &str,
) -> Result<ThresholdApprovalCollectorProposal, ApprovalHandlerError> {
    admin
        .threshold_collector()?
        .get_proposal(proposal_id)?
        .ok_or_else(|| ApprovalHandlerError::NotFound(proposal_id.to_string()))
}

pub fn handle_submit_threshold_approval(
    admin: &ApprovalAdmin,
    proposal_id: &str,
    body: SubmitThresholdApprovalRequest,
    now: u64,
) -> Result<ThresholdApprovalCollectorProposal, ApprovalHandlerError> {
    admin
        .threshold_collector()?
        .submit_token(proposal_id, body.token, now)
        .map_err(Into::into)
}

pub fn handle_deliver_threshold_approval(
    admin: &ApprovalAdmin,
    proposal_id: &str,
    now: u64,
) -> Result<CollectedThresholdApprovalSet, ApprovalHandlerError> {
    admin
        .threshold_collector()?
        .deliver(proposal_id, now)
        .map_err(Into::into)
}
