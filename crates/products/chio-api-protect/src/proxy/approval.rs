use super::*;

pub(crate) async fn list_pending_approvals_handler(
    State(state): State<Arc<ProxyState>>,
    Query(query): Query<PendingQuery>,
) -> Response {
    match handle_list_pending(&state.approval_admin, query) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn get_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(approval_id): Path<String>,
) -> Response {
    match handle_get_approval(&state.approval_admin, &approval_id) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn respond_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(approval_id): Path<String>,
    body: Result<Json<RespondRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::BadRequest(format!(
                "invalid approval response payload: {error}"
            )));
        }
    };

    let now = chrono::Utc::now().timestamp() as u64;
    match handle_respond(&state.approval_admin, &approval_id, body, now) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn batch_respond_approvals_handler(
    State(state): State<Arc<ProxyState>>,
    body: Result<Json<BatchRespondRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::BadRequest(format!(
                "invalid batch approval payload: {error}"
            )));
        }
    };

    let now = chrono::Utc::now().timestamp() as u64;
    match handle_batch_respond(&state.approval_admin, body, now) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn create_threshold_proposal_handler(
    State(state): State<Arc<ProxyState>>,
    body: Result<Json<CreateThresholdProposalRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::BadRequest(format!(
                "invalid threshold approval proposal payload: {error}"
            )));
        }
    };
    let now = chrono::Utc::now().timestamp() as u64;
    match handle_create_threshold_proposal(&state.approval_admin, body, now) {
        Ok(response) => approval_json(StatusCode::CREATED, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn get_threshold_proposal_handler(
    State(state): State<Arc<ProxyState>>,
    Path(proposal_id): Path<String>,
) -> Response {
    match handle_get_threshold_proposal(&state.approval_admin, &proposal_id) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn submit_threshold_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(proposal_id): Path<String>,
    body: Result<Json<SubmitThresholdApprovalRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::BadRequest(format!(
                "invalid threshold approval token payload: {error}"
            )));
        }
    };
    let now = chrono::Utc::now().timestamp() as u64;
    match handle_submit_threshold_approval(&state.approval_admin, &proposal_id, body, now) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn deliver_threshold_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(proposal_id): Path<String>,
) -> Response {
    let now = chrono::Utc::now().timestamp() as u64;
    match handle_deliver_threshold_approval(&state.approval_admin, &proposal_id, now) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

/// Body for `POST /approvals/submit`. Operator-friendly shape: the
/// caller hands the sidecar enough context to record a pending request
/// and the sidecar materializes the full `ApprovalRequest`, signing on
/// behalf of itself as the trusted approver. Manual flow only: the held call is not auto-resumed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SubmitApprovalRequest {
    capability_id: String,
    tool_server: String,
    tool_name: String,
    /// Hex SHA-256 of canonical-JSON tool args. The operator-respond
    /// shortcut binds the synthesized token to this hash.
    parameter_hash: String,
    /// Hex Ed25519 public key of the agent that initiated the held call.
    requested_by: String,
    /// Optional human-readable summary surfaced in dashboards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    /// Optional policy id; defaults to "policy-hermes-hitl".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_id: Option<String>,
    /// TTL in seconds; clamped to MAX_APPROVAL_TTL_SECS (3600) downstream.
    #[serde(default)]
    ttl_seconds: u64,
    /// Free-form short verb for human summaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    /// Reason the call was held (e.g. "shell.requires_approval").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    triggered_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SubmitApprovalResponse {
    approval_id: String,
    expires_at: u64,
    created_at: u64,
    trusted_approvers: Vec<String>,
}

pub(crate) async fn submit_approval_handler(
    State(state): State<Arc<ProxyState>>,
    body: Result<Json<SubmitApprovalRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::BadRequest(format!(
                "invalid approval submit payload: {error}"
            )));
        }
    };

    let now = chrono::Utc::now().timestamp() as u64;
    let ttl = if body.ttl_seconds == 0 {
        3600
    } else {
        body.ttl_seconds.min(3600)
    };
    let approval_id = format!("ap-{}", uuid::Uuid::now_v7());
    let approver_pubkey = state.signer_keypair.public_key();
    // When the caller does not supply a parseable subject pubkey we
    // synthesize the binding using the sidecar's own pubkey so the
    // operator-respond shortcut can sign a token whose subject still
    // matches the request. Production agents should always pass their
    // own hex-encoded Ed25519 pubkey via `requested_by`.
    let parsed_subject = PublicKey::from_hex(&body.requested_by).ok();
    let stored_subject_id = if parsed_subject.is_some() {
        body.requested_by.clone()
    } else {
        approver_pubkey.to_hex()
    };
    let stored_subject_pubkey = parsed_subject
        .clone()
        .or_else(|| Some(approver_pubkey.clone()));
    let approval = ApprovalRequest {
        approval_id: approval_id.clone(),
        policy_id: body
            .policy_id
            .unwrap_or_else(|| "policy-hermes-hitl".to_string()),
        subject_id: stored_subject_id,
        capability_id: body.capability_id.clone(),
        subject_public_key: stored_subject_pubkey,
        tool_server: body.tool_server.clone(),
        tool_name: body.tool_name.clone(),
        action: body.action.unwrap_or_else(|| "invoke".to_string()),
        parameter_hash: body.parameter_hash.clone(),
        expires_at: now.saturating_add(ttl),
        callback_hint: None,
        created_at: now,
        summary: body
            .summary
            .unwrap_or_else(|| format!("{}/{}", body.tool_server, body.tool_name)),
        governed_intent: None,
        trusted_approvers: vec![approver_pubkey.clone()],
        triggered_by: body.triggered_by,
    };

    if let Err(error) = state.approval_admin.store().store_pending(&approval) {
        let handler_err: ApprovalHandlerError = error.into();
        return approval_error_response(handler_err);
    }

    let response = SubmitApprovalResponse {
        approval_id,
        expires_at: approval.expires_at,
        created_at: approval.created_at,
        trusted_approvers: vec![approver_pubkey.to_hex()],
    };
    approval_json(StatusCode::CREATED, response)
}

/// Body for `POST /approvals/{id}/operator-respond`. The sidecar signs
/// the GovernedApprovalToken using its own keypair, which must already
/// be registered as a trusted approver on the request (the case for
/// approvals created via `/approvals/submit`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OperatorRespondRequest {
    outcome: ApprovalOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

pub(crate) async fn operator_respond_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(approval_id): Path<String>,
    body: Result<Json<OperatorRespondRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::BadRequest(format!(
                "invalid operator approval payload: {error}"
            )));
        }
    };

    let pending = match state.approval_admin.store().get_pending(&approval_id) {
        Ok(Some(request)) => request,
        Ok(None) => {
            return approval_error_response(ApprovalHandlerError::NotFound(approval_id));
        }
        Err(error) => {
            return approval_error_response(error.into());
        }
    };

    let approver_pubkey = state.signer_keypair.public_key();
    if !pending.trusted_approvers.contains(&approver_pubkey) {
        return approval_error_response(ApprovalHandlerError::Rejected(
            "sidecar signer is not a trusted approver for this request".into(),
        ));
    }

    // Subject pubkey: prefer the explicit binding on the request,
    // then try to parse subject_id as hex, and finally fall back to
    // the sidecar's own pubkey. The fallback keeps the operator path
    // useful for callers (chio-hermes v0.2) that submit holds without
    // a per-agent Ed25519 keypair; the resulting token is still bound
    // to the request_id and parameter_hash, so the audit trail records
    // exactly which call was approved even when the subject identity
    // is synthetic.
    let subject_pubkey = pending
        .subject_public_key
        .clone()
        .or_else(|| PublicKey::from_hex(&pending.subject_id).ok())
        .unwrap_or_else(|| approver_pubkey.clone());

    let now = chrono::Utc::now().timestamp() as u64;
    let decision = match body.outcome {
        ApprovalOutcome::Approved => GovernedApprovalDecision::Approved,
        ApprovalOutcome::Denied => GovernedApprovalDecision::Denied,
    };
    let token_body = GovernedApprovalTokenBody {
        id: format!("op-tok-{}", uuid::Uuid::now_v7()),
        approver: approver_pubkey.clone(),
        subject: subject_pubkey,
        governed_intent_hash: pending.parameter_hash.clone(),
        request_id: approval_id.clone(),
        threshold_proposal_hash: None,
        issued_at: now,
        expires_at: now.saturating_add(600),
        decision,
    };
    let token = match GovernedApprovalToken::sign(token_body, &state.signer_keypair) {
        Ok(token) => token,
        Err(error) => {
            return internal_json_error_response(
                "operator_respond_sign_failed",
                &format!("failed to sign operator approval token: {error}"),
            );
        }
    };

    let respond_body = RespondRequest {
        outcome: body.outcome.clone(),
        reason: body.reason,
        approver: approver_pubkey,
        token,
    };

    match handle_respond(&state.approval_admin, &approval_id, respond_body, now) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}
