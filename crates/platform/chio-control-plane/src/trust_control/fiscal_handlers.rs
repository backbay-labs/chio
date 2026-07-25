use super::*;
use chio_fiscal::{
    FiscalDenialReason, FiscalDomain, FiscalFallbackReason, FiscalResolution, GovernedSource,
    SignedFiscalActivation, SignedFiscalApproval, SignedFiscalContinuityCheckpoint,
    SignedFiscalProposal, SignedFiscalProposalAdmission,
};
use chio_store_sqlite::fiscal_store::FiscalStoreError;

use crate::fiscal_state_recovery::FiscalStartupRecoveryAction;
use crate::trust_control::report_rendering::forward_post_to_leader;
use crate::trust_control::report_validation::{
    resolve_control_read_principal, validate_service_auth, ResolvedControlReadPrincipal,
};

pub(crate) async fn handle_fiscal_runtime_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "trust control service has no fiscal runtime configured",
        );
    };
    match runtime.reconcile() {
        Ok(startup) => Json(json!({
            "schema": "chio.fiscal.runtime-status.v1",
            "recoveryAction": recovery_action_name(startup.recovery_action),
            "checkpoint": startup.checkpoint.signed(),
            "readiness": startup.readiness.signed(),
        }))
        .into_response(),
        Err(error) => plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()),
    }
}

pub(crate) async fn handle_fiscal_proposal_preview(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(proposal): Json<SignedFiscalProposal>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return fiscal_runtime_not_configured();
    };
    match runtime.preview_proposal(proposal) {
        Ok(proposal) => Json(json!({
            "schema": "chio.fiscal.proposal-preview.v1",
            "proposal": proposal.signed(),
            "proposalDigest": proposal.digest(),
        }))
        .into_response(),
        Err(error) => fiscal_operation_error(error),
    }
}

pub(crate) async fn handle_fiscal_proposal_persist(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(proposal): Json<SignedFiscalProposal>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, FISCAL_PROPOSALS_PATH, &proposal).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return fiscal_runtime_not_configured();
    };
    match runtime.persist_proposal(proposal) {
        Ok(proposal) => Json(json!({
            "schema": "chio.fiscal.proposal-persisted.v1",
            "proposal": proposal.signed(),
            "proposalDigest": proposal.digest(),
        }))
        .into_response(),
        Err(error) => fiscal_operation_error(error),
    }
}

pub(crate) async fn handle_fiscal_proposal_admit(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(proposal): Json<SignedFiscalProposal>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, FISCAL_PROPOSAL_ADMIT_PATH, &proposal).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return fiscal_runtime_not_configured();
    };
    match runtime.admit_proposal(proposal) {
        Ok(admission) => Json(json!({
            "schema": "chio.fiscal.proposal-admitted.v1",
            "admission": admission.signed(),
            "admissionDigest": admission.digest(),
        }))
        .into_response(),
        Err(error) => fiscal_operation_error(error),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FiscalApprovalPersistRequest {
    proposal: SignedFiscalProposal,
    admission: SignedFiscalProposalAdmission,
    approval: SignedFiscalApproval,
}

pub(crate) async fn handle_fiscal_approval_persist(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<FiscalApprovalPersistRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, FISCAL_APPROVALS_PATH, &request).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return fiscal_runtime_not_configured();
    };
    match runtime.persist_approval(request.proposal, request.admission, request.approval) {
        Ok(approval) => Json(json!({
            "schema": "chio.fiscal.approval-persisted.v1",
            "approval": approval.signed(),
            "approvalDigest": approval.digest(),
        }))
        .into_response(),
        Err(error) => fiscal_operation_error(error),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FiscalActivationCommitRequest {
    proposal: SignedFiscalProposal,
    admission: SignedFiscalProposalAdmission,
    activation: SignedFiscalActivation,
    next_checkpoint: SignedFiscalContinuityCheckpoint,
}

pub(crate) async fn handle_fiscal_activation_commit(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<FiscalActivationCommitRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, FISCAL_ACTIVATIONS_PATH, &request).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return fiscal_runtime_not_configured();
    };
    match runtime.activate(
        request.proposal,
        request.admission,
        request.activation,
        request.next_checkpoint,
    ) {
        Ok(checkpoint) => Json(json!({
            "schema": "chio.fiscal.activation-committed.v1",
            "checkpoint": checkpoint.signed(),
            "checkpointDigest": checkpoint.digest(),
        }))
        .into_response(),
        Err(error) => fiscal_operation_error(error),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FiscalResolveRequest {
    domain: FiscalDomain,
    #[serde(default)]
    request_currency: Option<String>,
}

pub(crate) async fn handle_fiscal_resolve(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<FiscalResolveRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return fiscal_runtime_not_configured();
    };
    match runtime.resolve(request.domain, request.request_currency.as_deref()) {
        Ok(FiscalResolution::Governed {
            schedule_id,
            sequence,
            source,
            params,
        }) => Json(json!({
            "schema": "chio.fiscal.resolution.v1",
            "outcome": "governed",
            "scheduleId": schedule_id,
            "sequence": sequence,
            "source": governed_source_name(source),
            "params": params,
        }))
        .into_response(),
        Ok(FiscalResolution::Fallback(reason)) => Json(json!({
            "schema": "chio.fiscal.resolution.v1",
            "outcome": "fallback",
            "reason": fallback_reason_name(reason),
        }))
        .into_response(),
        Ok(FiscalResolution::Denied(reason)) => Json(json!({
            "schema": "chio.fiscal.resolution.v1",
            "outcome": "denied",
            "reason": denial_reason_name(reason),
        }))
        .into_response(),
        Err(error) => fiscal_operation_error(error),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FiscalMarketplacePriceRequest {
    pub(crate) base: chio_appraisal::MarketplaceBasePrice,
    pub(crate) context: chio_appraisal::MarketplacePricingContext,
}

pub(crate) async fn handle_fiscal_marketplace_price(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<FiscalMarketplacePriceRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return fiscal_runtime_not_configured();
    };
    match runtime.with_resolver(|resolver| {
        chio_appraisal::compute_fiscal_marketplace_invocation_price(
            &request.base,
            &request.context,
            resolver,
        )
    }) {
        Ok(Ok(price)) => Json(price).into_response(),
        Ok(Err(error)) => plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()),
        Err(error) => fiscal_operation_error(error),
    }
}

pub(crate) async fn handle_fiscal_marketplace_credit_limit(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<FiscalMarketplaceCreditLimitRequest>,
) -> Response {
    let principal = match resolve_control_read_principal(&headers, &state.config) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    if matches!(
        &principal,
        ResolvedControlReadPrincipal::TenantRead { tenant_id }
            if tenant_id != &request.tenant_id
    ) {
        return plain_http_error(
            StatusCode::FORBIDDEN,
            "tenant read token cannot request another tenant's credit limit",
        );
    }
    let Some(runtime) = state.fiscal_runtime.as_ref() else {
        return fiscal_runtime_not_configured();
    };
    let revocation_store = match state.revocation_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    let publisher_revoked = match revocation_store.is_revoked(&request.tenant_id) {
        Ok(revoked) => revoked,
        Err(error) => {
            return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string());
        }
    };
    let Some(receipt_db_path) = state.config.receipt_db_path.as_deref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --receipt-db for marketplace credit limits",
        );
    };
    let trusted_kernel_keys = match trusted_kernel_keys_from_service_config(&state.config) {
        Ok(keys) => keys.unwrap_or_default(),
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let inspection = match issuance::inspect_local_reputation_with_read_context(
        &request.tenant_id,
        Some(receipt_db_path),
        state.config.budget_db_path.as_deref(),
        None,
        None,
        state.config.issuance_policy.as_ref(),
        &trusted_kernel_keys,
        &principal.receipt_read_context(),
    ) {
        Ok(inspection) => inspection,
        Err(error) => {
            return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string());
        }
    };
    let reputation_tier = if inspection.effective_score >= chio_reputation::TIER_2_THRESHOLD {
        chio_underwriting::MarketplaceLimitTier::Tier2
    } else if inspection.effective_score >= chio_reputation::TIER_1_THRESHOLD {
        chio_underwriting::MarketplaceLimitTier::Tier1
    } else {
        chio_underwriting::MarketplaceLimitTier::Tier0
    };
    let authoritative_request = chio_underwriting::MarketplaceCreditLimitRequest {
        tenant_id: request.tenant_id,
        reputation_tier,
        currency: request.currency,
        publisher_revoked,
    };
    match runtime.with_resolver(|resolver| {
        chio_underwriting::compute_fiscal_marketplace_credit_limit(&authoritative_request, resolver)
    }) {
        Ok(Ok(decision)) => Json(decision).into_response(),
        Ok(Err(reason)) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("fiscal marketplace credit-limit resolution denied: {reason:?}"),
        ),
        Err(error) => fiscal_operation_error(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FiscalMarketplaceCreditLimitRequest {
    pub(crate) tenant_id: String,
    pub(crate) currency: String,
}

fn fiscal_runtime_not_configured() -> Response {
    plain_http_error(
        StatusCode::CONFLICT,
        "trust control service has no fiscal runtime configured",
    )
}

fn fiscal_operation_error(error: TrustFiscalOperationError) -> Response {
    let status = match &error {
        TrustFiscalOperationError::InvalidArtifact(_) => StatusCode::UNPROCESSABLE_ENTITY,
        TrustFiscalOperationError::Store(FiscalStoreError::Conflict) => StatusCode::CONFLICT,
        TrustFiscalOperationError::Startup(_)
        | TrustFiscalOperationError::Store(_)
        | TrustFiscalOperationError::Commit(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    plain_http_error(status, &error.to_string())
}

const fn recovery_action_name(action: FiscalStartupRecoveryAction) -> &'static str {
    match action {
        FiscalStartupRecoveryAction::Ready => "ready",
        FiscalStartupRecoveryAction::DiscardedUnanchoredStage => "discarded_unanchored_stage",
        FiscalStartupRecoveryAction::FinalizedAnchoredStage => "finalized_anchored_stage",
    }
}

const fn governed_source_name(source: GovernedSource) -> &'static str {
    match source {
        GovernedSource::Active => "active",
        GovernedSource::LastKnownGood => "last_known_good",
    }
}

const fn fallback_reason_name(reason: FiscalFallbackReason) -> &'static str {
    match reason {
        FiscalFallbackReason::AuthoritativeBootstrap => "authoritative_bootstrap",
        FiscalFallbackReason::NeverActivated => "never_activated",
    }
}

const fn denial_reason_name(reason: FiscalDenialReason) -> &'static str {
    match reason {
        FiscalDenialReason::AnchorUnavailable => "anchor_unavailable",
        FiscalDenialReason::AnchorRollbackOrDivergence => "anchor_rollback_or_divergence",
        FiscalDenialReason::ActivatedStateUnavailable => "activated_state_unavailable",
        FiscalDenialReason::NoValidLastKnownGood => "no_valid_last_known_good",
        FiscalDenialReason::ClockRollback => "clock_rollback",
        FiscalDenialReason::VerificationFailed => "verification_failed",
    }
}
