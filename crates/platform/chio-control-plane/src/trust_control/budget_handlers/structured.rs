use super::*;

pub(super) fn structured_usage_view_for_event(
    store: &SqliteBudgetStore,
    event: &BudgetMutationRecord,
) -> Result<StructuredBudgetUsageView, Response> {
    let usage = store
        .usage_projection_for_event_id(&event.event_id)
        .map_err(structured_projection_error)?;
    match (event.usage_seq, usage) {
        (Some(expected_seq), Some(usage))
            if usage.seq == expected_seq
                && usage.capability_id == event.capability_id
                && usage.grant_index == event.grant_index
                && usage.invocation_count == event.invocation_count_after
                && usage.total_cost_exposed == event.total_cost_exposed_after
                && usage.total_cost_realized_spend == event.total_cost_realized_spend_after =>
        {
            Ok(usage.into())
        }
        (None, None) => Ok(StructuredBudgetUsageView {
            capability_id: event.capability_id.clone(),
            grant_index: event.grant_index,
            invocation_count: event.invocation_count_after,
            updated_at: event.recorded_at,
            seq: None,
            total_cost_exposed: event.total_cost_exposed_after,
            total_cost_realized_spend: event.total_cost_realized_spend_after,
        }),
        _ => Err(structured_projection_error(
            "structured usage did not match its referenced durable projection",
        )),
    }
}

pub(crate) fn structured_budget_store(
    state: &TrustServiceState,
) -> Result<(SqliteBudgetStore, BudgetEventAuthority), Response> {
    let authority_store = state.joint_authority_store.as_ref().ok_or_else(|| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "structured remote budget authority requires an injected, already-provisioned joint budget and revocation authority",
        )
    })?;
    let fence = authority_store.mutation_fence();
    Ok((
        state.budget_store()?,
        BudgetEventAuthority {
            authority_id: fence.store_uuid,
            lease_id: fence.lease_id,
            lease_epoch: fence.owner_epoch,
        },
    ))
}

fn structured_lifecycle_budget_store(
    state: &TrustServiceState,
    hold_id: &str,
) -> Result<(SqliteBudgetStore, Option<BudgetEventAuthority>), Response> {
    // This only projects later transitions for an already-authorized legacy
    // hold. Composite authorization remains disabled until a provisioned joint
    // authority is injected through structured_budget_store.
    if state.cluster.is_some() && state.joint_authority_store.is_none() {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "versioned rich budget lifecycle is unavailable with the legacy cluster coordinator",
        ));
    }
    let store = state.budget_store()?;
    let authority = resolve_budget_hold_authority(state, &store, Some(hold_id))?;
    Ok((store, authority))
}

pub(crate) async fn handle_structured_budget_authorize(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<StructuredBudgetAuthorizeRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, STRUCTURED_BUDGET_AUTHORIZE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (store, authority) = match structured_budget_store(&state) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let capability_id = payload.capability_id.clone();
    let grant_index = payload.grant_index;
    let hold_id = payload.hold_id.clone();
    let event_id = payload.event_id.clone();
    let request = match payload.into_core(Some(authority)) {
        Ok(request) => request,
        Err(error) => return structured_bad_request(error),
    };
    if let Err(error) = request.validate() {
        return structured_bad_request(error);
    }
    let decision = match store.authorize_budget_hold(request) {
        Ok(decision) => decision,
        Err(error) => {
            return budget_internal_error(&error, "structured budget authorization failed")
        }
    };
    let mutation_event_id = match &decision {
        BudgetAuthorizeHoldDecision::Authorized(value) => value.metadata.event_id.as_deref(),
        BudgetAuthorizeHoldDecision::ApprovalRequired(value) => value.metadata.event_id.as_deref(),
        BudgetAuthorizeHoldDecision::Denied(value) => value.metadata.event_id.as_deref(),
        BudgetAuthorizeHoldDecision::AlreadyCaptured(value) => value.metadata.event_id.as_deref(),
    };
    let Some(mutation_event_id) = mutation_event_id else {
        return structured_projection_error("structured authorization omitted mutation event");
    };
    let event = match store.mutation_event_for_event_id(mutation_event_id) {
        Ok(Some(event)) => event,
        Ok(None) => return structured_projection_error("authorization mutation was not durable"),
        Err(error) => return structured_projection_error(error),
    };
    if event.capability_id != capability_id
        || event.grant_index != grant_index
        || event.hold_id.as_deref() != Some(hold_id.as_str())
    {
        return structured_projection_error("authorization mutation changed request identity");
    };
    let response = match StructuredBudgetAuthorizeResponse::from_core(
        capability_id,
        grant_index,
        hold_id,
        event_id,
        decision,
        match structured_usage_view_for_event(&store, &event) {
            Ok(usage) => usage,
            Err(response) => return response,
        },
    ) {
        Ok(response) => response,
        Err(error) => return structured_projection_error(error),
    };
    let mutation = match response.projection.clone().into_mutation() {
        Ok(mutation) => mutation,
        Err(error) => return structured_projection_error(error),
    };
    if let Err(response) = validate_durable_mutation_projection(&event, &mutation) {
        return response;
    }
    let expected_outcome = match response.decision {
        StructuredBudgetAuthorizeDecisionView::Authorized => {
            Some(BudgetAuthorizationOutcome::Authorized)
        }
        StructuredBudgetAuthorizeDecisionView::ApprovalRequired => {
            Some(BudgetAuthorizationOutcome::ApprovalRequired)
        }
        StructuredBudgetAuthorizeDecisionView::Denied => Some(BudgetAuthorizationOutcome::Denied),
        StructuredBudgetAuthorizeDecisionView::AlreadyCaptured => None,
    };
    if event.authorization_outcome != expected_outcome {
        return structured_projection_error(
            "authorization decision did not match its durable event outcome",
        );
    }
    Json(response).into_response()
}

pub(crate) async fn handle_structured_budget_authorize_cumulative(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<StructuredBudgetAuthorizeCumulativeRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(error) = require_structured_schema(&payload.schema) {
        return structured_bad_request(error);
    }
    match forward_post_to_leader(
        &state,
        STRUCTURED_BUDGET_AUTHORIZE_CUMULATIVE_PATH,
        &payload,
    )
    .await
    {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (store, authority) = match structured_budget_store(&state) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let request_capability_id = payload.capability_id.clone();
    let request_grant_index = payload.grant_index;
    let request_hold_id = payload.hold_id.clone();
    let request_event_id = payload.event_id.clone();
    let admission_binding = match payload.admission_binding.try_into() {
        Ok(binding) => binding,
        Err(error) => return structured_bad_request(error),
    };
    let request = BudgetAuthorizeCumulativeApprovalRequest {
        capability_id: payload.capability_id,
        grant_index: match usize::try_from(payload.grant_index) {
            Ok(grant_index) => grant_index,
            Err(error) => return structured_bad_request(error),
        },
        operation_id: payload.operation_id,
        hold_id: payload.hold_id,
        admission_binding,
        approval_set_digest: payload.approval_set_digest,
        event_id: payload.event_id,
        authority: Some(authority),
    };
    if let Err(error) = request.validate() {
        return structured_bad_request(error);
    }
    let decision = match store.authorize_cumulative_approval(request) {
        Ok(BudgetCumulativeApprovalAuthorizationDecision::Authorized(mutation)) => {
            (StructuredBudgetMutationDecisionView::Applied, mutation)
        }
        Ok(BudgetCumulativeApprovalAuthorizationDecision::AlreadyAuthorized(mutation)) => (
            StructuredBudgetMutationDecisionView::AlreadyApplied,
            mutation,
        ),
        Err(error) => {
            return budget_internal_error(&error, "structured cumulative authorization failed")
        }
    };
    structured_mutation_response(
        &store,
        Some(&request_capability_id),
        Some(request_grant_index),
        request_hold_id,
        request_event_id,
        decision.0,
        decision.1,
    )
}

pub(crate) async fn handle_structured_budget_cumulative_operation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<StructuredBudgetCumulativeOperationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(error) = require_structured_schema(&payload.schema) {
        return structured_bad_request(error);
    }
    if payload.operation_id.is_empty() {
        return structured_bad_request("cumulative operation_id must not be empty");
    }
    let (store, _) = match structured_budget_store(&state) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let projection = match store.cumulative_approval_operation_projection(&payload.operation_id) {
        Ok(projection) => projection,
        Err(error) => {
            return budget_internal_error(&error, "structured cumulative operation lookup failed")
        }
    };
    let (usage, approval_set_digest, metadata) = match projection {
        Some((usage, event)) => (
            Some(usage.into()),
            event.cumulative_approval_set_digest,
            Some(
                BudgetCommitMetadata {
                    authority: event.authority,
                    guarantee_level: store.budget_guarantee_level(),
                    budget_profile: store.budget_authority_profile(),
                    metering_profile: store.budget_metering_profile(),
                    budget_commit_index: Some(event.event_seq),
                    event_id: Some(event.event_id),
                    recorded_at_unix_seconds: u64::try_from(event.recorded_at).ok(),
                }
                .into(),
            ),
        ),
        None => (None, None, None),
    };
    Json(StructuredBudgetCumulativeOperationResponse {
        schema: STRUCTURED_BUDGET_RESPONSE_SCHEMA.to_string(),
        operation_id: payload.operation_id,
        usage,
        approval_set_digest,
        metadata,
    })
    .into_response()
}

pub(crate) async fn handle_structured_budget_cancel_captured(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<StructuredBudgetCancelCapturedRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(error) = require_structured_schema(&payload.schema) {
        return structured_bad_request(error);
    }
    match forward_post_to_leader(&state, STRUCTURED_BUDGET_CANCEL_CAPTURED_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (store, authority) = match structured_lifecycle_budget_store(&state, &payload.hold_id) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let grant_index = match usize::try_from(payload.grant_index) {
        Ok(grant_index) => grant_index,
        Err(error) => return structured_bad_request(error),
    };
    let decision =
        match store.cancel_captured_before_dispatch(BudgetCancelCapturedBeforeDispatchRequest {
            capability_id: payload.capability_id.clone(),
            grant_index,
            hold_id: payload.hold_id.clone(),
            event_id: payload.event_id.clone(),
            authority,
        }) {
            Ok(BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(mutation)) => {
                (StructuredBudgetMutationDecisionView::Applied, mutation)
            }
            Ok(BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(mutation)) => (
                StructuredBudgetMutationDecisionView::AlreadyApplied,
                mutation,
            ),
            Err(error) => {
                return budget_internal_error(&error, "structured captured cancellation failed")
            }
        };
    structured_mutation_response(
        &store,
        Some(&payload.capability_id),
        Some(payload.grant_index),
        payload.hold_id,
        payload.event_id,
        decision.0,
        decision.1,
    )
}

pub(crate) async fn handle_structured_budget_capture_invocation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<StructuredBudgetCaptureInvocationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(error) = require_structured_schema(&payload.schema) {
        return structured_bad_request(error);
    }
    match forward_post_to_leader(&state, STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH, &payload).await
    {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (store, authority) = match structured_lifecycle_budget_store(&state, &payload.hold_id) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let grant_index = match usize::try_from(payload.grant_index) {
        Ok(grant_index) => grant_index,
        Err(error) => return structured_bad_request(error),
    };
    let request = BudgetCaptureInvocationRequest {
        capability_id: payload.capability_id.clone(),
        grant_index,
        hold_id: payload.hold_id.clone(),
        event_id: payload.event_id.clone(),
        trusted_time: None,
        authority,
    };
    if let Err(error) = request.validate() {
        return structured_bad_request(error);
    }
    let decision = match store.capture_invocation_reservations(request) {
        Ok(BudgetInvocationCaptureDecision::Captured(mutation)) => {
            (StructuredBudgetMutationDecisionView::Applied, mutation)
        }
        Ok(BudgetInvocationCaptureDecision::AlreadyCaptured(mutation)) => (
            StructuredBudgetMutationDecisionView::AlreadyApplied,
            mutation,
        ),
        Err(error) => return budget_internal_error(&error, "structured invocation capture failed"),
    };
    structured_mutation_response(
        &store,
        Some(&payload.capability_id),
        Some(payload.grant_index),
        payload.hold_id,
        payload.event_id,
        decision.0,
        decision.1,
    )
}

pub(crate) async fn handle_structured_budget_reverse(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<StructuredBudgetFencedReverseRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(error) = require_structured_schema(&payload.schema) {
        return structured_bad_request(error);
    }
    match forward_post_to_leader(&state, STRUCTURED_BUDGET_FENCED_REVERSE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (store, authority) = match structured_lifecycle_budget_store(&state, &payload.hold_id) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let grant_index = match usize::try_from(payload.grant_index) {
        Ok(grant_index) => grant_index,
        Err(error) => return structured_bad_request(error),
    };
    let request = BudgetReverseHoldRequest {
        capability_id: payload.capability_id.clone(),
        grant_index,
        reversed_exposure_units: payload.reversed_exposure_units,
        hold_id: Some(payload.hold_id.clone()),
        event_id: Some(payload.event_id.clone()),
        expected_cumulative_approval_state: payload
            .expected_cumulative_approval_state
            .map(Into::into),
        authority,
    };
    if let Err(error) = request.validate() {
        return structured_bad_request(error);
    }
    let mutation = match store.reverse_budget_hold(request) {
        Ok(mutation) => mutation,
        Err(error) => return budget_internal_error(&error, "structured reversal failed"),
    };
    structured_mutation_response(
        &store,
        Some(&payload.capability_id),
        Some(payload.grant_index),
        payload.hold_id,
        payload.event_id,
        StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
        mutation,
    )
}

pub(crate) async fn handle_structured_budget_release(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<StructuredBudgetReleaseRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(error) = require_structured_schema(&payload.schema) {
        return structured_bad_request(error);
    }
    match forward_post_to_leader(&state, STRUCTURED_BUDGET_RELEASE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (store, authority) = match structured_lifecycle_budget_store(&state, &payload.hold_id) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let grant_index = match usize::try_from(payload.grant_index) {
        Ok(grant_index) => grant_index,
        Err(error) => return structured_bad_request(error),
    };
    let request = BudgetReleaseHoldRequest {
        capability_id: payload.capability_id.clone(),
        grant_index,
        released_exposure_units: payload.released_exposure_units,
        hold_id: Some(payload.hold_id.clone()),
        event_id: Some(payload.event_id.clone()),
        authority,
    };
    if let Err(error) = request.validate() {
        return structured_bad_request(error);
    }
    let mutation = match store.release_budget_hold(request) {
        Ok(mutation) => mutation,
        Err(error) => return budget_internal_error(&error, "structured release failed"),
    };
    structured_mutation_response(
        &store,
        Some(&payload.capability_id),
        Some(payload.grant_index),
        payload.hold_id,
        payload.event_id,
        StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
        mutation,
    )
}

pub(crate) async fn handle_structured_budget_reconcile(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<StructuredBudgetReconcileRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(error) = require_structured_schema(&payload.schema) {
        return structured_bad_request(error);
    }
    match forward_post_to_leader(&state, STRUCTURED_BUDGET_RECONCILE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (store, authority) = match structured_lifecycle_budget_store(&state, &payload.hold_id) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let grant_index = match usize::try_from(payload.grant_index) {
        Ok(grant_index) => grant_index,
        Err(error) => return structured_bad_request(error),
    };
    let request = BudgetReconcileHoldRequest {
        capability_id: payload.capability_id.clone(),
        grant_index,
        exposed_cost_units: payload.exposed_cost_units,
        realized_spend_units: payload.realized_spend_units,
        hold_id: Some(payload.hold_id.clone()),
        event_id: Some(payload.event_id.clone()),
        authority,
    };
    if let Err(error) = request.validate() {
        return structured_bad_request(error);
    }
    let mutation = match store.reconcile_budget_hold(request) {
        Ok(mutation) => mutation,
        Err(error) => return budget_internal_error(&error, "structured reconciliation failed"),
    };
    structured_mutation_response(
        &store,
        Some(&payload.capability_id),
        Some(payload.grant_index),
        payload.hold_id,
        payload.event_id,
        StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
        mutation,
    )
}

pub(crate) async fn handle_structured_budget_capture_spend(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<StructuredBudgetCaptureSpendRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(error) = require_structured_schema(&payload.schema) {
        return structured_bad_request(error);
    }
    match forward_post_to_leader(&state, STRUCTURED_BUDGET_CAPTURE_SPEND_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (store, authority) = match structured_lifecycle_budget_store(&state, &payload.hold_id) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let grant_index = match usize::try_from(payload.grant_index) {
        Ok(grant_index) => grant_index,
        Err(error) => return structured_bad_request(error),
    };
    let request = BudgetCaptureHoldRequest {
        capability_id: payload.capability_id.clone(),
        grant_index,
        exposed_cost_units: payload.exposed_cost_units,
        realized_spend_units: payload.realized_spend_units,
        hold_id: Some(payload.hold_id.clone()),
        event_id: Some(payload.event_id.clone()),
        authority,
    };
    if let Err(error) = request.validate() {
        return structured_bad_request(error);
    }
    let mutation = match store.capture_budget_hold(request) {
        Ok(mutation) => mutation,
        Err(error) => return budget_internal_error(&error, "structured monetary capture failed"),
    };
    structured_mutation_response(
        &store,
        Some(&payload.capability_id),
        Some(payload.grant_index),
        payload.hold_id,
        payload.event_id,
        StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
        mutation,
    )
}
