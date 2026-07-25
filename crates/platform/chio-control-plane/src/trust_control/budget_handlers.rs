//! HTTP handlers for the budget-metering surface: budget listing and the
//! authorize/release/reconcile exposure-accounting endpoints.

use super::cluster::{
    budget_authority_guarantee_level, budget_authority_metadata_view,
    current_budget_event_authority, respond_after_budget_write_quorum_commit,
    respond_after_leader_visible_write, rollback_budget_authorize_exposure,
    wait_for_budget_write_quorum_commit, BudgetWriteToken,
};
use super::report_rendering::{
    forward_post_to_leader, json_response_with_leader_visibility_and_budget_commit,
};
use super::report_validation::{budget_visibility_matches, validate_service_auth};
use super::*;
use chio_log_redact::redacted;

#[path = "budget_handlers/structured.rs"]
mod structured;
pub(crate) use structured::*;

fn budget_internal_error(error: &BudgetStoreError, public_message: &'static str) -> Response {
    warn!(reason = %redacted!(error), message = public_message, "budget store operation failed");
    let status = if matches!(error, BudgetStoreError::Fenced { .. }) {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    plain_http_error(status, public_message)
}

fn validate_budget_request_identity(
    hold_id: Option<&str>,
    event_id: Option<&str>,
) -> Result<(), Response> {
    match (hold_id, event_id) {
        (None, None) => Ok(()),
        (None, Some(event_id)) if !event_id.is_empty() => Ok(()),
        (Some(hold_id), Some(event_id)) if !hold_id.is_empty() && !event_id.is_empty() => Ok(()),
        _ => Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "budget holdId requires a non-empty eventId and supplied identifiers must be non-empty",
        )),
    }
}

pub(crate) async fn handle_list_budgets(
    State(state): State<TrustServiceState>,
    Query(query): Query<BudgetQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match state.budget_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    let usages = match store.list_usages(list_limit(query.limit), query.capability_id.as_deref()) {
        Ok(usages) => usages,
        Err(error) => {
            return budget_internal_error(&error, "budget usage listing failed");
        }
    };

    Json(BudgetListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        capability_id: query.capability_id,
        count: usages.len(),
        usages: usages
            .into_iter()
            .map(|usage| BudgetUsageView {
                capability_id: usage.capability_id,
                grant_index: usage.grant_index,
                invocation_count: usage.invocation_count,
                total_cost_exposed: usage.total_cost_exposed,
                total_cost_realized_spend: usage.total_cost_realized_spend,
                updated_at: usage.updated_at,
                seq: None,
            })
            .collect(),
    })
    .into_response()
}

pub(crate) async fn handle_try_increment_budget(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<TryIncrementBudgetRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_INCREMENT_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match state.budget_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    let allowed = match store.try_increment(
        &payload.capability_id,
        payload.grant_index,
        payload.max_invocations,
    ) {
        Ok(allowed) => allowed,
        Err(error) => {
            return budget_internal_error(&error, "budget increment failed");
        }
    };
    respond_after_leader_visible_write(
        &state,
        "budget state was not visible on the leader after write",
        || {
            let invocation_count = store
                .get_usage(&payload.capability_id, payload.grant_index)
                .map(|usage| usage.map(|usage| usage.invocation_count))
                .map_err(|error| budget_internal_error(&error, "budget usage lookup failed"))?;
            if budget_visibility_matches(allowed, invocation_count, payload.max_invocations) {
                Ok(Some(TryIncrementBudgetResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed,
                    invocation_count,
                    budget_authority: budget_authority_metadata_view(
                        &state,
                        None,
                        budget_authority_guarantee_level(&state, None),
                    ),
                }))
            } else {
                Ok(None)
            }
        },
    )
}

/// Mint a unique event_id for a budget write whose caller omitted `eventId`, so
/// the mutation event is stored under a KNOWN id and `budget_write_token` can look
/// up THIS write's exact event_seq instead of falling back to the authority MAX
/// (which a concurrent same-authority write to another capability can raise,
/// making the quorum wait target a later event and spuriously roll back / 503 a
/// write that itself reached quorum).
///
/// Uniqueness: a process-local monotonic counter + wall-clock nanos + pid, so it
/// cannot collide with a concurrent write or a caller-supplied id. An omitted
/// `eventId` already carries NO idempotency guarantee (the store would otherwise
/// auto-generate one internally), so minting it here changes no retry semantics.
fn generated_budget_event_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "cluster-budget-write-{}-{nanos}-{sequence}",
        std::process::id()
    )
}

/// Build the quorum-witness token for a budget write from its origin authority
/// and THIS write's own event_seq.
///
/// The seq is looked up by the write's `event_id` (the mutation event is stored
/// under that id at the seq it was allocated), which is race-free and, for an
/// idempotent retry, resolves to the ORIGINAL event's seq. Deriving it from
/// MAX(event_seq) for the authority would be wrong: a concurrent same-authority
/// commit (or a retry while later same-origin events exist) raises that MAX
/// above this write's seq, so the quorum wait would target a later event and
/// `handle_try_charge_cost` would roll back a write that itself reached quorum.
/// The handlers now always mint an event_id when the
/// caller omitted one (`generated_budget_event_id`), so the by-id lookup is
/// precise; the authority-MAX fallback remains only as a defensive path (row not
/// found) and can only OVER-target the seq (wait longer), never under-target it,
/// so the witness still never over-counts (fail-closed). A single-node write (no
/// authority) carries an unclustered token, and the quorum wait short-circuits.
fn budget_write_token(
    store: &SqliteBudgetStore,
    authority: Option<&BudgetEventAuthority>,
    event_id: Option<&str>,
) -> Result<BudgetWriteToken, Response> {
    let http_error = |error: BudgetStoreError| {
        budget_internal_error(&error, "budget write witness lookup failed")
    };
    match authority {
        Some(current) => {
            let stored = match event_id {
                Some(event_id) => store
                    .mutation_event_witness_for_event_id(event_id)
                    .map_err(http_error)?,
                None => None,
            };
            let (event_seq, origin_id, budget_term) = match stored {
                // Existing event with a stored authority: use ITS origin + term so
                // an idempotent retry after leadership moved targets the ORIGINAL
                // origin peers advertise it under, not the current leader.
                Some((seq, Some(authority_id), lease_epoch)) => (
                    seq,
                    authority_id,
                    lease_epoch.unwrap_or(current.lease_epoch),
                ),
                // Existing event with a legacy null authority: use the current lease.
                Some((seq, None, _)) => (seq, current.authority_id.clone(), current.lease_epoch),
                // No stored event (or no event_id): fall back to the authority MAX
                // under the current lease. Over-targets (waits longer), never
                // under-targets, so the witness still never over-counts.
                None => {
                    let seq = store
                        .max_mutation_event_seq_for_authority(&current.authority_id)
                        .map_err(http_error)?;
                    (seq, current.authority_id.clone(), current.lease_epoch)
                }
            };
            Ok(BudgetWriteToken {
                origin_id,
                event_seq,
                budget_term,
            })
        }
        None => Ok(BudgetWriteToken {
            origin_id: String::new(),
            event_seq: 0,
            budget_term: 0,
        }),
    }
}

pub(crate) async fn handle_try_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<TryChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(response) =
        validate_budget_request_identity(payload.hold_id.as_deref(), payload.event_id.as_deref())
    {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_AUTHORIZE_EXPOSURE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let authority = match current_budget_event_authority(&state) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let store = match state.budget_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    let effective_event_id = payload
        .event_id
        .clone()
        .unwrap_or_else(generated_budget_event_id);
    let (already_captured, admission, denied) = if payload.hold_id.is_none() {
        let allowed = match store.try_charge_cost_with_ids_and_authority(
            &payload.capability_id,
            payload.grant_index,
            payload.max_invocations,
            payload.cost_units,
            payload.max_cost_per_invocation,
            payload.max_total_cost_units,
            None,
            Some(&effective_event_id),
            authority.as_ref(),
        ) {
            Ok(allowed) => allowed,
            Err(error) => return budget_internal_error(&error, "budget authorization failed"),
        };
        let event = match store.mutation_event_for_event_id(&effective_event_id) {
            Ok(Some(event)) => event,
            Ok(None) => {
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "budget authorization did not retain its event identity",
                )
            }
            Err(error) => {
                return budget_internal_error(&error, "budget authorization event lookup failed")
            }
        };
        let committed_cost_units_after = match event
            .total_cost_exposed_after
            .checked_add(event.total_cost_realized_spend_after)
        {
            Some(committed) => committed,
            None => {
                return budget_internal_error(
                    &BudgetStoreError::Overflow("committed budget cost overflowed u64".to_string()),
                    "budget authorization projection failed",
                )
            }
        };
        let metadata = BudgetCommitMetadata {
            authority: event.authority,
            guarantee_level: store.budget_guarantee_level(),
            budget_profile: store.budget_authority_profile(),
            metering_profile: store.budget_metering_profile(),
            budget_commit_index: Some(event.event_seq),
            event_id: Some(event.event_id),
            recorded_at_unix_seconds: u64::try_from(event.recorded_at).ok(),
        };
        if allowed {
            (
                false,
                Some((
                    metadata,
                    event.exposure_units,
                    event.realized_spend_units,
                    event.invocation_count_after,
                    committed_cost_units_after,
                )),
                None,
            )
        } else {
            (
                false,
                None,
                Some((
                    metadata,
                    event.invocation_count_after,
                    committed_cost_units_after,
                )),
            )
        }
    } else {
        let decision = match store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: payload.capability_id.clone(),
            grant_index: payload.grant_index,
            max_invocations: payload.max_invocations,
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: payload.cost_units,
            max_cost_per_invocation: payload.max_cost_per_invocation,
            max_total_cost_units: payload.max_total_cost_units,
            hold_id: payload.hold_id.clone(),
            event_id: Some(effective_event_id),
            authority: authority.clone(),
        }) {
            Ok(decision) => decision,
            Err(error) => return budget_internal_error(&error, "budget authorization failed"),
        };
        match decision {
            BudgetAuthorizeHoldDecision::Authorized(authorized) => (
                false,
                Some((
                    authorized.metadata,
                    authorized.authorized_exposure_units,
                    0,
                    authorized.invocation_count_after,
                    authorized.committed_cost_units_after,
                )),
                None,
            ),
            BudgetAuthorizeHoldDecision::AlreadyCaptured(mutation) => (
                true,
                Some((
                    mutation.metadata,
                    mutation.exposure_units,
                    mutation.realized_spend_units,
                    mutation.invocation_count_after,
                    mutation.committed_cost_units_after,
                )),
                None,
            ),
            BudgetAuthorizeHoldDecision::ApprovalRequired(_) => {
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "legacy budget endpoint received an unsupported cumulative approval decision",
                )
            }
            BudgetAuthorizeHoldDecision::Denied(denied) => (
                false,
                None,
                Some((
                    denied.metadata,
                    denied.invocation_count_after,
                    denied.committed_cost_units_after,
                )),
            ),
        }
    };
    if let Some((
        admission_metadata,
        exposure_units,
        realized_spend_units,
        mutation_invocation_count_after,
        mutation_committed_cost_units_after,
    )) = admission
    {
        let event_id = match admission_metadata.event_id {
            Some(event_id) => event_id,
            None => {
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "budget authorization did not retain its event identity",
                )
            }
        };
        let write = match budget_write_token(&store, authority.as_ref(), Some(&event_id)) {
            Ok(write) => write,
            Err(response) => return response,
        };
        let committed_response = match store.get_usage(&payload.capability_id, payload.grant_index)
        {
            Ok(Some(usage)) => Some(TryChargeCostResponse {
                capability_id: payload.capability_id.clone(),
                grant_index: payload.grant_index,
                allowed: !already_captured,
                decision: if already_captured {
                    BudgetAuthorizeExposureDecision::AlreadyCaptured
                } else {
                    BudgetAuthorizeExposureDecision::Authorized
                },
                hold_id: payload.hold_id.clone(),
                event_id: Some(event_id),
                exposure_units: Some(exposure_units),
                realized_spend_units: Some(realized_spend_units),
                mutation_invocation_count_after: Some(mutation_invocation_count_after),
                mutation_committed_cost_units_after: Some(mutation_committed_cost_units_after),
                usage_seq: Some(usage.seq),
                invocation_count: Some(usage.invocation_count),
                total_cost_exposed: Some(usage.total_cost_exposed),
                total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                budget_authority: budget_authority_metadata_view(
                    &state,
                    Some(usage.seq),
                    budget_authority_guarantee_level(&state, Some(usage.seq)),
                ),
                budget_commit: None,
            }),
            Ok(None) => None,
            Err(error) => {
                return budget_internal_error(&error, "budget usage lookup failed");
            }
        };
        let Some(response) = committed_response else {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "budget exposure state was not visible on the leader after write",
            );
        };
        let commit_index = write.event_seq;
        let budget_commit = match wait_for_budget_write_quorum_commit(&state, write).await {
            Ok(budget_commit) => budget_commit,
            Err(_) => {
                if already_captured {
                    return plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "captured budget authorization replay could not confirm quorum commit; admission retained",
                    );
                }
                let rollback_result = rollback_budget_authorize_exposure(
                    &state,
                    &payload,
                    authority.as_ref(),
                    commit_index,
                );
                return match rollback_result {
                    Ok(()) => plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!(
                            "budget authorize became leader-visible at commit index {commit_index} but failed quorum commit; local exposure rollback succeeded"
                        ),
                    ),
                    Err(error) => budget_internal_error(
                        &error,
                        "budget authorize quorum failure and rollback failed; admission retained",
                    ),
                };
            }
        };
        json_response_with_leader_visibility_and_budget_commit(&state, response, budget_commit)
    } else if let Some((denied_metadata, invocation_count_after, committed_cost_units_after)) =
        denied
    {
        respond_after_leader_visible_write(
            &state,
            "budget exposure state was not visible on the leader after write",
            || {
                let usage = store
                    .get_usage(&payload.capability_id, payload.grant_index)
                    .map_err(|error| budget_internal_error(&error, "budget usage lookup failed"))?;
                Ok(Some(TryChargeCostResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed: false,
                    decision: BudgetAuthorizeExposureDecision::Denied,
                    hold_id: payload.hold_id.clone(),
                    event_id: denied_metadata.event_id.clone(),
                    exposure_units: None,
                    realized_spend_units: None,
                    mutation_invocation_count_after: Some(invocation_count_after),
                    mutation_committed_cost_units_after: Some(committed_cost_units_after),
                    usage_seq: usage.as_ref().map(|usage| usage.seq),
                    invocation_count: usage.as_ref().map(|usage| usage.invocation_count),
                    total_cost_exposed: usage.as_ref().map(|usage| usage.total_cost_exposed),
                    total_cost_realized_spend: usage
                        .as_ref()
                        .map(|usage| usage.total_cost_realized_spend),
                    budget_authority: budget_authority_metadata_view(
                        &state,
                        None,
                        budget_authority_guarantee_level(&state, None),
                    ),
                    budget_commit: None,
                }))
            },
        )
    } else {
        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, "missing budget decision")
    }
}

pub(crate) async fn handle_reverse_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ReverseChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(response) =
        validate_budget_request_identity(payload.hold_id.as_deref(), payload.event_id.as_deref())
    {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_RELEASE_EXPOSURE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match state.budget_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    let authority = match resolve_budget_hold_authority(&state, &store, payload.hold_id.as_deref())
    {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    // Mint an event_id when omitted so the witness waits on this reverse's exact
    // event_seq, not the authority MAX.
    let effective_event_id = payload
        .event_id
        .clone()
        .unwrap_or_else(generated_budget_event_id);
    let mutation = if let Some(hold_id) = payload.hold_id.as_deref() {
        match store.reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: payload.capability_id.clone(),
            grant_index: payload.grant_index,
            reversed_exposure_units: payload.cost_units,
            hold_id: Some(hold_id.to_string()),
            event_id: Some(effective_event_id.clone()),
            expected_cumulative_approval_state: None,
            authority: authority.clone(),
        }) {
            Ok(mutation) => Some(mutation),
            Err(error) => return budget_internal_error(&error, "budget exposure release failed"),
        }
    } else {
        if let Err(error) = store.reverse_charge_cost_with_ids_and_authority(
            &payload.capability_id,
            payload.grant_index,
            payload.cost_units,
            None,
            Some(effective_event_id.as_str()),
            authority.as_ref(),
        ) {
            return budget_internal_error(&error, "budget exposure release failed");
        }
        None
    };
    let structured_projection = if let Some(mutation) = mutation {
        let grant_index = match u32::try_from(payload.grant_index) {
            Ok(grant_index) => grant_index,
            Err(error) => return structured_projection_error(error),
        };
        match structured_mutation_projection(
            &store,
            Some(&payload.capability_id),
            Some(grant_index),
            payload.hold_id.clone().unwrap_or_default(),
            effective_event_id.clone(),
            StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
            mutation,
        ) {
            Ok(projection) => projection,
            Err(response) => return response,
        }
    } else {
        None
    };
    let write = match budget_write_token(
        &store,
        authority.as_ref(),
        Some(effective_event_id.as_str()),
    ) {
        Ok(write) => write,
        Err(response) => return response,
    };
    let committed_response = match lifecycle_response_usage(
        &store,
        &payload.capability_id,
        payload.grant_index,
        structured_projection.as_ref(),
    ) {
        Ok(Some(usage)) => {
            let budget_authority = match lifecycle_budget_authority_metadata(
                &state,
                structured_projection.as_ref(),
                usage.seq,
            ) {
                Ok(authority) => authority,
                Err(response) => return response,
            };
            Some((
                ReverseChargeCostResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    hold_id: payload.hold_id.clone(),
                    event_id: Some(effective_event_id.clone()),
                    invocation_count: Some(usage.invocation_count),
                    total_cost_exposed: Some(usage.total_cost_exposed),
                    total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                    usage_seq: Some(usage.seq),
                    budget_authority,
                    budget_commit: None,
                    structured_projection,
                },
                write,
            ))
        }
        Ok(None) => None,
        Err(response) => return response,
    };
    respond_after_budget_write_quorum_commit(
        &state,
        "released budget exposure state was not visible on the leader after write",
        committed_response,
    )
    .await
}

pub(crate) async fn handle_capture_invocation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CaptureInvocationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_CAPTURE_INVOCATION_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match state.budget_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    let authority = match resolve_budget_hold_authority(&state, &store, Some(&payload.hold_id)) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let (decision, mutation) =
        match store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: payload.capability_id.clone(),
            grant_index: payload.grant_index,
            hold_id: payload.hold_id.clone(),
            event_id: payload.event_id.clone(),
            trusted_time: None,
            authority: authority.clone(),
        }) {
            Ok(BudgetInvocationCaptureDecision::Captured(mutation)) => {
                (CaptureInvocationDecision::Captured, mutation)
            }
            Ok(BudgetInvocationCaptureDecision::AlreadyCaptured(mutation)) => {
                (CaptureInvocationDecision::AlreadyCaptured, mutation)
            }
            Err(error) => {
                return budget_internal_error(&error, "budget invocation capture failed");
            }
        };
    let Some(event_id) = mutation.metadata.event_id.clone() else {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "capture mutation did not retain its event identity",
        );
    };
    let structured_projection = match structured_mutation_projection(
        &store,
        Some(&payload.capability_id),
        match u32::try_from(payload.grant_index) {
            Ok(grant_index) => Some(grant_index),
            Err(error) => return structured_projection_error(error),
        },
        payload.hold_id.clone(),
        payload.event_id.clone(),
        match decision {
            CaptureInvocationDecision::Captured => StructuredBudgetMutationDecisionView::Applied,
            CaptureInvocationDecision::AlreadyCaptured => {
                StructuredBudgetMutationDecisionView::AlreadyApplied
            }
        },
        mutation.clone(),
    ) {
        Ok(projection) => projection,
        Err(response) => return response,
    };
    let usage = match lifecycle_response_usage(
        &store,
        &payload.capability_id,
        payload.grant_index,
        structured_projection.as_ref(),
    ) {
        Ok(Some(usage)) => usage,
        Ok(None) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "captured budget usage was not visible on the leader after write",
            )
        }
        Err(response) => return response,
    };
    let budget_authority = match lifecycle_budget_authority_metadata(
        &state,
        structured_projection.as_ref(),
        usage.seq,
    ) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let write = match budget_write_token(&store, authority.as_ref(), Some(&event_id)) {
        Ok(write) => write,
        Err(response) => return response,
    };
    respond_after_budget_write_quorum_commit(
        &state,
        "captured budget invocation state was not visible on the leader after write",
        Some((
            CaptureInvocationResponse {
                capability_id: payload.capability_id,
                grant_index: payload.grant_index,
                hold_id: payload.hold_id,
                event_id,
                decision,
                exposure_units: mutation.exposure_units,
                invocation_count_after: mutation.invocation_count_after,
                usage_invocation_count: usage.invocation_count,
                committed_cost_units_after: mutation.committed_cost_units_after,
                total_cost_exposed_after: usage.total_cost_exposed,
                total_cost_realized_spend_after: usage.total_cost_realized_spend,
                usage_seq: Some(usage.seq),
                budget_authority,
                budget_commit: None,
                structured_projection,
            },
            write,
        )),
    )
    .await
}

pub(crate) async fn handle_reduce_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ReduceChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(response) =
        validate_budget_request_identity(payload.hold_id.as_deref(), payload.event_id.as_deref())
    {
        return response;
    }
    let released_exposure_units = payload.release_units();
    match forward_post_to_leader(&state, BUDGET_RECONCILE_SPEND_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match state.budget_store() {
        Ok(store) => store,
        Err(response) => return response,
    };
    let authority = match resolve_budget_hold_authority(&state, &store, payload.hold_id.as_deref())
    {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    // Mint an event_id when omitted so the witness waits on this reconcile's exact
    // event_seq, not the authority MAX.
    let effective_event_id = payload
        .event_id
        .clone()
        .unwrap_or_else(generated_budget_event_id);
    let lifecycle_amounts =
        match (payload.exposure_units, payload.realized_spend_units) {
            (None, None) => None,
            (Some(exposure_units), Some(realized_spend_units)) => {
                Some((exposure_units, realized_spend_units))
            }
            _ => return structured_bad_request(
                "budget lifecycle request must provide both exposure and realized spend or neither",
            ),
        };
    let mutation = if let Some(hold_id) = payload.hold_id.as_deref() {
        let result = match lifecycle_amounts {
            None => store.release_budget_hold(BudgetReleaseHoldRequest {
                capability_id: payload.capability_id.clone(),
                grant_index: payload.grant_index,
                released_exposure_units,
                hold_id: Some(hold_id.to_string()),
                event_id: Some(effective_event_id.clone()),
                authority: authority.clone(),
            }),
            Some((exposed_cost_units, realized_spend_units)) => {
                store.reconcile_budget_hold(BudgetReconcileHoldRequest {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    exposed_cost_units,
                    realized_spend_units,
                    hold_id: Some(hold_id.to_string()),
                    event_id: Some(effective_event_id.clone()),
                    authority: authority.clone(),
                })
            }
        };
        match result {
            Ok(mutation) => Some(mutation),
            Err(error) => return budget_internal_error(&error, "budget reconciliation failed"),
        }
    } else {
        let result = match lifecycle_amounts {
            Some((exposure_units, realized_spend_units)) => store
                .settle_charge_cost_with_ids_and_authority(
                    &payload.capability_id,
                    payload.grant_index,
                    exposure_units,
                    realized_spend_units,
                    None,
                    Some(effective_event_id.as_str()),
                    authority.as_ref(),
                ),
            None => store.reduce_charge_cost_with_ids_and_authority(
                &payload.capability_id,
                payload.grant_index,
                released_exposure_units,
                None,
                Some(effective_event_id.as_str()),
                authority.as_ref(),
            ),
        };
        if let Err(error) = result {
            return budget_internal_error(&error, "budget reconciliation failed");
        }
        None
    };
    let structured_projection = if let Some(mutation) = mutation {
        let grant_index = match u32::try_from(payload.grant_index) {
            Ok(grant_index) => grant_index,
            Err(error) => return structured_projection_error(error),
        };
        match structured_mutation_projection(
            &store,
            Some(&payload.capability_id),
            Some(grant_index),
            payload.hold_id.clone().unwrap_or_default(),
            effective_event_id.clone(),
            StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied,
            mutation,
        ) {
            Ok(projection) => projection,
            Err(response) => return response,
        }
    } else {
        None
    };
    let write = match budget_write_token(
        &store,
        authority.as_ref(),
        Some(effective_event_id.as_str()),
    ) {
        Ok(write) => write,
        Err(response) => return response,
    };
    let committed_response = match lifecycle_response_usage(
        &store,
        &payload.capability_id,
        payload.grant_index,
        structured_projection.as_ref(),
    ) {
        Ok(Some(usage)) => {
            let budget_authority = match lifecycle_budget_authority_metadata(
                &state,
                structured_projection.as_ref(),
                usage.seq,
            ) {
                Ok(authority) => authority,
                Err(response) => return response,
            };
            Some((
                ReduceChargeCostResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    hold_id: payload.hold_id.clone(),
                    event_id: Some(effective_event_id.clone()),
                    invocation_count: Some(usage.invocation_count),
                    total_cost_exposed: Some(usage.total_cost_exposed),
                    total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                    released_exposure_units: Some(released_exposure_units),
                    usage_seq: Some(usage.seq),
                    budget_authority,
                    budget_commit: None,
                    structured_projection,
                },
                write,
            ))
        }
        Ok(None) => None,
        Err(response) => return response,
    };
    respond_after_budget_write_quorum_commit(
        &state,
        "reconciled budget spend state was not visible on the leader after write",
        committed_response,
    )
    .await
}

fn structured_bad_request(error: impl std::fmt::Display) -> Response {
    plain_http_error(StatusCode::BAD_REQUEST, &error.to_string())
}

fn structured_projection_error(error: impl std::fmt::Display) -> Response {
    warn!(reason = %redacted!(error), "structured budget projection failed");
    plain_http_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "structured budget projection failed",
    )
}

fn structured_mutation_projection(
    store: &SqliteBudgetStore,
    expected_capability_id: Option<&str>,
    expected_grant_index: Option<u32>,
    request_hold_id: String,
    request_event_id: String,
    decision: StructuredBudgetMutationDecisionView,
    mutation: BudgetHoldMutationDecision,
) -> Result<Option<StructuredBudgetMutationResponse>, Response> {
    if mutation.admission_binding.is_none() {
        return Ok(None);
    }
    exact_structured_mutation_projection(
        store,
        expected_capability_id,
        expected_grant_index,
        request_hold_id,
        request_event_id,
        decision,
        mutation,
    )
    .map(Some)
}

pub(crate) fn exact_structured_mutation_projection(
    store: &SqliteBudgetStore,
    expected_capability_id: Option<&str>,
    expected_grant_index: Option<u32>,
    request_hold_id: String,
    request_event_id: String,
    decision: StructuredBudgetMutationDecisionView,
    mutation: BudgetHoldMutationDecision,
) -> Result<StructuredBudgetMutationResponse, Response> {
    if mutation.admission_binding.is_some() && mutation.metadata.authority.is_none() {
        return Err(structured_projection_error(
            "structured mutation omitted authority",
        ));
    }
    let Some(event_id) = mutation.metadata.event_id.as_deref() else {
        return Err(structured_projection_error(
            "mutation omitted event identity",
        ));
    };
    let event = match store.mutation_event_for_event_id(event_id) {
        Ok(Some(event)) => event,
        Ok(None) => {
            return Err(structured_projection_error(
                "mutation event was not durable",
            ))
        }
        Err(error) => return Err(structured_projection_error(error)),
    };
    if expected_capability_id.is_some_and(|expected| event.capability_id != expected)
        || expected_grant_index.is_some_and(|expected| event.grant_index != expected)
        || event.hold_id.as_deref() != Some(request_hold_id.as_str())
    {
        return Err(structured_projection_error(
            "mutation event changed the request identity",
        ));
    }
    validate_durable_mutation_projection(&event, &mutation)?;
    let usage = structured::structured_usage_view_for_event(store, &event)?;
    StructuredBudgetMutationResponse::from_core(
        event.capability_id,
        event.grant_index,
        request_hold_id,
        request_event_id,
        decision,
        mutation,
        usage,
    )
    .map_err(structured_projection_error)
}

fn validate_durable_mutation_projection(
    event: &BudgetMutationRecord,
    mutation: &BudgetHoldMutationDecision,
) -> Result<(), Response> {
    let committed_cost_units_after = event
        .total_cost_exposed_after
        .checked_add(event.total_cost_realized_spend_after)
        .ok_or_else(|| structured_projection_error("mutation event cost overflowed"))?;
    if event.hold_id != mutation.hold_id
        || event.admission_binding != mutation.admission_binding
        || event.exposure_units != mutation.exposure_units
        || event.realized_spend_units != mutation.realized_spend_units
        || event.invocation_count_after != mutation.invocation_count_after
        || event.invocation_quota_usages != mutation.invocation_quota_usages
        || event.cumulative_approval != mutation.cumulative_approval
        || event.invocation_state_after != mutation.invocation_state
        || event.monetary_state_after != mutation.monetary_state
        || event.authority != mutation.metadata.authority
        || Some(event.event_seq) != mutation.metadata.budget_commit_index
        || mutation.metadata.event_id.as_deref() != Some(event.event_id.as_str())
        || committed_cost_units_after != mutation.committed_cost_units_after
    {
        return Err(structured_projection_error(
            "mutation projection did not match its durable event",
        ));
    }
    Ok(())
}

fn structured_mutation_response(
    store: &SqliteBudgetStore,
    expected_capability_id: Option<&str>,
    expected_grant_index: Option<u32>,
    request_hold_id: String,
    request_event_id: String,
    decision: StructuredBudgetMutationDecisionView,
    mutation: BudgetHoldMutationDecision,
) -> Response {
    match exact_structured_mutation_projection(
        store,
        expected_capability_id,
        expected_grant_index,
        request_hold_id,
        request_event_id,
        decision,
        mutation,
    ) {
        Ok(response) => Json(response).into_response(),
        Err(response) => response,
    }
}

fn lifecycle_response_usage(
    store: &SqliteBudgetStore,
    capability_id: &str,
    grant_index: usize,
    projection: Option<&StructuredBudgetMutationResponse>,
) -> Result<Option<BudgetUsageRecord>, Response> {
    if let Some(projection) = projection {
        let usage = projection.usage.clone().ok_or_else(|| {
            structured_projection_error("structured lifecycle mutation omitted event-time usage")
        })?;
        return usage
            .try_into()
            .map(Some)
            .map_err(structured_projection_error);
    }
    store
        .get_usage(capability_id, grant_index)
        .map_err(|error| budget_internal_error(&error, "budget usage lookup failed"))
}

fn lifecycle_budget_authority_metadata(
    state: &TrustServiceState,
    projection: Option<&StructuredBudgetMutationResponse>,
    usage_seq: u64,
) -> Result<Option<BudgetAuthorityMetadataView>, Response> {
    let Some(projection) = projection else {
        return Ok(budget_authority_metadata_view(
            state,
            Some(usage_seq),
            budget_authority_guarantee_level(state, Some(usage_seq)),
        ));
    };
    let authority = projection
        .projection
        .metadata
        .authority
        .as_ref()
        .ok_or_else(|| structured_projection_error("structured mutation omitted authority"))?;
    let budget_commit_index = projection
        .projection
        .metadata
        .budget_commit_index
        .filter(|index| *index > 0)
        .ok_or_else(|| structured_projection_error("structured mutation omitted commit index"))?;
    Ok(Some(BudgetAuthorityMetadataView {
        authority_id: authority.authority_id.clone(),
        leader_url: state.config.advertise_url.clone().unwrap_or_default(),
        budget_term: authority.lease_epoch,
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
        lease_expires_at: 0,
        lease_ttl_ms: 0,
        guarantee_level: projection.projection.metadata.guarantee_level.clone(),
        budget_commit_index: Some(budget_commit_index),
    }))
}

fn resolve_budget_hold_authority(
    state: &TrustServiceState,
    store: &SqliteBudgetStore,
    hold_id: Option<&str>,
) -> Result<Option<BudgetEventAuthority>, Response> {
    if let Some(authority_store) = state.joint_authority_store.as_ref() {
        let fence = authority_store.mutation_fence();
        return Ok(Some(BudgetEventAuthority {
            authority_id: fence.store_uuid,
            lease_id: fence.lease_id,
            lease_epoch: fence.owner_epoch,
        }));
    }
    if let Some(hold_id) = hold_id {
        match store.hold_authority(hold_id) {
            Ok(Some(authority)) => return Ok(Some(authority)),
            Ok(None) => {}
            Err(error) => {
                return Err(budget_internal_error(
                    &error,
                    "budget hold authority lookup failed",
                ));
            }
        }
    }
    current_budget_event_authority(state)
}

#[cfg(test)]
#[path = "budget_handlers/tests.rs"]
mod budget_handlers_tests;
