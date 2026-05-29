//! HTTP handlers for the budget-metering surface: budget listing and the
//! authorize/release/reconcile exposure-accounting endpoints.

use super::*;

pub(crate) async fn handle_list_budgets(
    State(state): State<TrustServiceState>,
    Query(query): Query<BudgetQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let usages = match store.list_usages(list_limit(query.limit), query.capability_id.as_deref()) {
        Ok(usages) => usages,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
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
    let store = match open_budget_store(&state.config) {
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
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    respond_after_leader_visible_write(
        &state,
        "budget state was not visible on the leader after write",
        || {
            let invocation_count = store
                .get_usage(&payload.capability_id, payload.grant_index)
                .map(|usage| usage.map(|usage| usage.invocation_count))
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
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

pub(crate) async fn handle_try_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<TryChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
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
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let allowed = match store.try_charge_cost_with_ids_and_authority(
        &payload.capability_id,
        payload.grant_index,
        payload.max_invocations,
        payload.cost_units,
        payload.max_cost_per_invocation,
        payload.max_total_cost_units,
        payload.hold_id.as_deref(),
        payload.event_id.as_deref(),
        authority.as_ref(),
    ) {
        Ok(allowed) => allowed,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    if allowed {
        let committed_response = match store.get_usage(&payload.capability_id, payload.grant_index)
        {
            Ok(Some(usage)) => Some((
                TryChargeCostResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed,
                    invocation_count: Some(usage.invocation_count),
                    total_cost_exposed: Some(usage.total_cost_exposed),
                    total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                    budget_authority: budget_authority_metadata_view(
                        &state,
                        Some(usage.seq),
                        budget_authority_guarantee_level(&state, Some(usage.seq)),
                    ),
                    budget_commit: None,
                },
                usage.seq,
            )),
            Ok(None) => None,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        };
        drop(store);
        let Some((response, budget_seq)) = committed_response else {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "budget exposure state was not visible on the leader after write",
            );
        };
        let budget_commit = match wait_for_budget_write_quorum_commit(&state, budget_seq).await {
            Ok(budget_commit) => budget_commit,
            Err(_) => {
                let rollback_result =
                    rollback_budget_authorize_exposure(&state, &payload, authority.as_ref());
                return match rollback_result {
                    Ok(()) => plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!(
                            "budget authorize became leader-visible at commit index {budget_seq} but failed quorum commit; local exposure rollback succeeded"
                        ),
                    ),
                    Err(error) => plain_http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!(
                            "budget authorize became leader-visible at commit index {budget_seq} but failed quorum commit and local exposure rollback also failed: {error}"
                        ),
                    ),
                };
            }
        };
        json_response_with_leader_visibility_and_budget_commit(&state, response, budget_commit)
    } else {
        respond_after_leader_visible_write(
            &state,
            "budget exposure state was not visible on the leader after write",
            || {
                let usage = store
                    .get_usage(&payload.capability_id, payload.grant_index)
                    .map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })?;
                Ok(Some(TryChargeCostResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed,
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
    match forward_post_to_leader(&state, BUDGET_RELEASE_EXPOSURE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let authority =
        match resolve_budget_hold_authority(&state, &mut store, payload.hold_id.as_deref()) {
            Ok(authority) => authority,
            Err(response) => return response,
        };
    if let Err(error) = store.reverse_charge_cost_with_ids_and_authority(
        &payload.capability_id,
        payload.grant_index,
        payload.cost_units,
        payload.hold_id.as_deref(),
        payload.event_id.as_deref(),
        authority.as_ref(),
    ) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let committed_response = match store.get_usage(&payload.capability_id, payload.grant_index) {
        Ok(Some(usage)) => Some((
            ReverseChargeCostResponse {
                capability_id: payload.capability_id.clone(),
                grant_index: payload.grant_index,
                invocation_count: Some(usage.invocation_count),
                total_cost_exposed: Some(usage.total_cost_exposed),
                total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                budget_authority: budget_authority_metadata_view(
                    &state,
                    Some(usage.seq),
                    budget_authority_guarantee_level(&state, Some(usage.seq)),
                ),
                budget_commit: None,
            },
            usage.seq,
        )),
        Ok(None) => None,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    drop(store);
    respond_after_budget_write_quorum_commit(
        &state,
        "released budget exposure state was not visible on the leader after write",
        committed_response,
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
    let released_exposure_units = payload.release_units();
    match forward_post_to_leader(&state, BUDGET_RECONCILE_SPEND_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let authority =
        match resolve_budget_hold_authority(&state, &mut store, payload.hold_id.as_deref()) {
            Ok(authority) => authority,
            Err(response) => return response,
        };
    let reconcile_result = if let (Some(exposure_units), Some(realized_spend_units)) =
        (payload.exposure_units, payload.realized_spend_units)
    {
        store.settle_charge_cost_with_ids_and_authority(
            &payload.capability_id,
            payload.grant_index,
            exposure_units,
            realized_spend_units,
            payload.hold_id.as_deref(),
            payload.event_id.as_deref(),
            authority.as_ref(),
        )
    } else {
        store.reduce_charge_cost_with_ids_and_authority(
            &payload.capability_id,
            payload.grant_index,
            released_exposure_units,
            payload.hold_id.as_deref(),
            payload.event_id.as_deref(),
            authority.as_ref(),
        )
    };
    if let Err(error) = reconcile_result {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let committed_response = match store.get_usage(&payload.capability_id, payload.grant_index) {
        Ok(Some(usage)) => Some((
            ReduceChargeCostResponse {
                capability_id: payload.capability_id.clone(),
                grant_index: payload.grant_index,
                invocation_count: Some(usage.invocation_count),
                total_cost_exposed: Some(usage.total_cost_exposed),
                total_cost_realized_spend: Some(usage.total_cost_realized_spend),
                released_exposure_units: Some(released_exposure_units),
                budget_authority: budget_authority_metadata_view(
                    &state,
                    Some(usage.seq),
                    budget_authority_guarantee_level(&state, Some(usage.seq)),
                ),
                budget_commit: None,
            },
            usage.seq,
        )),
        Ok(None) => None,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    drop(store);
    respond_after_budget_write_quorum_commit(
        &state,
        "reconciled budget spend state was not visible on the leader after write",
        committed_response,
    )
    .await
}

fn resolve_budget_hold_authority(
    state: &TrustServiceState,
    store: &mut SqliteBudgetStore,
    hold_id: Option<&str>,
) -> Result<Option<BudgetEventAuthority>, Response> {
    if let Some(hold_id) = hold_id {
        match store.hold_authority(hold_id) {
            Ok(Some(authority)) => return Ok(Some(authority)),
            Ok(None) => {}
            Err(error) => {
                return Err(plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &error.to_string(),
                ));
            }
        }
    }
    current_budget_event_authority(state)
}
