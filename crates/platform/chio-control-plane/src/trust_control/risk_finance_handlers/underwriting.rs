use super::*;
use crate::trust_control::report_rendering::forward_post_to_leader;

pub(crate) async fn handle_underwriting_policy_input(
    State(state): State<TrustServiceState>,
    Query(query): Query<UnderwritingPolicyInputQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting input queries",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let keypair = match load_behavioral_feed_signing_keypair(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
    ) {
        Ok(keypair) => keypair,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    let trusted_kernel_keys = vec![keypair.public_key().to_hex()];
    match build_underwriting_policy_input(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &query,
        chio_kernel::ReceiptReadContext::admin_service(),
        &trusted_kernel_keys,
    ) {
        Ok(report) => match SignedUnderwritingPolicyInput::sign(report, &keypair) {
            Ok(signed) => Json::<SignedUnderwritingPolicyInput>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_underwriting_decision_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<UnderwritingPolicyInputQuery>,
    headers: HeaderMap,
) -> Response {
    let read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "underwriting decision report",
    ) {
        Ok(context) => context,
        Err(response) => return response,
    };

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting decision queries",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    let trusted_kernel_keys = match trusted_kernel_keys_from_service_config(&state.config) {
        Ok(keys) => keys.unwrap_or_default(),
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "trust service authority material is configured but could not be loaded: {error}"
                ),
            );
        }
    };
    match build_underwriting_decision_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &query,
        read_context,
        &trusted_kernel_keys,
    ) {
        Ok(report) => Json::<UnderwritingDecisionReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_underwriting_simulation_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingSimulationRequest>,
) -> Response {
    let read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "underwriting simulation report",
    ) {
        Ok(context) => context,
        Err(response) => return response,
    };

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting simulation queries",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    let trusted_kernel_keys = match trusted_kernel_keys_from_service_config(&state.config) {
        Ok(keys) => keys.unwrap_or_default(),
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "trust service authority material is configured but could not be loaded: {error}"
                ),
            );
        }
    };
    match build_underwriting_simulation_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &request,
        read_context,
        &trusted_kernel_keys,
    ) {
        Ok(report) => Json::<UnderwritingSimulationReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_query_underwriting_decisions(
    State(state): State<TrustServiceState>,
    Query(query): Query<UnderwritingDecisionQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_underwriting_decisions(&query) {
        Ok(report) => Json::<UnderwritingDecisionListReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_underwriting_decision(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingDecisionIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    // Fiscal underwriting resolves the premium against the active schedule. A
    // follower can be stale or in fallback, so governed issuance must run on the
    // elected leader before resolution, signing, or persistence.
    if state.fiscal_runtime.is_some() {
        match forward_post_to_leader(&state, UNDERWRITING_DECISION_ISSUE_PATH, &request).await {
            Ok(Some(response)) => return response,
            Ok(None) => {}
            Err(response) => return response,
        }
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting decision issuance",
            );
        }
    };

    match issue_signed_underwriting_decision_detailed(
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &request.query,
        request.supersedes_decision_id.as_deref(),
        chio_kernel::ReceiptReadContext::admin_service(),
        state.fiscal_runtime.as_deref(),
    ) {
        Ok(decision) => Json::<SignedUnderwritingDecision>(decision).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_create_underwriting_appeal(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingAppealCreateRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let mut receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.create_underwriting_appeal(&request) {
        Ok(record) => Json::<UnderwritingAppealRecord>(record).into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(ReceiptStoreError::Conflict(message)) => {
            plain_http_error(StatusCode::CONFLICT, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_resolve_underwriting_appeal(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingAppealResolveRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let mut receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.resolve_underwriting_appeal(&request) {
        Ok(record) => Json::<UnderwritingAppealRecord>(record).into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(ReceiptStoreError::Conflict(message)) => {
            plain_http_error(StatusCode::CONFLICT, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}
