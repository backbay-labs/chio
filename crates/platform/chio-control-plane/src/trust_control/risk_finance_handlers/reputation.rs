use super::*;

pub(crate) async fn handle_local_reputation(
    State(state): State<TrustServiceState>,
    AxumPath(subject_key): AxumPath<String>,
    Query(query): Query<LocalReputationQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if state.config.receipt_db_path.is_none() {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust service is missing receipt_db_path for local reputation queries",
        );
    }

    let read_context = ReceiptReadContext::admin_service();
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
    match issuance::inspect_local_reputation_with_read_context(
        &subject_key,
        state.config.receipt_db_path.as_deref(),
        state.config.budget_db_path.as_deref(),
        query.since,
        query.until,
        state.config.issuance_policy.as_ref(),
        &trusted_kernel_keys,
        &read_context,
    ) {
        Ok(mut inspection) => {
            if let Some(receipt_db_path) = state.config.receipt_db_path.as_deref() {
                match reputation::build_imported_trust_report(
                    receipt_db_path,
                    &inspection.subject_key,
                    inspection.since,
                    inspection.until,
                    unix_timestamp_now(),
                    &inspection.scoring,
                ) {
                    Ok(report) => inspection.imported_trust = Some(report),
                    Err(error) => {
                        return plain_http_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &error.to_string(),
                        );
                    }
                }
            }
            Json(inspection).into_response()
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_reputation_compare(
    State(state): State<TrustServiceState>,
    AxumPath(subject_key): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<ReputationCompareRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if state.config.receipt_db_path.is_none() {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust service is missing receipt_db_path for reputation compare queries",
        );
    }

    let read_context = ReceiptReadContext::admin_service();
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
    let local = match issuance::inspect_local_reputation_with_read_context(
        &subject_key,
        state.config.receipt_db_path.as_deref(),
        state.config.budget_db_path.as_deref(),
        request.since,
        request.until,
        state.config.issuance_policy.as_ref(),
        &trusted_kernel_keys,
        &read_context,
    ) {
        Ok(local) => local,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let shared_evidence = {
        let store = match open_receipt_store(&state.config) {
            Ok(store) => store,
            Err(response) => return response,
        };
        match store.query_shared_evidence_report(&SharedEvidenceQuery {
            agent_subject: Some(local.subject_key.clone()),
            since: request.since,
            until: request.until,
            read_context: Some(chio_kernel::ReceiptReadContext::admin_service()),
            ..SharedEvidenceQuery::default()
        }) {
            Ok(report) => report,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        }
    };
    let imported_trust = match state.config.receipt_db_path.as_deref() {
        Some(receipt_db_path) => match reputation::build_imported_trust_report(
            receipt_db_path,
            &local.subject_key,
            local.since,
            local.until,
            unix_timestamp_now(),
            &local.scoring,
        ) {
            Ok(report) => Some(report),
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        },
        None => None,
    };
    match reputation::build_reputation_comparison(
        local,
        &request.passport,
        request.verifier_policy.as_ref(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
        shared_evidence,
        imported_trust,
    ) {
        Ok(comparison) => {
            Json::<reputation::PortableReputationComparison>(comparison).into_response()
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_portable_reputation_summary(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<PortableReputationSummaryIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match service_runtime::reputation::issue_signed_portable_reputation_summary(
        &state.config,
        &request,
    ) {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_issue_portable_negative_event(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<PortableNegativeEventIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match service_runtime::reputation::issue_signed_portable_negative_event(&state.config, &request)
    {
        Ok(artifact) => Json(artifact).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_evaluate_portable_reputation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<PortableReputationEvaluationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match service_runtime::reputation::evaluate_portable_reputation_request(&request) {
        Ok(report) => Json(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}
