use super::*;

pub(crate) async fn handle_capital_book_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CapitalBookQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        resolve_admin_report_read_context(&headers, &state.config, "capital book report")
    {
        return response;
    }

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

    match build_capital_book_report_from_store(&receipt_store, &query) {
        Ok(report) => match SignedCapitalBookReport::sign(report, &keypair) {
            Ok(signed) => Json::<SignedCapitalBookReport>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_issue_capital_execution_instruction(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CapitalExecutionInstructionRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "capital instruction issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_capital_execution_instruction_detailed(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(signed) => Json::<SignedCapitalExecutionInstruction>(signed).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_issue_capital_allocation_decision(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CapitalAllocationDecisionRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "capital allocation issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_capital_allocation_decision_detailed(
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &request,
    ) {
        Ok(signed) => Json::<SignedCapitalAllocationDecision>(signed).into_response(),
        Err(error) => error.into_response(),
    }
}
