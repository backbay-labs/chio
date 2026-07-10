use super::*;

pub(crate) async fn handle_runtime_attestation_appraisal_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<RuntimeAttestationAppraisalRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    match build_signed_runtime_attestation_appraisal_report(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.runtime_assurance_policy.as_ref(),
        &request.runtime_attestation,
    ) {
        Ok(report) => Json::<SignedRuntimeAttestationAppraisalReport>(report).into_response(),
        Err(error @ CliError::Chio(_)) => {
            plain_http_error(StatusCode::BAD_REQUEST, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_runtime_attestation_appraisal_result_export(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<RuntimeAttestationAppraisalResultExportRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    match build_signed_runtime_attestation_appraisal_result(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.runtime_assurance_policy.as_ref(),
        &request,
    ) {
        Ok(result) => Json::<SignedRuntimeAttestationAppraisalResult>(result).into_response(),
        Err(error @ CliError::Chio(_)) => {
            plain_http_error(StatusCode::BAD_REQUEST, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_runtime_attestation_appraisal_import(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<RuntimeAttestationAppraisalImportRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    Json::<RuntimeAttestationAppraisalImportReport>(
        build_runtime_attestation_appraisal_import_report(&request, unix_timestamp_now()),
    )
    .into_response()
}
