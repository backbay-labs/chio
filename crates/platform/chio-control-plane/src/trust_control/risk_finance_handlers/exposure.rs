use super::*;

pub(crate) async fn handle_exposure_ledger_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    let read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "exposure ledger report",
    ) {
        Ok(context) => context,
        Err(response) => return response,
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

    match build_exposure_ledger_report_with_context(&receipt_store, &query, read_context) {
        Ok(report) => match SignedExposureLedgerReport::sign(report, &keypair) {
            Ok(signed) => Json::<SignedExposureLedgerReport>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}
