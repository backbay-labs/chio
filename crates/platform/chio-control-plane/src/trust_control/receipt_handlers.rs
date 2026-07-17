//! HTTP handlers for the receipt and reporting surface: tool/child receipts and
//! queries, receipt analytics, evidence export/import, operator and economic
//! reports, settlement and metered-billing reconciliation, authorization
//! reports, and capability lineage.

use super::cluster::respond_after_leader_visible_write;
use super::report_rendering::{forward_post_to_leader, receipt_decision_kind, terminal_state_kind};
use super::report_validation::{
    resolve_control_read_principal, validate_metered_billing_reconciliation_request,
    validate_service_auth, ResolvedControlReadPrincipal,
};
use super::reports::{
    build_economic_completion_flow_report, build_operator_report, build_signed_behavioral_feed,
};
use super::*;

pub(crate) async fn handle_list_tool_receipts(
    State(state): State<TrustServiceState>,
    Query(query): Query<ToolReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    let principal = match resolve_control_read_principal(&headers, &state.config) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    // Point-load by receipt id: resolve exactly one receipt from the durable
    // store (bounded to one row) so a bounded in-memory mirror eviction on the
    // kernel does not cause a false denial of a governed call-chain
    // continuation. A by-id load is not tenant-scoped, so it is restricted to
    // the admin service principal (fail-closed): a tenant read token must use
    // the tenant-filtered list surface instead.
    if let Some(receipt_id) = query.receipt_id.as_deref() {
        if !matches!(principal, ResolvedControlReadPrincipal::AdminService) {
            return plain_http_error(
                StatusCode::FORBIDDEN,
                "receipt point-load by id requires the admin service token",
            );
        }
        let receipts = match store.load_chio_receipt(receipt_id) {
            Ok(Some(receipt)) => match serde_json::to_value(receipt) {
                Ok(value) => vec![value],
                Err(error) => {
                    return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
                }
            },
            Ok(None) => Vec::new(),
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        };
        return Json(ReceiptListResponse {
            configured: true,
            backend: "sqlite".to_string(),
            kind: "tool".to_string(),
            count: receipts.len(),
            filters: json!({ "receiptId": receipt_id }),
            receipts,
        })
        .into_response();
    }
    let kernel_query = ReceiptQuery {
        capability_id: query.capability_id.clone(),
        tool_server: query.tool_server.clone(),
        tool_name: query.tool_name.clone(),
        outcome: query.decision.clone(),
        since: None,
        until: None,
        min_cost: None,
        max_cost: None,
        cursor: None,
        limit: list_limit(query.limit),
        agent_subject: None,
        tenant_filter: None,
        read_context: Some(principal.receipt_read_context()),
    };
    let result = match store.query_receipts(&kernel_query) {
        Ok(result) => result,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let receipts = match result
        .receipts
        .into_iter()
        .map(|stored| serde_json::to_value(stored.receipt))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    Json(ReceiptListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        kind: "tool".to_string(),
        count: receipts.len(),
        filters: json!({
            "capabilityId": query.capability_id,
            "toolServer": query.tool_server,
            "toolName": query.tool_name,
            "decision": query.decision,
        }),
        receipts,
    })
    .into_response()
}

pub(crate) async fn handle_append_tool_receipt(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(receipt): Json<ChioReceipt>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, TOOL_RECEIPTS_PATH, &receipt).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.append_chio_receipt(&receipt) {
        Ok(()) => respond_after_leader_visible_write(
            &state,
            "tool receipt was not visible on the leader after write",
            || {
                let read_context = chio_kernel::ReceiptReadContext::admin_service();
                let receipts = store
                    .list_tool_receipts_with_context(
                        &read_context,
                        MAX_LIST_LIMIT,
                        Some(&receipt.capability_id),
                        Some(&receipt.tool_server),
                        Some(&receipt.tool_name),
                        Some(receipt_decision_kind(&receipt)),
                    )
                    .map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })?;
                if receipts
                    .into_iter()
                    .any(|candidate| candidate.id == receipt.id)
                {
                    Ok(Some(json!({
                        "stored": true,
                        "receiptId": receipt.id.clone(),
                    })))
                } else {
                    Ok(None)
                }
            },
        ),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_list_child_receipts(
    State(state): State<TrustServiceState>,
    Query(query): Query<ChildReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    let principal = match resolve_control_read_principal(&headers, &state.config) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    if matches!(principal, ResolvedControlReadPrincipal::TenantRead { .. }) {
        return plain_http_error(
            StatusCode::FORBIDDEN,
            "tenant read token cannot list child receipts until child receipts carry tenant attribution",
        );
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    // Point-load by receipt id (admin service only: tenant read tokens are
    // already rejected above). Resolves exactly one child receipt from the
    // durable store so bounded-mirror eviction on the kernel does not falsely
    // deny a governed call-chain continuation.
    if let Some(receipt_id) = query.receipt_id.as_deref() {
        let receipts = match store.load_child_receipt(receipt_id) {
            Ok(Some(receipt)) => match serde_json::to_value(receipt) {
                Ok(value) => vec![value],
                Err(error) => {
                    return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
                }
            },
            Ok(None) => Vec::new(),
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        };
        return Json(ReceiptListResponse {
            configured: true,
            backend: "sqlite".to_string(),
            kind: "child".to_string(),
            count: receipts.len(),
            filters: json!({ "receiptId": receipt_id }),
            receipts,
        })
        .into_response();
    }
    let read_context = principal.receipt_read_context();
    let receipts = match store.list_child_receipts_with_context(
        &read_context,
        list_limit(query.limit),
        query.session_id.as_deref(),
        query.parent_request_id.as_deref(),
        query.request_id.as_deref(),
        query.operation_kind.as_deref(),
        query.terminal_state.as_deref(),
    ) {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let receipts = match receipts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    Json(ReceiptListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        kind: "child".to_string(),
        count: receipts.len(),
        filters: json!({
            "sessionId": query.session_id,
            "parentRequestId": query.parent_request_id,
            "requestId": query.request_id,
            "operationKind": query.operation_kind,
            "terminalState": query.terminal_state,
        }),
        receipts,
    })
    .into_response()
}

pub(crate) async fn handle_query_receipts(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptQueryHttpQuery>,
    headers: HeaderMap,
) -> Response {
    let principal = match resolve_control_read_principal(&headers, &state.config) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let kernel_query = ReceiptQuery {
        capability_id: query.capability_id.clone(),
        tool_server: query.tool_server.clone(),
        tool_name: query.tool_name.clone(),
        outcome: query.outcome.clone(),
        since: query.since,
        until: query.until,
        min_cost: query.min_cost,
        max_cost: query.max_cost,
        cursor: query.cursor,
        limit: list_limit(query.limit),
        agent_subject: query.agent_subject.clone(),
        tenant_filter: None,
        read_context: Some(principal.receipt_read_context()),
    };
    let result = match store.query_receipts(&kernel_query) {
        Ok(result) => result,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let receipts = match result
        .receipts
        .into_iter()
        .map(|stored| serde_json::to_value(stored.receipt))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(ReceiptQueryResponse {
        total_count: result.total_count,
        next_cursor: result.next_cursor,
        receipts,
    })
    .into_response()
}

pub(crate) fn resolve_admin_report_read_context(
    headers: &HeaderMap,
    config: &TrustServiceConfig,
    surface: &str,
) -> Result<ReceiptReadContext, Response> {
    match resolve_control_read_principal(headers, config)? {
        ResolvedControlReadPrincipal::AdminService => Ok(ReceiptReadContext::admin_service()),
        ResolvedControlReadPrincipal::TenantRead { .. } => Err(plain_http_error(
            StatusCode::FORBIDDEN,
            &format!("{surface} requires admin receipt read authority"),
        )),
    }
}

pub(crate) async fn handle_receipt_analytics(
    State(state): State<TrustServiceState>,
    Query(mut query): Query<ReceiptAnalyticsQuery>,
    headers: HeaderMap,
) -> Response {
    query.read_context =
        match resolve_admin_report_read_context(&headers, &state.config, "receipt analytics") {
            Ok(context) => Some(context),
            Err(response) => return response,
        };
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.query_receipt_analytics(&query) {
        Ok(response) => Json::<ReceiptAnalyticsResponse>(response).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_evidence_export(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<evidence_export::RemoteEvidenceExportRequest>,
) -> Response {
    let principal = match resolve_control_read_principal(&headers, &state.config) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let query = match principal.authorize_evidence_export_query(request.query) {
        Ok(query) => query,
        Err(response) => return response,
    };
    let prepared = match evidence_export::prepare_evidence_export(
        query,
        request.require_proofs,
        request.federation_policy,
    ) {
        Ok(prepared) => prepared,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let query = match principal.authorize_evidence_export_query(prepared.query) {
        Ok(query) => query,
        Err(response) => return response,
    };
    let bundle = match store.build_evidence_export_bundle(&query) {
        Ok(bundle) => bundle,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let transparency = match store.build_evidence_export_transparency_summary(&bundle.checkpoints) {
        Ok(transparency) => transparency,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    if let Err(error) =
        evidence_export::validate_evidence_bundle_requirements(&bundle, prepared.require_proofs)
    {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    Json(evidence_export::RemoteEvidenceExportResponse {
        bundle,
        transparency: Some(transparency),
        federation_policy: prepared.federation_policy,
    })
    .into_response()
}

pub(crate) async fn handle_evidence_import(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<evidence_export::RemoteEvidenceImportRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, EVIDENCE_IMPORT_PATH, &request).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    if let Err(error) = evidence_export::validate_import_package_data(&request.package) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let share_import = match evidence_export::build_federated_share_import(&request.package) {
        Ok(share) => share,
        Err(error) => {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
    };
    let mut store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.import_federated_evidence_share(&share_import) {
        Ok(share) => Json(evidence_export::RemoteEvidenceImportResponse { share }).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_cost_attribution_report(
    State(state): State<TrustServiceState>,
    Query(mut query): Query<CostAttributionQuery>,
    headers: HeaderMap,
) -> Response {
    query.read_context =
        match resolve_admin_report_read_context(&headers, &state.config, "cost attribution report")
        {
            Ok(context) => Some(context),
            Err(response) => return response,
        };
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.query_cost_attribution_report(&query) {
        Ok(report) => Json::<CostAttributionReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_shared_evidence_report(
    State(state): State<TrustServiceState>,
    Query(mut query): Query<SharedEvidenceQuery>,
    headers: HeaderMap,
) -> Response {
    query.read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "shared evidence report",
    ) {
        Ok(context) => Some(context),
        Err(response) => return response,
    };
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.query_shared_evidence_report(&query) {
        Ok(report) => Json::<SharedEvidenceReferenceReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_operator_report(
    State(state): State<TrustServiceState>,
    Query(mut query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    query.read_context =
        match resolve_admin_report_read_context(&headers, &state.config, "operator report") {
            Ok(context) => Some(context),
            Err(response) => return response,
        };

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let budget_store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_operator_report(&receipt_store, &budget_store, &query) {
        Ok(report) => Json::<OperatorReport>(report).into_response(),
        Err(response) => response,
    }
}

pub(crate) async fn handle_behavioral_feed_report(
    State(state): State<TrustServiceState>,
    Query(mut query): Query<BehavioralFeedQuery>,
    headers: HeaderMap,
) -> Response {
    query.read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "behavioral feed report",
    ) {
        Ok(context) => Some(context),
        Err(response) => return response,
    };

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "behavioral feed export requires --receipt-db on the trust-control service",
            );
        }
    };

    match build_signed_behavioral_feed(
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &query,
    ) {
        Ok(feed) => Json::<SignedBehavioralFeed>(feed).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_settlement_report(
    State(state): State<TrustServiceState>,
    Query(mut query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    query.read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "settlement reconciliation report",
    ) {
        Ok(context) => Some(context),
        Err(response) => return response,
    };

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_settlement_reconciliation_report(&query) {
        Ok(report) => Json::<SettlementReconciliationReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_record_settlement_reconciliation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<SettlementReconciliationUpdateRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.upsert_settlement_reconciliation(
        &request.receipt_id,
        request.reconciliation_state,
        request.note.as_deref(),
    ) {
        Ok(updated_at) => Json(SettlementReconciliationUpdateResponse {
            receipt_id: request.receipt_id,
            reconciliation_state: request.reconciliation_state,
            note: request.note,
            updated_at: updated_at as u64,
        })
        .into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_metered_billing_report(
    State(state): State<TrustServiceState>,
    Query(mut query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    query.read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "metered billing report",
    ) {
        Ok(context) => Some(context),
        Err(response) => return response,
    };

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_metered_billing_reconciliation_report(&query) {
        Ok(report) => Json::<MeteredBillingReconciliationReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_economic_receipt_report(
    State(state): State<TrustServiceState>,
    Query(mut query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    query.read_context =
        match resolve_admin_report_read_context(&headers, &state.config, "economic receipt report")
        {
            Ok(context) => Some(context),
            Err(response) => return response,
        };

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_economic_receipt_projection_report(&query) {
        Ok(report) => Json::<EconomicReceiptProjectionReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_economic_completion_flow_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    let read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "economic completion flow report",
    ) {
        Ok(context) => context,
        Err(response) => return response,
    };

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_economic_completion_flow_report(&receipt_store, &query, read_context) {
        Ok(report) => Json::<EconomicCompletionFlowReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(crate) async fn handle_authorization_context_report(
    State(state): State<TrustServiceState>,
    Query(mut query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    query.read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "authorization context report",
    ) {
        Ok(context) => Some(context),
        Err(response) => return response,
    };

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_authorization_context_report(&query) {
        Ok(report) => Json::<AuthorizationContextReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_authorization_profile_metadata_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = resolve_admin_report_read_context(
        &headers,
        &state.config,
        "authorization profile metadata report",
    ) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    Json::<ChioOAuthAuthorizationMetadataReport>(
        receipt_store.authorization_profile_metadata_report(),
    )
    .into_response()
}

pub(crate) async fn handle_authorization_review_pack_report(
    State(state): State<TrustServiceState>,
    Query(mut query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    query.read_context = match resolve_admin_report_read_context(
        &headers,
        &state.config,
        "authorization review pack report",
    ) {
        Ok(context) => Some(context),
        Err(response) => return response,
    };

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_authorization_review_pack(&query) {
        Ok(report) => Json::<ChioOAuthAuthorizationReviewPack>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_record_metered_billing_reconciliation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<MeteredBillingReconciliationUpdateRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(message) = validate_metered_billing_reconciliation_request(&request) {
        return plain_http_error(StatusCode::BAD_REQUEST, &message);
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let evidence = MeteredBillingEvidenceRecord {
        usage_evidence: chio_core::receipt::governance::MeteredUsageEvidenceReceiptMetadata {
            evidence_kind: request.adapter_kind.clone(),
            evidence_id: request.evidence_id.clone(),
            observed_units: request.observed_units,
            evidence_sha256: request.evidence_sha256.clone(),
        },
        billed_cost: request.billed_cost.clone(),
        recorded_at: request.recorded_at,
    };

    match receipt_store.upsert_metered_billing_reconciliation(
        &request.receipt_id,
        &evidence,
        request.reconciliation_state,
        request.note.as_deref(),
    ) {
        Ok(updated_at) => Json(MeteredBillingReconciliationUpdateResponse {
            receipt_id: request.receipt_id,
            evidence,
            reconciliation_state: request.reconciliation_state,
            note: request.note,
            updated_at: updated_at as u64,
        })
        .into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(ReceiptStoreError::Conflict(message)) => {
            plain_http_error(StatusCode::CONFLICT, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

pub(crate) async fn handle_record_lineage_snapshot(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<RecordCapabilitySnapshotRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, LINEAGE_RECORD_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    if let Err(error) = store
        .record_capability_snapshot(&payload.capability, payload.parent_capability_id.as_deref())
    {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    respond_after_leader_visible_write(
        &state,
        "capability lineage was not visible on the leader after write",
        || {
            let visible = store
                .get_lineage(&payload.capability.id)
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?
                .is_some();
            if visible {
                Ok(Some(json!({
                    "stored": true,
                    "capabilityId": payload.capability.id.clone(),
                })))
            } else {
                Ok(None)
            }
        },
    )
}

/// GET /v1/lineage/:capability_id
///
/// Returns the CapabilitySnapshot for the given capability ID, or 404 if not found.
pub(crate) async fn handle_get_lineage(
    State(state): State<TrustServiceState>,
    AxumPath(capability_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.get_combined_lineage(&capability_id) {
        Ok(Some(snapshot)) => Json(snapshot).into_response(),
        Ok(None) => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("capability not found: {capability_id}"),
        ),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

/// GET /v1/lineage/:capability_id/chain
///
/// Returns the full delegation chain for the given capability ID, root-first.
pub(crate) async fn handle_get_delegation_chain(
    State(state): State<TrustServiceState>,
    AxumPath(capability_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.get_combined_delegation_chain(&capability_id) {
        Ok(chain) => Json(chain).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

/// GET /v1/agents/:subject_key/receipts
///
/// Convenience endpoint: returns receipts for a given agent subject key.
/// Delegates to the same query_receipts call as GET /v1/receipts/query with
/// agentSubject set, passing through limit and cursor from query params.
pub(crate) async fn handle_agent_receipts(
    State(state): State<TrustServiceState>,
    AxumPath(subject_key): AxumPath<String>,
    Query(query): Query<AgentReceiptsHttpQuery>,
    headers: HeaderMap,
) -> Response {
    let principal = match resolve_control_read_principal(&headers, &state.config) {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let kernel_query = ReceiptQuery {
        agent_subject: Some(subject_key),
        cursor: query.cursor,
        limit: list_limit(query.limit),
        read_context: Some(principal.receipt_read_context()),
        ..Default::default()
    };
    let result = match store.query_receipts(&kernel_query) {
        Ok(result) => result,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let receipts = match result
        .receipts
        .into_iter()
        .map(|stored| serde_json::to_value(stored.receipt))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    Json(ReceiptQueryResponse {
        total_count: result.total_count,
        next_cursor: result.next_cursor,
        receipts,
    })
    .into_response()
}

pub(crate) async fn handle_append_child_receipt(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(receipt): Json<ChildRequestReceipt>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, CHILD_RECEIPTS_PATH, &receipt).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.append_child_receipt(&receipt) {
        Ok(()) => respond_after_leader_visible_write(
            &state,
            "child receipt was not visible on the leader after write",
            || {
                let read_context = chio_kernel::ReceiptReadContext::admin_service();
                let receipts = store
                    .list_child_receipts_with_context(
                        &read_context,
                        MAX_LIST_LIMIT,
                        Some(receipt.session_id.as_str()),
                        Some(receipt.parent_request_id.as_str()),
                        Some(receipt.request_id.as_str()),
                        Some(receipt.operation_kind.as_str()),
                        Some(terminal_state_kind(&receipt.terminal_state)),
                    )
                    .map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })?;
                if receipts
                    .into_iter()
                    .any(|candidate| candidate.id == receipt.id)
                {
                    Ok(Some(json!({
                        "stored": true,
                        "receiptId": receipt.id.clone(),
                    })))
                } else {
                    Ok(None)
                }
            },
        ),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}
