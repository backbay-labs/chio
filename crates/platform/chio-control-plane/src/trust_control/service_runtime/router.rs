use super::super::cluster::{
    handle_internal_authority_snapshot, handle_internal_budgets_delta,
    handle_internal_child_receipts_delta, handle_internal_cluster_partition,
    handle_internal_cluster_snapshot, handle_internal_cluster_status,
    handle_internal_lineage_delta, handle_internal_revocations_delta,
    handle_internal_tool_receipts_delta,
};
use super::super::*;
use axum::extract::DefaultBodyLimit;

/// Body-size ceiling for evidence import, overriding the service-wide 1 MiB cap
/// on this one route. An exported evidence bundle legitimately embeds many
/// receipts plus its manifest and transparency data, so a whole-bundle import
/// routinely exceeds the general request cap; it still needs a bound so the
/// buffered `Json` decode cannot grow without limit.
const EVIDENCE_IMPORT_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Body-size ceiling for a stream-receipt append, overriding the service-wide
/// 1 MiB cap on the two receipt-append routes. A stream receipt embeds one
/// 64-hex-char chunk digest per retained chunk, and a kernel retains up to its
/// configured chunk cap (over a million chunks by default), so a full receipt
/// (a sidecar sync or a cross-node replication of a receipt that was valid under
/// the receipt format) runs to tens of MiB and dwarfs the general request cap.
/// The bound covers the default chunk ceiling (around 67 MiB of digests) with
/// room for the surrounding receipt envelope, while still bounding the buffered
/// `Json` decode so an oversized body cannot grow without limit.
const RECEIPT_APPEND_MAX_BODY_BYTES: usize = 128 * 1024 * 1024;
const ADMISSION_AUTHORITY_MAX_BODY_BYTES: usize = 384 * 1024 * 1024;

pub(crate) fn build_router(state: TrustServiceState) -> Router {
    // Seed the fixed alert-pack label sets at zero before this serve process can
    // be scraped. The trust-control /metrics route renders the fail-open /
    // dispatch-failure / capability-revocation families, but unlike the chio-cli,
    // chio-wall, and tower startup paths the service-runtime does not otherwise
    // call preregister_known_label_sets. On a fresh, healthy-but-quiet control
    // plane those families would be absent, so the shipped absent_over_time
    // backstops would page on a scrape gap that never happened. Idempotent.
    chio_metrics_spec::runtime::preregister_known_label_sets();

    let router = trust_control_health::install_health_routes(Router::new())
        .route(
            INTERNAL_ADMISSION_AUTHORITY_PATH,
            post(super::admission_authority::handle_admission_authority)
                .layer(DefaultBodyLimit::max(ADMISSION_AUTHORITY_MAX_BODY_BYTES)),
        )
        .route(
            AUTHORITY_PATH,
            get(handle_authority_status).post(handle_rotate_authority),
        )
        .route(ISSUE_CAPABILITY_PATH, post(handle_issue_capability))
        .route(FEDERATED_ISSUE_PATH, post(handle_federated_issue))
        .route(SCIM_USERS_PATH, post(handle_scim_create_user))
        .route(SCIM_USER_PATH, delete(handle_scim_delete_user))
        .route(
            FEDERATION_PROVIDERS_PATH,
            get(handle_list_enterprise_providers),
        )
        .route(
            FEDERATION_PROVIDER_PATH,
            get(handle_get_enterprise_provider)
                .put(handle_upsert_enterprise_provider)
                .delete(handle_delete_enterprise_provider),
        )
        .route(
            FEDERATION_POLICIES_PATH,
            get(handle_list_federation_policies),
        )
        .route(
            FEDERATION_POLICY_PATH,
            get(handle_get_federation_policy)
                .put(handle_upsert_federation_policy)
                .delete(handle_delete_federation_policy),
        )
        .route(
            FEDERATION_POLICY_EVALUATE_PATH,
            post(handle_evaluate_federation_policy),
        )
        .route(
            CERTIFICATIONS_PATH,
            get(handle_list_certifications).post(handle_publish_certification),
        )
        .route(CERTIFICATION_PATH, get(handle_get_certification))
        .route(
            CERTIFICATION_RESOLVE_PATH,
            get(handle_resolve_certification),
        )
        .route(
            CERTIFICATION_DISCOVERY_PATH,
            post(handle_publish_certification_network),
        )
        .route(
            CERTIFICATION_DISCOVERY_RESOLVE_PATH,
            get(handle_discover_certification),
        )
        .route(
            CERTIFICATION_DISCOVERY_SEARCH_PATH,
            get(handle_search_certification_marketplace),
        )
        .route(
            CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH,
            get(handle_transparency_certification_marketplace),
        )
        .route(
            CERTIFICATION_DISCOVERY_CONSUME_PATH,
            post(handle_consume_certification_marketplace),
        )
        .route(CERTIFICATION_REVOKE_PATH, post(handle_revoke_certification))
        .route(
            CERTIFICATION_DISPUTE_PATH,
            post(handle_dispute_certification),
        )
        .route(
            PUBLIC_CERTIFICATION_METADATA_PATH,
            get(handle_public_certification_metadata),
        )
        .route(
            PUBLIC_CERTIFICATION_RESOLVE_PATH,
            get(handle_public_resolve_certification),
        )
        .route(
            PUBLIC_CERTIFICATION_SEARCH_PATH,
            get(handle_public_search_certifications),
        )
        .route(
            PUBLIC_CERTIFICATION_TRANSPARENCY_PATH,
            get(handle_public_certification_transparency),
        )
        .route(
            PUBLIC_GENERIC_NAMESPACE_PATH,
            get(handle_public_generic_namespace),
        )
        .route(
            PUBLIC_GENERIC_LISTINGS_PATH,
            get(handle_public_generic_listings),
        )
        .route(
            GENERIC_TRUST_ACTIVATION_ISSUE_PATH,
            post(handle_issue_generic_trust_activation),
        )
        .route(
            GENERIC_TRUST_ACTIVATION_EVALUATE_PATH,
            post(handle_evaluate_generic_trust_activation),
        )
        .route(
            GENERIC_GOVERNANCE_CHARTER_ISSUE_PATH,
            post(handle_issue_generic_governance_charter),
        )
        .route(
            GENERIC_GOVERNANCE_CASE_ISSUE_PATH,
            post(handle_issue_generic_governance_case),
        )
        .route(
            GENERIC_GOVERNANCE_CASE_EVALUATE_PATH,
            post(handle_evaluate_generic_governance_case),
        )
        .merge(finding_market_routes())
        .route(
            OPEN_MARKET_FEE_SCHEDULE_ISSUE_PATH,
            post(handle_issue_open_market_fee_schedule),
        )
        .route(
            OPEN_MARKET_PENALTY_ISSUE_PATH,
            post(handle_issue_open_market_penalty),
        )
        .route(
            OPEN_MARKET_PENALTY_EVALUATE_PATH,
            post(handle_evaluate_open_market_penalty),
        )
        .route(
            FISCAL_RUNTIME_STATUS_PATH,
            get(handle_fiscal_runtime_status),
        )
        .route(FISCAL_PROPOSALS_PATH, post(handle_fiscal_proposal_persist))
        .route(
            FISCAL_PROPOSAL_ADMIT_PATH,
            post(handle_fiscal_proposal_admit),
        )
        .route(FISCAL_APPROVALS_PATH, post(handle_fiscal_approval_persist))
        .route(
            FISCAL_ACTIVATIONS_PATH,
            post(handle_fiscal_activation_commit),
        )
        .route(FISCAL_RESOLVE_PATH, post(handle_fiscal_resolve))
        .route(
            FISCAL_MARKETPLACE_PRICE_PATH,
            post(handle_fiscal_marketplace_price),
        )
        .route(
            FISCAL_MARKETPLACE_CREDIT_LIMIT_PATH,
            post(handle_fiscal_marketplace_credit_limit),
        )
        .route(
            FISCAL_PROPOSAL_PREVIEW_PATH,
            post(handle_fiscal_proposal_preview),
        )
        .route(
            PASSPORT_ISSUER_METADATA_PATH,
            get(handle_passport_issuer_metadata),
        )
        .route(
            PUBLIC_PASSPORT_ISSUER_DISCOVERY_PATH,
            get(handle_public_passport_issuer_discovery),
        )
        .route(
            PUBLIC_PASSPORT_VERIFIER_DISCOVERY_PATH,
            get(handle_public_passport_verifier_discovery),
        )
        .route(
            PUBLIC_PASSPORT_DISCOVERY_TRANSPARENCY_PATH,
            get(handle_public_passport_discovery_transparency),
        )
        .route(PASSPORT_ISSUER_JWKS_PATH, get(handle_passport_issuer_jwks))
        .route(
            PASSPORT_SD_JWT_TYPE_METADATA_PATH,
            get(handle_passport_sd_jwt_type_metadata),
        )
        .route(
            CHIO_PASSPORT_JWT_VC_JSON_TYPE_METADATA_PATH,
            get(handle_passport_jwt_vc_json_type_metadata),
        )
        .route(
            PASSPORT_ISSUANCE_OFFERS_PATH,
            post(handle_create_passport_issuance_offer),
        )
        .route(
            PASSPORT_ISSUANCE_TOKEN_PATH,
            post(handle_redeem_passport_issuance_token),
        )
        .route(
            PASSPORT_ISSUANCE_CREDENTIAL_PATH,
            post(handle_redeem_passport_issuance_credential),
        )
        .route(
            PASSPORT_STATUSES_PATH,
            get(handle_list_passport_statuses).post(handle_publish_passport_status),
        )
        .route(PASSPORT_STATUS_PATH, get(handle_get_passport_status))
        .route(
            PASSPORT_STATUS_RESOLVE_PATH,
            get(handle_resolve_passport_status),
        )
        .route(
            PUBLIC_PASSPORT_STATUS_RESOLVE_PATH,
            get(handle_public_resolve_passport_status),
        )
        .route(
            PASSPORT_STATUS_REVOKE_PATH,
            post(handle_revoke_passport_status),
        )
        .route(
            PASSPORT_VERIFIER_POLICIES_PATH,
            get(handle_list_verifier_policies),
        )
        .route(
            PASSPORT_VERIFIER_POLICY_PATH,
            get(handle_get_verifier_policy)
                .put(handle_upsert_verifier_policy)
                .delete(handle_delete_verifier_policy),
        )
        .route(
            PASSPORT_CHALLENGES_PATH,
            post(handle_create_passport_challenge),
        )
        .route(
            PASSPORT_CHALLENGE_VERIFY_PATH,
            post(handle_verify_passport_challenge),
        )
        .route(
            PUBLIC_PASSPORT_CHALLENGE_PATH,
            get(handle_public_get_passport_challenge),
        )
        .route(
            PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH,
            post(handle_public_verify_passport_challenge),
        )
        .route(
            OID4VP_VERIFIER_METADATA_PATH,
            get(handle_oid4vp_verifier_metadata),
        )
        .route(
            PASSPORT_OID4VP_REQUESTS_PATH,
            post(handle_create_oid4vp_request),
        )
        .route(
            PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH,
            get(handle_public_get_wallet_exchange),
        )
        .route(
            PUBLIC_PASSPORT_OID4VP_REQUEST_PATH,
            get(handle_public_get_oid4vp_request),
        )
        .route(
            PUBLIC_PASSPORT_OID4VP_LAUNCH_PATH,
            get(handle_public_launch_oid4vp_request),
        )
        .route(
            PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH,
            post(handle_public_submit_oid4vp_response),
        )
        .route(
            REVOCATIONS_PATH,
            get(handle_list_revocations).post(handle_revoke_capability),
        )
        .route(
            TOOL_RECEIPTS_PATH,
            get(handle_list_tool_receipts)
                .post(handle_append_tool_receipt)
                .layer(DefaultBodyLimit::max(RECEIPT_APPEND_MAX_BODY_BYTES)),
        )
        .route(
            CHILD_RECEIPTS_PATH,
            get(handle_list_child_receipts)
                .post(handle_append_child_receipt)
                .layer(DefaultBodyLimit::max(RECEIPT_APPEND_MAX_BODY_BYTES)),
        )
        .route(BUDGETS_PATH, get(handle_list_budgets))
        .route(BUDGET_INCREMENT_PATH, post(handle_try_increment_budget))
        .route(BUDGET_AUTHORIZE_EXPOSURE_PATH, post(handle_try_charge_cost))
        .route(
            BUDGET_CAPTURE_INVOCATION_PATH,
            post(handle_capture_invocation),
        )
        .route(
            BUDGET_RELEASE_EXPOSURE_PATH,
            post(handle_reverse_charge_cost),
        )
        .route(BUDGET_RECONCILE_SPEND_PATH, post(handle_reduce_charge_cost))
        .route(
            STRUCTURED_BUDGET_AUTHORIZE_PATH,
            post(handle_structured_budget_authorize),
        )
        .route(
            STRUCTURED_BUDGET_AUTHORIZE_CUMULATIVE_PATH,
            post(handle_structured_budget_authorize_cumulative),
        )
        .route(
            STRUCTURED_BUDGET_CUMULATIVE_OPERATION_PATH,
            post(handle_structured_budget_cumulative_operation),
        )
        .route(
            STRUCTURED_BUDGET_CANCEL_CAPTURED_PATH,
            post(handle_structured_budget_cancel_captured),
        )
        .route(
            STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH,
            post(handle_structured_budget_capture_invocation),
        )
        .route(
            STRUCTURED_BUDGET_FENCED_REVERSE_PATH,
            post(handle_structured_budget_reverse),
        )
        .route(
            STRUCTURED_BUDGET_RELEASE_PATH,
            post(handle_structured_budget_release),
        )
        .route(
            STRUCTURED_BUDGET_RECONCILE_PATH,
            post(handle_structured_budget_reconcile),
        )
        .route(
            STRUCTURED_BUDGET_CAPTURE_SPEND_PATH,
            post(handle_structured_budget_capture_spend),
        )
        .route(
            INTERNAL_CLUSTER_STATUS_PATH,
            get(handle_internal_cluster_status),
        )
        .route(
            INTERNAL_CLUSTER_SNAPSHOT_PATH,
            get(handle_internal_cluster_snapshot),
        )
        .route(
            INTERNAL_CLUSTER_PARTITION_PATH,
            post(handle_internal_cluster_partition),
        )
        .route(
            INTERNAL_AUTHORITY_SNAPSHOT_PATH,
            get(handle_internal_authority_snapshot),
        )
        .route(
            INTERNAL_REVOCATIONS_DELTA_PATH,
            get(handle_internal_revocations_delta),
        )
        .route(
            INTERNAL_TOOL_RECEIPTS_DELTA_PATH,
            get(handle_internal_tool_receipts_delta),
        )
        .route(
            INTERNAL_CHILD_RECEIPTS_DELTA_PATH,
            get(handle_internal_child_receipts_delta),
        )
        .route(
            INTERNAL_BUDGETS_DELTA_PATH,
            get(handle_internal_budgets_delta),
        )
        .route(
            INTERNAL_LINEAGE_DELTA_PATH,
            get(handle_internal_lineage_delta),
        )
        .route(RECEIPT_QUERY_PATH, get(handle_query_receipts))
        .route(RECEIPT_ANALYTICS_PATH, get(handle_receipt_analytics))
        .route(EVIDENCE_EXPORT_PATH, post(handle_evidence_export))
        .route(
            EVIDENCE_IMPORT_PATH,
            post(handle_evidence_import)
                .layer(DefaultBodyLimit::max(EVIDENCE_IMPORT_MAX_BODY_BYTES)),
        )
        .route(
            FEDERATION_EVIDENCE_SHARES_PATH,
            get(handle_shared_evidence_report),
        )
        .route(COST_ATTRIBUTION_PATH, get(handle_cost_attribution_report))
        .route(OPERATOR_REPORT_PATH, get(handle_operator_report))
        .route(
            COMPTROLLER_SURFACE_PATH,
            get(handle_comptroller_surface_report),
        )
        .route(
            RUNTIME_ATTESTATION_APPRAISAL_PATH,
            post(handle_runtime_attestation_appraisal_report),
        )
        .route(
            RUNTIME_ATTESTATION_APPRAISAL_RESULT_PATH,
            post(handle_runtime_attestation_appraisal_result_export),
        )
        .route(
            RUNTIME_ATTESTATION_APPRAISAL_IMPORT_PATH,
            post(handle_runtime_attestation_appraisal_import),
        )
        .route(BEHAVIORAL_FEED_PATH, get(handle_behavioral_feed_report))
        .route(EXPOSURE_LEDGER_PATH, get(handle_exposure_ledger_report))
        .route(CREDIT_SCORECARD_PATH, get(handle_credit_scorecard_report))
        .route(CAPITAL_BOOK_PATH, get(handle_capital_book_report))
        .route(
            CAPITAL_INSTRUCTION_ISSUE_PATH,
            post(handle_issue_capital_execution_instruction),
        )
        .route(
            CAPITAL_ALLOCATION_ISSUE_PATH,
            post(handle_issue_capital_allocation_decision),
        )
        .route(
            CREDIT_FACILITY_REPORT_PATH,
            get(handle_credit_facility_report),
        )
        .route(
            CREDIT_FACILITY_ISSUE_PATH,
            post(handle_issue_credit_facility),
        )
        .route(
            CREDIT_FACILITIES_REPORT_PATH,
            get(handle_query_credit_facilities),
        )
        .route(CREDIT_BOND_REPORT_PATH, get(handle_credit_bond_report))
        .route(CREDIT_BOND_ISSUE_PATH, post(handle_issue_credit_bond))
        .route(CREDIT_BONDS_REPORT_PATH, get(handle_query_credit_bonds))
        .route(
            CREDIT_BONDED_EXECUTION_SIMULATION_PATH,
            post(handle_credit_bonded_execution_simulation_report),
        )
        .route(
            CREDIT_LOSS_LIFECYCLE_REPORT_PATH,
            get(handle_credit_loss_lifecycle_report),
        )
        .route(
            CREDIT_LOSS_LIFECYCLE_ISSUE_PATH,
            post(handle_issue_credit_loss_lifecycle),
        )
        .route(
            CREDIT_LOSS_LIFECYCLE_LIST_PATH,
            get(handle_query_credit_loss_lifecycle),
        )
        .route(CREDIT_BACKTEST_PATH, get(handle_credit_backtest_report))
        .route(
            CREDIT_PROVIDER_RISK_PACKAGE_PATH,
            get(handle_credit_provider_risk_package_report),
        )
        .route(
            LIABILITY_PROVIDER_ISSUE_PATH,
            post(handle_issue_liability_provider),
        )
        .route(
            LIABILITY_PROVIDERS_REPORT_PATH,
            get(handle_query_liability_providers),
        )
        .route(
            LIABILITY_PROVIDER_RESOLVE_PATH,
            get(handle_resolve_liability_provider),
        )
        .route(
            LIABILITY_QUOTE_REQUEST_ISSUE_PATH,
            post(handle_issue_liability_quote_request),
        )
        .route(
            LIABILITY_QUOTE_RESPONSE_ISSUE_PATH,
            post(handle_issue_liability_quote_response),
        )
        .route(
            LIABILITY_PRICING_AUTHORITY_ISSUE_PATH,
            post(handle_issue_liability_pricing_authority),
        )
        .route(
            LIABILITY_PLACEMENT_ISSUE_PATH,
            post(handle_issue_liability_placement),
        )
        .route(
            LIABILITY_BOUND_COVERAGE_ISSUE_PATH,
            post(handle_issue_liability_bound_coverage),
        )
        .route(
            LIABILITY_AUTO_BIND_DECISION_ISSUE_PATH,
            post(handle_issue_liability_auto_bind),
        )
        .route(
            LIABILITY_MARKET_WORKFLOW_REPORT_PATH,
            get(handle_query_liability_market_workflows),
        )
        .route(
            LIABILITY_CLAIM_PACKAGE_ISSUE_PATH,
            post(handle_issue_liability_claim_package),
        )
        .route(
            LIABILITY_CLAIM_RESPONSE_ISSUE_PATH,
            post(handle_issue_liability_claim_response),
        )
        .route(
            LIABILITY_CLAIM_DISPUTE_ISSUE_PATH,
            post(handle_issue_liability_claim_dispute),
        )
        .route(
            LIABILITY_CLAIM_ADJUDICATION_ISSUE_PATH,
            post(handle_issue_liability_claim_adjudication),
        )
        .route(
            LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ISSUE_PATH,
            post(handle_issue_liability_claim_payout_instruction),
        )
        .route(
            LIABILITY_CLAIM_PAYOUT_RECEIPT_ISSUE_PATH,
            post(handle_issue_liability_claim_payout_receipt),
        )
        .route(
            LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ISSUE_PATH,
            post(handle_issue_liability_claim_settlement_instruction),
        )
        .route(
            LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ISSUE_PATH,
            post(handle_issue_liability_claim_settlement_receipt),
        )
        .route(
            LIABILITY_CLAIM_WORKFLOW_REPORT_PATH,
            get(handle_query_liability_claim_workflows),
        )
        .route(SETTLEMENT_REPORT_PATH, get(handle_settlement_report))
        .route(
            SETTLEMENT_RECONCILE_PATH,
            post(handle_record_settlement_reconciliation),
        )
        .route(
            METERED_BILLING_REPORT_PATH,
            get(handle_metered_billing_report),
        )
        .route(
            METERED_BILLING_RECONCILE_PATH,
            post(handle_record_metered_billing_reconciliation),
        )
        .route(
            ECONOMIC_RECEIPT_REPORT_PATH,
            get(handle_economic_receipt_report),
        )
        .route(
            ECONOMIC_COMPLETION_FLOW_REPORT_PATH,
            get(handle_economic_completion_flow_report),
        )
        .route(
            AUTHORIZATION_CONTEXT_REPORT_PATH,
            get(handle_authorization_context_report),
        )
        .route(
            AUTHORIZATION_PROFILE_METADATA_PATH,
            get(handle_authorization_profile_metadata_report),
        )
        .route(
            AUTHORIZATION_REVIEW_PACK_PATH,
            get(handle_authorization_review_pack_report),
        )
        .route(
            UNDERWRITING_INPUT_PATH,
            get(handle_underwriting_policy_input),
        )
        .route(
            UNDERWRITING_DECISION_PATH,
            get(handle_underwriting_decision_report),
        )
        .route(
            UNDERWRITING_SIMULATION_PATH,
            post(handle_underwriting_simulation_report),
        )
        .route(
            UNDERWRITING_DECISIONS_REPORT_PATH,
            get(handle_query_underwriting_decisions),
        )
        .route(
            UNDERWRITING_DECISION_ISSUE_PATH,
            post(handle_issue_underwriting_decision),
        )
        .route(
            UNDERWRITING_APPEALS_PATH,
            post(handle_create_underwriting_appeal),
        )
        .route(
            UNDERWRITING_APPEAL_RESOLVE_PATH,
            post(handle_resolve_underwriting_appeal),
        )
        .route(LOCAL_REPUTATION_PATH, get(handle_local_reputation))
        .route(REPUTATION_COMPARE_PATH, post(handle_reputation_compare))
        .route(
            PORTABLE_REPUTATION_SUMMARY_ISSUE_PATH,
            post(handle_issue_portable_reputation_summary),
        )
        .route(
            PORTABLE_NEGATIVE_EVENT_ISSUE_PATH,
            post(handle_issue_portable_negative_event),
        )
        .route(
            PORTABLE_REPUTATION_EVALUATE_PATH,
            post(handle_evaluate_portable_reputation),
        )
        .route(LINEAGE_RECORD_PATH, post(handle_record_lineage_snapshot))
        .route(LINEAGE_PATH, get(handle_get_lineage))
        .route(LINEAGE_CHAIN_PATH, get(handle_get_delegation_chain))
        .route(AGENT_RECEIPTS_PATH, get(handle_agent_receipts))
        // Prometheus scrape endpoint, composed from the kernel guard families and
        // the alert-pack families. Inherits the same serving posture as the other
        // trust-control routes.
        .route("/metrics", get(handle_trust_control_metrics));

    // Wire the dashboard SPA after all API routes so it acts as a catch-all.
    // API routes registered above take priority over the fallback service.
    // The conditional avoids a hard startup failure when the dashboard has not
    // been built (e.g. in CI or API-only deployments).
    let dashboard_dir = std::path::Path::new(DASHBOARD_DIST_DIR);
    let router = if dashboard_dir.join("index.html").exists() {
        let spa_fallback = ServeFile::new(dashboard_dir.join("index.html"));
        let spa_service = ServeDir::new(dashboard_dir).not_found_service(spa_fallback);
        router.fallback_service(spa_service)
    } else {
        warn!(
            "dashboard/dist/index.html not found -- dashboard UI will not be served. \
             Run 'npm run build' in crates/products/chio-cli/dashboard/ to enable."
        );
        router
    };

    let router = router.with_state(state);

    // Dashboard SPA is served from the same origin via ServeDir -- no CORS
    // headers needed.

    // Apply Content-Security-Policy to every response to restrict resource
    // loading to same-origin and prevent XSS escalation.
    let csp_value = HeaderValue::from_static(CSP_VALUE);
    router.layer(SetResponseHeaderLayer::overriding(
        axum::http::header::CONTENT_SECURITY_POLICY,
        csp_value,
    ))
}

/// Prometheus scrape body for the trust-control surface: the kernel guard
/// families plus the alert-pack families, composed (never fabricated) from the
/// chio-metrics-spec runtime families.
///
/// The route shares the trust-control listener, which binds `config.listen` and
/// may be externally reachable, so it fails closed: it requires the SAME
/// service-token bearer auth the authority/receipt/passport/budget routes
/// enforce before returning operational counters and guard labels. Prometheus
/// scrapes it with a configured bearer token.
async fn handle_trust_control_metrics(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = super::super::report_validation::validate_service_auth(
        &headers,
        &state.config.service_token,
    ) {
        return response;
    }
    let alert_pack = || {
        let mut out = String::new();
        chio_metrics_spec::runtime::render_alert_pack_families(&mut out);
        out
    };
    let body = chio_metrics_spec::runtime::compose_metrics_body(&[
        &chio_kernel::render_guard_metrics_prometheus,
        &alert_pack,
    ]);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}

/// Cognition-market finding routes. Publish takes a
/// tighter body cap than the service-wide limit; dependency uploads keep
/// the 1 MiB bound. Feature-off builds get an empty router here.
#[cfg(feature = "cognition-market-experimental")]
fn finding_market_routes() -> Router<TrustServiceState> {
    Router::new()
        .route(
            FINDINGS_PUBLISH_PATH,
            post(handle_publish_finding)
                .layer(DefaultBodyLimit::max(FINDING_PUBLISH_MAX_BODY_BYTES)),
        )
        .route(FINDING_PATH, get(handle_get_finding))
        .route(
            FINDINGS_SEARCH_PATH,
            get(handle_search_findings_get).post(handle_search_findings_post),
        )
        .route(
            FINDINGS_RECIPES_PATH,
            post(handle_upload_finding_dependency)
                .layer(DefaultBodyLimit::max(FINDING_DEPENDENCY_MAX_BODY_BYTES)),
        )
        .route(
            FINDINGS_PROFILES_PATH,
            post(handle_register_finding_profile)
                .layer(DefaultBodyLimit::max(FINDING_DEPENDENCY_MAX_BODY_BYTES)),
        )
        .route(
            FINDINGS_COLLATERAL_PATH,
            post(handle_register_finding_collateral),
        )
        .route(FINDING_ACTIVATE_PATH, post(handle_activate_finding))
        .route(
            FINDING_PARTICIPATION_PATH,
            post(handle_finding_participation),
        )
        .route(FINDING_ADMISSION_PATH, get(handle_get_finding_admission))
        .route(
            FINDING_PURCHASE_PATH,
            post(handle_purchase_finding)
                .layer(DefaultBodyLimit::max(FINDING_PURCHASE_MAX_BODY_BYTES)),
        )
}

#[cfg(not(feature = "cognition-market-experimental"))]
fn finding_market_routes() -> Router<TrustServiceState> {
    Router::new()
}

#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;

#[cfg(all(test, feature = "cognition-market-experimental"))]
#[path = "finding_market_exit_tests.rs"]
mod finding_market_exit_tests;

#[cfg(all(test, feature = "cognition-market-experimental"))]
#[path = "finding_wedge_purchase_e2e_tests.rs"]
mod finding_wedge_purchase_e2e_tests;

#[cfg(all(test, feature = "cognition-market-experimental"))]
#[path = "finding_challenge_enforcement_e2e_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod finding_challenge_enforcement_e2e_tests;
