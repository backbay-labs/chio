#[path = "service_runtime/budget.rs"]
pub mod budget;
#[path = "service_runtime/client.rs"]
pub mod client;
#[path = "service_runtime/errors.rs"]
mod errors;
#[path = "service_runtime/issuance.rs"]
pub mod issuance;
#[path = "service_runtime/public_registry.rs"]
pub mod public_registry;
#[path = "service_runtime/remote_authority.rs"]
pub mod remote_authority;
#[path = "service_runtime/remote_stores.rs"]
pub mod remote_stores;
#[path = "service_runtime/reputation.rs"]
pub mod reputation;

use super::*;

pub(crate) async fn serve_async(config: TrustServiceConfig) -> Result<(), CliError> {
    config.validate()?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let enterprise_provider_registry = load_enterprise_provider_registry(
        config.enterprise_providers_file.as_deref(),
        "trust_control",
    )?;
    let verifier_policy_registry =
        load_verifier_policy_registry(config.verifier_policies_file.as_deref(), "trust_control")?;
    let cluster = build_cluster_state(&config, local_addr)?;
    let state = TrustServiceState {
        config,
        enterprise_provider_registry,
        verifier_policy_registry,
        federation_admission_rate_limiter: Arc::new(Mutex::new(
            FederationAdmissionRateLimiter::default(),
        )),
        cluster,
    };
    if state.cluster.is_some() {
        tokio::spawn(run_cluster_sync_loop(state.clone()));
    }
    let router = trust_control_health::install_health_routes(Router::new())
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
            get(handle_list_tool_receipts).post(handle_append_tool_receipt),
        )
        .route(
            CHILD_RECEIPTS_PATH,
            get(handle_list_child_receipts).post(handle_append_child_receipt),
        )
        .route(BUDGETS_PATH, get(handle_list_budgets))
        .route(BUDGET_INCREMENT_PATH, post(handle_try_increment_budget))
        .route(BUDGET_AUTHORIZE_EXPOSURE_PATH, post(handle_try_charge_cost))
        .route(
            BUDGET_RELEASE_EXPOSURE_PATH,
            post(handle_reverse_charge_cost),
        )
        .route(BUDGET_RECONCILE_SPEND_PATH, post(handle_reduce_charge_cost))
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
        .route(EVIDENCE_IMPORT_PATH, post(handle_evidence_import))
        .route(
            FEDERATION_EVIDENCE_SHARES_PATH,
            get(handle_shared_evidence_report),
        )
        .route(COST_ATTRIBUTION_PATH, get(handle_cost_attribution_report))
        .route(OPERATOR_REPORT_PATH, get(handle_operator_report))
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
        .route(AGENT_RECEIPTS_PATH, get(handle_agent_receipts));

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
             Run 'npm run build' in crates/chio-cli/dashboard/ to enable."
        );
        router
    };

    let router = router.with_state(state);

    // Dashboard SPA is served from the same origin via ServeDir -- no CORS
    // headers needed. If the dashboard is ever served from a separate origin,
    // add tower-http CorsLayer.

    // Apply Content-Security-Policy to every response to restrict resource
    // loading to same-origin and prevent XSS escalation.
    let csp_value = HeaderValue::from_static(CSP_VALUE);
    let router = router.layer(SetResponseHeaderLayer::overriding(
        axum::http::header::CONTENT_SECURITY_POLICY,
        csp_value,
    ));

    info!(listen_addr = %local_addr, "serving Chio trust control service");
    eprintln!("Chio trust control service listening on http://{local_addr}");

    axum::serve(listener, router).await.map_err(|error| {
        CliError::cli_other_error(format!("trust control service failed: {error}"))
    })
}

#[cfg(test)]
mod service_runtime_tests {
    use super::budget::build_remote_budget_store;
    use super::client::{
        build_client, build_public_client, certification_marketplace_search_path,
        certification_marketplace_transparency_path, encode_path_segment, path_with_encoded_param,
        should_retry_status,
    };
    use super::errors::{
        into_budget_store_error, into_receipt_store_error, into_revocation_store_error,
    };
    use super::issuance::ensure_signed_by_trusted_authority;
    use super::*;
    use chio_test_support::prelude::*;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CapturedRequest {
        method: String,
        target: String,
        headers: BTreeMap<String, String>,
        body: String,
    }

    struct StaticResponseServer {
        url: String,
        captured: Arc<Mutex<Vec<CapturedRequest>>>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl StaticResponseServer {
        fn spawn(status: u16, body: &str, content_type: &str, expected_requests: usize) -> Self {
            let listener =
                TcpListener::bind("127.0.0.1:0").test_expect("bind static response server");
            let addr = listener.local_addr().test_expect("server local addr");
            let body = body.to_string();
            let content_type = content_type.to_string();
            let captured = Arc::new(Mutex::new(Vec::new()));
            let captured_requests = Arc::clone(&captured);
            let join = thread::spawn(move || {
                for _ in 0..expected_requests {
                    let (mut stream, _) = listener.accept().test_expect("accept request");
                    let request = read_http_request(&mut stream);
                    captured_requests
                        .lock()
                        .test_expect("capture request")
                        .push(request);
                    write!(
                        stream,
                        "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .test_expect("write response");
                    stream.flush().test_expect("flush response");
                }
            });
            Self {
                url: format!("http://{addr}"),
                captured,
                join: Some(join),
            }
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.captured
                .lock()
                .test_expect("captured requests")
                .clone()
        }
    }

    impl Drop for StaticResponseServer {
        fn drop(&mut self) {
            if let Some(join) = self.join.take() {
                join.join().test_expect("join response server");
            }
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> CapturedRequest {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut headers_end = None;
        let mut content_length = 0usize;
        loop {
            let read = stream.read(&mut chunk).test_expect("read HTTP request");
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if headers_end.is_none() {
                if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                    headers_end = Some(position + 4);
                    content_length =
                        parse_content_length(&String::from_utf8_lossy(&buffer[..position + 4]));
                }
            }
            if let Some(headers_end) = headers_end {
                if buffer.len() >= headers_end + content_length {
                    break;
                }
            }
        }

        let headers_end = headers_end.test_expect("HTTP request headers terminator");
        let header_text = String::from_utf8_lossy(&buffer[..headers_end]);
        let mut lines = header_text.split("\r\n").filter(|line| !line.is_empty());
        let request_line = lines.next().test_expect("request line");
        let mut request_line_parts = request_line.split_whitespace();
        let method = request_line_parts
            .next()
            .test_expect("request method")
            .to_string();
        let target = request_line_parts
            .next()
            .test_expect("request target")
            .to_string();
        let headers = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
            })
            .collect::<BTreeMap<_, _>>();
        let body = String::from_utf8_lossy(&buffer[headers_end..]).to_string();

        CapturedRequest {
            method,
            target,
            headers,
            body,
        }
    }

    fn parse_content_length(headers: &str) -> usize {
        headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.trim().eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn assert_bearer_request(
        request: &CapturedRequest,
        method: &str,
        path_prefix: &str,
        fragments: &[&str],
    ) {
        assert_eq!(request.method, method);
        assert!(
            request.target.starts_with(path_prefix),
            "unexpected target: {}",
            request.target
        );
        for fragment in fragments {
            assert!(
                request.target.contains(fragment),
                "expected `{}` in target `{}`",
                fragment,
                request.target
            );
        }
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer secret")
        );
    }

    fn assert_json_post(request: &CapturedRequest, path: &str, body_fragments: &[&str]) {
        assert_bearer_request(request, "POST", path, &[]);
        let content_type = request
            .headers
            .get("content-type")
            .test_expect("content-type header");
        assert!(content_type.starts_with("application/json"));
        for fragment in body_fragments {
            assert!(
                request.body.contains(fragment),
                "expected `{}` in body `{}`",
                fragment,
                request.body
            );
        }
    }

    #[test]
    fn build_client_rejects_empty_control_url_and_normalizes_endpoints() {
        let error = match build_client(" , , ", "token") {
            Ok(_) => panic!("empty control URL should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("control URL must not be empty"));

        let client = build_client(" http://one/ , http://two// ,,", "secret")
            .test_expect("build client with normalized endpoints");
        assert_eq!(
            client.endpoints.as_ref(),
            &vec!["http://one".to_string(), "http://two".to_string()]
        );
        assert_eq!(client.endpoint_order(), vec![0, 1]);

        client.mark_preferred(1);
        assert_eq!(client.endpoint_order(), vec![1, 0]);
    }

    #[test]
    fn build_client_rejects_blank_or_padded_control_token() {
        for token in ["", "   ", " secret", "secret "] {
            let error = match build_client("http://control.example.test", token) {
                Ok(_) => panic!("blank or padded control token should fail"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("control token"),
                "unexpected error for token `{token:?}`: {error}",
            );
        }
    }

    #[test]
    fn build_public_client_allows_empty_token_for_public_endpoints_and_keeps_endpoint_validation() {
        let client = build_public_client(" http://one/ , http://two// ,,")
            .test_expect("build public client with normalized endpoints");
        assert_eq!(
            client.endpoints.as_ref(),
            &vec!["http://one".to_string(), "http://two".to_string()]
        );
        assert_eq!(client.token.as_ref(), "");

        for endpoint in [
            " , , ",
            "not-a-url",
            "https://user:pass@control.example.test",
            "https://control.example.test?token=secret",
            "https://control.example.test#fragment",
        ] {
            let error = match build_public_client(endpoint) {
                Ok(_) => panic!("malformed or ambiguous public control endpoint should fail"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("control URL"),
                "unexpected error for public endpoint `{endpoint}`: {error}",
            );
        }
    }

    #[test]
    fn build_client_rejects_malformed_or_ambient_authority_endpoints() {
        for endpoint in [
            "not-a-url",
            "file:///tmp/chio.sock",
            "https://user:pass@control.example.test",
            "https://control.example.test?token=secret",
            "https://control.example.test#fragment",
        ] {
            let error = match build_client(endpoint, "secret") {
                Ok(_) => panic!("malformed or ambiguous control endpoint should fail"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("control URL"),
                "unexpected error for endpoint `{endpoint}`: {error}",
            );
        }
    }

    #[test]
    fn path_helpers_encode_segments_and_certification_paths() {
        assert_eq!(encode_path_segment("a/b c"), "a%2Fb%20c");
        assert_eq!(
            path_with_encoded_param("/v1/items/{item_id}", "item_id", "alpha/beta"),
            "/v1/items/alpha%2Fbeta"
        );

        let search_path =
            certification_marketplace_search_path(&CertificationMarketplaceSearchQuery {
                filters: CertificationPublicSearchQuery {
                    tool_server_id: Some("tool/server".to_string()),
                    criteria_profile: None,
                    evidence_profile: None,
                    status: Some(CertificationRegistryState::Active),
                },
                operator_ids: Some("alpha,beta".to_string()),
            });
        assert!(search_path.starts_with(CERTIFICATION_DISCOVERY_SEARCH_PATH));
        assert!(search_path.contains("toolServerId=tool%2Fserver"));
        assert!(search_path.contains("status=active"));
        assert!(search_path.contains("operatorIds=alpha%2Cbeta"));

        let transparency_path = certification_marketplace_transparency_path(
            &CertificationMarketplaceTransparencyQuery {
                filters: CertificationTransparencyQuery {
                    tool_server_id: Some("tool/server".to_string()),
                },
                operator_ids: Some("alpha,beta".to_string()),
            },
        );
        assert!(transparency_path.starts_with(CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH));
        assert!(transparency_path.contains("toolServerId=tool%2Fserver"));
        assert!(transparency_path.contains("operatorIds=alpha%2Cbeta"));
    }

    #[test]
    fn request_json_retries_retryable_status_and_marks_preferred_endpoint() {
        let retry =
            StaticResponseServer::spawn(503, "{\"error\":\"retry\"}", "application/json", 1);
        let success = StaticResponseServer::spawn(200, "{\"ok\":true}", "application/json", 1);
        let client = build_client(&format!("{},{}", retry.url, success.url), "secret")
            .test_expect("build failover client");

        let response: Value = client
            .request_json(
                |agent, url, token| {
                    assert_eq!(token, "secret");
                    agent
                        .get(url)
                        .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                        .call()
                },
                "/status",
            )
            .test_expect("retry to healthy endpoint");

        assert_eq!(response["ok"], Value::Bool(true));
        assert_eq!(client.endpoint_order(), vec![1, 0]);
    }

    #[test]
    fn request_text_without_service_auth_reads_text_response() {
        let server = StaticResponseServer::spawn(200, "ready", "text/plain", 1);
        let client = build_client(&server.url, "secret").test_expect("build text client");

        let body = client
            .request_text_without_service_auth(|agent, url| agent.get(url).call(), "/health")
            .test_expect("read text response");

        assert_eq!(body, "ready");
    }

    #[test]
    fn trust_control_get_wrappers_encode_queries_and_service_auth() {
        let server = StaticResponseServer::spawn(200, "{}", "application/json", 26);
        let client = build_client(&server.url, "secret").test_expect("build client");

        let _ = client.list_revocations(&RevocationQuery {
            capability_id: Some("cap-1".to_string()),
            limit: Some(2),
        });
        let _ = client.list_tool_receipts(&ToolReceiptQuery {
            capability_id: Some("cap-2".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("echo".to_string()),
            decision: Some("allow".to_string()),
            limit: Some(3),
        });
        let _ = client.list_child_receipts(&ChildReceiptQuery {
            session_id: Some("session-1".to_string()),
            parent_request_id: Some("parent-1".to_string()),
            request_id: Some("child-1".to_string()),
            operation_kind: Some("create_message".to_string()),
            terminal_state: Some("completed".to_string()),
            limit: Some(4),
        });
        let _ = client.query_receipts(&ReceiptQueryHttpQuery {
            capability_id: Some("cap-3".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("query".to_string()),
            outcome: Some("allow".to_string()),
            since: Some(10),
            until: Some(20),
            min_cost: Some(1),
            max_cost: Some(9),
            cursor: Some(7),
            limit: Some(5),
            agent_subject: Some("agent-1".to_string()),
        });
        let _ = client.shared_evidence_report(&SharedEvidenceQuery {
            capability_id: Some("cap-4".to_string()),
            agent_subject: Some("agent-2".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("share".to_string()),
            since: Some(30),
            until: Some(40),
            issuer: Some("issuer-1".to_string()),
            partner: Some("partner-1".to_string()),
            limit: Some(6),
            read_context: None,
        });

        let exposure_query = ExposureLedgerQuery {
            capability_id: Some("cap-exposure".to_string()),
            agent_subject: Some("agent-3".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("exposure".to_string()),
            since: Some(50),
            until: Some(60),
            receipt_limit: Some(7),
            decision_limit: Some(8),
        };
        let _ = client.behavioral_feed(&BehavioralFeedQuery {
            capability_id: Some("cap-feed".to_string()),
            agent_subject: Some("agent-3".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("behavior".to_string()),
            since: Some(50),
            until: Some(60),
            receipt_limit: Some(7),
            read_context: None,
        });
        let _ = client.exposure_ledger(&exposure_query);
        let _ = client.credit_scorecard(&exposure_query);
        let _ = client.credit_facility_report(&exposure_query);
        let _ = client.credit_bond_report(&exposure_query);

        let _ = client.capital_book(&CapitalBookQuery {
            capability_id: Some("cap-capital".to_string()),
            agent_subject: Some("agent-4".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("capital".to_string()),
            since: Some(70),
            until: Some(80),
            receipt_limit: Some(9),
            facility_limit: Some(10),
            bond_limit: Some(11),
            loss_event_limit: Some(12),
        });
        let _ = client.list_credit_facilities(&CreditFacilityListQuery {
            facility_id: Some("facility-1".to_string()),
            capability_id: Some("cap-facility".to_string()),
            agent_subject: Some("agent-5".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("facility".to_string()),
            disposition: None,
            lifecycle_state: None,
            limit: Some(13),
        });
        let _ = client.list_credit_bonds(&CreditBondListQuery {
            bond_id: Some("bond-1".to_string()),
            facility_id: Some("facility-1".to_string()),
            capability_id: Some("cap-bond".to_string()),
            agent_subject: Some("agent-6".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("bond".to_string()),
            disposition: None,
            lifecycle_state: None,
            limit: Some(14),
        });
        let _ = client.credit_backtest(&CreditBacktestQuery {
            capability_id: Some("cap-backtest".to_string()),
            agent_subject: Some("agent-7".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("backtest".to_string()),
            since: Some(90),
            until: Some(100),
            receipt_limit: Some(15),
            decision_limit: Some(16),
            window_seconds: Some(120),
            window_count: Some(3),
            stale_after_seconds: Some(240),
        });
        let _ = client.credit_provider_risk_package(&CreditProviderRiskPackageQuery {
            capability_id: Some("cap-provider".to_string()),
            agent_subject: Some("agent-8".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("provider".to_string()),
            since: Some(110),
            until: Some(120),
            receipt_limit: Some(17),
            decision_limit: Some(18),
            recent_loss_limit: Some(4),
        });
        let _ = client.list_liability_providers(&LiabilityProviderListQuery {
            provider_id: Some("provider-1".to_string()),
            jurisdiction: Some("us-ny".to_string()),
            coverage_class: None,
            currency: Some("usd".to_string()),
            lifecycle_state: None,
            limit: Some(19),
        });
        let _ = client.liability_market_workflows(&LiabilityMarketWorkflowQuery {
            quote_request_id: Some("quote-1".to_string()),
            provider_id: Some("provider-2".to_string()),
            agent_subject: Some("agent-9".to_string()),
            jurisdiction: Some("us-ca".to_string()),
            coverage_class: None,
            currency: Some("usd".to_string()),
            limit: Some(20),
        });

        let operator_query = OperatorReportQuery {
            capability_id: Some("cap-operator".to_string()),
            agent_subject: Some("agent-10".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("report".to_string()),
            since: Some(130),
            until: Some(140),
            group_limit: Some(21),
            time_bucket: None,
            attribution_limit: Some(22),
            budget_limit: Some(23),
            settlement_limit: Some(24),
            metered_limit: Some(25),
            authorization_limit: Some(26),
            economic_limit: Some(27),
            read_context: None,
        };
        let _ = client.operator_report(&operator_query);
        let _ = client.metered_billing_report(&operator_query);
        let _ = client.authorization_context_report(&operator_query);
        let _ = client.authorization_profile_metadata();
        let _ = client.authorization_review_pack(&operator_query);

        let underwriting_input_query = UnderwritingPolicyInputQuery {
            capability_id: Some("cap-underwriting".to_string()),
            agent_subject: Some("agent-11".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("underwrite".to_string()),
            since: Some(150),
            until: Some(160),
            receipt_limit: Some(27),
        };
        let _ = client.underwriting_policy_input(&underwriting_input_query);
        let _ = client.underwriting_decision(&underwriting_input_query);
        let _ = client.list_underwriting_decisions(&UnderwritingDecisionQuery {
            decision_id: Some("decision-1".to_string()),
            capability_id: Some("cap-decision".to_string()),
            agent_subject: Some("agent-12".to_string()),
            tool_server: Some("tool/server".to_string()),
            tool_name: Some("decision".to_string()),
            outcome: None,
            lifecycle_state: None,
            appeal_status: None,
            limit: Some(28),
        });
        let _ = client.local_reputation(
            "subject/key 9",
            &LocalReputationQuery {
                since: Some(170),
                until: Some(180),
            },
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 26);
        assert_bearer_request(
            &requests[0],
            "GET",
            REVOCATIONS_PATH,
            &["capabilityId=cap-1", "limit=2"],
        );
        assert_bearer_request(
            &requests[1],
            "GET",
            TOOL_RECEIPTS_PATH,
            &[
                "capabilityId=cap-2",
                "toolServer=tool%2Fserver",
                "toolName=echo",
                "decision=allow",
                "limit=3",
            ],
        );
        assert_bearer_request(
            &requests[2],
            "GET",
            CHILD_RECEIPTS_PATH,
            &[
                "sessionId=session-1",
                "parentRequestId=parent-1",
                "requestId=child-1",
                "operationKind=create_message",
                "terminalState=completed",
                "limit=4",
            ],
        );
        assert_bearer_request(
            &requests[3],
            "GET",
            RECEIPT_QUERY_PATH,
            &[
                "capabilityId=cap-3",
                "toolServer=tool%2Fserver",
                "toolName=query",
                "outcome=allow",
                "since=10",
                "until=20",
                "minCost=1",
                "maxCost=9",
                "cursor=7",
                "limit=5",
                "agentSubject=agent-1",
            ],
        );
        assert_bearer_request(
            &requests[4],
            "GET",
            FEDERATION_EVIDENCE_SHARES_PATH,
            &[
                "capabilityId=cap-4",
                "agentSubject=agent-2",
                "toolServer=tool%2Fserver",
                "toolName=share",
                "issuer=issuer-1",
                "partner=partner-1",
                "limit=6",
            ],
        );
        assert_bearer_request(
            &requests[5],
            "GET",
            BEHAVIORAL_FEED_PATH,
            &[
                "capabilityId=cap-feed",
                "agentSubject=agent-3",
                "toolServer=tool%2Fserver",
                "toolName=behavior",
                "receiptLimit=7",
            ],
        );
        assert_bearer_request(
            &requests[6],
            "GET",
            EXPOSURE_LEDGER_PATH,
            &[
                "capabilityId=cap-exposure",
                "agentSubject=agent-3",
                "toolServer=tool%2Fserver",
                "toolName=exposure",
                "receiptLimit=7",
                "decisionLimit=8",
            ],
        );
        assert_bearer_request(
            &requests[7],
            "GET",
            CREDIT_SCORECARD_PATH,
            &["capabilityId=cap-exposure"],
        );
        assert_bearer_request(
            &requests[8],
            "GET",
            CREDIT_FACILITY_REPORT_PATH,
            &["capabilityId=cap-exposure"],
        );
        assert_bearer_request(
            &requests[9],
            "GET",
            CREDIT_BOND_REPORT_PATH,
            &["capabilityId=cap-exposure"],
        );
        assert_bearer_request(
            &requests[10],
            "GET",
            CAPITAL_BOOK_PATH,
            &[
                "capabilityId=cap-capital",
                "agentSubject=agent-4",
                "receiptLimit=9",
                "facilityLimit=10",
                "bondLimit=11",
                "lossEventLimit=12",
            ],
        );
        assert_bearer_request(
            &requests[11],
            "GET",
            CREDIT_FACILITIES_REPORT_PATH,
            &[
                "facilityId=facility-1",
                "capabilityId=cap-facility",
                "toolServer=tool%2Fserver",
                "limit=13",
            ],
        );
        assert_bearer_request(
            &requests[12],
            "GET",
            CREDIT_BONDS_REPORT_PATH,
            &[
                "bondId=bond-1",
                "facilityId=facility-1",
                "capabilityId=cap-bond",
                "toolServer=tool%2Fserver",
                "limit=14",
            ],
        );
        assert_bearer_request(
            &requests[13],
            "GET",
            CREDIT_BACKTEST_PATH,
            &[
                "capabilityId=cap-backtest",
                "agentSubject=agent-7",
                "windowSeconds=120",
                "windowCount=3",
                "staleAfterSeconds=240",
            ],
        );
        assert_bearer_request(
            &requests[14],
            "GET",
            CREDIT_PROVIDER_RISK_PACKAGE_PATH,
            &[
                "capabilityId=cap-provider",
                "agentSubject=agent-8",
                "recentLossLimit=4",
            ],
        );
        assert_bearer_request(
            &requests[15],
            "GET",
            LIABILITY_PROVIDERS_REPORT_PATH,
            &[
                "providerId=provider-1",
                "jurisdiction=us-ny",
                "currency=usd",
                "limit=19",
            ],
        );
        assert_bearer_request(
            &requests[16],
            "GET",
            LIABILITY_MARKET_WORKFLOW_REPORT_PATH,
            &[
                "quoteRequestId=quote-1",
                "providerId=provider-2",
                "agentSubject=agent-9",
                "jurisdiction=us-ca",
                "currency=usd",
                "limit=20",
            ],
        );
        assert_bearer_request(
            &requests[17],
            "GET",
            OPERATOR_REPORT_PATH,
            &[
                "capabilityId=cap-operator",
                "agentSubject=agent-10",
                "groupLimit=21",
                "authorizationLimit=26",
            ],
        );
        assert_bearer_request(
            &requests[18],
            "GET",
            METERED_BILLING_REPORT_PATH,
            &["meteredLimit=25"],
        );
        assert_bearer_request(
            &requests[19],
            "GET",
            AUTHORIZATION_CONTEXT_REPORT_PATH,
            &["authorizationLimit=26"],
        );
        assert_bearer_request(
            &requests[20],
            "GET",
            AUTHORIZATION_PROFILE_METADATA_PATH,
            &[],
        );
        assert_bearer_request(
            &requests[21],
            "GET",
            AUTHORIZATION_REVIEW_PACK_PATH,
            &["authorizationLimit=26"],
        );
        assert_bearer_request(
            &requests[22],
            "GET",
            UNDERWRITING_INPUT_PATH,
            &[
                "capabilityId=cap-underwriting",
                "agentSubject=agent-11",
                "toolServer=tool%2Fserver",
                "receiptLimit=27",
            ],
        );
        assert_bearer_request(
            &requests[23],
            "GET",
            UNDERWRITING_DECISION_PATH,
            &[
                "capabilityId=cap-underwriting",
                "agentSubject=agent-11",
                "toolServer=tool%2Fserver",
                "receiptLimit=27",
            ],
        );
        assert_bearer_request(
            &requests[24],
            "GET",
            UNDERWRITING_DECISIONS_REPORT_PATH,
            &[
                "decisionId=decision-1",
                "capabilityId=cap-decision",
                "agentSubject=agent-12",
                "toolServer=tool%2Fserver",
                "limit=28",
            ],
        );
        assert_bearer_request(
            &requests[25],
            "GET",
            &path_with_encoded_param(LOCAL_REPUTATION_PATH, "subject_key", "subject/key 9"),
            &["since=170", "until=180"],
        );
    }

    #[test]
    fn trust_control_post_wrappers_send_json_bodies_and_encoded_paths() {
        let server = StaticResponseServer::spawn(200, "{}", "application/json", 7);
        let client = build_client(&server.url, "secret").test_expect("build client");

        let _ = client.issue_credit_facility(&CreditFacilityIssueRequest {
            query: ExposureLedgerQuery {
                capability_id: Some("cap-post-facility".to_string()),
                agent_subject: Some("agent-post".to_string()),
                tool_server: Some("tool/post".to_string()),
                tool_name: Some("facility".to_string()),
                since: Some(200),
                until: Some(210),
                receipt_limit: Some(5),
                decision_limit: Some(6),
            },
            supersedes_facility_id: Some("facility-prev".to_string()),
        });
        let _ = client.issue_credit_bond(&CreditBondIssueRequest {
            query: ExposureLedgerQuery {
                capability_id: Some("cap-post-bond".to_string()),
                agent_subject: Some("agent-post".to_string()),
                tool_server: Some("tool/post".to_string()),
                tool_name: Some("bond".to_string()),
                since: Some(220),
                until: Some(230),
                receipt_limit: Some(7),
                decision_limit: Some(8),
            },
            supersedes_bond_id: Some("bond-prev".to_string()),
        });
        let _ = client.issue_underwriting_decision(&UnderwritingDecisionIssueRequest {
            query: UnderwritingPolicyInputQuery {
                capability_id: Some("cap-post-underwriting".to_string()),
                agent_subject: Some("agent-post".to_string()),
                tool_server: Some("tool/post".to_string()),
                tool_name: Some("underwrite".to_string()),
                since: Some(240),
                until: Some(250),
                receipt_limit: Some(9),
            },
            supersedes_decision_id: Some("decision-prev".to_string()),
        });
        let _ = client.issue_portable_reputation_summary(&PortableReputationSummaryIssueRequest {
            subject_key: "subject-post".to_string(),
            since: Some(260),
            until: Some(270),
            issued_at: Some(280),
            expires_at: Some(290),
            note: Some("summary note".to_string()),
        });
        let _ = client.issue_portable_negative_event(
            &chio_credentials::PortableNegativeEventIssueRequest {
                subject_key: "subject-post".to_string(),
                kind: chio_credentials::PortableNegativeEventKind::FraudSignal,
                severity: 0.9,
                observed_at: 300,
                published_at: Some(310),
                expires_at: Some(320),
                evidence_refs: vec![chio_credentials::PortableNegativeEventEvidenceReference {
                    kind: chio_credentials::PortableNegativeEventEvidenceKind::External,
                    reference_id: "case-1".to_string(),
                    uri: Some("https://issuer.example/cases/1".to_string()),
                    sha256: None,
                }],
                note: Some("negative event".to_string()),
            },
        );
        let _ = client.evaluate_portable_reputation(
            &chio_credentials::PortableReputationEvaluationRequest {
                subject_key: "subject-post".to_string(),
                summaries: Vec::new(),
                negative_events: Vec::new(),
                weighting_profile: chio_credentials::PortableReputationWeightingProfile {
                    profile_id: "profile-1".to_string(),
                    allowed_issuer_operator_ids: vec!["https://issuer.example".to_string()],
                    issuer_weights: BTreeMap::from([("https://issuer.example".to_string(), 1.0)]),
                    max_summary_age_secs: 3600,
                    max_event_age_secs: 3600,
                    reject_probationary: false,
                    negative_event_weight: 0.5,
                    blocking_event_kinds: vec![
                        chio_credentials::PortableNegativeEventKind::FraudSignal,
                    ],
                },
                evaluated_at: Some(330),
            },
        );
        let _ = client.local_reputation(
            "subject/key post",
            &LocalReputationQuery {
                since: Some(340),
                until: Some(350),
            },
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 7);
        assert_json_post(
            &requests[0],
            CREDIT_FACILITY_ISSUE_PATH,
            &[
                "\"supersedesFacilityId\":\"facility-prev\"",
                "\"capabilityId\":\"cap-post-facility\"",
            ],
        );
        assert_json_post(
            &requests[1],
            CREDIT_BOND_ISSUE_PATH,
            &[
                "\"supersedesBondId\":\"bond-prev\"",
                "\"capabilityId\":\"cap-post-bond\"",
            ],
        );
        assert_json_post(
            &requests[2],
            UNDERWRITING_DECISION_ISSUE_PATH,
            &[
                "\"supersedesDecisionId\":\"decision-prev\"",
                "\"capabilityId\":\"cap-post-underwriting\"",
            ],
        );
        assert_json_post(
            &requests[3],
            PORTABLE_REPUTATION_SUMMARY_ISSUE_PATH,
            &[
                "\"subjectKey\":\"subject-post\"",
                "\"note\":\"summary note\"",
            ],
        );
        assert_json_post(
            &requests[4],
            PORTABLE_NEGATIVE_EVENT_ISSUE_PATH,
            &[
                "\"subjectKey\":\"subject-post\"",
                "\"referenceId\":\"case-1\"",
                "\"severity\":0.9",
            ],
        );
        assert_json_post(
            &requests[5],
            PORTABLE_REPUTATION_EVALUATE_PATH,
            &[
                "\"subjectKey\":\"subject-post\"",
                "\"profileId\":\"profile-1\"",
                "\"negativeEventWeight\":0.5",
            ],
        );
        assert_bearer_request(
            &requests[6],
            "GET",
            &path_with_encoded_param(LOCAL_REPUTATION_PATH, "subject_key", "subject/key post"),
            &["since=340", "until=350"],
        );
    }

    #[test]
    fn budget_wrappers_use_split_budget_routes() {
        let server = StaticResponseServer::spawn(200, "{}", "application/json", 3);
        let client = build_client(&server.url, "secret").test_expect("build client");

        let _ = client.try_charge_cost("cap-budget", 2, Some(9), 120, Some(150), Some(900));
        let _ = client.reverse_charge_cost("cap-budget", 2, 120);
        let _ = client.reconcile_budget_spend("cap-budget", 2, 120, 75);

        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert_json_post(
            &requests[0],
            BUDGET_AUTHORIZE_EXPOSURE_PATH,
            &[
                "\"exposureUnits\":120",
                "\"maxExposurePerInvocation\":150",
                "\"maxTotalExposureUnits\":900",
            ],
        );
        assert_json_post(
            &requests[1],
            BUDGET_RELEASE_EXPOSURE_PATH,
            &["\"exposureUnits\":120"],
        );
        assert_json_post(
            &requests[2],
            BUDGET_RECONCILE_SPEND_PATH,
            &[
                "\"authorizedExposureUnits\":120",
                "\"realizedSpendUnits\":75",
                "\"reductionUnits\":45",
            ],
        );
    }

    #[test]
    fn budget_wrappers_include_budget_event_identity_when_provided() {
        let server = StaticResponseServer::spawn(200, "{}", "application/json", 3);
        let client = build_client(&server.url, "secret").test_expect("build client");

        let _ = client.try_charge_cost_with_ids(
            "cap-budget",
            2,
            Some(9),
            120,
            Some(150),
            Some(900),
            Some("hold-budget"),
            Some("hold-budget:authorize"),
        );
        let _ = client.reverse_charge_cost_with_ids(
            "cap-budget",
            2,
            120,
            Some("hold-budget"),
            Some("hold-budget:reverse"),
        );
        let _ = client.reconcile_budget_spend_with_ids(
            "cap-budget",
            2,
            120,
            75,
            Some("hold-budget"),
            Some("hold-budget:reconcile"),
        );

        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert_json_post(
            &requests[0],
            BUDGET_AUTHORIZE_EXPOSURE_PATH,
            &[
                "\"holdId\":\"hold-budget\"",
                "\"eventId\":\"hold-budget:authorize\"",
            ],
        );
        assert_json_post(
            &requests[1],
            BUDGET_RELEASE_EXPOSURE_PATH,
            &[
                "\"holdId\":\"hold-budget\"",
                "\"eventId\":\"hold-budget:reverse\"",
            ],
        );
        assert_json_post(
            &requests[2],
            BUDGET_RECONCILE_SPEND_PATH,
            &[
                "\"holdId\":\"hold-budget\"",
                "\"eventId\":\"hold-budget:reconcile\"",
            ],
        );
    }

    #[test]
    fn budget_usage_view_round_trips_split_and_aggregate_fields() {
        let usage: BudgetUsageView = serde_json::from_value(serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 3,
            "invocationCount": 4,
            "totalExposureCharged": 75,
            "totalRealizedSpend": 60,
            "updatedAt": 1234,
            "seq": 9
        }))
        .test_expect("parse split budget usage view");

        assert_eq!(usage.capability_id, "cap-budget");
        assert_eq!(usage.grant_index, 3);
        assert_eq!(usage.invocation_count, 4);
        assert_eq!(usage.total_cost_exposed, 75);
        assert_eq!(usage.total_cost_realized_spend, 60);
        assert_eq!(usage.updated_at, 1234);
        assert_eq!(usage.seq, Some(9));

        let encoded = serde_json::to_value(&usage).test_expect("serialize budget usage view");
        assert_eq!(encoded["totalExposureCharged"], 75);
        assert_eq!(encoded["totalRealizedSpend"], 60);
        assert!(encoded.get("totalCostCharged").is_none());
    }

    #[test]
    fn remote_budget_store_preserves_authority_term_and_commit_metadata() {
        let body = serde_json::json!({
            "capabilityId": "cap-budget",
            "grantIndex": 2,
            "allowed": true,
            "invocationCount": 5,
            "totalExposureCharged": 120,
            "totalRealizedSpend": 75,
            "budgetAuthority": {
                "authorityId": "http://leader-a",
                "leaderUrl": "http://leader-a",
                "budgetTerm": 7,
                "leaseId": "http://leader-a#term-7",
                "leaseEpoch": 7,
                "leaseExpiresAt": 5000,
                "leaseTtlMs": 750,
                "guaranteeLevel": "ha_quorum_commit",
                "budgetCommitIndex": 41
            },
            "budgetCommit": {
                "budgetSeq": 41,
                "commitIndex": 41,
                "quorumCommitted": true,
                "quorumSize": 2,
                "committedNodes": 2,
                "witnessUrls": ["http://leader-a", "http://peer-b"],
                "authorityId": "http://leader-a",
                "budgetTerm": 7,
                "leaseId": "http://leader-a#term-7",
                "leaseEpoch": 7
            }
        })
        .to_string();
        let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
        let store = build_remote_budget_store(&server.url, "secret")
            .test_expect("build remote budget store");

        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap-budget".to_string(),
                grant_index: 2,
                max_invocations: Some(9),
                requested_exposure_units: 120,
                max_cost_per_invocation: Some(150),
                max_total_cost_units: Some(900),
                hold_id: Some("hold-budget".to_string()),
                event_id: Some("hold-budget:authorize".to_string()),
                authority: None,
            })
            .test_expect("authorize remote budget hold");

        let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
            panic!("expected remote authorize to succeed");
        };
        let authority = authorized
            .metadata
            .authority
            .test_expect("budget authority metadata");
        assert_eq!(authority.authority_id, "http://leader-a");
        assert_eq!(authority.lease_id, "http://leader-a#term-7");
        assert_eq!(authority.lease_epoch, 7);
        assert_eq!(authorized.metadata.budget_commit_index, Some(41));
        assert_eq!(
            authorized.metadata.guarantee_level,
            BudgetGuaranteeLevel::HaLinearizable
        );
        assert_eq!(
            authorized.metadata.event_id.as_deref(),
            Some("hold-budget:authorize")
        );

        let usage = store
            .get_usage("cap-budget", 2)
            .test_expect("get cached usage")
            .test_expect("cached usage record");
        assert_eq!(usage.seq, 41);
        assert_eq!(usage.invocation_count, 5);
        assert_eq!(usage.total_cost_exposed, 120);
        assert_eq!(usage.total_cost_realized_spend, 75);
    }

    #[test]
    fn authority_key_cache_from_status_validates_and_deduplicates_current_key() {
        let current = Keypair::generate().public_key().to_hex();
        let trusted_only = Keypair::generate().public_key().to_hex();

        let cache = AuthorityKeyCache::from_status(&TrustAuthorityStatus {
            configured: true,
            backend: Some("sqlite".to_string()),
            public_key: Some(current.clone()),
            generation: Some(7),
            rotated_at: Some(11),
            applies_to_future_sessions_only: false,
            trusted_public_keys: vec![trusted_only.clone()],
        })
        .test_expect("cache from valid status");

        assert_eq!(
            cache.current.as_ref().test_expect("current key").to_hex(),
            current
        );
        assert_eq!(cache.trusted.len(), 2);
        assert!(cache
            .trusted
            .iter()
            .any(|public_key| public_key.to_hex() == current));
        assert!(cache
            .trusted
            .iter()
            .any(|public_key| public_key.to_hex() == trusted_only));

        let missing_current = match AuthorityKeyCache::from_status(&TrustAuthorityStatus {
            configured: true,
            backend: None,
            public_key: None,
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: false,
            trusted_public_keys: Vec::new(),
        }) {
            Ok(_) => panic!("missing current key should fail"),
            Err(error) => error,
        };
        assert!(missing_current
            .to_string()
            .contains("no current authority public key"));

        let unconfigured = match AuthorityKeyCache::from_status(&TrustAuthorityStatus {
            configured: false,
            backend: None,
            public_key: Some(current),
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: false,
            trusted_public_keys: Vec::new(),
        }) {
            Ok(_) => panic!("unconfigured authority should fail"),
            Err(error) => error,
        };
        assert!(unconfigured
            .to_string()
            .contains("does not have an authority configured"));
    }

    #[test]
    fn trusted_authority_signer_check_accepts_rotated_keys() {
        let current = Keypair::generate().public_key();
        let previous = Keypair::generate().public_key();
        let outsider = Keypair::generate().public_key();
        let trusted = vec![previous.clone(), current];

        ensure_signed_by_trusted_authority("trust activation", &previous, &trusted)
            .test_expect("previous authority key should remain trusted");
        let error = ensure_signed_by_trusted_authority("trust activation", &outsider, &trusted)
            .test_expect_err("outsider signer should fail closed");
        assert!(error
            .to_string()
            .contains("does not match a trusted trust-control authority signer"));
    }

    #[test]
    fn retry_statuses_and_error_adapters_match_expected_behavior() {
        assert!(should_retry_status(500));
        assert!(should_retry_status(502));
        assert!(should_retry_status(503));
        assert!(should_retry_status(504));
        assert!(!should_retry_status(400));
        assert!(!should_retry_status(401));

        let message = "backend unavailable".to_string();
        let receipt_error = into_receipt_store_error(CliError::cli_other_error(message.clone()));
        let revocation_error =
            into_revocation_store_error(CliError::cli_other_error(message.clone()));
        let budget_error = into_budget_store_error(CliError::cli_other_error(message.clone()));

        assert!(receipt_error.to_string().contains(&message));
        assert!(revocation_error.to_string().contains(&message));
        assert!(budget_error.to_string().contains(&message));
    }
}
