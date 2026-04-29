async fn serve_async(config: TrustServiceConfig) -> Result<(), CliError> {
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

    axum::serve(listener, router)
        .await
        .map_err(|error| CliError::Other(format!("trust control service failed: {error}")))
}

pub fn build_client(
    control_url: &str,
    control_token: &str,
) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(control_url, control_token, None)
}

fn build_cluster_peer_client(
    control_url: &str,
    control_token: &str,
    node_id: &str,
) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(
        control_url,
        control_token,
        Some(ClusterPeerClientAuth {
            node_id: Arc::<str>::from(normalize_cluster_url(node_id)?),
        }),
    )
}

fn build_client_with_cluster_peer(
    control_url: &str,
    control_token: &str,
    cluster_peer_auth: Option<ClusterPeerClientAuth>,
) -> Result<TrustControlClient, CliError> {
    let endpoints = control_url
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_end_matches('/').to_string())
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        return Err(CliError::Other("control URL must not be empty".to_string()));
    }
    let http = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    Ok(TrustControlClient {
        endpoints: Arc::new(endpoints),
        preferred_index: Arc::new(Mutex::new(0)),
        token: Arc::<str>::from(control_token.to_string()),
        http,
        cluster_peer_auth,
    })
}

fn encode_path_segment(segment: &str) -> String {
    utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string()
}

fn path_with_encoded_param(template: &str, param_name: &str, value: &str) -> String {
    template.replace(&format!("{{{param_name}}}"), &encode_path_segment(value))
}

pub fn resolve_public_certification(
    registry_url: &str,
    tool_server_id: &str,
) -> Result<CertificationResolutionResponse, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::Other(
            "public certification registry URL must not be empty".to_string(),
        ));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let path = path_with_encoded_param(
        PUBLIC_CERTIFICATION_RESOLVE_PATH,
        "tool_server_id",
        tool_server_id,
    );
    let response = agent
        .get(&format!("{endpoint}{path}"))
        .call()
        .map_err(|error| {
            CliError::Other(format!(
                "failed to query public certification registry {endpoint}: {error}"
            ))
        })?;
    response.into_json().map_err(|error| {
        CliError::Other(format!(
            "failed to parse public certification response from {endpoint}: {error}"
        ))
    })
}

pub fn resolve_public_certification_metadata(
    registry_url: &str,
) -> Result<CertificationPublicMetadata, CliError> {
    public_certification_get_json(registry_url, PUBLIC_CERTIFICATION_METADATA_PATH)
}

pub fn resolve_public_generic_namespace(
    registry_url: &str,
) -> Result<SignedGenericNamespace, CliError> {
    public_registry_get_json(registry_url, PUBLIC_GENERIC_NAMESPACE_PATH)
}

pub fn search_public_generic_listings(
    registry_url: &str,
    query: &GenericListingQuery,
) -> Result<GenericListingReport, CliError> {
    public_registry_get_json_with_query(registry_url, PUBLIC_GENERIC_LISTINGS_PATH, query)
}

pub fn issue_signed_generic_trust_activation(
    config: &TrustServiceConfig,
    request: &GenericTrustActivationIssueRequest,
) -> Result<SignedGenericTrustActivation, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.requested_at.unwrap_or(now_unix_secs()?);
    let artifact = build_generic_trust_activation_artifact(
        &local_operator.operator_id,
        local_operator.operator_name.clone(),
        request,
        issued_at,
    )
    .map_err(CliError::Other)?;
    SignedGenericTrustActivation::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::Other(format!("failed to sign trust activation artifact: {error}"))
    })
}

pub fn evaluate_generic_trust_activation_request(
    request: &GenericTrustActivationEvaluationRequest,
) -> Result<GenericTrustActivationEvaluation, CliError> {
    let now = request.evaluated_at.unwrap_or(now_unix_secs()?);
    evaluate_generic_trust_activation(request, now).map_err(CliError::Other)
}

pub fn issue_signed_generic_governance_charter(
    config: &TrustServiceConfig,
    request: &GenericGovernanceCharterIssueRequest,
) -> Result<SignedGenericGovernanceCharter, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.issued_at.unwrap_or(now_unix_secs()?);
    let artifact = build_generic_governance_charter_artifact(
        &local_operator.operator_id,
        local_operator.operator_name.clone(),
        request,
        issued_at,
    )
    .map_err(CliError::Other)?;
    SignedGenericGovernanceCharter::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign governance charter artifact: {error}"
        ))
    })
}

pub fn issue_signed_generic_governance_case(
    config: &TrustServiceConfig,
    request: &GenericGovernanceCaseIssueRequest,
) -> Result<SignedGenericGovernanceCase, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.opened_at.unwrap_or(now_unix_secs()?);
    let artifact =
        build_generic_governance_case_artifact(&local_operator.operator_id, request, issued_at)
            .map_err(CliError::Other)?;
    SignedGenericGovernanceCase::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::Other(format!("failed to sign governance case artifact: {error}"))
    })
}

pub fn evaluate_generic_governance_case_request(
    request: &GenericGovernanceCaseEvaluationRequest,
) -> Result<GenericGovernanceCaseEvaluation, CliError> {
    let now = request.evaluated_at.unwrap_or(now_unix_secs()?);
    evaluate_generic_governance_case(request, now).map_err(CliError::Other)
}

pub fn issue_signed_open_market_fee_schedule(
    config: &TrustServiceConfig,
    request: &OpenMarketFeeScheduleIssueRequest,
) -> Result<SignedOpenMarketFeeSchedule, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.issued_at.unwrap_or(now_unix_secs()?);
    let artifact = build_open_market_fee_schedule_artifact(
        &local_operator.operator_id,
        local_operator.operator_name.clone(),
        request,
        issued_at,
    )
    .map_err(CliError::Other)?;
    SignedOpenMarketFeeSchedule::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign open-market fee schedule artifact: {error}"
        ))
    })
}

pub fn issue_signed_open_market_penalty(
    config: &TrustServiceConfig,
    request: &OpenMarketPenaltyIssueRequest,
) -> Result<SignedOpenMarketPenalty, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.opened_at.unwrap_or(now_unix_secs()?);
    let artifact =
        build_open_market_penalty_artifact(&local_operator.operator_id, request, issued_at)
            .map_err(CliError::Other)?;
    SignedOpenMarketPenalty::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign open-market penalty artifact: {error}"
        ))
    })
}

pub fn evaluate_open_market_penalty_request(
    request: &OpenMarketPenaltyEvaluationRequest,
) -> Result<OpenMarketPenaltyEvaluation, CliError> {
    let now = request.evaluated_at.unwrap_or(now_unix_secs()?);
    evaluate_open_market_penalty(request, now).map_err(CliError::Other)
}

pub fn issue_signed_portable_reputation_summary(
    config: &TrustServiceConfig,
    request: &PortableReputationSummaryIssueRequest,
) -> Result<SignedPortableReputationSummary, CliError> {
    if config.receipt_db_path.is_none() {
        return Err(CliError::Other(
            "trust service is missing receipt_db_path for portable reputation summary issuance"
                .to_string(),
        ));
    }
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.issued_at.unwrap_or(now_unix_secs()?);
    let inspection = issuance::inspect_local_reputation(
        &request.subject_key,
        config.receipt_db_path.as_deref(),
        config.budget_db_path.as_deref(),
        request.since,
        request.until,
        config.issuance_policy.as_ref(),
    )
    .map_err(|error| CliError::Other(error.to_string()))?;
    let Some(receipt_db_path) = config.receipt_db_path.as_deref() else {
        return Err(CliError::Other(
            "receipt db path is required for imported trust reporting".to_string(),
        ));
    };
    let imported_trust = reputation::build_imported_trust_report(
        receipt_db_path,
        &inspection.subject_key,
        inspection.since,
        inspection.until,
        issued_at,
        &inspection.scoring,
    )?;
    let artifact = build_portable_reputation_summary_artifact(
        &local_operator.operator_id,
        request,
        &inspection.scorecard,
        chio_credentials::PortableReputationSummaryArtifactContext {
            issuer_operator_name: local_operator.operator_name.clone(),
            effective_score: inspection.effective_score,
            probationary: inspection.probationary,
            imported_signal_count: Some(imported_trust.signal_count),
            accepted_imported_signal_count: Some(imported_trust.accepted_count),
            issued_at,
        },
    )?;
    SignedPortableReputationSummary::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign portable reputation summary artifact: {error}"
        ))
    })
}

pub fn issue_signed_portable_negative_event(
    config: &TrustServiceConfig,
    request: &PortableNegativeEventIssueRequest,
) -> Result<SignedPortableNegativeEvent, CliError> {
    let signer_keypair = load_behavioral_feed_signing_keypair(
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    )?;
    let local_operator = public_generic_registry_publisher(config)?;
    let issued_at = request.published_at.unwrap_or(now_unix_secs()?);
    let artifact = build_portable_negative_event_artifact(
        &local_operator.operator_id,
        local_operator.operator_name.clone(),
        request,
        issued_at,
    )?;
    SignedPortableNegativeEvent::sign(artifact, &signer_keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign portable negative event artifact: {error}"
        ))
    })
}

pub fn evaluate_portable_reputation_request(
    request: &PortableReputationEvaluationRequest,
) -> Result<PortableReputationEvaluation, CliError> {
    let now = request.evaluated_at.unwrap_or(now_unix_secs()?);
    evaluate_portable_reputation(request, now).map_err(|error| CliError::Other(error.to_string()))
}

fn evaluate_federation_policy_request(
    state: &TrustServiceState,
    request: &FederationAdmissionEvaluationRequest,
    now: u64,
) -> Result<FederationAdmissionEvaluationResponse, CliError> {
    let (_, registry) = load_federation_policy_registry_for_admin(&state.config)?;
    let record = registry.get(&request.policy_id).cloned().ok_or_else(|| {
        CliError::Other(format!(
            "federation policy `{}` was not found",
            request.policy_id
        ))
    })?;
    verify_federation_admission_policy_record(&record)?;

    let policy = &record.policy.body;
    let proof_of_work_required = record.anti_sybil.proof_of_work_bits.is_some();
    let proof_of_work_verified = record
        .anti_sybil
        .proof_of_work_bits
        .map(|difficulty_bits| {
            request.proof_of_work_nonce.as_deref().is_some_and(|nonce| {
                verify_admission_proof_of_work(
                    &request.policy_id,
                    &request.subject_key,
                    nonce,
                    difficulty_bits,
                )
            })
        })
        .unwrap_or(true);
    let bond_backed_required = record.anti_sybil.bond_backed_only;
    let bond_backed_satisfied = !bond_backed_required
        || request.requested_admission_class == GenericTrustAdmissionClass::BondBacked;

    let mut response = FederationAdmissionEvaluationResponse {
        policy_id: request.policy_id.clone(),
        subject_key: request.subject_key.clone(),
        requested_admission_class: request.requested_admission_class,
        accepted: false,
        decision_reason: String::new(),
        proof_of_work_required,
        proof_of_work_verified,
        bond_backed_required,
        bond_backed_satisfied,
        minimum_reputation_score: record.minimum_reputation_score,
        observed_reputation_score: None,
        rate_limit: None,
    };

    if !policy
        .allowed_admission_classes
        .contains(&request.requested_admission_class)
    {
        response.decision_reason =
            "requested admission class is not allowed by the signed federation policy".to_string();
        return Ok(response);
    }

    if proof_of_work_required && !proof_of_work_verified {
        response.decision_reason =
            "proof-of-work nonce did not satisfy the configured federation policy difficulty"
                .to_string();
        return Ok(response);
    }

    if !bond_backed_satisfied {
        response.decision_reason =
            "federation policy requires bond_backed admission for permissionless entry".to_string();
        return Ok(response);
    }

    if let Some(minimum_score) = record.minimum_reputation_score {
        let inspection = issuance::inspect_local_reputation(
            &request.subject_key,
            state.config.receipt_db_path.as_deref(),
            state.config.budget_db_path.as_deref(),
            None,
            None,
            state.config.issuance_policy.as_ref(),
        )
        .map_err(|error| {
            CliError::Other(format!(
                "failed to inspect local reputation for federation admission: {error}"
            ))
        })?;
        response.observed_reputation_score = Some(inspection.effective_score);
        if inspection.effective_score < minimum_score {
            response.decision_reason = format!(
                "effective local reputation score {:.4} is below the federation threshold {:.4}",
                inspection.effective_score, minimum_score
            );
            return Ok(response);
        }
    }

    if let Some(limit) = record.anti_sybil.rate_limit.as_ref() {
        let mut limiter = state
            .federation_admission_rate_limiter
            .lock()
            .map_err(|_| {
                CliError::Other("federation admission rate limiter is poisoned".to_string())
            })?;
        let status = limiter.check_and_record(&request.policy_id, &request.subject_key, limit, now);
        let limited = status.retry_after_seconds.is_some();
        response.rate_limit = Some(status);
        if limited {
            response.decision_reason =
                "federation admission rate limit exceeded for the configured policy window"
                    .to_string();
            return Ok(response);
        }
    }

    response.accepted = true;
    response.decision_reason =
        "subject satisfied the configured federation reputation and anti-sybil controls"
            .to_string();
    Ok(response)
}

pub fn search_public_certifications(
    registry_url: &str,
    query: &CertificationPublicSearchQuery,
) -> Result<CertificationPublicSearchResponse, CliError> {
    public_certification_get_json_with_query(registry_url, PUBLIC_CERTIFICATION_SEARCH_PATH, query)
}

pub fn resolve_public_certification_transparency(
    registry_url: &str,
    query: &CertificationTransparencyQuery,
) -> Result<CertificationTransparencyResponse, CliError> {
    public_certification_get_json_with_query(
        registry_url,
        PUBLIC_CERTIFICATION_TRANSPARENCY_PATH,
        query,
    )
}

fn public_certification_get_json<T: for<'de> Deserialize<'de>>(
    registry_url: &str,
    path: &str,
) -> Result<T, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::Other(
            "public certification registry URL must not be empty".to_string(),
        ));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let response = agent
        .get(&format!("{endpoint}{path}"))
        .call()
        .map_err(|error| {
            CliError::Other(format!(
                "failed to query public certification registry {endpoint}: {error}"
            ))
        })?;
    response.into_json().map_err(|error| {
        CliError::Other(format!(
            "failed to parse public certification response from {endpoint}: {error}"
        ))
    })
}

fn public_registry_get_json<T: for<'de> Deserialize<'de>>(
    registry_url: &str,
    path: &str,
) -> Result<T, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::Other(
            "public registry URL must not be empty".to_string(),
        ));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let response = agent
        .get(&format!("{endpoint}{path}"))
        .call()
        .map_err(|error| {
            CliError::Other(format!(
                "failed to query public registry {endpoint}: {error}"
            ))
        })?;
    response.into_json().map_err(|error| {
        CliError::Other(format!(
            "failed to parse public registry response from {endpoint}: {error}"
        ))
    })
}

fn public_registry_get_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
    registry_url: &str,
    path: &str,
    query: &Q,
) -> Result<T, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::Other(
            "public registry URL must not be empty".to_string(),
        ));
    }
    let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
        CliError::Other(format!("failed to encode public registry query: {error}"))
    })?;
    let url = if encoded_query.is_empty() {
        format!("{endpoint}{path}")
    } else {
        format!("{endpoint}{path}?{encoded_query}")
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let response = agent.get(&url).call().map_err(|error| {
        CliError::Other(format!(
            "failed to query public registry {endpoint}: {error}"
        ))
    })?;
    response.into_json().map_err(|error| {
        CliError::Other(format!(
            "failed to parse public registry response from {endpoint}: {error}"
        ))
    })
}

fn public_certification_get_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
    registry_url: &str,
    path: &str,
    query: &Q,
) -> Result<T, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::Other(
            "public certification registry URL must not be empty".to_string(),
        ));
    }
    let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
        CliError::Other(format!(
            "failed to encode public certification query: {error}"
        ))
    })?;
    let url = if encoded_query.is_empty() {
        format!("{endpoint}{path}")
    } else {
        format!("{endpoint}{path}?{encoded_query}")
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let response = agent.get(&url).call().map_err(|error| {
        CliError::Other(format!(
            "failed to query public certification registry {endpoint}: {error}"
        ))
    })?;
    response.into_json().map_err(|error| {
        CliError::Other(format!(
            "failed to parse public certification response from {endpoint}: {error}"
        ))
    })
}

pub fn build_remote_receipt_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn ReceiptStore>, CliError> {
    Ok(Box::new(RemoteReceiptStore {
        client: build_client(control_url, control_token)?,
    }))
}

pub fn build_remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn BudgetStore>, CliError> {
    Ok(Box::new(RemoteBudgetStore {
        client: build_client(control_url, control_token)?,
        cached_usage: Mutex::new(HashMap::new()),
    }))
}

pub fn build_remote_revocation_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn RevocationStore>, CliError> {
    Ok(Box::new(RemoteRevocationStore {
        client: build_client(control_url, control_token)?,
    }))
}

pub fn build_remote_capability_authority(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    let client = build_client(control_url, control_token)?;
    let status = client.authority_status()?;
    let cache = AuthorityKeyCache::from_status(&status)?;
    Ok(Box::new(RemoteCapabilityAuthority {
        client,
        cache: Mutex::new(cache),
    }))
}

impl TrustControlClient {
    pub fn authority_status(&self) -> Result<TrustAuthorityStatus, CliError> {
        self.get_json(AUTHORITY_PATH)
    }

    pub fn rotate_authority(&self) -> Result<TrustAuthorityStatus, CliError> {
        self.post_json::<Value, TrustAuthorityStatus>(AUTHORITY_PATH, &json!({}))
    }

    pub fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, CliError> {
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, None)
    }

    pub fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, CliError> {
        let response: IssueCapabilityResponse = self.post_json(
            ISSUE_CAPABILITY_PATH,
            &IssueCapabilityRequest {
                subject_public_key: subject.to_hex(),
                scope,
                ttl_seconds,
                runtime_attestation,
            },
        )?;
        Ok(response.capability)
    }

    pub fn federated_issue(
        &self,
        request: &FederatedIssueRequest,
    ) -> Result<FederatedIssueResponse, CliError> {
        self.post_json(FEDERATED_ISSUE_PATH, request)
    }

    pub fn list_enterprise_providers(&self) -> Result<EnterpriseProviderListResponse, CliError> {
        self.get_json(FEDERATION_PROVIDERS_PATH)
    }

    pub fn get_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Result<EnterpriseProviderRecord, CliError> {
        self.get_json(&path_with_encoded_param(
            FEDERATION_PROVIDER_PATH,
            "provider_id",
            provider_id,
        ))
    }

    pub fn upsert_enterprise_provider(
        &self,
        provider_id: &str,
        record: &EnterpriseProviderRecord,
    ) -> Result<EnterpriseProviderRecord, CliError> {
        self.put_json(
            &path_with_encoded_param(FEDERATION_PROVIDER_PATH, "provider_id", provider_id),
            record,
        )
    }

    pub fn delete_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Result<EnterpriseProviderDeleteResponse, CliError> {
        self.delete_json(&path_with_encoded_param(
            FEDERATION_PROVIDER_PATH,
            "provider_id",
            provider_id,
        ))
    }

    pub fn list_federation_policies(
        &self,
    ) -> Result<FederationAdmissionPolicyListResponse, CliError> {
        self.get_json(FEDERATION_POLICIES_PATH)
    }

    pub fn get_federation_policy(
        &self,
        policy_id: &str,
    ) -> Result<FederationAdmissionPolicyRecord, CliError> {
        self.get_json(&path_with_encoded_param(
            FEDERATION_POLICY_PATH,
            "policy_id",
            policy_id,
        ))
    }

    pub fn upsert_federation_policy(
        &self,
        policy_id: &str,
        record: &FederationAdmissionPolicyRecord,
    ) -> Result<FederationAdmissionPolicyRecord, CliError> {
        self.put_json(
            &path_with_encoded_param(FEDERATION_POLICY_PATH, "policy_id", policy_id),
            record,
        )
    }

    pub fn delete_federation_policy(
        &self,
        policy_id: &str,
    ) -> Result<FederationAdmissionPolicyDeleteResponse, CliError> {
        self.delete_json(&path_with_encoded_param(
            FEDERATION_POLICY_PATH,
            "policy_id",
            policy_id,
        ))
    }

    pub fn evaluate_federation_policy(
        &self,
        request: &FederationAdmissionEvaluationRequest,
    ) -> Result<FederationAdmissionEvaluationResponse, CliError> {
        self.post_json(FEDERATION_POLICY_EVALUATE_PATH, request)
    }

    pub fn issue_generic_trust_activation(
        &self,
        request: &GenericTrustActivationIssueRequest,
    ) -> Result<SignedGenericTrustActivation, CliError> {
        self.post_json(GENERIC_TRUST_ACTIVATION_ISSUE_PATH, request)
    }

    pub fn evaluate_generic_trust_activation(
        &self,
        request: &GenericTrustActivationEvaluationRequest,
    ) -> Result<GenericTrustActivationEvaluation, CliError> {
        self.post_json(GENERIC_TRUST_ACTIVATION_EVALUATE_PATH, request)
    }

    pub fn issue_generic_governance_charter(
        &self,
        request: &GenericGovernanceCharterIssueRequest,
    ) -> Result<SignedGenericGovernanceCharter, CliError> {
        self.post_json(GENERIC_GOVERNANCE_CHARTER_ISSUE_PATH, request)
    }

    pub fn issue_generic_governance_case(
        &self,
        request: &GenericGovernanceCaseIssueRequest,
    ) -> Result<SignedGenericGovernanceCase, CliError> {
        self.post_json(GENERIC_GOVERNANCE_CASE_ISSUE_PATH, request)
    }

    pub fn evaluate_generic_governance_case(
        &self,
        request: &GenericGovernanceCaseEvaluationRequest,
    ) -> Result<GenericGovernanceCaseEvaluation, CliError> {
        self.post_json(GENERIC_GOVERNANCE_CASE_EVALUATE_PATH, request)
    }

    pub fn issue_open_market_fee_schedule(
        &self,
        request: &OpenMarketFeeScheduleIssueRequest,
    ) -> Result<SignedOpenMarketFeeSchedule, CliError> {
        self.post_json(OPEN_MARKET_FEE_SCHEDULE_ISSUE_PATH, request)
    }

    pub fn issue_open_market_penalty(
        &self,
        request: &OpenMarketPenaltyIssueRequest,
    ) -> Result<SignedOpenMarketPenalty, CliError> {
        self.post_json(OPEN_MARKET_PENALTY_ISSUE_PATH, request)
    }

    pub fn evaluate_open_market_penalty(
        &self,
        request: &OpenMarketPenaltyEvaluationRequest,
    ) -> Result<OpenMarketPenaltyEvaluation, CliError> {
        self.post_json(OPEN_MARKET_PENALTY_EVALUATE_PATH, request)
    }

    pub fn list_certifications(&self) -> Result<CertificationRegistryListResponse, CliError> {
        self.get_json(CERTIFICATIONS_PATH)
    }

    pub fn get_certification(
        &self,
        artifact_id: &str,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.get_json(&path_with_encoded_param(
            CERTIFICATION_PATH,
            "artifact_id",
            artifact_id,
        ))
    }

    pub fn publish_certification(
        &self,
        artifact: &SignedCertificationCheck,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.post_json(CERTIFICATIONS_PATH, artifact)
    }

    pub fn resolve_certification(
        &self,
        tool_server_id: &str,
    ) -> Result<CertificationResolutionResponse, CliError> {
        self.get_json(&path_with_encoded_param(
            CERTIFICATION_RESOLVE_PATH,
            "tool_server_id",
            tool_server_id,
        ))
    }

    pub fn discover_certification(
        &self,
        tool_server_id: &str,
    ) -> Result<CertificationDiscoveryResponse, CliError> {
        self.get_json(&path_with_encoded_param(
            CERTIFICATION_DISCOVERY_RESOLVE_PATH,
            "tool_server_id",
            tool_server_id,
        ))
    }

    pub fn publish_certification_network(
        &self,
        request: &CertificationNetworkPublishRequest,
    ) -> Result<CertificationNetworkPublishResponse, CliError> {
        self.post_json("/v1/certifications/discovery/publish", request)
    }

    pub fn search_certification_marketplace(
        &self,
        query: &CertificationMarketplaceSearchQuery,
    ) -> Result<CertificationPublicSearchResponse, CliError> {
        self.get_json(&certification_marketplace_search_path(query))
    }

    pub fn certification_marketplace_transparency(
        &self,
        query: &CertificationMarketplaceTransparencyQuery,
    ) -> Result<CertificationTransparencyResponse, CliError> {
        self.get_json(&certification_marketplace_transparency_path(query))
    }

    pub fn consume_certification_marketplace(
        &self,
        request: &CertificationConsumptionRequest,
    ) -> Result<CertificationConsumptionResponse, CliError> {
        self.post_json(CERTIFICATION_DISCOVERY_CONSUME_PATH, request)
    }

    pub fn revoke_certification(
        &self,
        artifact_id: &str,
        request: &CertificationRevocationRequest,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.post_json(
            &path_with_encoded_param(CERTIFICATION_REVOKE_PATH, "artifact_id", artifact_id),
            request,
        )
    }

    pub fn dispute_certification(
        &self,
        artifact_id: &str,
        request: &CertificationDisputeRequest,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.post_json(
            &path_with_encoded_param(CERTIFICATION_DISPUTE_PATH, "artifact_id", artifact_id),
            request,
        )
    }

    pub fn list_passport_statuses(&self) -> Result<PassportStatusListResponse, CliError> {
        self.get_json(PASSPORT_STATUSES_PATH)
    }

    pub fn passport_issuer_metadata(&self) -> Result<Oid4vciCredentialIssuerMetadata, CliError> {
        self.public_get_json(PASSPORT_ISSUER_METADATA_PATH)
    }

    pub fn create_passport_issuance_offer(
        &self,
        request: &CreatePassportIssuanceOfferRequest,
    ) -> Result<PassportIssuanceOfferRecord, CliError> {
        self.post_json(PASSPORT_ISSUANCE_OFFERS_PATH, request)
    }

    pub fn redeem_passport_issuance_token(
        &self,
        request: &Oid4vciTokenRequest,
    ) -> Result<Oid4vciTokenResponse, CliError> {
        self.public_post_json(PASSPORT_ISSUANCE_TOKEN_PATH, request)
    }

    pub fn redeem_passport_issuance_credential(
        &self,
        access_token: &str,
        request: &Oid4vciCredentialRequest,
    ) -> Result<Oid4vciCredentialResponse, CliError> {
        self.bearer_post_json(PASSPORT_ISSUANCE_CREDENTIAL_PATH, access_token, request)
    }

    pub fn get_passport_status(
        &self,
        passport_id: &str,
    ) -> Result<PassportLifecycleRecord, CliError> {
        self.get_json(&path_with_encoded_param(
            PASSPORT_STATUS_PATH,
            "passport_id",
            passport_id,
        ))
    }

    pub fn publish_passport_status(
        &self,
        request: &PublishPassportStatusRequest,
    ) -> Result<PassportLifecycleRecord, CliError> {
        self.post_json(PASSPORT_STATUSES_PATH, request)
    }

    pub fn resolve_passport_status(
        &self,
        passport_id: &str,
    ) -> Result<PassportLifecycleResolution, CliError> {
        self.get_json(&path_with_encoded_param(
            PASSPORT_STATUS_RESOLVE_PATH,
            "passport_id",
            passport_id,
        ))
    }

    pub fn public_resolve_passport_status(
        &self,
        passport_id: &str,
    ) -> Result<PassportLifecycleResolution, CliError> {
        self.public_get_json(&path_with_encoded_param(
            PUBLIC_PASSPORT_STATUS_RESOLVE_PATH,
            "passport_id",
            passport_id,
        ))
    }

    pub fn revoke_passport_status(
        &self,
        passport_id: &str,
        request: &PassportStatusRevocationRequest,
    ) -> Result<PassportLifecycleRecord, CliError> {
        self.post_json(
            &path_with_encoded_param(PASSPORT_STATUS_REVOKE_PATH, "passport_id", passport_id),
            request,
        )
    }

    pub fn list_verifier_policies(&self) -> Result<VerifierPolicyListResponse, CliError> {
        self.get_json(PASSPORT_VERIFIER_POLICIES_PATH)
    }

    pub fn get_verifier_policy(
        &self,
        policy_id: &str,
    ) -> Result<SignedPassportVerifierPolicy, CliError> {
        self.get_json(&path_with_encoded_param(
            PASSPORT_VERIFIER_POLICY_PATH,
            "policy_id",
            policy_id,
        ))
    }

    pub fn upsert_verifier_policy(
        &self,
        policy_id: &str,
        document: &SignedPassportVerifierPolicy,
    ) -> Result<SignedPassportVerifierPolicy, CliError> {
        self.put_json(
            &path_with_encoded_param(PASSPORT_VERIFIER_POLICY_PATH, "policy_id", policy_id),
            document,
        )
    }

    pub fn delete_verifier_policy(
        &self,
        policy_id: &str,
    ) -> Result<VerifierPolicyDeleteResponse, CliError> {
        self.delete_json(&path_with_encoded_param(
            PASSPORT_VERIFIER_POLICY_PATH,
            "policy_id",
            policy_id,
        ))
    }

    pub fn create_passport_challenge(
        &self,
        request: &CreatePassportChallengeRequest,
    ) -> Result<CreatePassportChallengeResponse, CliError> {
        self.post_json(PASSPORT_CHALLENGES_PATH, request)
    }

    pub fn verify_passport_challenge(
        &self,
        request: &VerifyPassportChallengeRequest,
    ) -> Result<PassportPresentationVerification, CliError> {
        self.post_json(PASSPORT_CHALLENGE_VERIFY_PATH, request)
    }

    pub fn public_get_passport_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<PassportPresentationChallenge, CliError> {
        self.public_get_json(&path_with_encoded_param(
            PUBLIC_PASSPORT_CHALLENGE_PATH,
            "challenge_id",
            challenge_id,
        ))
    }

    pub fn public_verify_passport_challenge(
        &self,
        request: &VerifyPassportChallengeRequest,
    ) -> Result<PassportPresentationVerification, CliError> {
        self.public_post_json(PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH, request)
    }

    pub fn create_oid4vp_request(
        &self,
        request: &CreateOid4vpRequest,
    ) -> Result<CreateOid4vpRequestResponse, CliError> {
        self.post_json(PASSPORT_OID4VP_REQUESTS_PATH, request)
    }

    pub fn public_get_oid4vp_request(&self, request_id: &str) -> Result<String, CliError> {
        self.public_get_text(&path_with_encoded_param(
            PUBLIC_PASSPORT_OID4VP_REQUEST_PATH,
            "request_id",
            request_id,
        ))
    }

    pub fn public_get_wallet_exchange(
        &self,
        request_id: &str,
    ) -> Result<WalletExchangeStatusResponse, CliError> {
        self.public_get_json(&path_with_encoded_param(
            PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH,
            "request_id",
            request_id,
        ))
    }

    pub fn public_submit_oid4vp_response(
        &self,
        response_jwt: &str,
    ) -> Result<Oid4vpPresentationVerification, CliError> {
        self.public_post_form(
            PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH,
            &[("response", response_jwt)],
        )
    }

    pub fn list_revocations(
        &self,
        query: &RevocationQuery,
    ) -> Result<RevocationListResponse, CliError> {
        self.get_json_with_query(REVOCATIONS_PATH, query)
    }

    pub fn revoke_capability(
        &self,
        capability_id: &str,
    ) -> Result<RevokeCapabilityResponse, CliError> {
        self.post_json(
            REVOCATIONS_PATH,
            &RevokeCapabilityRequest {
                capability_id: capability_id.to_string(),
            },
        )
    }

    pub fn list_tool_receipts(
        &self,
        query: &ToolReceiptQuery,
    ) -> Result<ReceiptListResponse, CliError> {
        self.get_json_with_query(TOOL_RECEIPTS_PATH, query)
    }

    pub fn list_child_receipts(
        &self,
        query: &ChildReceiptQuery,
    ) -> Result<ReceiptListResponse, CliError> {
        self.get_json_with_query(CHILD_RECEIPTS_PATH, query)
    }

    pub fn query_receipts(
        &self,
        query: &ReceiptQueryHttpQuery,
    ) -> Result<ReceiptQueryResponse, CliError> {
        self.get_json_with_query(RECEIPT_QUERY_PATH, query)
    }

    pub fn export_evidence(
        &self,
        request: &evidence_export::RemoteEvidenceExportRequest,
    ) -> Result<evidence_export::RemoteEvidenceExportResponse, CliError> {
        self.post_json(EVIDENCE_EXPORT_PATH, request)
    }

    pub fn import_evidence(
        &self,
        request: &evidence_export::RemoteEvidenceImportRequest,
    ) -> Result<evidence_export::RemoteEvidenceImportResponse, CliError> {
        self.post_json(EVIDENCE_IMPORT_PATH, request)
    }

    pub fn shared_evidence_report(
        &self,
        query: &SharedEvidenceQuery,
    ) -> Result<SharedEvidenceReferenceReport, CliError> {
        self.get_json_with_query(FEDERATION_EVIDENCE_SHARES_PATH, query)
    }

    // Kept for API parity with the trust-control service surface even though
    // the current CLI command set does not invoke it directly.
    #[allow(dead_code)]
    pub fn cost_attribution_report(
        &self,
        query: &CostAttributionQuery,
    ) -> Result<CostAttributionReport, CliError> {
        self.get_json_with_query(COST_ATTRIBUTION_PATH, query)
    }

    // Kept for API parity with the trust-control service surface even though
    // the current CLI command set does not invoke it directly.
    #[allow(dead_code)]
    pub fn operator_report(&self, query: &OperatorReportQuery) -> Result<OperatorReport, CliError> {
        self.get_json_with_query(OPERATOR_REPORT_PATH, query)
    }

    pub fn behavioral_feed(
        &self,
        query: &BehavioralFeedQuery,
    ) -> Result<SignedBehavioralFeed, CliError> {
        self.get_json_with_query(BEHAVIORAL_FEED_PATH, query)
    }

    pub fn exposure_ledger(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<SignedExposureLedgerReport, CliError> {
        self.get_json_with_query(EXPOSURE_LEDGER_PATH, query)
    }

    pub fn credit_scorecard(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<SignedCreditScorecardReport, CliError> {
        self.get_json_with_query(CREDIT_SCORECARD_PATH, query)
    }

    pub fn capital_book(
        &self,
        query: &CapitalBookQuery,
    ) -> Result<SignedCapitalBookReport, CliError> {
        self.get_json_with_query(CAPITAL_BOOK_PATH, query)
    }

    pub fn issue_capital_execution_instruction(
        &self,
        request: &CapitalExecutionInstructionRequest,
    ) -> Result<SignedCapitalExecutionInstruction, CliError> {
        self.post_json(CAPITAL_INSTRUCTION_ISSUE_PATH, request)
    }

    pub fn issue_capital_allocation_decision(
        &self,
        request: &CapitalAllocationDecisionRequest,
    ) -> Result<SignedCapitalAllocationDecision, CliError> {
        self.post_json(CAPITAL_ALLOCATION_ISSUE_PATH, request)
    }

    pub fn credit_facility_report(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<CreditFacilityReport, CliError> {
        self.get_json_with_query(CREDIT_FACILITY_REPORT_PATH, query)
    }

    pub fn issue_credit_facility(
        &self,
        request: &CreditFacilityIssueRequest,
    ) -> Result<SignedCreditFacility, CliError> {
        self.post_json(CREDIT_FACILITY_ISSUE_PATH, request)
    }

    pub fn list_credit_facilities(
        &self,
        query: &CreditFacilityListQuery,
    ) -> Result<CreditFacilityListReport, CliError> {
        self.get_json_with_query(CREDIT_FACILITIES_REPORT_PATH, query)
    }

    pub fn credit_bond_report(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<CreditBondReport, CliError> {
        self.get_json_with_query(CREDIT_BOND_REPORT_PATH, query)
    }

    pub fn issue_credit_bond(
        &self,
        request: &CreditBondIssueRequest,
    ) -> Result<SignedCreditBond, CliError> {
        self.post_json(CREDIT_BOND_ISSUE_PATH, request)
    }

    pub fn list_credit_bonds(
        &self,
        query: &CreditBondListQuery,
    ) -> Result<CreditBondListReport, CliError> {
        self.get_json_with_query(CREDIT_BONDS_REPORT_PATH, query)
    }

    pub fn simulate_credit_bonded_execution(
        &self,
        request: &CreditBondedExecutionSimulationRequest,
    ) -> Result<CreditBondedExecutionSimulationReport, CliError> {
        self.post_json(CREDIT_BONDED_EXECUTION_SIMULATION_PATH, request)
    }

    pub fn credit_loss_lifecycle_report(
        &self,
        query: &CreditLossLifecycleQuery,
    ) -> Result<CreditLossLifecycleReport, CliError> {
        self.get_json_with_query(CREDIT_LOSS_LIFECYCLE_REPORT_PATH, query)
    }

    pub fn issue_credit_loss_lifecycle(
        &self,
        request: &CreditLossLifecycleIssueRequest,
    ) -> Result<SignedCreditLossLifecycle, CliError> {
        self.post_json(CREDIT_LOSS_LIFECYCLE_ISSUE_PATH, request)
    }

    pub fn list_credit_loss_lifecycle(
        &self,
        query: &CreditLossLifecycleListQuery,
    ) -> Result<CreditLossLifecycleListReport, CliError> {
        self.get_json_with_query(CREDIT_LOSS_LIFECYCLE_LIST_PATH, query)
    }

    pub fn credit_backtest(
        &self,
        query: &CreditBacktestQuery,
    ) -> Result<CreditBacktestReport, CliError> {
        self.get_json_with_query(CREDIT_BACKTEST_PATH, query)
    }

    pub fn credit_provider_risk_package(
        &self,
        query: &CreditProviderRiskPackageQuery,
    ) -> Result<SignedCreditProviderRiskPackage, CliError> {
        self.get_json_with_query(CREDIT_PROVIDER_RISK_PACKAGE_PATH, query)
    }

    pub fn issue_liability_provider(
        &self,
        request: &LiabilityProviderIssueRequest,
    ) -> Result<SignedLiabilityProvider, CliError> {
        self.post_json(LIABILITY_PROVIDER_ISSUE_PATH, request)
    }

    pub fn list_liability_providers(
        &self,
        query: &LiabilityProviderListQuery,
    ) -> Result<LiabilityProviderListReport, CliError> {
        self.get_json_with_query(LIABILITY_PROVIDERS_REPORT_PATH, query)
    }

    pub fn resolve_liability_provider(
        &self,
        query: &LiabilityProviderResolutionQuery,
    ) -> Result<LiabilityProviderResolutionReport, CliError> {
        self.get_json_with_query(LIABILITY_PROVIDER_RESOLVE_PATH, query)
    }

    pub fn issue_liability_quote_request(
        &self,
        request: &LiabilityQuoteRequestIssueRequest,
    ) -> Result<SignedLiabilityQuoteRequest, CliError> {
        self.post_json(LIABILITY_QUOTE_REQUEST_ISSUE_PATH, request)
    }

    pub fn issue_liability_quote_response(
        &self,
        request: &LiabilityQuoteResponseIssueRequest,
    ) -> Result<SignedLiabilityQuoteResponse, CliError> {
        self.post_json(LIABILITY_QUOTE_RESPONSE_ISSUE_PATH, request)
    }

    pub fn issue_liability_pricing_authority(
        &self,
        request: &LiabilityPricingAuthorityIssueRequest,
    ) -> Result<SignedLiabilityPricingAuthority, CliError> {
        self.post_json(LIABILITY_PRICING_AUTHORITY_ISSUE_PATH, request)
    }

    pub fn issue_liability_placement(
        &self,
        request: &LiabilityPlacementIssueRequest,
    ) -> Result<SignedLiabilityPlacement, CliError> {
        self.post_json(LIABILITY_PLACEMENT_ISSUE_PATH, request)
    }

    pub fn issue_liability_bound_coverage(
        &self,
        request: &LiabilityBoundCoverageIssueRequest,
    ) -> Result<SignedLiabilityBoundCoverage, CliError> {
        self.post_json(LIABILITY_BOUND_COVERAGE_ISSUE_PATH, request)
    }

    pub fn issue_liability_auto_bind(
        &self,
        request: &LiabilityAutoBindIssueRequest,
    ) -> Result<SignedLiabilityAutoBindDecision, CliError> {
        self.post_json(LIABILITY_AUTO_BIND_DECISION_ISSUE_PATH, request)
    }

    pub fn liability_market_workflows(
        &self,
        query: &LiabilityMarketWorkflowQuery,
    ) -> Result<LiabilityMarketWorkflowReport, CliError> {
        self.get_json_with_query(LIABILITY_MARKET_WORKFLOW_REPORT_PATH, query)
    }

    pub fn issue_liability_claim_package(
        &self,
        request: &LiabilityClaimPackageIssueRequest,
    ) -> Result<SignedLiabilityClaimPackage, CliError> {
        self.post_json(LIABILITY_CLAIM_PACKAGE_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_response(
        &self,
        request: &LiabilityClaimResponseIssueRequest,
    ) -> Result<SignedLiabilityClaimResponse, CliError> {
        self.post_json(LIABILITY_CLAIM_RESPONSE_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_dispute(
        &self,
        request: &LiabilityClaimDisputeIssueRequest,
    ) -> Result<SignedLiabilityClaimDispute, CliError> {
        self.post_json(LIABILITY_CLAIM_DISPUTE_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_adjudication(
        &self,
        request: &LiabilityClaimAdjudicationIssueRequest,
    ) -> Result<SignedLiabilityClaimAdjudication, CliError> {
        self.post_json(LIABILITY_CLAIM_ADJUDICATION_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_payout_instruction(
        &self,
        request: &LiabilityClaimPayoutInstructionIssueRequest,
    ) -> Result<SignedLiabilityClaimPayoutInstruction, CliError> {
        self.post_json(LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_payout_receipt(
        &self,
        request: &LiabilityClaimPayoutReceiptIssueRequest,
    ) -> Result<SignedLiabilityClaimPayoutReceipt, CliError> {
        self.post_json(LIABILITY_CLAIM_PAYOUT_RECEIPT_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_settlement_instruction(
        &self,
        request: &LiabilityClaimSettlementInstructionIssueRequest,
    ) -> Result<SignedLiabilityClaimSettlementInstruction, CliError> {
        self.post_json(LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_settlement_receipt(
        &self,
        request: &LiabilityClaimSettlementReceiptIssueRequest,
    ) -> Result<SignedLiabilityClaimSettlementReceipt, CliError> {
        self.post_json(LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ISSUE_PATH, request)
    }

    pub fn liability_claim_workflows(
        &self,
        query: &LiabilityClaimWorkflowQuery,
    ) -> Result<LiabilityClaimWorkflowReport, CliError> {
        self.get_json_with_query(LIABILITY_CLAIM_WORKFLOW_REPORT_PATH, query)
    }

    pub fn runtime_attestation_appraisal(
        &self,
        request: &RuntimeAttestationAppraisalRequest,
    ) -> Result<SignedRuntimeAttestationAppraisalReport, CliError> {
        self.post_json(RUNTIME_ATTESTATION_APPRAISAL_PATH, request)
    }

    pub fn runtime_attestation_appraisal_result(
        &self,
        request: &RuntimeAttestationAppraisalResultExportRequest,
    ) -> Result<SignedRuntimeAttestationAppraisalResult, CliError> {
        self.post_json(RUNTIME_ATTESTATION_APPRAISAL_RESULT_PATH, request)
    }

    pub fn import_runtime_attestation_appraisal(
        &self,
        request: &RuntimeAttestationAppraisalImportRequest,
    ) -> Result<RuntimeAttestationAppraisalImportReport, CliError> {
        self.post_json(RUNTIME_ATTESTATION_APPRAISAL_IMPORT_PATH, request)
    }

    pub fn metered_billing_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<MeteredBillingReconciliationReport, CliError> {
        self.get_json_with_query(METERED_BILLING_REPORT_PATH, query)
    }

    pub fn authorization_context_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<AuthorizationContextReport, CliError> {
        self.get_json_with_query(AUTHORIZATION_CONTEXT_REPORT_PATH, query)
    }

    pub fn authorization_profile_metadata(
        &self,
    ) -> Result<ChioOAuthAuthorizationMetadataReport, CliError> {
        self.get_json(AUTHORIZATION_PROFILE_METADATA_PATH)
    }

    pub fn authorization_review_pack(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<ChioOAuthAuthorizationReviewPack, CliError> {
        self.get_json_with_query(AUTHORIZATION_REVIEW_PACK_PATH, query)
    }

    pub fn underwriting_policy_input(
        &self,
        query: &UnderwritingPolicyInputQuery,
    ) -> Result<SignedUnderwritingPolicyInput, CliError> {
        self.get_json_with_query(UNDERWRITING_INPUT_PATH, query)
    }

    pub fn underwriting_decision(
        &self,
        query: &UnderwritingPolicyInputQuery,
    ) -> Result<UnderwritingDecisionReport, CliError> {
        self.get_json_with_query(UNDERWRITING_DECISION_PATH, query)
    }

    pub fn simulate_underwriting_decision(
        &self,
        request: &UnderwritingSimulationRequest,
    ) -> Result<UnderwritingSimulationReport, CliError> {
        self.post_json(UNDERWRITING_SIMULATION_PATH, request)
    }

    pub fn issue_underwriting_decision(
        &self,
        request: &UnderwritingDecisionIssueRequest,
    ) -> Result<SignedUnderwritingDecision, CliError> {
        self.post_json(UNDERWRITING_DECISION_ISSUE_PATH, request)
    }

    pub fn list_underwriting_decisions(
        &self,
        query: &UnderwritingDecisionQuery,
    ) -> Result<UnderwritingDecisionListReport, CliError> {
        self.get_json_with_query(UNDERWRITING_DECISIONS_REPORT_PATH, query)
    }

    pub fn create_underwriting_appeal(
        &self,
        request: &UnderwritingAppealCreateRequest,
    ) -> Result<UnderwritingAppealRecord, CliError> {
        self.post_json(UNDERWRITING_APPEALS_PATH, request)
    }

    pub fn resolve_underwriting_appeal(
        &self,
        request: &UnderwritingAppealResolveRequest,
    ) -> Result<UnderwritingAppealRecord, CliError> {
        self.post_json(UNDERWRITING_APPEAL_RESOLVE_PATH, request)
    }

    pub fn record_metered_billing_reconciliation(
        &self,
        request: &MeteredBillingReconciliationUpdateRequest,
    ) -> Result<MeteredBillingReconciliationUpdateResponse, CliError> {
        self.post_json(METERED_BILLING_RECONCILE_PATH, request)
    }

    pub fn local_reputation(
        &self,
        subject_key: &str,
        query: &LocalReputationQuery,
    ) -> Result<issuance::LocalReputationInspection, CliError> {
        self.get_json_with_query(
            &path_with_encoded_param(LOCAL_REPUTATION_PATH, "subject_key", subject_key),
            query,
        )
    }

    pub fn reputation_compare(
        &self,
        subject_key: &str,
        request: &ReputationCompareRequest,
    ) -> Result<reputation::PortableReputationComparison, CliError> {
        self.post_json(
            &path_with_encoded_param(REPUTATION_COMPARE_PATH, "subject_key", subject_key),
            request,
        )
    }

    pub fn issue_portable_reputation_summary(
        &self,
        request: &PortableReputationSummaryIssueRequest,
    ) -> Result<SignedPortableReputationSummary, CliError> {
        self.post_json(PORTABLE_REPUTATION_SUMMARY_ISSUE_PATH, request)
    }

    pub fn issue_portable_negative_event(
        &self,
        request: &PortableNegativeEventIssueRequest,
    ) -> Result<SignedPortableNegativeEvent, CliError> {
        self.post_json(PORTABLE_NEGATIVE_EVENT_ISSUE_PATH, request)
    }

    pub fn evaluate_portable_reputation(
        &self,
        request: &PortableReputationEvaluationRequest,
    ) -> Result<PortableReputationEvaluation, CliError> {
        self.post_json(PORTABLE_REPUTATION_EVALUATE_PATH, request)
    }

    pub fn append_tool_receipt(&self, receipt: &ChioReceipt) -> Result<(), CliError> {
        let _: Value = self.post_json(TOOL_RECEIPTS_PATH, receipt)?;
        Ok(())
    }

    pub fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), CliError> {
        let _: Value = self.post_json(CHILD_RECEIPTS_PATH, receipt)?;
        Ok(())
    }

    pub fn record_capability_snapshot(
        &self,
        capability: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), CliError> {
        let _: Value = self.post_json(
            LINEAGE_RECORD_PATH,
            &RecordCapabilitySnapshotRequest {
                capability: capability.clone(),
                parent_capability_id: parent_capability_id.map(ToOwned::to_owned),
            },
        )?;
        Ok(())
    }

    pub fn list_budgets(&self, query: &BudgetQuery) -> Result<BudgetListResponse, CliError> {
        self.get_json_with_query(BUDGETS_PATH, query)
    }

    fn try_increment_budget(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<TryIncrementBudgetResponse, CliError> {
        self.post_json(
            BUDGET_INCREMENT_PATH,
            &TryIncrementBudgetRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                max_invocations,
            },
        )
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<TryChargeCostResponse, CliError> {
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            None,
            None,
        )
    }

    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<TryChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_AUTHORIZE_EXPOSURE_PATH,
            &TryChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<ReverseChargeCostResponse, CliError> {
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReverseChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_RELEASE_EXPOSURE_PATH,
            &ReverseChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                cost_units,
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_RECONCILE_SPEND_PATH,
            &ReduceChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                cost_units,
                exposure_units: None,
                realized_spend_units: None,
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    fn reconcile_budget_spend(
        &self,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        realized_spend_units: u64,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reconcile_budget_spend_with_ids(
            capability_id,
            grant_index,
            authorized_exposure_units,
            realized_spend_units,
            None,
            None,
        )
    }

    fn reconcile_budget_spend_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        realized_spend_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        let released_exposure_units = authorized_exposure_units
            .checked_sub(realized_spend_units)
            .ok_or_else(|| {
                CliError::Other(
                    "realized spend cannot exceed authorized exposure during reconciliation"
                        .to_string(),
                )
            })?;
        self.post_json(
            BUDGET_RECONCILE_SPEND_PATH,
            &ReduceChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                cost_units: released_exposure_units,
                exposure_units: Some(authorized_exposure_units),
                realized_spend_units: Some(realized_spend_units),
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    fn cluster_status(&self) -> Result<ClusterStatusResponse, CliError> {
        self.get_internal_json(INTERNAL_CLUSTER_STATUS_PATH, None)
    }

    fn authority_snapshot(&self) -> Result<AuthoritySnapshotView, CliError> {
        self.get_internal_json(INTERNAL_AUTHORITY_SNAPSHOT_PATH, None)
    }

    fn cluster_snapshot(&self) -> Result<ClusterStateSnapshotResponse, CliError> {
        self.get_internal_json(INTERNAL_CLUSTER_SNAPSHOT_PATH, None)
    }

    fn revocation_deltas(
        &self,
        query: &RevocationDeltaQuery,
    ) -> Result<RevocationDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_REVOCATIONS_DELTA_PATH, query, None)
    }

    fn tool_receipt_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<ReceiptDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_TOOL_RECEIPTS_DELTA_PATH, query, None)
    }

    fn child_receipt_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<ReceiptDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_CHILD_RECEIPTS_DELTA_PATH, query, None)
    }

    fn lineage_deltas(&self, query: &ReceiptDeltaQuery) -> Result<LineageDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_LINEAGE_DELTA_PATH, query, None)
    }

    fn budget_deltas(&self, query: &BudgetDeltaQuery) -> Result<BudgetDeltaResponse, CliError> {
        self.get_internal_json_with_query(INTERNAL_BUDGETS_DELTA_PATH, query, None)
    }

    fn get_internal_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        term: Option<u64>,
    ) -> Result<T, CliError> {
        self.request_internal_get_json(path, path, term)
    }

    fn get_internal_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &Q,
        term: Option<u64>,
    ) -> Result<T, CliError> {
        let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
            CliError::Other(format!("failed to encode trust control query: {error}"))
        })?;
        let url = if encoded_query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{encoded_query}")
        };
        self.request_internal_get_json(&url, path, term)
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, CliError> {
        self.request_json(
            |client, url, token| {
                client
                    .get(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            path,
        )
    }

    fn public_get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, CliError> {
        self.request_json_without_service_auth(|client, url| client.get(url).call(), path)
    }

    fn public_get_text(&self, path: &str) -> Result<String, CliError> {
        self.request_text_without_service_auth(|client, url| client.get(url).call(), path)
    }

    fn get_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &Q,
    ) -> Result<T, CliError> {
        let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
            CliError::Other(format!("failed to encode trust control query: {error}"))
        })?;
        let url = if encoded_query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{encoded_query}")
        };
        self.request_json(
            |client, base_url, token| {
                client
                    .get(&format!("{base_url}{url}"))
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            "",
        )
    }

    fn post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::Other(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json(
            |client, url, token| {
                client
                    .post(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    fn post_internal_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
        term: Option<u64>,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::Other(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_internal_post_json(path, json, term)
    }

    fn public_post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::Other(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json_without_service_auth(
            |client, url| client.post(url).send_json(json.clone()),
            path,
        )
    }

    fn public_post_form<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &[(&str, &str)],
    ) -> Result<T, CliError> {
        self.request_json_without_service_auth(|client, url| client.post(url).send_form(body), path)
    }

    fn bearer_post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        bearer_token: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::Other(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json_with_bearer(
            |client, url| {
                client
                    .post(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {bearer_token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    fn put_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::Other(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json(
            |client, url, token| {
                client
                    .put(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    fn delete_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, CliError> {
        self.request_json(
            |client, url, token| {
                client
                    .delete(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            path,
        )
    }

    fn request_internal_get_json<T>(
        &self,
        request_path: &str,
        auth_endpoint: &str,
        term: Option<u64>,
    ) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], request_path);
            let request = if self.cluster_peer_auth.is_some() {
                self.build_internal_get_request(&self.http, &url, auth_endpoint, term)?
            } else {
                self.http
                    .get(&url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token))
            };
            match request.call() {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::Other(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(_, response)) => {
                    last_error = Some(response.into_string().unwrap_or_default());
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(format!("trust control service transport failed: {error}"));
                }
            }
        }
        Err(CliError::Other(last_error.unwrap_or_else(|| {
            "trust control service request failed".to_string()
        })))
    }

    fn request_internal_post_json<T>(
        &self,
        path: &str,
        body: Value,
        term: Option<u64>,
    ) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            let request = if self.cluster_peer_auth.is_some() {
                self.build_internal_post_request(&self.http, &url, path, term)?
            } else {
                self.http
                    .post(&url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token))
            };
            match request.send_json(body.clone()) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::Other(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(_, response)) => {
                    last_error = Some(response.into_string().unwrap_or_default());
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(format!("trust control service transport failed: {error}"));
                }
            }
        }
        Err(CliError::Other(last_error.unwrap_or_else(|| {
            "trust control service request failed".to_string()
        })))
    }

    fn build_internal_get_request(
        &self,
        client: &Agent,
        url: &str,
        endpoint: &str,
        term: Option<u64>,
    ) -> Result<ureq::Request, CliError> {
        let Some(cluster_peer_auth) = self.cluster_peer_auth.as_ref() else {
            return Ok(client
                .get(url)
                .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token)));
        };
        let issued_at = unix_timestamp_now() as i64;
        let signature = cluster_peer_auth_signature(
            &self.token,
            cluster_peer_auth.node_id.as_ref(),
            endpoint,
            issued_at,
            term,
        )?;
        let mut request = client
            .get(url)
            .set(CLUSTER_NODE_ID_HEADER, cluster_peer_auth.node_id.as_ref())
            .set(CLUSTER_AUTH_ISSUED_AT_HEADER, &issued_at.to_string())
            .set(CLUSTER_AUTH_SIGNATURE_HEADER, &signature);
        if let Some(term) = term {
            request = request.set(CLUSTER_AUTH_TERM_HEADER, &term.to_string());
        }
        Ok(request)
    }

    fn build_internal_post_request(
        &self,
        client: &Agent,
        url: &str,
        endpoint: &str,
        term: Option<u64>,
    ) -> Result<ureq::Request, CliError> {
        let Some(cluster_peer_auth) = self.cluster_peer_auth.as_ref() else {
            return Ok(client
                .post(url)
                .set(AUTHORIZATION.as_str(), &format!("Bearer {}", self.token)));
        };
        let issued_at = unix_timestamp_now() as i64;
        let signature = cluster_peer_auth_signature(
            &self.token,
            cluster_peer_auth.node_id.as_ref(),
            endpoint,
            issued_at,
            term,
        )?;
        let mut request = client
            .post(url)
            .set(CLUSTER_NODE_ID_HEADER, cluster_peer_auth.node_id.as_ref())
            .set(CLUSTER_AUTH_ISSUED_AT_HEADER, &issued_at.to_string())
            .set(CLUSTER_AUTH_SIGNATURE_HEADER, &signature);
        if let Some(term) = term {
            request = request.set(CLUSTER_AUTH_TERM_HEADER, &term.to_string());
        }
        Ok(request)
    }

    fn request_json<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url, &self.token) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::Other(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::Other("trust control service request failed with no endpoints".to_string())
        }))
    }

    fn request_json_without_service_auth<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::Other(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::Other("trust control service request failed with no endpoints".to_string())
        }))
    }

    fn request_text_without_service_auth<F>(
        &self,
        request: F,
        path: &str,
    ) -> Result<String, CliError>
    where
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return response.into_string().map_err(|error| {
                        CliError::Other(format!(
                            "failed to decode trust control text response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::Other("trust control service request failed with no endpoints".to_string())
        }))
    }

    fn request_json_with_bearer<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        self.request_json_without_service_auth(request, path)
    }

    fn endpoint_order(&self) -> Vec<usize> {
        let preferred = match self.preferred_index.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        };
        let total = self.endpoints.len();
        (0..total)
            .map(|offset| (preferred + offset) % total)
            .collect()
    }

    fn mark_preferred(&self, index: usize) {
        match self.preferred_index.lock() {
            Ok(mut guard) => *guard = index,
            Err(poisoned) => *poisoned.into_inner() = index,
        }
    }
}

fn certification_marketplace_search_path(query: &CertificationMarketplaceSearchQuery) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    if let Some(tool_server_id) = query.filters.tool_server_id.as_deref() {
        serializer.append_pair("toolServerId", tool_server_id);
    }
    if let Some(criteria_profile) = query.filters.criteria_profile.as_deref() {
        serializer.append_pair("criteriaProfile", criteria_profile);
    }
    if let Some(evidence_profile) = query.filters.evidence_profile.as_deref() {
        serializer.append_pair("evidenceProfile", evidence_profile);
    }
    if let Some(status) = query.filters.status {
        serializer.append_pair("status", status.label());
    }
    if let Some(operator_ids) = query.operator_ids.as_deref() {
        serializer.append_pair("operatorIds", operator_ids);
    }
    let encoded = serializer.finish();
    if encoded.is_empty() {
        CERTIFICATION_DISCOVERY_SEARCH_PATH.to_string()
    } else {
        format!("{CERTIFICATION_DISCOVERY_SEARCH_PATH}?{encoded}")
    }
}

fn certification_marketplace_transparency_path(
    query: &CertificationMarketplaceTransparencyQuery,
) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    if let Some(tool_server_id) = query.filters.tool_server_id.as_deref() {
        serializer.append_pair("toolServerId", tool_server_id);
    }
    if let Some(operator_ids) = query.operator_ids.as_deref() {
        serializer.append_pair("operatorIds", operator_ids);
    }
    let encoded = serializer.finish();
    if encoded.is_empty() {
        CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH.to_string()
    } else {
        format!("{CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH}?{encoded}")
    }
}

impl RemoteCapabilityAuthority {
    pub fn refresh_status(&self) -> Result<(), CliError> {
        let status = self.client.authority_status()?;
        let cache = AuthorityKeyCache::from_status(&status)?;
        match self.cache.lock() {
            Ok(mut guard) => *guard = cache,
            Err(poisoned) => *poisoned.into_inner() = cache,
        }
        Ok(())
    }

    fn refresh_status_if_stale(&self) {
        let should_refresh = match self.cache.lock() {
            Ok(guard) => guard.refreshed_at.elapsed() >= AUTHORITY_CACHE_TTL,
            Err(poisoned) => poisoned.into_inner().refreshed_at.elapsed() >= AUTHORITY_CACHE_TTL,
        };
        if should_refresh {
            let _ = self.refresh_status();
        }
    }
}

impl CapabilityAuthority for RemoteCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.refresh_status_if_stale();
        match self.cache.lock() {
            Ok(guard) => match &guard.current {
                Some(public_key) => public_key.clone(),
                None => unreachable!("remote capability authority cache missing current key"),
            },
            Err(poisoned) => match &poisoned.into_inner().current {
                Some(public_key) => public_key.clone(),
                None => unreachable!("remote capability authority cache missing current key"),
            },
        }
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        self.refresh_status_if_stale();
        match self.cache.lock() {
            Ok(guard) => guard.trusted.clone(),
            Err(poisoned) => poisoned.into_inner().trusted.clone(),
        }
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, None)
    }

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        let capability = self
            .client
            .issue_capability_with_attestation(subject, scope, ttl_seconds, runtime_attestation)
            .map_err(|error| {
                chio_kernel::KernelError::CapabilityIssuanceFailed(error.to_string())
            })?;
        match self.cache.lock() {
            Ok(mut guard) => {
                guard.current = Some(capability.issuer.clone());
                if !guard.trusted.contains(&capability.issuer) {
                    guard.trusted.push(capability.issuer.clone());
                }
                guard.refreshed_at = Instant::now();
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.current = Some(capability.issuer.clone());
                if !guard.trusted.contains(&capability.issuer) {
                    guard.trusted.push(capability.issuer.clone());
                }
                guard.refreshed_at = Instant::now();
            }
        }
        Ok(capability)
    }
}

impl RevocationStore for RemoteRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        self.client
            .list_revocations(&RevocationQuery {
                capability_id: Some(capability_id.to_string()),
                limit: Some(1),
            })
            .map(|response| response.revoked.unwrap_or(false))
            .map_err(into_revocation_store_error)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        self.client
            .revoke_capability(capability_id)
            .map(|response| response.newly_revoked)
            .map_err(into_revocation_store_error)
    }
}

impl ReceiptStore for RemoteReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.client
            .append_tool_receipt(receipt)
            .map_err(into_receipt_store_error)
    }

    fn append_child_receipt(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        self.client
            .append_child_receipt(receipt)
            .map_err(into_receipt_store_error)
    }

    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.client
            .record_capability_snapshot(token, parent_capability_id)
            .map_err(into_receipt_store_error)
    }

    fn resolve_credit_bond(
        &self,
        bond_id: &str,
    ) -> Result<Option<chio_kernel::CreditBondRow>, ReceiptStoreError> {
        self.client
            .list_credit_bonds(&CreditBondListQuery {
                bond_id: Some(bond_id.to_string()),
                facility_id: None,
                capability_id: None,
                agent_subject: None,
                tool_server: None,
                tool_name: None,
                disposition: None,
                lifecycle_state: None,
                limit: Some(1),
            })
            .map(|report| report.bonds.into_iter().next())
            .map_err(into_receipt_store_error)
    }
}

impl BudgetStore for RemoteBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.client
            .try_increment_budget(capability_id, grant_index, max_invocations)
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(response.budget_authority.as_ref(), None),
                    response.invocation_count,
                    None,
                    None,
                );
                response.allowed
            })
            .map_err(into_budget_store_error)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.client
            .try_charge_cost(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
            )
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
                response.allowed
            })
            .map_err(into_budget_store_error)
    }

    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.client
            .try_charge_cost_with_ids(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id,
                event_id,
            )
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
                response.allowed
            })
            .map_err(into_budget_store_error)
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reverse_charge_cost(capability_id, grant_index, cost_units)
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reduce_charge_cost(capability_id, grant_index, cost_units)
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, hold_id, event_id)
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reconcile_budget_spend(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
            )
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reconcile_budget_spend_with_ids(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
                hold_id,
                event_id,
            )
            .map(|response| {
                self.cache_usage(
                    capability_id,
                    grant_index,
                    response_budget_commit_index(
                        response.budget_authority.as_ref(),
                        response.budget_commit.as_ref(),
                    ),
                    response.invocation_count,
                    response.total_cost_exposed,
                    response.total_cost_realized_spend,
                );
            })
            .map_err(into_budget_store_error)
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let response = self
            .client
            .try_charge_cost_with_ids(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.requested_exposure_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
            )
            .map_err(into_budget_store_error)?;
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        let usage = self.cached_usage_or_default(&request.capability_id, request.grant_index);
        let metadata = self.remote_budget_commit_metadata(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
            request.event_id.clone(),
        );
        if response.allowed {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: request.hold_id,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after: usage.committed_cost_units()?,
                    invocation_count_after: usage.invocation_count,
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after: usage.committed_cost_units()?,
                invocation_count_after: usage.invocation_count,
                metadata,
            }))
        }
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let response = self
            .client
            .reverse_charge_cost_with_ids(
                &request.capability_id,
                request.grant_index,
                request.reversed_exposure_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
            )
            .map_err(into_budget_store_error)?;
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        let usage = self.cached_usage_or_default(&request.capability_id, request.grant_index);
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage.committed_cost_units()?,
            invocation_count_after: usage.invocation_count,
            metadata: self.remote_budget_commit_metadata(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
                request.authority.as_ref(),
                request.event_id,
            ),
        })
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let response = self
            .client
            .reduce_charge_cost_with_ids(
                &request.capability_id,
                request.grant_index,
                request.released_exposure_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
            )
            .map_err(into_budget_store_error)?;
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        let usage = self.cached_usage_or_default(&request.capability_id, request.grant_index);
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: usage.committed_cost_units()?,
            invocation_count_after: usage.invocation_count,
            metadata: self.remote_budget_commit_metadata(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
                request.authority.as_ref(),
                request.event_id,
            ),
        })
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let response = self
            .client
            .reconcile_budget_spend_with_ids(
                &request.capability_id,
                request.grant_index,
                request.exposed_cost_units,
                request.realized_spend_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
            )
            .map_err(into_budget_store_error)?;
        self.cache_usage(
            &request.capability_id,
            request.grant_index,
            response_budget_commit_index(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
            ),
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        let usage = self.cached_usage_or_default(&request.capability_id, request.grant_index);
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after: usage.committed_cost_units()?,
            invocation_count_after: usage.invocation_count,
            metadata: self.remote_budget_commit_metadata(
                response.budget_authority.as_ref(),
                response.budget_commit.as_ref(),
                request.authority.as_ref(),
                request.event_id,
            ),
        })
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.client
            .list_budgets(&BudgetQuery {
                capability_id: capability_id.map(ToOwned::to_owned),
                limit: Some(limit),
            })
            .map(|response| {
                let usages: Vec<_> = response
                    .usages
                    .into_iter()
                    .map(|usage| BudgetUsageRecord {
                        capability_id: usage.capability_id,
                        grant_index: usage.grant_index,
                        invocation_count: usage.invocation_count,
                        updated_at: usage.updated_at,
                        seq: usage.seq.unwrap_or(0),
                        total_cost_exposed: usage.total_cost_exposed,
                        total_cost_realized_spend: usage.total_cost_realized_spend,
                    })
                    .collect();
                self.replace_cached_usages(capability_id, &usages);
                usages
            })
            .map_err(into_budget_store_error)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        if let Some(cached) = self.cached_usage(capability_id, grant_index) {
            return Ok(Some(cached));
        }
        self.list_usages(MAX_LIST_LIMIT, Some(capability_id))
            .map(|usages| {
                usages
                    .into_iter()
                    .find(|usage| usage.grant_index == grant_index as u32)
            })
    }
}

impl RemoteBudgetStore {
    fn cache_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
        seq: Option<u64>,
        invocation_count: Option<u32>,
        total_cost_exposed: Option<u64>,
        total_cost_realized_spend: Option<u64>,
    ) {
        let mut cached_usage = match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let key = (capability_id.to_string(), grant_index as u32);
        let updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);

        match (
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        ) {
            (None, None, None) => {
                cached_usage.remove(&key);
            }
            _ => {
                let entry = cached_usage
                    .entry(key)
                    .or_insert_with(|| BudgetUsageRecord {
                        capability_id: capability_id.to_string(),
                        grant_index: grant_index as u32,
                        invocation_count: 0,
                        updated_at,
                        seq: seq.unwrap_or(0),
                        total_cost_exposed: 0,
                        total_cost_realized_spend: 0,
                    });
                if let Some(seq) = seq {
                    entry.seq = seq;
                }
                if let Some(invocation_count) = invocation_count {
                    entry.invocation_count = invocation_count;
                }
                if let Some(total_cost_exposed) = total_cost_exposed {
                    entry.total_cost_exposed = total_cost_exposed;
                }
                if let Some(total_cost_realized_spend) = total_cost_realized_spend {
                    entry.total_cost_realized_spend = total_cost_realized_spend;
                }
                entry.updated_at = updated_at;
            }
        }
    }

    fn cached_usage(&self, capability_id: &str, grant_index: usize) -> Option<BudgetUsageRecord> {
        match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
            .get(&(capability_id.to_string(), grant_index as u32))
            .cloned()
    }

    fn replace_cached_usages(&self, capability_id: Option<&str>, usages: &[BudgetUsageRecord]) {
        let mut cached_usage = match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(capability_id) = capability_id {
            cached_usage
                .retain(|(cached_capability_id, _), _| cached_capability_id != capability_id);
        } else {
            cached_usage.clear();
        }

        for usage in usages {
            cached_usage.insert(
                (usage.capability_id.clone(), usage.grant_index),
                usage.clone(),
            );
        }
    }

    fn cached_usage_or_default(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> BudgetUsageRecord {
        self.cached_usage(capability_id, grant_index)
            .unwrap_or_else(|| BudgetUsageRecord {
                capability_id: capability_id.to_string(),
                grant_index: grant_index as u32,
                invocation_count: 0,
                updated_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs() as i64)
                    .unwrap_or(0),
                seq: 0,
                total_cost_exposed: 0,
                total_cost_realized_spend: 0,
            })
    }

    fn remote_budget_commit_metadata(
        &self,
        authority: Option<&BudgetAuthorityMetadataView>,
        commit: Option<&BudgetWriteCommitView>,
        fallback_authority: Option<&BudgetEventAuthority>,
        event_id: Option<String>,
    ) -> BudgetCommitMetadata {
        BudgetCommitMetadata {
            authority: remote_budget_event_authority(authority, commit)
                .or_else(|| fallback_authority.cloned()),
            guarantee_level: remote_budget_guarantee_level(authority, commit),
            budget_profile: self.budget_authority_profile(),
            metering_profile: self.budget_metering_profile(),
            budget_commit_index: response_budget_commit_index(authority, commit),
            event_id,
        }
    }
}

fn response_budget_commit_index(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
) -> Option<u64> {
    commit
        .map(|commit| commit.commit_index)
        .or_else(|| authority.and_then(|authority| authority.budget_commit_index))
}

fn remote_budget_event_authority(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
) -> Option<BudgetEventAuthority> {
    authority
        .map(|authority| BudgetEventAuthority {
            authority_id: authority.authority_id.clone(),
            lease_id: authority.lease_id.clone(),
            lease_epoch: authority.lease_epoch,
        })
        .or_else(|| {
            commit.map(|commit| BudgetEventAuthority {
                authority_id: commit.authority_id.clone(),
                lease_id: commit.lease_id.clone(),
                lease_epoch: commit.lease_epoch,
            })
        })
}

fn remote_budget_guarantee_level(
    authority: Option<&BudgetAuthorityMetadataView>,
    commit: Option<&BudgetWriteCommitView>,
) -> BudgetGuaranteeLevel {
    match authority.map(|authority| authority.guarantee_level.as_str()) {
        Some("single_node_atomic") => BudgetGuaranteeLevel::SingleNodeAtomic,
        Some("ha_quorum_commit") | Some("ha_linearizable") => BudgetGuaranteeLevel::HaLinearizable,
        Some("partition_escrowed") => BudgetGuaranteeLevel::PartitionEscrowed,
        Some("ha_leader_visible") | Some("advisory_posthoc") => {
            BudgetGuaranteeLevel::AdvisoryPosthoc
        }
        Some(_) => {
            if commit.is_some_and(|commit| commit.quorum_committed) {
                BudgetGuaranteeLevel::HaLinearizable
            } else {
                BudgetGuaranteeLevel::AdvisoryPosthoc
            }
        }
        None => {
            if commit.is_some_and(|commit| commit.quorum_committed) {
                BudgetGuaranteeLevel::HaLinearizable
            } else {
                BudgetGuaranteeLevel::SingleNodeAtomic
            }
        }
    }
}

impl AuthorityKeyCache {
    fn from_status(status: &TrustAuthorityStatus) -> Result<Self, CliError> {
        if !status.configured {
            return Err(CliError::Other(
                "trust control service does not have an authority configured".to_string(),
            ));
        }
        let current = status
            .public_key
            .as_deref()
            .map(PublicKey::from_hex)
            .transpose()?;
        if current.is_none() {
            return Err(CliError::Other(
                "trust control service returned no current authority public key".to_string(),
            ));
        }
        let trusted = status
            .trusted_public_keys
            .iter()
            .map(|value| PublicKey::from_hex(value))
            .collect::<Result<Vec<_>, _>>()?;
        let mut trusted = trusted;
        if let Some(current) = current.as_ref() {
            if !trusted.iter().any(|public_key| public_key == current) {
                trusted.push(current.clone());
            }
        }
        Ok(Self {
            current,
            trusted,
            refreshed_at: Instant::now(),
        })
    }
}

fn should_retry_status(status: u16) -> bool {
    matches!(status, 500 | 502 | 503 | 504)
}

fn into_receipt_store_error(error: CliError) -> ReceiptStoreError {
    ReceiptStoreError::Io(std::io::Error::other(error.to_string()))
}

fn into_revocation_store_error(error: CliError) -> RevocationStoreError {
    RevocationStoreError::Io(std::io::Error::other(error.to_string()))
}

fn into_budget_store_error(error: CliError) -> BudgetStoreError {
    BudgetStoreError::Io(std::io::Error::other(error.to_string()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod service_runtime_tests {
    use super::*;
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
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind static response server");
            let addr = listener.local_addr().expect("server local addr");
            let body = body.to_string();
            let content_type = content_type.to_string();
            let captured = Arc::new(Mutex::new(Vec::new()));
            let captured_requests = Arc::clone(&captured);
            let join = thread::spawn(move || {
                for _ in 0..expected_requests {
                    let (mut stream, _) = listener.accept().expect("accept request");
                    let request = read_http_request(&mut stream);
                    captured_requests
                        .lock()
                        .expect("capture request")
                        .push(request);
                    write!(
                        stream,
                        "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .expect("write response");
                    stream.flush().expect("flush response");
                }
            });
            Self {
                url: format!("http://{addr}"),
                captured,
                join: Some(join),
            }
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.captured.lock().expect("captured requests").clone()
        }
    }

    impl Drop for StaticResponseServer {
        fn drop(&mut self) {
            if let Some(join) = self.join.take() {
                join.join().expect("join response server");
            }
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> CapturedRequest {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut headers_end = None;
        let mut content_length = 0usize;
        loop {
            let read = stream.read(&mut chunk).expect("read HTTP request");
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

        let headers_end = headers_end.expect("HTTP request headers terminator");
        let header_text = String::from_utf8_lossy(&buffer[..headers_end]);
        let mut lines = header_text.split("\r\n").filter(|line| !line.is_empty());
        let request_line = lines.next().expect("request line");
        let mut request_line_parts = request_line.split_whitespace();
        let method = request_line_parts
            .next()
            .expect("request method")
            .to_string();
        let target = request_line_parts
            .next()
            .expect("request target")
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
            .expect("content-type header");
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
            .expect("build client with normalized endpoints");
        assert_eq!(
            client.endpoints.as_ref(),
            &vec!["http://one".to_string(), "http://two".to_string()]
        );
        assert_eq!(client.endpoint_order(), vec![0, 1]);

        client.mark_preferred(1);
        assert_eq!(client.endpoint_order(), vec![1, 0]);
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
            .expect("build failover client");

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
            .expect("retry to healthy endpoint");

        assert_eq!(response["ok"], Value::Bool(true));
        assert_eq!(client.endpoint_order(), vec![1, 0]);
    }

    #[test]
    fn request_text_without_service_auth_reads_text_response() {
        let server = StaticResponseServer::spawn(200, "ready", "text/plain", 1);
        let client = build_client(&server.url, "secret").expect("build text client");

        let body = client
            .request_text_without_service_auth(|agent, url| agent.get(url).call(), "/health")
            .expect("read text response");

        assert_eq!(body, "ready");
    }

    #[test]
    fn trust_control_get_wrappers_encode_queries_and_service_auth() {
        let server = StaticResponseServer::spawn(200, "{}", "application/json", 26);
        let client = build_client(&server.url, "secret").expect("build client");

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
        let client = build_client(&server.url, "secret").expect("build client");

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
        let client = build_client(&server.url, "secret").expect("build client");

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
        let client = build_client(&server.url, "secret").expect("build client");

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
        .expect("parse split budget usage view");

        assert_eq!(usage.capability_id, "cap-budget");
        assert_eq!(usage.grant_index, 3);
        assert_eq!(usage.invocation_count, 4);
        assert_eq!(usage.total_cost_exposed, 75);
        assert_eq!(usage.total_cost_realized_spend, 60);
        assert_eq!(usage.updated_at, 1234);
        assert_eq!(usage.seq, Some(9));

        let encoded = serde_json::to_value(&usage).expect("serialize budget usage view");
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
        let store =
            build_remote_budget_store(&server.url, "secret").expect("build remote budget store");

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
            .expect("authorize remote budget hold");

        let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
            panic!("expected remote authorize to succeed");
        };
        let authority = authorized
            .metadata
            .authority
            .expect("budget authority metadata");
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
            .expect("get cached usage")
            .expect("cached usage record");
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
        .expect("cache from valid status");

        assert_eq!(
            cache.current.as_ref().expect("current key").to_hex(),
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
    fn retry_statuses_and_error_adapters_match_expected_behavior() {
        assert!(should_retry_status(500));
        assert!(should_retry_status(502));
        assert!(should_retry_status(503));
        assert!(should_retry_status(504));
        assert!(!should_retry_status(400));
        assert!(!should_retry_status(401));

        let message = "backend unavailable".to_string();
        let receipt_error = into_receipt_store_error(CliError::Other(message.clone()));
        let revocation_error = into_revocation_store_error(CliError::Other(message.clone()));
        let budget_error = into_budget_store_error(CliError::Other(message.clone()));

        assert!(receipt_error.to_string().contains(&message));
        assert!(revocation_error.to_string().contains(&message));
        assert!(budget_error.to_string().contains(&message));
    }
}
