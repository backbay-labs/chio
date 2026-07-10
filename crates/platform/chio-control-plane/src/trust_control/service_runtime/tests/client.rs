use super::super::super::*;
use super::super::client::{
    build_client, build_public_client, certification_marketplace_search_path,
    certification_marketplace_transparency_path, encode_path_segment, path_with_encoded_param,
};
use super::support::{assert_bearer_request, assert_json_post, StaticResponseServer};
use chio_test_support::prelude::*;
use std::collections::BTreeMap;

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

    let search_path = certification_marketplace_search_path(&CertificationMarketplaceSearchQuery {
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

    let transparency_path =
        certification_marketplace_transparency_path(&CertificationMarketplaceTransparencyQuery {
            filters: CertificationTransparencyQuery {
                tool_server_id: Some("tool/server".to_string()),
            },
            operator_ids: Some("alpha,beta".to_string()),
        });
    assert!(transparency_path.starts_with(CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH));
    assert!(transparency_path.contains("toolServerId=tool%2Fserver"));
    assert!(transparency_path.contains("operatorIds=alpha%2Cbeta"));
}

#[test]
fn request_json_retries_retryable_status_and_marks_preferred_endpoint() {
    let retry = StaticResponseServer::spawn(503, "{\"error\":\"retry\"}", "application/json", 1);
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
        receipt_id: None,
        capability_id: Some("cap-2".to_string()),
        tool_server: Some("tool/server".to_string()),
        tool_name: Some("echo".to_string()),
        decision: Some("allow".to_string()),
        limit: Some(3),
    });
    let _ = client.list_child_receipts(&ChildReceiptQuery {
        receipt_id: None,
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

fn sample_tool_receipt(id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 11,
            capability_id: "cap-evicted".to_string(),
            tool_server: "wrapped-http-mock".to_string(),
            tool_name: "echo_json".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"message": "hi"}))
                .test_unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .test_unwrap()
}

fn sample_child_receipt(id: &str) -> ChildRequestReceipt {
    let keypair = Keypair::generate();
    ChildRequestReceipt::sign(
        chio_core::receipt::lineage::ChildRequestReceiptBody {
            id: id.to_string(),
            timestamp: 13,
            session_id: chio_core::session::SessionId::new("sess-evicted".to_string()),
            parent_request_id: chio_core::session::RequestId::new("parent-evicted".to_string()),
            request_id: chio_core::session::RequestId::new("child-evicted".to_string()),
            operation_kind: chio_core::session::OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: "outcome-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .test_unwrap()
}

fn receipt_list_response_body(kind: &str, receipts: Vec<serde_json::Value>) -> String {
    serde_json::to_string(&ReceiptListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        kind: kind.to_string(),
        count: receipts.len(),
        filters: serde_json::json!({ "receiptId": "id" }),
        receipts,
    })
    .test_expect("serialize receipt list response")
}

#[test]
fn remote_receipt_store_point_loads_tool_receipt_by_id() {
    // The RemoteReceiptStore point load must issue a real by-id query over the
    // control-plane protocol and resolve the receipt, so a store-authoritative
    // --control-url deployment can recover a parent receipt evicted from the
    // kernel's bounded mirror.
    let receipt = sample_tool_receipt("receipt-evicted-1");
    // `ChioReceipt::sign` content-addresses the id, so resolve it from the signed
    // receipt rather than the body seed string.
    let expected_id = receipt.id.clone();
    let value = serde_json::to_value(&receipt).test_expect("serialize tool receipt");
    let body = receipt_list_response_body("tool", vec![value]);
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);

    let store = super::super::remote_stores::build_remote_receipt_store(&server.url, "secret")
        .test_expect("build remote receipt store");
    let loaded = store
        .load_chio_receipt(&expected_id)
        .test_expect("point load must not error");
    let loaded = loaded.test_expect("point load must resolve the receipt (Ok(None) before fix)");
    assert_eq!(loaded.id, expected_id);

    // The client must have issued a GET to the tool-receipts endpoint carrying
    // the receiptId point-load filter.
    let requests = server.requests();
    assert_bearer_request(&requests[0], "GET", TOOL_RECEIPTS_PATH, &["receiptId="]);
}

#[test]
fn remote_receipt_store_point_loads_child_receipt_by_id() {
    let receipt = sample_child_receipt("child-receipt-evicted-1");
    let value = serde_json::to_value(&receipt).test_expect("serialize child receipt");
    let body = receipt_list_response_body("child", vec![value]);
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);

    let store = super::super::remote_stores::build_remote_receipt_store(&server.url, "secret")
        .test_expect("build remote receipt store");
    let loaded = store
        .load_child_receipt("child-receipt-evicted-1")
        .test_expect("point load must not error");
    let loaded = loaded.test_expect("point load must resolve the child receipt");
    assert_eq!(loaded.id, "child-receipt-evicted-1");

    let requests = server.requests();
    assert_bearer_request(&requests[0], "GET", CHILD_RECEIPTS_PATH, &["receiptId="]);
}

#[test]
fn remote_receipt_store_point_load_miss_returns_none() {
    // A genuine miss on the remote store resolves to None (fail-closed: the
    // caller then denies the dependent claim), distinct from an error.
    let body = receipt_list_response_body("tool", Vec::new());
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);

    let store = super::super::remote_stores::build_remote_receipt_store(&server.url, "secret")
        .test_expect("build remote receipt store");
    let loaded = store
        .load_chio_receipt("receipt-absent")
        .test_expect("point load must not error on a miss");
    assert!(loaded.is_none(), "a remote miss must resolve to None");
}

#[test]
fn remote_tool_point_load_rejects_mismatched_receipt_id() {
    // A rolling-upgrade or non-conforming control-plane can ignore the
    // `receiptId` filter and return an unrelated receipt as the first row.
    // `has_local_receipt_id` treats any Some(_) as "the requested parent exists",
    // so accepting a mismatched id would let a governed parent-receipt existence
    // check pass on the WRONG receipt. The store must verify the returned id and
    // treat a mismatch as a fail-closed miss.
    let receipt = sample_tool_receipt("actually-returned-receipt");
    let returned_id = receipt.id.clone();
    let value = serde_json::to_value(&receipt).test_expect("serialize tool receipt");
    let body = receipt_list_response_body("tool", vec![value]);
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);

    let store = super::super::remote_stores::build_remote_receipt_store(&server.url, "secret")
        .test_expect("build remote receipt store");
    // Ask for a DIFFERENT id than the server returns.
    let requested_id = format!("{returned_id}-not-this-one");
    let loaded = store
        .load_chio_receipt(&requested_id)
        .test_expect("point load must not error");
    // A mismatched id is a fail-closed miss, not accepted verbatim as the first
    // row.
    assert!(
        loaded.is_none(),
        "a receipt whose id does not match the requested id must be rejected as a miss"
    );
}

#[test]
fn remote_child_point_load_rejects_mismatched_receipt_id() {
    // Same id-verification requirement as the tool point load, for child receipts.
    let receipt = sample_child_receipt("actually-returned-child");
    let value = serde_json::to_value(&receipt).test_expect("serialize child receipt");
    let body = receipt_list_response_body("child", vec![value]);
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);

    let store = super::super::remote_stores::build_remote_receipt_store(&server.url, "secret")
        .test_expect("build remote receipt store");
    let loaded = store
        .load_child_receipt("a-different-child-id")
        .test_expect("point load must not error");
    assert!(
        loaded.is_none(),
        "a child receipt whose id does not match the requested id must be rejected as a miss"
    );
}
