#![allow(clippy::expect_used, clippy::too_many_arguments, clippy::unwrap_used)]

mod support;

use support::receipt_query::*;

macro_rules! skip_when_loopback_denied {
    ($test_name:ident) => {
        if chio_test_support::loopback::skip_when_loopback_bind_denied(stringify!($test_name)) {
            return;
        }
    };
}

#[test]
fn test_liability_market_quote_and_bind_workflow_surfaces() {
    skip_when_loopback_denied!(test_liability_market_quote_and_bind_workflow_surfaces);
    run_large_stack_test(
        "test_liability_market_quote_and_bind_workflow_surfaces",
        test_liability_market_quote_and_bind_workflow_surfaces_inner,
    );
}

fn test_liability_market_quote_and_bind_workflow_surfaces_inner() {
    let dir = unique_dir("chio-liability-market-workflow");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-market-1";
    let issuer_key = "issuer-liability-market-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_credit_history_receipt(
                    &format!("rc-liability-market-{day}"),
                    &format!("cap-liability-market-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    4_000,
                    "USD",
                    true,
                ))
                .expect("append liability-market receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-market-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 120,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let _: SignedCreditFacility = facility_issue.json().expect("parse issued facility");

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "120"),
            ("decisionLimit", "50"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request provider risk package");
    assert_eq!(risk_package_response.status(), reqwest::StatusCode::OK);
    let risk_package: SignedCreditProviderRiskPackage = risk_package_response
        .json()
        .expect("parse provider risk package");

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book report");
    let capital_book_status = capital_book_response.status();
    let capital_book_json = capital_book_response
        .text()
        .expect("read capital book report body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book export failed with body: {capital_book_json}"
    );

    let provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-gamma",
                "displayName": "Carrier Gamma",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-gamma.example.com",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "workflow qualification"
                }
            }
        }))
        .send()
        .expect("issue liability provider");
    assert_eq!(provider_issue.status(), reqwest::StatusCode::OK);
    let _: SignedLiabilityProvider = provider_issue
        .json()
        .expect("parse issued liability provider");

    let requested_effective_from = unix_now_secs().saturating_add(7_200);
    let requested_effective_until = requested_effective_from.saturating_add(30 * 86_400);
    let quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-gamma",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": 25000, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue liability quote request");
    assert_eq!(quote_request_response.status(), reqwest::StatusCode::OK);
    let quote_request: SignedLiabilityQuoteRequest =
        quote_request_response.json().expect("parse quote request");
    assert!(quote_request
        .verify_signature()
        .expect("verify quote request signature"));

    let quote_response_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": quote_request,
            "providerQuoteRef": "carrier-gamma-quote-1",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 25000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 1200, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue liability quote response");
    let quote_response_status = quote_response_response.status();
    let quote_response_body = quote_response_response
        .text()
        .expect("read quote response body");
    assert_eq!(
        quote_response_status,
        reqwest::StatusCode::OK,
        "quote response request failed with body: {quote_response_body}"
    );
    let quote_response: SignedLiabilityQuoteResponse =
        serde_json::from_str(&quote_response_body).expect("parse quote response");
    assert!(quote_response
        .verify_signature()
        .expect("verify quote response signature"));

    let placement_response = client
        .post(format!("{base_url}/v1/liability/placements/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteResponse": quote_response,
            "selectedCoverageAmount": { "units": 25000, "currency": "USD" },
            "selectedPremiumAmount": { "units": 1200, "currency": "USD" },
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "placementRef": "placement-gamma-1"
        }))
        .send()
        .expect("issue liability placement");
    assert_eq!(placement_response.status(), reqwest::StatusCode::OK);
    let placement: SignedLiabilityPlacement = placement_response.json().expect("parse placement");
    assert!(placement
        .verify_signature()
        .expect("verify placement signature"));

    let bound_coverage_response = client
        .post(format!("{base_url}/v1/liability/bound-coverages/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "placement": placement,
            "policyNumber": "POL-GAMMA-1",
            "carrierReference": "bind-gamma-1",
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "coverageAmount": { "units": 25000, "currency": "USD" },
            "premiumAmount": { "units": 1200, "currency": "USD" }
        }))
        .send()
        .expect("issue bound coverage");
    assert_eq!(bound_coverage_response.status(), reqwest::StatusCode::OK);
    let bound_coverage: SignedLiabilityBoundCoverage = bound_coverage_response
        .json()
        .expect("parse bound coverage");
    assert!(bound_coverage
        .verify_signature()
        .expect("verify bound coverage signature"));

    let workflow_response = client
        .get(format!("{base_url}/v1/reports/liability-market"))
        .query(&[
            ("agentSubject", subject_key),
            ("coverageClass", "tool_execution"),
            ("currency", "USD"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("query liability market workflows");
    assert_eq!(workflow_response.status(), reqwest::StatusCode::OK);
    let workflow_report: LiabilityMarketWorkflowReport =
        workflow_response.json().expect("parse workflow report");
    assert_eq!(workflow_report.summary.matching_requests, 1);
    assert_eq!(workflow_report.summary.quote_responses, 1);
    assert_eq!(workflow_report.summary.quoted_responses, 1);
    assert_eq!(workflow_report.summary.placements, 1);
    assert_eq!(workflow_report.summary.bound_coverages, 1);
    let row = workflow_report.workflows.first().expect("workflow row");
    assert_eq!(
        row.quote_request.body.risk_package.body.subject_key,
        subject_key
    );
    assert_eq!(
        row.latest_quote_response
            .as_ref()
            .expect("latest response")
            .body
            .provider_quote_ref,
        "carrier-gamma-quote-1"
    );
    assert_eq!(
        row.bound_coverage
            .as_ref()
            .expect("bound coverage")
            .body
            .policy_number,
        "POL-GAMMA-1"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_liability_market_pricing_authority_and_auto_bind_surfaces() {
    skip_when_loopback_denied!(test_liability_market_pricing_authority_and_auto_bind_surfaces);
    run_large_stack_test(
        "test_liability_market_pricing_authority_and_auto_bind_surfaces",
        test_liability_market_pricing_authority_and_auto_bind_surfaces_inner,
    );
}

fn test_liability_market_pricing_authority_and_auto_bind_surfaces_inner() {
    let dir = unique_dir("chio-liability-market-auto-bind");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-market-auto-bind-1";
    let issuer_key = "issuer-liability-market-auto-bind-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-liability-autobind-{day}"),
                    &format!("cap-liability-autobind-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append liability auto-bind receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-market-auto-bind-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let facility: SignedCreditFacility = facility_issue.json().expect("parse issued facility");
    assert_eq!(
        facility.body.report.disposition,
        chio_core::credit::CreditFacilityDisposition::Grant,
        "unexpected facility report: {:?}",
        facility.body.report
    );
    assert!(
        facility.body.report.terms.is_some(),
        "facility grant missing terms: {:?}",
        facility.body.report
    );

    let underwriting_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200
            }
        }))
        .send()
        .expect("issue underwriting decision");
    assert_eq!(underwriting_issue.status(), reqwest::StatusCode::OK);
    let underwriting_decision: SignedUnderwritingDecision = underwriting_issue
        .json()
        .expect("parse underwriting decision");
    let authority_max_premium = underwriting_decision
        .body
        .premium
        .quoted_amount
        .clone()
        .unwrap_or_else(|| MonetaryAmount {
            units: 25_000,
            currency: "USD".to_string(),
        });
    let quoted_premium_units = authority_max_premium.units.min(1_200);
    assert!(quoted_premium_units > 1);

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "20"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book");
    let capital_book_status = capital_book_response.status();
    let capital_book_body = capital_book_response
        .text()
        .expect("read capital book response body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book request failed with body: {capital_book_body}"
    );
    let capital_book: SignedCapitalBookReport =
        serde_json::from_str(&capital_book_body).expect("parse capital book");
    let facility_source = capital_book
        .body
        .sources
        .iter()
        .find(|source| source.facility_id.as_deref() == Some(facility.body.facility_id.as_str()))
        .expect("capital book facility source");
    let available_coverage_units = facility_source
        .committed_amount
        .as_ref()
        .expect("capital book committed amount")
        .units
        .saturating_sub(
            facility_source
                .disbursed_amount
                .as_ref()
                .map_or(0, |amount| amount.units),
        )
        .saturating_sub(
            facility_source
                .impaired_amount
                .as_ref()
                .map_or(0, |amount| amount.units),
        );
    let requested_coverage_units = available_coverage_units.min(25_000);
    assert!(requested_coverage_units > 0);

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request provider risk package");
    assert_eq!(risk_package_response.status(), reqwest::StatusCode::OK);
    let risk_package: SignedCreditProviderRiskPackage = risk_package_response
        .json()
        .expect("parse provider risk package");

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book report");
    let capital_book_status = capital_book_response.status();
    let capital_book_json = capital_book_response
        .text()
        .expect("read capital book report body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book export failed with body: {capital_book_json}"
    );

    let provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-theta",
                "displayName": "Carrier Theta",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-theta.example.com",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "auto-bind qualification"
                }
            }
        }))
        .send()
        .expect("issue liability provider");
    assert_eq!(provider_issue.status(), reqwest::StatusCode::OK);
    let _: SignedLiabilityProvider = provider_issue
        .json()
        .expect("parse issued liability provider");

    let requested_effective_from = unix_now_secs().saturating_add(7_200);
    let requested_effective_until = requested_effective_from.saturating_add(30 * 86_400);
    let quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-theta",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue liability quote request");
    assert_eq!(quote_request_response.status(), reqwest::StatusCode::OK);
    let quote_request: SignedLiabilityQuoteRequest =
        quote_request_response.json().expect("parse quote request");

    let pricing_authority_response = client
        .post(format!("{base_url}/v1/liability/pricing-authorities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": quote_request,
            "facility": facility,
            "underwritingDecision": underwriting_decision,
            "capitalBook": capital_book,
            "envelope": {
                "kind": "provider_delegate",
                "delegateId": "carrier-theta-underwriter"
            },
            "maxCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
            "maxPremiumAmount": authority_max_premium,
            "expiresAt": unix_now_secs().saturating_add(3000),
            "autoBindEnabled": true
        }))
        .send()
        .expect("issue pricing authority");
    assert_eq!(pricing_authority_response.status(), reqwest::StatusCode::OK);
    let pricing_authority: SignedLiabilityPricingAuthority = pricing_authority_response
        .json()
        .expect("parse pricing authority");
    assert!(pricing_authority
        .verify_signature()
        .expect("verify pricing authority signature"));

    let quote_response_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": pricing_authority.body.quote_request.clone(),
            "providerQuoteRef": "carrier-theta-quote-1",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
                "quotedPremiumAmount": { "units": quoted_premium_units, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue liability quote response");
    let quote_response_status = quote_response_response.status();
    let quote_response_body = quote_response_response
        .text()
        .expect("read quote response body");
    assert_eq!(
        quote_response_status,
        reqwest::StatusCode::OK,
        "quote response request failed with body: {quote_response_body}"
    );
    let quote_response: SignedLiabilityQuoteResponse =
        serde_json::from_str(&quote_response_body).expect("parse quote response");

    let auto_bind_response = client
        .post(format!("{base_url}/v1/liability/auto-bind/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "authority": pricing_authority.clone(),
            "quoteResponse": quote_response.clone(),
            "policyNumber": "POL-THETA-1",
            "carrierReference": "bind-theta-1",
            "placementRef": "placement-theta-auto-1"
        }))
        .send()
        .expect("issue liability auto-bind");
    let auto_bind_status = auto_bind_response.status();
    let auto_bind_body = auto_bind_response
        .text()
        .expect("read auto-bind response body");
    assert_eq!(
        auto_bind_status,
        reqwest::StatusCode::OK,
        "auto-bind request failed with body: {auto_bind_body}"
    );
    let auto_bind: SignedLiabilityAutoBindDecision =
        serde_json::from_str(&auto_bind_body).expect("parse auto-bind decision");
    assert!(auto_bind
        .verify_signature()
        .expect("verify auto-bind signature"));
    assert_eq!(
        auto_bind.body.disposition,
        chio_kernel::LiabilityAutoBindDisposition::AutoBound
    );
    assert!(auto_bind.body.placement.is_some());
    assert!(auto_bind.body.bound_coverage.is_some());

    let workflow_response = client
        .get(format!("{base_url}/v1/reports/liability-market"))
        .query(&[
            ("agentSubject", subject_key),
            ("coverageClass", "tool_execution"),
            ("currency", "USD"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("query liability market workflows");
    let workflow_status = workflow_response.status();
    let workflow_body = workflow_response
        .text()
        .expect("read workflow response body");
    assert_eq!(
        workflow_status,
        reqwest::StatusCode::OK,
        "workflow report request failed with body: {workflow_body}"
    );
    let workflow_report: serde_json::Value =
        serde_json::from_str(&workflow_body).expect("parse workflow report");
    assert_eq!(workflow_report["summary"]["matchingRequests"], 1);
    assert_eq!(workflow_report["summary"]["pricingAuthorities"], 1);
    assert_eq!(workflow_report["summary"]["autoBindDecisions"], 1);
    assert_eq!(workflow_report["summary"]["autoBoundDecisions"], 1);
    assert_eq!(workflow_report["summary"]["placements"], 1);
    assert_eq!(workflow_report["summary"]["boundCoverages"], 1);
    let row = workflow_report["workflows"]
        .as_array()
        .and_then(|rows| rows.first())
        .expect("workflow row");
    assert!(row["pricingAuthority"].is_object());
    assert!(row["latestAutoBindDecision"].is_object());
    assert_eq!(row["boundCoverage"]["body"]["policyNumber"], "POL-THETA-1");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_liability_market_auto_bind_rejects_stale_provider_and_out_of_envelope_quotes() {
    skip_when_loopback_denied!(
        test_liability_market_auto_bind_rejects_stale_provider_and_out_of_envelope_quotes
    );
    run_large_stack_test(
        "test_liability_market_auto_bind_rejects_stale_provider_and_out_of_envelope_quotes",
        test_liability_market_auto_bind_rejects_stale_provider_and_out_of_envelope_quotes_inner,
    );
}

fn test_liability_market_auto_bind_rejects_stale_provider_and_out_of_envelope_quotes_inner() {
    let dir = unique_dir("chio-liability-market-auto-bind-negative");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-market-auto-bind-negative-1";
    let issuer_key = "issuer-liability-market-auto-bind-negative-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            let exposure_units = if day < 10 { 100 } else { 5_000 };
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-liability-autobind-negative-{day}"),
                    &format!("cap-liability-autobind-negative-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    exposure_units,
                    "USD",
                    false,
                    false,
                ))
                .expect("append liability auto-bind negative receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-market-auto-bind-negative-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let initial_facility: SignedCreditFacility = facility_issue.json().expect("parse facility");
    let facility = {
        let issued_at = unix_now_secs();
        let mut report = initial_facility.body.report.clone();
        report.disposition = chio_core::credit::CreditFacilityDisposition::Grant;
        report.prerequisites.manual_review_required = false;
        report.terms = Some(chio_core::credit::CreditFacilityTerms {
            credit_limit: MonetaryAmount {
                units: 1_000_000,
                currency: "USD".to_string(),
            },
            utilization_ceiling_bps: 8_000,
            reserve_ratio_bps: 1_500,
            concentration_cap_bps: 3_000,
            ttl_seconds: 14 * 86_400,
            capital_source: chio_core::credit::CreditFacilityCapitalSource::OperatorInternal,
        });
        let artifact = chio_core::credit::CreditFacilityArtifact {
            schema: chio_core::credit::CREDIT_FACILITY_ARTIFACT_SCHEMA.to_string(),
            facility_id: format!("cfd-phase114-negative-{issued_at}"),
            issued_at,
            expires_at: issued_at.saturating_add(14 * 86_400),
            lifecycle_state: chio_core::credit::CreditFacilityLifecycleState::Active,
            supersedes_facility_id: Some(initial_facility.body.facility_id.clone()),
            report,
        };
        let signed = SignedCreditFacility::sign(artifact, &Keypair::generate())
            .expect("sign controlled grant facility");
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .record_credit_facility(&signed)
            .expect("record controlled grant facility");
        signed
    };

    let underwriting_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200
            }
        }))
        .send()
        .expect("issue underwriting decision");
    assert_eq!(underwriting_issue.status(), reqwest::StatusCode::OK);
    let underwriting_decision: SignedUnderwritingDecision = underwriting_issue
        .json()
        .expect("parse underwriting decision");
    let authority_max_premium = underwriting_decision
        .body
        .premium
        .quoted_amount
        .clone()
        .unwrap_or_else(|| MonetaryAmount {
            units: 25_000,
            currency: "USD".to_string(),
        });
    let quoted_premium_units = authority_max_premium.units.min(1_200);
    assert!(quoted_premium_units > 1);

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book");
    let capital_book_status = capital_book_response.status();
    let capital_book_body = capital_book_response
        .text()
        .expect("read capital book response body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book request failed with body: {capital_book_body}"
    );
    let capital_book: SignedCapitalBookReport =
        serde_json::from_str(&capital_book_body).expect("parse capital book");
    let facility_source = capital_book
        .body
        .sources
        .iter()
        .find(|source| source.facility_id.as_deref() == Some(facility.body.facility_id.as_str()))
        .expect("capital book facility source");
    let available_coverage_units = facility_source
        .committed_amount
        .as_ref()
        .expect("capital book committed amount")
        .units
        .saturating_sub(
            facility_source
                .disbursed_amount
                .as_ref()
                .map_or(0, |amount| amount.units),
        )
        .saturating_sub(
            facility_source
                .impaired_amount
                .as_ref()
                .map_or(0, |amount| amount.units),
        );
    let requested_coverage_units = available_coverage_units.min(20_000);
    assert!(requested_coverage_units > 0);

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request provider risk package");
    assert_eq!(risk_package_response.status(), reqwest::StatusCode::OK);
    let risk_package: SignedCreditProviderRiskPackage = risk_package_response
        .json()
        .expect("parse provider risk package");

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book report");
    let capital_book_status = capital_book_response.status();
    let capital_book_json = capital_book_response
        .text()
        .expect("read capital book report body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book export failed with body: {capital_book_json}"
    );

    let provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-iota",
                "displayName": "Carrier Iota",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-iota.example.com",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "auto-bind negative qualification"
                }
            }
        }))
        .send()
        .expect("issue liability provider");
    assert_eq!(provider_issue.status(), reqwest::StatusCode::OK);
    let initial_provider: SignedLiabilityProvider =
        provider_issue.json().expect("parse initial provider");

    let requested_effective_from = unix_now_secs().saturating_add(3_600);
    let requested_effective_until = requested_effective_from.saturating_add(14 * 86_400);
    let quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-iota",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue liability quote request");
    assert_eq!(quote_request_response.status(), reqwest::StatusCode::OK);
    let quote_request: SignedLiabilityQuoteRequest =
        quote_request_response.json().expect("parse quote request");

    let pricing_authority_response = client
        .post(format!("{base_url}/v1/liability/pricing-authorities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": quote_request,
            "facility": facility,
            "underwritingDecision": underwriting_decision,
            "capitalBook": capital_book,
            "envelope": {
                "kind": "provider_delegate",
                "delegateId": "carrier-iota-underwriter"
            },
            "maxCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
            "maxPremiumAmount": { "units": quoted_premium_units - 1, "currency": "USD" },
            "expiresAt": unix_now_secs().saturating_add(3000),
            "autoBindEnabled": true
        }))
        .send()
        .expect("issue pricing authority");
    assert_eq!(pricing_authority_response.status(), reqwest::StatusCode::OK);
    let pricing_authority: SignedLiabilityPricingAuthority = pricing_authority_response
        .json()
        .expect("parse pricing authority");

    let quote_response_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": pricing_authority.body.quote_request.clone(),
            "providerQuoteRef": "carrier-iota-quote-1",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
                "quotedPremiumAmount": { "units": quoted_premium_units, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue liability quote response");
    assert_eq!(quote_response_response.status(), reqwest::StatusCode::OK);
    let quote_response: SignedLiabilityQuoteResponse = quote_response_response
        .json()
        .expect("parse quote response");

    let excessive_auto_bind = client
        .post(format!("{base_url}/v1/liability/auto-bind/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "authority": pricing_authority.clone(),
            "quoteResponse": quote_response.clone(),
            "policyNumber": "POL-IOTA-1"
        }))
        .send()
        .expect("issue excessive auto-bind");
    assert_eq!(excessive_auto_bind.status(), reqwest::StatusCode::CONFLICT);
    let excessive_body: serde_json::Value = excessive_auto_bind
        .json()
        .expect("parse excessive auto-bind body");
    assert!(excessive_body["error"]
        .as_str()
        .expect("excessive auto-bind error")
        .contains("pricing authority ceiling"));

    let superseding_provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-iota",
                "displayName": "Carrier Iota",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-iota.example.com/v2",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "superseding provider record"
                }
            },
            "supersedesProviderRecordId": initial_provider.body.provider_record_id
        }))
        .send()
        .expect("issue superseding provider");
    assert_eq!(superseding_provider_issue.status(), reqwest::StatusCode::OK);

    let stale_input_path = dir.join("stale-auto-bind.json");
    std::fs::write(
        &stale_input_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "authority": pricing_authority,
            "quoteResponse": quote_response,
            "policyNumber": "POL-IOTA-STALE-1"
        }))
        .expect("serialize stale auto-bind input"),
    )
    .expect("write stale auto-bind input");
    let stale_auto_bind = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "auto-bind-issue",
            "--input-file",
            stale_input_path.to_str().expect("stale input path"),
        ])
        .output()
        .expect("run stale auto-bind CLI");
    assert!(
        !stale_auto_bind.status.success(),
        "stale auto-bind CLI unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stale_auto_bind.stdout),
        String::from_utf8_lossy(&stale_auto_bind.stderr)
    );
    let stale_stdout = String::from_utf8_lossy(&stale_auto_bind.stdout);
    let stale_stderr = String::from_utf8_lossy(&stale_auto_bind.stderr);
    assert!(
        stale_stderr.contains("stale provider record"),
        "unexpected stale auto-bind CLI failure\nstdout:\n{stale_stdout}\nstderr:\n{stale_stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_liability_market_rejects_stale_provider_expired_quote_and_placement_mismatch() {
    skip_when_loopback_denied!(
        test_liability_market_rejects_stale_provider_expired_quote_and_placement_mismatch
    );
    run_large_stack_test(
        "test_liability_market_rejects_stale_provider_expired_quote_and_placement_mismatch",
        test_liability_market_rejects_stale_provider_expired_quote_and_placement_mismatch_inner,
    );
}

fn test_liability_market_rejects_stale_provider_expired_quote_and_placement_mismatch_inner() {
    let dir = unique_dir("chio-liability-market-negative");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-market-negative-1";
    let issuer_key = "issuer-liability-market-negative-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_credit_history_receipt(
                    &format!("rc-liability-negative-{day}"),
                    &format!("cap-liability-negative-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    true,
                ))
                .expect("append liability-negative receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-market-negative-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 90,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "90"),
            ("decisionLimit", "50"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request provider risk package");
    assert_eq!(risk_package_response.status(), reqwest::StatusCode::OK);
    let risk_package: SignedCreditProviderRiskPackage = risk_package_response
        .json()
        .expect("parse provider risk package");

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book report");
    let capital_book_status = capital_book_response.status();
    let capital_book_json = capital_book_response
        .text()
        .expect("read capital book report body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book export failed with body: {capital_book_json}"
    );

    let provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-delta",
                "displayName": "Carrier Delta",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-delta.example.com",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "negative test provider admission"
                }
            }
        }))
        .send()
        .expect("issue liability provider");
    assert_eq!(provider_issue.status(), reqwest::StatusCode::OK);
    let initial_provider: SignedLiabilityProvider = provider_issue
        .json()
        .expect("parse initial liability provider");

    let requested_effective_from = unix_now_secs().saturating_add(3_600);
    let requested_effective_until = requested_effective_from.saturating_add(14 * 86_400);
    let initial_quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-delta",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": 20000, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue initial quote request");
    assert_eq!(
        initial_quote_request_response.status(),
        reqwest::StatusCode::OK
    );
    let initial_quote_request: SignedLiabilityQuoteRequest = initial_quote_request_response
        .json()
        .expect("parse initial quote request");

    let superseding_provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-delta",
                "displayName": "Carrier Delta",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-delta.example.com/v2",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "superseding provider record"
                }
            },
            "supersedesProviderRecordId": initial_provider.body.provider_record_id
        }))
        .send()
        .expect("issue superseding provider");
    assert_eq!(superseding_provider_issue.status(), reqwest::StatusCode::OK);

    let stale_quote_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": initial_quote_request,
            "providerQuoteRef": "carrier-delta-stale",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 20000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 900, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue stale quote response");
    assert_eq!(stale_quote_response.status(), reqwest::StatusCode::CONFLICT);
    let stale_body: serde_json::Value = stale_quote_response
        .json()
        .expect("parse stale response body");
    assert!(stale_body["error"]
        .as_str()
        .expect("stale response error")
        .contains("stale provider record"));

    let fresh_quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-delta",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": 22000, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue fresh quote request");
    assert_eq!(
        fresh_quote_request_response.status(),
        reqwest::StatusCode::OK
    );
    let fresh_quote_request: SignedLiabilityQuoteRequest = fresh_quote_request_response
        .json()
        .expect("parse fresh quote request");

    let expiring_quote_expires_at = unix_now_secs().saturating_add(15);
    let expiring_quote_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": fresh_quote_request,
            "providerQuoteRef": "carrier-delta-expiring",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 22000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 950, "currency": "USD" },
                "expiresAt": expiring_quote_expires_at
            }
        }))
        .send()
        .expect("issue expiring quote response");
    assert_eq!(expiring_quote_response.status(), reqwest::StatusCode::OK);
    let expiring_quote_response: SignedLiabilityQuoteResponse = expiring_quote_response
        .json()
        .expect("parse expiring quote response");

    let sleep_until_expired = expiring_quote_response
        .body
        .quoted_terms
        .as_ref()
        .expect("expiring quote response should carry quoted terms")
        .expires_at
        .saturating_sub(unix_now_secs())
        .saturating_add(1);
    thread::sleep(Duration::from_secs(sleep_until_expired));

    let expired_placement = client
        .post(format!("{base_url}/v1/liability/placements/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteResponse": expiring_quote_response,
            "selectedCoverageAmount": { "units": 22000, "currency": "USD" },
            "selectedPremiumAmount": { "units": 950, "currency": "USD" },
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "placementRef": "expired-placement"
        }))
        .send()
        .expect("issue expired placement");
    assert_eq!(expired_placement.status(), reqwest::StatusCode::CONFLICT);
    let expired_body: serde_json::Value = expired_placement
        .json()
        .expect("parse expired placement body");
    assert!(
        expired_body["error"]
            .as_str()
            .expect("expired placement error")
            .contains("quote expires")
            || expired_body["error"]
                .as_str()
                .expect("expired placement error")
                .contains("after the quote expires")
    );

    let mismatch_quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-delta",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": 23000, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue mismatch quote request");
    assert_eq!(
        mismatch_quote_request_response.status(),
        reqwest::StatusCode::OK
    );
    let mismatch_quote_request: SignedLiabilityQuoteRequest = mismatch_quote_request_response
        .json()
        .expect("parse mismatch quote request");

    let mismatch_quote_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": mismatch_quote_request,
            "providerQuoteRef": "carrier-delta-mismatch",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 23000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 975, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue mismatch quote response");
    assert_eq!(mismatch_quote_response.status(), reqwest::StatusCode::OK);
    let mismatch_quote_response: SignedLiabilityQuoteResponse = mismatch_quote_response
        .json()
        .expect("parse mismatch quote response");

    let mismatched_placement = client
        .post(format!("{base_url}/v1/liability/placements/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteResponse": mismatch_quote_response,
            "selectedCoverageAmount": { "units": 22000, "currency": "USD" },
            "selectedPremiumAmount": { "units": 975, "currency": "USD" },
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "placementRef": "mismatched-placement"
        }))
        .send()
        .expect("issue mismatched placement");
    assert_eq!(mismatched_placement.status(), reqwest::StatusCode::CONFLICT);
    let mismatch_body: serde_json::Value = mismatched_placement
        .json()
        .expect("parse mismatched placement body");
    assert!(mismatch_body["error"]
        .as_str()
        .expect("mismatched placement error")
        .contains("must match"));

    let _ = std::fs::remove_dir_all(&dir);
}
