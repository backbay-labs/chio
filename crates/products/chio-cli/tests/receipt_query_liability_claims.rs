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
fn test_liability_claim_workflow_surfaces() {
    skip_when_loopback_denied!(test_liability_claim_workflow_surfaces);
    run_large_stack_test(
        "test_liability_claim_workflow_surfaces",
        test_liability_claim_workflow_surfaces_inner,
    );
}

fn test_liability_claim_workflow_surfaces_inner() {
    let dir = unique_dir("chio-liability-claims-workflow");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-claims-1";
    let issuer_key = "issuer-liability-claims-1";
    let now = unix_now_secs();
    let mut rc_liability_claims_0_id = String::new();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            let receipt = make_governed_authorization_receipt_with_options(
                &format!("rc-liability-claims-{day}"),
                &format!("cap-liability-claims-{day}"),
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub((day + 2) * 86_400),
                SettlementStatus::Settled,
                "USD",
                4_000,
                "USD",
                false,
                false,
            );
            if day == 0 {
                rc_liability_claims_0_id = receipt.id.clone();
            }
            store
                .append_chio_receipt(&receipt)
                .expect("append liability claim receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-claims-token";
    let mut service = spawn_trust_service(
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
                "receiptLimit": 1000,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue claim backing facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let facility: SignedCreditFacility = facility_issue.json().expect("parse issued facility");
    assert_eq!(
        facility.body.report.disposition,
        chio_core::credit::CreditFacilityDisposition::Grant,
        "unexpected claim workflow facility report: {:?}",
        facility.body.report
    );
    assert!(
        facility.body.report.terms.is_some(),
        "claim workflow facility grant missing terms: {:?}",
        facility.body.report
    );

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-liability-claims-pending-1",
                "cap-liability-claims-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Pending,
                "USD",
                8_000,
                "USD",
                true,
            ))
            .expect("append pending claim receipt");
    }

    let exposure_response = client
        .get(format!("{base_url}/v1/reports/exposure-ledger"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request exposure ledger");
    assert_eq!(exposure_response.status(), reqwest::StatusCode::OK);
    let exposure: SignedExposureLedgerReport = exposure_response
        .json()
        .expect("parse signed exposure ledger");

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 1000,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue liability claim bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse issued bond");

    let rc_liability_claims_failed_1 = make_credit_history_receipt(
        "rc-liability-claims-failed-1",
        "cap-liability-claims-failed-1",
        subject_key,
        issuer_key,
        "ledger",
        "transfer",
        unix_now_secs().saturating_sub(60),
        SettlementStatus::Failed,
        "USD",
        8_500,
        "USD",
        true,
    );
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&rc_liability_claims_failed_1)
            .expect("append failed claim receipt");
    }

    let loss_event =
        record_test_credit_loss_event(&receipt_db_path, &bond, "cll-liability-claims-1", 8_500);

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
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
                "providerId": "carrier-claims",
                "displayName": "Carrier Claims",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-claims.example.com",
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
                    "sourceRef": "liability-claims-runbook",
                    "changeReason": "workflow qualification"
                }
            }
        }))
        .send()
        .expect("issue liability claim provider");
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
            "providerId": "carrier-claims",
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

    let quote_response_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": quote_request,
            "providerQuoteRef": "carrier-claims-quote-1",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 25000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 1200, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue liability quote response");
    assert_eq!(quote_response_response.status(), reqwest::StatusCode::OK);
    let quote_response: SignedLiabilityQuoteResponse = quote_response_response
        .json()
        .expect("parse quote response");

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
            "placementRef": "placement-claims-1"
        }))
        .send()
        .expect("issue liability placement");
    assert_eq!(placement_response.status(), reqwest::StatusCode::OK);
    let placement: SignedLiabilityPlacement = placement_response.json().expect("parse placement");

    let bound_coverage_response = client
        .post(format!("{base_url}/v1/liability/bound-coverages/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "placement": placement,
            "policyNumber": "POL-CLAIMS-1",
            "carrierReference": "bind-claims-1",
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

    let claim_response = client
        .post(format!("{base_url}/v1/liability/claims/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "boundCoverage": bound_coverage,
            "exposure": exposure,
            "bond": bond,
            "lossEvent": loss_event,
            "claimant": "acme@example.com",
            "claimEventAt": requested_effective_from.saturating_add(600),
            "claimAmount": { "units": 20000, "currency": "USD" },
            "claimRef": "CLAIM-1",
            "narrative": "tool execution loss package",
            "receiptIds": [rc_liability_claims_0_id, rc_liability_claims_failed_1.id]
        }))
        .send()
        .expect("issue liability claim");
    assert_eq!(claim_response.status(), reqwest::StatusCode::OK);
    let claim: SignedLiabilityClaimPackage = claim_response.json().expect("parse claim package");
    assert!(claim.verify_signature().expect("verify claim signature"));

    let claim_response_issue = client
        .post(format!("{base_url}/v1/liability/claim-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "claim": claim,
            "providerResponseRef": "claims-response-1",
            "disposition": "accepted",
            "coveredAmount": { "units": 15000, "currency": "USD" },
            "responseNote": "partial acceptance"
        }))
        .send()
        .expect("issue claim response");
    assert_eq!(claim_response_issue.status(), reqwest::StatusCode::OK);
    let provider_response: SignedLiabilityClaimResponse =
        claim_response_issue.json().expect("parse claim response");
    assert!(provider_response
        .verify_signature()
        .expect("verify claim response signature"));

    let dispute_issue = match client
        .post(format!("{base_url}/v1/liability/disputes/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerResponse": provider_response,
            "openedBy": "insured@example.com",
            "reason": "remaining loss not covered",
            "note": "requesting neutral review"
        }))
        .send()
    {
        Ok(response) => response,
        Err(error) => {
            let status = service
                .child
                .try_wait()
                .expect("poll trust service after dispute failure");
            let stderr = read_child_stderr(&mut service.child);
            panic!(
                "issue claim dispute: {error:?}\nservice_status: {status:?}\nservice_stderr:\n{stderr}"
            );
        }
    };
    assert_eq!(dispute_issue.status(), reqwest::StatusCode::OK);
    let dispute: SignedLiabilityClaimDispute = dispute_issue.json().expect("parse claim dispute");
    assert!(dispute
        .verify_signature()
        .expect("verify dispute signature"));

    let roster_policy_path = dir.join("roster-policy.json");
    std::fs::write(
        &roster_policy_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "roster": ["arbiter@example.com"],
            "allowed_decision_rules": ["rule.auto-settle.v1"],
            "roster_anchor": "integration-test-roster-anchor-1"
        }))
        .expect("serialize roster policy"),
    )
    .expect("write roster policy file");

    let adjudication_input_path = dir.join("liability-adjudication.json");
    std::fs::write(
        &adjudication_input_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "dispute": dispute,
            "adjudicator": "arbiter@example.com",
            "outcome": "partial_settlement",
            "awardedAmount": { "units": 18000, "currency": "USD" },
            "decisionRuleRef": "rule.auto-settle.v1",
            "note": "additional evidence supports a larger settlement"
        }))
        .expect("serialize adjudication input"),
    )
    .expect("write adjudication input");

    drop(service);

    let adjudication_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "adjudication-issue",
            "--input-file",
            adjudication_input_path
                .to_str()
                .expect("adjudication input path"),
            "--roster-policy-file",
            roster_policy_path.to_str().expect("roster policy path"),
        ])
        .output()
        .expect("run liability adjudication CLI");
    assert!(
        adjudication_output.status.success(),
        "liability adjudication CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&adjudication_output.stdout),
        String::from_utf8_lossy(&adjudication_output.stderr)
    );
    let adjudication_json =
        String::from_utf8(adjudication_output.stdout).expect("adjudication CLI json");
    assert!(adjudication_json.contains("\"adjudicationId\""));

    let rc_liability_claims_payout_1 = make_governed_authorization_receipt_with_options(
        "rc-liability-claims-payout-1",
        "cap-liability-claims-payout-1",
        subject_key,
        issuer_key,
        "ledger",
        "transfer",
        unix_now_secs().saturating_sub(30),
        SettlementStatus::Settled,
        "USD",
        18_000,
        "USD",
        false,
        false,
    );
    let governed_receipt_id = rc_liability_claims_payout_1.id.as_str();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&rc_liability_claims_payout_1)
            .expect("append settled payout governed receipt");
    }

    let capital_instruction_input_path = dir.join("liability-payout-capital-instruction.json");
    let capital_instruction_now = unix_now_secs();
    let (capital_instruction_authority_chain, capital_instruction_custodian_id) =
        signed_capital_authority_chain(
            CapitalExecutionRole::OperatorTreasury,
            capital_instruction_now.saturating_sub(30),
            capital_instruction_now.saturating_add(3600),
            capital_instruction_now.saturating_sub(20),
            capital_instruction_now.saturating_add(3600),
        );
    std::fs::write(
        &capital_instruction_input_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 1000,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "sourceKind": "facility_commitment",
            "action": "transfer_funds",
            "governedReceiptId": governed_receipt_id,
            "amount": { "units": 18000, "currency": "USD" },
            "authorityChain": capital_instruction_authority_chain,
            "executionWindow": {
                "notBefore": capital_instruction_now.saturating_sub(60),
                "notAfter": capital_instruction_now.saturating_add(3600)
            },
            "rail": {
                "kind": "manual",
                "railId": "claim-payout-manual-1",
                "custodyProviderId": capital_instruction_custodian_id,
                "sourceAccountRef": "facility-claims-main"
            },
            "description": "automatic claim payout transfer"
        }))
        .expect("serialize payout capital instruction"),
    )
    .expect("write payout capital instruction");

    // Bind the governed receipt against the trusted exposure ledger by scoring
    // with the same authority the trust service uses.
    let authority_seed_path = trust_service_authority_seed_path(&receipt_db_path);
    let capital_instruction_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-seed-file",
            authority_seed_path
                .to_str()
                .expect("authority seed file path"),
            "trust",
            "capital-instruction",
            "issue",
            "--input-file",
            capital_instruction_input_path
                .to_str()
                .expect("payout capital instruction path"),
        ])
        .output()
        .expect("run payout capital instruction CLI");
    assert!(
        capital_instruction_output.status.success(),
        "payout capital instruction CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&capital_instruction_output.stdout),
        String::from_utf8_lossy(&capital_instruction_output.stderr)
    );
    let capital_instruction_json =
        String::from_utf8(capital_instruction_output.stdout).expect("capital instruction json");
    assert!(capital_instruction_json.contains("\"instructionId\""));
    assert!(capital_instruction_json.contains("\"transfer_funds\""));
    assert!(capital_instruction_json.contains("\"facility_commitment\""));

    let payout_instruction_input_path = dir.join("liability-payout-instruction.json");
    std::fs::write(
        &payout_instruction_input_path,
        format!(
            "{{\n  \"adjudication\": {adjudication_json},\n  \"capitalInstruction\": {capital_instruction_json},\n  \"note\": \"execute the adjudicated automatic payout\"\n}}\n"
        ),
    )
    .expect("write payout instruction input");

    let payout_instruction_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-payout-instruction-issue",
            "--input-file",
            payout_instruction_input_path
                .to_str()
                .expect("payout instruction input path"),
            "--roster-policy-file",
            roster_policy_path.to_str().expect("roster policy path"),
        ])
        .output()
        .expect("run payout instruction CLI");
    assert!(
        payout_instruction_output.status.success(),
        "payout instruction CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&payout_instruction_output.stdout),
        String::from_utf8_lossy(&payout_instruction_output.stderr)
    );
    let payout_instruction_json =
        String::from_utf8(payout_instruction_output.stdout).expect("payout instruction json");
    assert!(payout_instruction_json.contains("\"payoutInstructionId\""));

    let payout_receipt_input_path = dir.join("liability-payout-receipt.json");
    std::fs::write(
        &payout_receipt_input_path,
        format!(
            "{{\n  \"payoutInstruction\": {payout_instruction_json},\n  \"payoutReceiptRef\": \"claim-payout-confirmation-1\",\n  \"reconciliationState\": \"matched\",\n  \"observedExecution\": {{\n    \"observedAt\": {},\n    \"externalReferenceId\": \"claim-payout-wire-1\",\n    \"amount\": {{ \"units\": 18000, \"currency\": \"USD\" }}\n  }},\n  \"note\": \"custodian matched the payout transfer\"\n}}\n",
            unix_now_secs()
        ),
    )
    .expect("write payout receipt input");

    let payout_receipt_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-payout-receipt-issue",
            "--input-file",
            payout_receipt_input_path
                .to_str()
                .expect("payout receipt input path"),
        ])
        .output()
        .expect("run payout receipt CLI");
    assert!(
        payout_receipt_output.status.success(),
        "payout receipt CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&payout_receipt_output.stdout),
        String::from_utf8_lossy(&payout_receipt_output.stderr)
    );
    let payout_receipt_json =
        String::from_utf8(payout_receipt_output.stdout).expect("payout receipt json");
    assert!(payout_receipt_json.contains("\"payoutReceiptId\""));
    assert!(payout_receipt_json.contains("\"matched\""));

    let stale_settlement_instruction_input_path =
        dir.join("liability-stale-settlement-instruction.json");
    let stale_settlement_now = unix_now_secs();
    let (stale_settlement_authority_chain, stale_settlement_custodian_id) =
        signed_capital_authority_chain(
            CapitalExecutionRole::FacilityProvider,
            stale_settlement_now.saturating_sub(600),
            stale_settlement_now.saturating_sub(10),
            stale_settlement_now.saturating_sub(60),
            stale_settlement_now.saturating_add(3600),
        );
    let stale_settlement_authority_chain_json =
        serde_json::to_string_pretty(&stale_settlement_authority_chain)
            .expect("serialize stale settlement authority chain");
    std::fs::write(
        &stale_settlement_instruction_input_path,
        format!(
            "{{\n  \"payoutReceipt\": {payout_receipt_json},\n  \"capitalBook\": {capital_book_json},\n  \"settlementKind\": \"facility_reimbursement\",\n  \"settlementAmount\": {{ \"units\": 18000, \"currency\": \"USD\" }},\n  \"topology\": {{\n    \"payer\": {{ \"role\": \"facility_provider\", \"partyId\": \"facility-provider-claims-1\" }},\n    \"payee\": {{ \"role\": \"operator_treasury\", \"partyId\": \"operator-treasury-claims-1\" }},\n    \"beneficiary\": {{ \"role\": \"agent_counterparty\", \"partyId\": \"acme@example.com\" }}\n  }},\n  \"authorityChain\": {stale_settlement_authority_chain_json},\n  \"executionWindow\": {{\n    \"notBefore\": {},\n    \"notAfter\": {}\n  }},\n  \"rail\": {{\n    \"kind\": \"wire\",\n    \"railId\": \"claims-settlement-wire-1\",\n    \"custodyProviderId\": \"{stale_settlement_custodian_id}\",\n    \"sourceAccountRef\": \"facility-provider-recovery-1\"\n  }},\n  \"settlementReference\": \"facility-recovery-reference-1\",\n  \"note\": \"reimburse the operator treasury after claim payout\"\n}}\n",
            stale_settlement_now.saturating_sub(120),
            stale_settlement_now.saturating_add(3600)
        ),
    )
    .expect("write stale settlement instruction input");

    let stale_settlement_instruction_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-settlement-instruction-issue",
            "--input-file",
            stale_settlement_instruction_input_path
                .to_str()
                .expect("stale settlement instruction input path"),
            "--roster-policy-file",
            roster_policy_path.to_str().expect("roster policy path"),
        ])
        .output()
        .expect("run stale settlement instruction CLI");
    assert!(
        !stale_settlement_instruction_output.status.success(),
        "stale settlement instruction CLI unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stale_settlement_instruction_output.stdout),
        String::from_utf8_lossy(&stale_settlement_instruction_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&stale_settlement_instruction_output.stderr).contains("stale"),
        "unexpected stale settlement instruction stderr\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stale_settlement_instruction_output.stdout),
        String::from_utf8_lossy(&stale_settlement_instruction_output.stderr)
    );

    let settlement_instruction_input_path = dir.join("liability-settlement-instruction.json");
    let settlement_now = unix_now_secs();
    let (settlement_authority_chain, settlement_custodian_id) = signed_capital_authority_chain(
        CapitalExecutionRole::FacilityProvider,
        settlement_now.saturating_sub(30),
        settlement_now.saturating_add(3600),
        settlement_now.saturating_sub(20),
        settlement_now.saturating_add(3600),
    );
    let settlement_authority_chain_json = serde_json::to_string_pretty(&settlement_authority_chain)
        .expect("serialize settlement authority chain");
    std::fs::write(
        &settlement_instruction_input_path,
        format!(
            "{{\n  \"payoutReceipt\": {payout_receipt_json},\n  \"capitalBook\": {capital_book_json},\n  \"settlementKind\": \"facility_reimbursement\",\n  \"settlementAmount\": {{ \"units\": 18000, \"currency\": \"USD\" }},\n  \"topology\": {{\n    \"payer\": {{ \"role\": \"facility_provider\", \"partyId\": \"facility-provider-claims-1\" }},\n    \"payee\": {{ \"role\": \"operator_treasury\", \"partyId\": \"operator-treasury-claims-1\" }},\n    \"beneficiary\": {{ \"role\": \"agent_counterparty\", \"partyId\": \"acme@example.com\" }}\n  }},\n  \"authorityChain\": {settlement_authority_chain_json},\n  \"executionWindow\": {{\n    \"notBefore\": {},\n    \"notAfter\": {}\n  }},\n  \"rail\": {{\n    \"kind\": \"wire\",\n    \"railId\": \"claims-settlement-wire-1\",\n    \"custodyProviderId\": \"{settlement_custodian_id}\",\n    \"sourceAccountRef\": \"facility-provider-recovery-1\"\n  }},\n  \"settlementReference\": \"facility-recovery-reference-1\",\n  \"note\": \"reimburse the operator treasury after claim payout\"\n}}\n",
            settlement_now.saturating_sub(120),
            settlement_now.saturating_add(3600)
        ),
    )
    .expect("write settlement instruction input");

    let settlement_instruction_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-settlement-instruction-issue",
            "--input-file",
            settlement_instruction_input_path
                .to_str()
                .expect("settlement instruction input path"),
            "--roster-policy-file",
            roster_policy_path.to_str().expect("roster policy path"),
        ])
        .output()
        .expect("run settlement instruction CLI");
    assert!(
        settlement_instruction_output.status.success(),
        "settlement instruction CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&settlement_instruction_output.stdout),
        String::from_utf8_lossy(&settlement_instruction_output.stderr)
    );
    let settlement_instruction_json = String::from_utf8(settlement_instruction_output.stdout)
        .expect("settlement instruction json");
    assert!(settlement_instruction_json.contains("\"settlementInstructionId\""));
    assert!(settlement_instruction_json.contains("\"facility_reimbursement\""));

    let mismatched_settlement_receipt_input_path =
        dir.join("liability-settlement-receipt-mismatched.json");
    std::fs::write(
        &mismatched_settlement_receipt_input_path,
        format!(
            "{{\n  \"settlementInstruction\": {settlement_instruction_json},\n  \"settlementReceiptRef\": \"claim-settlement-confirmation-bad-1\",\n  \"reconciliationState\": \"matched\",\n  \"observedExecution\": {{\n    \"observedAt\": {},\n    \"externalReferenceId\": \"claim-settlement-wire-bad-1\",\n    \"amount\": {{ \"units\": 18000, \"currency\": \"USD\" }}\n  }},\n  \"observedPayerId\": \"unexpected-facility-provider\",\n  \"observedPayeeId\": \"operator-treasury-claims-1\",\n  \"note\": \"this should fail closed because the observed payer does not match\"\n}}\n",
            unix_now_secs()
        ),
    )
    .expect("write mismatched settlement receipt input");

    let mismatched_settlement_receipt_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-settlement-receipt-issue",
            "--input-file",
            mismatched_settlement_receipt_input_path
                .to_str()
                .expect("mismatched settlement receipt input path"),
        ])
        .output()
        .expect("run mismatched settlement receipt CLI");
    assert!(
        !mismatched_settlement_receipt_output.status.success(),
        "mismatched settlement receipt CLI unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mismatched_settlement_receipt_output.stdout),
        String::from_utf8_lossy(&mismatched_settlement_receipt_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&mismatched_settlement_receipt_output.stderr)
            .contains("payer/payee"),
        "unexpected mismatched settlement receipt stderr\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mismatched_settlement_receipt_output.stdout),
        String::from_utf8_lossy(&mismatched_settlement_receipt_output.stderr)
    );

    let settlement_receipt_input_path = dir.join("liability-settlement-receipt.json");
    std::fs::write(
        &settlement_receipt_input_path,
        format!(
            "{{\n  \"settlementInstruction\": {settlement_instruction_json},\n  \"settlementReceiptRef\": \"claim-settlement-confirmation-1\",\n  \"reconciliationState\": \"matched\",\n  \"observedExecution\": {{\n    \"observedAt\": {},\n    \"externalReferenceId\": \"claim-settlement-wire-1\",\n    \"amount\": {{ \"units\": 18000, \"currency\": \"USD\" }}\n  }},\n  \"observedPayerId\": \"facility-provider-claims-1\",\n  \"observedPayeeId\": \"operator-treasury-claims-1\",\n  \"note\": \"facility reimbursement matched the settlement topology\"\n}}\n",
            unix_now_secs()
        ),
    )
    .expect("write settlement receipt input");

    let settlement_receipt_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-settlement-receipt-issue",
            "--input-file",
            settlement_receipt_input_path
                .to_str()
                .expect("settlement receipt input path"),
        ])
        .output()
        .expect("run settlement receipt CLI");
    assert!(
        settlement_receipt_output.status.success(),
        "settlement receipt CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&settlement_receipt_output.stdout),
        String::from_utf8_lossy(&settlement_receipt_output.stderr)
    );
    let settlement_receipt_json =
        String::from_utf8(settlement_receipt_output.stdout).expect("settlement receipt json");
    assert!(settlement_receipt_json.contains("\"settlementReceiptId\""));
    assert!(settlement_receipt_json.contains("\"matched\""));

    let duplicate_payout_receipt_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-payout-receipt-issue",
            "--input-file",
            payout_receipt_input_path
                .to_str()
                .expect("payout receipt input path"),
        ])
        .output()
        .expect("run duplicate payout receipt CLI");
    assert!(
        !duplicate_payout_receipt_output.status.success(),
        "duplicate payout receipt CLI unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&duplicate_payout_receipt_output.stdout),
        String::from_utf8_lossy(&duplicate_payout_receipt_output.stderr)
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "liability-market",
            "claims-list",
            "--policy-number",
            "POL-CLAIMS-1",
        ])
        .output()
        .expect("run liability claims list CLI");
    assert!(
        cli_output.status.success(),
        "liability claims list CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let claims_stdout = String::from_utf8_lossy(&cli_output.stdout);
    assert!(claims_stdout.contains("matching_claims:       1"));
    assert!(claims_stdout.contains("provider_responses:    1"));
    assert!(claims_stdout.contains("disputes:              1"));
    assert!(claims_stdout.contains("adjudications:         1"));
    assert!(claims_stdout.contains("payout_instructions:   1"));
    assert!(claims_stdout.contains("payout_receipts:       1"));
    assert!(claims_stdout.contains("matched_payouts:       1"));
    assert!(claims_stdout.contains("settlement_instructions:1"));
    assert!(claims_stdout.contains("settlement_receipts:   1"));
    assert!(claims_stdout.contains("matched_settlements:   1"));
    assert!(claims_stdout.contains("counterparty_mismatch_settlements:0"));
    assert!(claims_stdout.contains("policy=POL-CLAIMS-1"));
    assert!(claims_stdout.contains("payout_instruction="));
    assert!(claims_stdout.contains("payout_receipt="));
    assert!(claims_stdout.contains("settlement_instruction="));
    assert!(claims_stdout.contains("settlement_receipt="));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_liability_claim_rejects_oversized_claims_and_invalid_disputes() {
    skip_when_loopback_denied!(test_liability_claim_rejects_oversized_claims_and_invalid_disputes);
    let dir = unique_dir("chio-liability-claims-negative");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-claims-negative-1";
    let issuer_key = "issuer-liability-claims-negative-1";
    let now = unix_now_secs();
    let mut rc_liability_claims_negative_1_id = String::new();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..100_u64 {
            let receipt = make_credit_history_receipt(
                &format!("rc-liability-claims-negative-{day}"),
                &format!("cap-liability-claims-negative-{day}"),
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
            );
            if day == 1 {
                rc_liability_claims_negative_1_id = receipt.id.clone();
            }
            store
                .append_chio_receipt(&receipt)
                .expect("append negative liability claim receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-claims-negative-token";
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
                "receiptLimit": 100,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue negative facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-liability-claims-negative-pending-1",
                "cap-liability-claims-negative-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Pending,
                "USD",
                8_000,
                "USD",
                true,
            ))
            .expect("append negative pending receipt");
    }

    let exposure_response = client
        .get(format!("{base_url}/v1/reports/exposure-ledger"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request negative exposure ledger");
    assert_eq!(exposure_response.status(), reqwest::StatusCode::OK);
    let exposure: SignedExposureLedgerReport = exposure_response
        .json()
        .expect("parse negative exposure ledger");

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 100,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue negative bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse negative bond");

    let rc_liability_claims_negative_failed_1 = make_credit_history_receipt(
        "rc-liability-claims-negative-failed-1",
        "cap-liability-claims-negative-failed-1",
        subject_key,
        issuer_key,
        "ledger",
        "transfer",
        unix_now_secs().saturating_sub(60),
        SettlementStatus::Failed,
        "USD",
        7_500,
        "USD",
        true,
    );
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&rc_liability_claims_negative_failed_1)
            .expect("append negative failed receipt");
    }

    let loss_event = record_test_credit_loss_event(
        &receipt_db_path,
        &bond,
        "cll-liability-claims-negative-1",
        7_500,
    );

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request negative provider risk package");
    assert_eq!(risk_package_response.status(), reqwest::StatusCode::OK);
    let risk_package: SignedCreditProviderRiskPackage = risk_package_response
        .json()
        .expect("parse negative provider risk package");

    let provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-claims-negative",
                "displayName": "Carrier Claims Negative",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-claims-negative.example.com",
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
                    "sourceRef": "liability-claims-runbook",
                    "changeReason": "negative qualification"
                }
            }
        }))
        .send()
        .expect("issue negative provider");
    assert_eq!(provider_issue.status(), reqwest::StatusCode::OK);

    let requested_effective_from = unix_now_secs().saturating_add(7_200);
    let requested_effective_until = requested_effective_from.saturating_add(30 * 86_400);
    let quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-claims-negative",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": 20000, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue negative quote request");
    assert_eq!(quote_request_response.status(), reqwest::StatusCode::OK);
    let quote_request: SignedLiabilityQuoteRequest = quote_request_response
        .json()
        .expect("parse negative quote request");

    let quote_response_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": quote_request,
            "providerQuoteRef": "carrier-claims-negative-quote-1",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 20000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 1000, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue negative quote response");
    assert_eq!(quote_response_response.status(), reqwest::StatusCode::OK);
    let quote_response: SignedLiabilityQuoteResponse = quote_response_response
        .json()
        .expect("parse negative quote response");

    let placement_response = client
        .post(format!("{base_url}/v1/liability/placements/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteResponse": quote_response,
            "selectedCoverageAmount": { "units": 20000, "currency": "USD" },
            "selectedPremiumAmount": { "units": 1000, "currency": "USD" },
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "placementRef": "placement-claims-negative-1"
        }))
        .send()
        .expect("issue negative placement");
    assert_eq!(placement_response.status(), reqwest::StatusCode::OK);
    let placement: SignedLiabilityPlacement =
        placement_response.json().expect("parse negative placement");

    let bound_coverage_response = client
        .post(format!("{base_url}/v1/liability/bound-coverages/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "placement": placement,
            "policyNumber": "POL-CLAIMS-NEG-1",
            "carrierReference": "bind-claims-neg-1",
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "coverageAmount": { "units": 20000, "currency": "USD" },
            "premiumAmount": { "units": 1000, "currency": "USD" }
        }))
        .send()
        .expect("issue negative bound coverage");
    assert_eq!(bound_coverage_response.status(), reqwest::StatusCode::OK);
    let bound_coverage: SignedLiabilityBoundCoverage = bound_coverage_response
        .json()
        .expect("parse negative bound coverage");

    let oversized_claim = client
        .post(format!("{base_url}/v1/liability/claims/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "boundCoverage": bound_coverage.clone(),
            "exposure": exposure.clone(),
            "bond": bond.clone(),
            "lossEvent": loss_event.clone(),
            "claimant": "acme@example.com",
            "claimEventAt": requested_effective_from.saturating_add(600),
            "claimAmount": { "units": 25001, "currency": "USD" },
            "claimRef": "CLAIM-NEG-OVERSIZED",
            "narrative": "oversized claim should fail",
            "receiptIds": ["rc-liability-claims-negative-0"]
        }))
        .send()
        .expect("issue oversized claim");
    assert_eq!(oversized_claim.status(), reqwest::StatusCode::BAD_REQUEST);
    let oversized_body: serde_json::Value =
        oversized_claim.json().expect("parse oversized claim body");
    assert!(oversized_body["error"]
        .as_str()
        .expect("oversized claim error")
        .contains("claim_amount cannot exceed bound coverage amount"));

    let valid_claim_response = client
        .post(format!("{base_url}/v1/liability/claims/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "boundCoverage": bound_coverage,
            "exposure": exposure,
            "bond": bond,
            "lossEvent": loss_event,
            "claimant": "acme@example.com",
            "claimEventAt": requested_effective_from.saturating_add(600),
            "claimAmount": { "units": 10000, "currency": "USD" },
            "claimRef": "CLAIM-NEG-VALID",
            "narrative": "valid claim for dispute-state test",
            "receiptIds": [
                rc_liability_claims_negative_1_id,
                rc_liability_claims_negative_failed_1.id
            ]
        }))
        .send()
        .expect("issue valid negative claim");
    assert_eq!(valid_claim_response.status(), reqwest::StatusCode::OK);
    let valid_claim: SignedLiabilityClaimPackage = valid_claim_response
        .json()
        .expect("parse valid negative claim");

    let accepted_response = client
        .post(format!("{base_url}/v1/liability/claim-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "claim": valid_claim,
            "providerResponseRef": "claims-negative-response-1",
            "disposition": "accepted",
            "coveredAmount": { "units": 10000, "currency": "USD" },
            "responseNote": "fully accepted claim"
        }))
        .send()
        .expect("issue fully accepted response");
    assert_eq!(accepted_response.status(), reqwest::StatusCode::OK);
    let accepted_response: SignedLiabilityClaimResponse = accepted_response
        .json()
        .expect("parse fully accepted response");

    let invalid_dispute = client
        .post(format!("{base_url}/v1/liability/disputes/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerResponse": accepted_response,
            "openedBy": "insured@example.com",
            "reason": "should fail because response is fully accepted"
        }))
        .send()
        .expect("issue invalid dispute");
    assert_eq!(invalid_dispute.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid_dispute_body: serde_json::Value =
        invalid_dispute.json().expect("parse invalid dispute body");
    assert!(invalid_dispute_body["error"]
        .as_str()
        .expect("invalid dispute error")
        .contains("denied or partially accepted"));

    let _ = std::fs::remove_dir_all(&dir);
}
