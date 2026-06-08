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
fn test_underwriting_policy_input_export_surfaces() {
    skip_when_loopback_denied!(test_underwriting_policy_input_export_surfaces);
    let dir = unique_dir("chio-underwriting-input");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-1";
    let issuer_key = "issuer-underwrite-1";
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-underwrite-1",
                "cap-underwrite-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                6_000,
            ))
            .expect("append governed underwriting receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-input-token";
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

    let response = client
        .get(format!("{base_url}/v1/reports/underwriting-input"))
        .query(&[
            ("agentSubject", subject_key),
            ("toolServer", "ledger"),
            ("toolName", "transfer"),
            ("receiptLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send underwriting input request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let input: SignedUnderwritingPolicyInput =
        response.json().expect("parse signed underwriting input");
    assert!(input
        .verify_signature()
        .expect("verify underwriting input signature"));
    assert_eq!(input.body.schema, "chio.underwriting.policy-input.v1");
    assert_eq!(input.body.filters.receipt_limit, Some(10));
    assert_eq!(input.body.receipts.matching_receipts, 1);
    assert_eq!(input.body.receipts.runtime_assurance_receipts, 1);
    assert_eq!(input.body.receipts.call_chain_receipts, 1);
    assert_eq!(input.body.receipts.metered_receipts, 1);
    assert_eq!(
        input
            .body
            .runtime_assurance
            .as_ref()
            .expect("runtime assurance summary")
            .highest_tier,
        Some(RuntimeAssuranceTier::Verified)
    );
    assert_eq!(
        input
            .body
            .certification
            .as_ref()
            .expect("certification summary")
            .state,
        chio_core::underwriting::UnderwritingCertificationState::Unavailable
    );
    let reasons = input
        .body
        .signals
        .iter()
        .map(|signal| signal.reason)
        .collect::<Vec<_>>();
    assert!(reasons.contains(&chio_core::underwriting::UnderwritingReasonCode::ProbationaryHistory));
    assert!(
        reasons.contains(&chio_core::underwriting::UnderwritingReasonCode::MissingCertification)
    );
    assert!(
        reasons.contains(&chio_core::underwriting::UnderwritingReasonCode::MeteredBillingMismatch)
    );
    assert!(reasons.contains(&chio_core::underwriting::UnderwritingReasonCode::DelegatedCallChain));

    // Sign the CLI export with the same authority the trust service uses so the
    // signer keys match below.
    let authority_seed_path = trust_service_authority_seed_path(&receipt_db_path);
    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-seed-file",
            authority_seed_path
                .to_str()
                .expect("authority seed file path"),
            "trust",
            "underwriting-input",
            "export",
            "--agent-subject",
            subject_key,
            "--tool-server",
            "ledger",
            "--tool-name",
            "transfer",
            "--receipt-limit",
            "10",
        ])
        .output()
        .expect("run underwriting input CLI");
    assert!(
        cli_output.status.success(),
        "underwriting input CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_input: SignedUnderwritingPolicyInput =
        serde_json::from_slice(&cli_output.stdout).expect("parse underwriting input CLI json");
    assert!(cli_input
        .verify_signature()
        .expect("verify underwriting input CLI signature"));
    assert_eq!(cli_input.body.schema, "chio.underwriting.policy-input.v1");
    assert_eq!(cli_input.body.receipts.matching_receipts, 1);
    assert_eq!(cli_input.signer_key, input.signer_key);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_policy_input_requires_anchor() {
    skip_when_loopback_denied!(test_underwriting_policy_input_requires_anchor);
    let setup = setup_with_receipts("chio-underwriting-anchor");

    let response = setup
        .client
        .get(format!("{}/v1/reports/underwriting-input", setup.base_url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send underwriting input request without anchor");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().expect("parse underwriting input error");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("at least one anchor"));

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_underwriting_decision_report_surfaces() {
    skip_when_loopback_denied!(test_underwriting_decision_report_surfaces);
    let dir = unique_dir("chio-underwriting-decision");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-decision-1";
    let issuer_key = "issuer-underwrite-decision-1";
    let timestamp = unix_now_secs().saturating_sub(60);
    let rc_decision_1 = make_governed_authorization_receipt(
        "rc-decision-1",
        "cap-decision-1",
        subject_key,
        issuer_key,
        "ledger",
        "transfer",
        timestamp,
    );
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&rc_decision_1)
            .expect("append governed underwriting decision receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-decision-token";
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

    let response = client
        .get(format!("{base_url}/v1/reports/underwriting-decision"))
        .query(&[("agentSubject", subject_key), ("receiptLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send underwriting decision request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingDecisionReport =
        response.json().expect("parse underwriting decision report");
    assert_eq!(report.schema, "chio.underwriting.decision-report.v1");
    assert_eq!(
        report.outcome,
        chio_core::underwriting::UnderwritingDecisionOutcome::ReduceCeiling
    );
    assert_eq!(report.suggested_ceiling_factor, Some(0.5));
    assert_eq!(report.input.receipts.matching_receipts, 1);
    let metered_finding = report
        .findings
        .iter()
        .find(|finding| {
            finding.signal_reason
                == Some(chio_core::underwriting::UnderwritingReasonCode::MeteredBillingMismatch)
        })
        .expect("metered finding");
    assert!(!metered_finding.evidence_refs.is_empty());
    assert_eq!(
        metered_finding.evidence_refs[0].kind,
        chio_core::underwriting::UnderwritingEvidenceKind::MeteredBillingReconciliation
    );
    let call_chain_finding = report
        .findings
        .iter()
        .find(|finding| {
            finding.signal_reason
                == Some(chio_core::underwriting::UnderwritingReasonCode::DelegatedCallChain)
        })
        .expect("call-chain finding");
    assert!(!call_chain_finding.evidence_refs.is_empty());
    assert_eq!(
        call_chain_finding.evidence_refs[0].reference_id,
        rc_decision_1.id
    );

    // Score the CLI evaluation against the same trusted kernel key as the
    // service so the seeded receipt is visible and outcomes match.
    let authority_seed_path = trust_service_authority_seed_path(&receipt_db_path);
    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-seed-file",
            authority_seed_path
                .to_str()
                .expect("authority seed file path"),
            "trust",
            "underwriting-decision",
            "evaluate",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "10",
        ])
        .output()
        .expect("run underwriting decision CLI");
    assert!(
        cli_output.status.success(),
        "underwriting decision CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: UnderwritingDecisionReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse underwriting decision CLI json");
    assert_eq!(cli_report.schema, "chio.underwriting.decision-report.v1");
    assert_eq!(cli_report.outcome, report.outcome);
    assert_eq!(cli_report.policy.version, report.policy.version);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_decision_steps_up_without_receipt_history() {
    skip_when_loopback_denied!(test_underwriting_decision_steps_up_without_receipt_history);
    let setup = setup_with_receipts("chio-underwriting-decision-empty");

    let response = setup
        .client
        .get(format!(
            "{}/v1/reports/underwriting-decision",
            setup.base_url
        ))
        .query(&[("capabilityId", "cap-missing")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send underwriting decision request without history");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingDecisionReport =
        response.json().expect("parse underwriting decision report");
    assert_eq!(
        report.outcome,
        chio_core::underwriting::UnderwritingDecisionOutcome::StepUp
    );
    assert!(report.findings.iter().any(|finding| {
        finding.reason
            == chio_core::underwriting::UnderwritingDecisionReasonCode::InsufficientReceiptHistory
    }));

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_underwriting_decision_requires_anchor() {
    skip_when_loopback_denied!(test_underwriting_decision_requires_anchor);
    let setup = setup_with_receipts("chio-underwriting-decision-anchor");

    let response = setup
        .client
        .get(format!(
            "{}/v1/reports/underwriting-decision",
            setup.base_url
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send underwriting decision request without anchor");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response
        .json()
        .expect("parse underwriting decision error response");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("at least one anchor"));

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_underwriting_decision_issue_requires_anchor() {
    skip_when_loopback_denied!(test_underwriting_decision_issue_requires_anchor);
    let setup = setup_with_receipts("chio-underwriting-issue-anchor");

    let response = setup
        .client
        .post(format!(
            "{}/v1/underwriting/decisions/issue",
            setup.base_url
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .json(&serde_json::json!({
            "query": {
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send underwriting issue request without anchor");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response
        .json()
        .expect("parse underwriting decision issue error response");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("at least one anchor"));

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_underwriting_decision_links_failed_settlement_evidence() {
    skip_when_loopback_denied!(test_underwriting_decision_links_failed_settlement_evidence);
    let dir = unique_dir("chio-underwriting-failed-settlement");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let rc_failed_settlement_1 = make_governed_authorization_receipt_with_options(
        "rc-failed-settlement-1",
        "cap-failed-settlement-1",
        "subject-failed-settlement-1",
        "issuer-failed-settlement-1",
        "ledger",
        "transfer",
        unix_now_secs().saturating_sub(60),
        SettlementStatus::Failed,
        "USD",
        4_200,
        "USD",
        false,
        false,
    );
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&rc_failed_settlement_1)
            .expect("append failed settlement underwriting receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-failed-settlement-token";
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

    let response = client
        .get(format!("{base_url}/v1/reports/underwriting-decision"))
        .query(&[
            ("agentSubject", "subject-failed-settlement-1"),
            ("receiptLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send underwriting decision request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingDecisionReport =
        response.json().expect("parse underwriting decision report");
    let failed_settlement_finding = report
        .findings
        .iter()
        .find(|finding| {
            finding.signal_reason
                == Some(chio_core::underwriting::UnderwritingReasonCode::FailedSettlementExposure)
        })
        .expect("failed settlement finding");
    assert_eq!(
        failed_settlement_finding.evidence_refs[0].kind,
        chio_core::underwriting::UnderwritingEvidenceKind::SettlementReconciliation
    );
    assert_eq!(
        failed_settlement_finding.evidence_refs[0].reference_id,
        rc_failed_settlement_1.id
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_simulation_report_surfaces() {
    skip_when_loopback_denied!(test_underwriting_simulation_report_surfaces);
    let dir = unique_dir("chio-underwriting-simulation");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let policy_file = dir.join("underwriting-policy.yaml");

    let subject_key = "subject-underwrite-sim-1";
    let issuer_key = "issuer-underwrite-sim-1";
    let base_timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..=14_u64 {
            store
                .append_chio_receipt(&make_underwriting_simulation_receipt(
                    &format!("rc-sim-{day}"),
                    "cap-sim-1",
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    base_timestamp.saturating_sub(day * 86_400),
                    RuntimeAssuranceTier::Attested,
                ))
                .expect("append underwriting simulation receipt");
        }
    }

    let simulation_policy = chio_kernel::UnderwritingDecisionPolicy {
        version: "chio.underwriting.decision-policy.simulated-history-floor.v1".to_string(),
        minimum_receipt_history: 30,
        ..chio_kernel::UnderwritingDecisionPolicy::default()
    };
    std::fs::write(
        &policy_file,
        serde_yml::to_string(&simulation_policy).expect("serialize simulation policy"),
    )
    .expect("write simulation policy");

    let listen = reserve_listen_addr();
    let service_token = "underwriting-simulation-token";
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

    let response = client
        .post(format!("{base_url}/v1/reports/underwriting-simulation"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 20
            },
            "policy": simulation_policy
        }))
        .send()
        .expect("send underwriting simulation request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingSimulationReport = response
        .json()
        .expect("parse underwriting simulation report");
    assert_eq!(report.schema, "chio.underwriting.simulation-report.v1");
    assert_eq!(
        report.default_evaluation.outcome,
        chio_core::underwriting::UnderwritingDecisionOutcome::ReduceCeiling
    );
    assert_eq!(
        report.simulated_evaluation.outcome,
        chio_core::underwriting::UnderwritingDecisionOutcome::StepUp
    );
    assert!(report.delta.outcome_changed);
    assert!(report
        .delta
        .added_reasons
        .contains(&"insufficient_receipt_history".to_string()));

    // Score the CLI simulation against the same trusted kernel key as the
    // service so the seeded receipts pass reputation integrity validation.
    let authority_seed_path = trust_service_authority_seed_path(&receipt_db_path);
    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-seed-file",
            authority_seed_path
                .to_str()
                .expect("authority seed file path"),
            "trust",
            "underwriting-decision",
            "simulate",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "20",
            "--policy-file",
            policy_file.to_str().expect("policy path"),
        ])
        .output()
        .expect("run underwriting simulation CLI");
    assert!(
        cli_output.status.success(),
        "underwriting simulation CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: UnderwritingSimulationReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse underwriting simulation CLI");
    assert_eq!(
        cli_report.simulated_evaluation.outcome,
        report.simulated_evaluation.outcome
    );
    assert_eq!(
        cli_report.delta.outcome_changed,
        report.delta.outcome_changed
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_decision_issue_and_list_surfaces() {
    skip_when_loopback_denied!(test_underwriting_decision_issue_and_list_surfaces);
    let dir = unique_dir("chio-underwriting-issue");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-issue-1";
    let issuer_key = "issuer-underwrite-issue-1";
    let timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-issue-1",
                "cap-issue-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp,
            ))
            .expect("append governed underwriting issue receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-issue-token";
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

    let remote_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send underwriting decision issue request");
    assert_eq!(remote_issue.status(), reqwest::StatusCode::OK);
    let remote_decision: SignedUnderwritingDecision = remote_issue
        .json()
        .expect("parse signed underwriting decision");
    assert!(remote_decision
        .verify_signature()
        .expect("verify signed underwriting decision"));
    assert_eq!(remote_decision.body.schema, "chio.underwriting.decision.v1");
    assert_eq!(
        remote_decision.body.review_state,
        chio_core::underwriting::UnderwritingReviewState::Approved
    );
    assert_eq!(
        remote_decision.body.budget.action,
        chio_core::underwriting::UnderwritingBudgetAction::Reduce
    );
    assert_eq!(
        remote_decision
            .body
            .premium
            .quoted_amount
            .as_ref()
            .map(|amount| amount.units),
        Some(168)
    );

    let remote_list = client
        .get(format!("{base_url}/v1/reports/underwriting-decisions"))
        .query(&[("agentSubject", subject_key), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send underwriting decision list request");
    assert_eq!(remote_list.status(), reqwest::StatusCode::OK);
    let list_report: UnderwritingDecisionListReport = remote_list
        .json()
        .expect("parse underwriting decision list");
    assert_eq!(list_report.summary.matching_decisions, 1);
    assert_eq!(list_report.summary.returned_decisions, 1);
    assert_eq!(list_report.summary.total_quoted_premium_units, 168);
    assert_eq!(
        list_report.summary.total_quoted_premium_currency.as_deref(),
        Some("USD")
    );
    assert_eq!(
        list_report
            .summary
            .quoted_premium_totals_by_currency
            .get("USD")
            .copied(),
        Some(168)
    );
    assert_eq!(
        list_report.decisions[0].decision.body.decision_id,
        remote_decision.body.decision_id
    );

    let cli_issue = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "underwriting-decision",
            "issue",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "10",
            "--supersedes-decision-id",
            &remote_decision.body.decision_id,
        ])
        .output()
        .expect("run underwriting decision issue CLI");
    assert!(
        cli_issue.status.success(),
        "underwriting decision issue CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_issue.stdout),
        String::from_utf8_lossy(&cli_issue.stderr)
    );
    let cli_decision: SignedUnderwritingDecision =
        serde_json::from_slice(&cli_issue.stdout).expect("parse underwriting decision issue CLI");
    assert!(cli_decision
        .verify_signature()
        .expect("verify underwriting decision issue CLI signature"));

    let cli_list = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "underwriting-decision",
            "list",
            "--agent-subject",
            subject_key,
            "--limit",
            "10",
        ])
        .output()
        .expect("run underwriting decision list CLI");
    assert!(
        cli_list.status.success(),
        "underwriting decision list CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_list.stdout),
        String::from_utf8_lossy(&cli_list.stderr)
    );
    let cli_list_report: UnderwritingDecisionListReport =
        serde_json::from_slice(&cli_list.stdout).expect("parse underwriting decision list CLI");
    assert_eq!(cli_list_report.summary.matching_decisions, 2);
    assert!(cli_list_report
        .decisions
        .iter()
        .any(|row| row.decision.body.decision_id == cli_decision.body.decision_id));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_decision_issue_with_mixed_currency_exposure_withholds_premium() {
    skip_when_loopback_denied!(
        test_underwriting_decision_issue_with_mixed_currency_exposure_withholds_premium
    );
    let dir = unique_dir("chio-underwriting-mixed-currency");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-mixed-1";
    let issuer_key = "issuer-underwrite-mixed-1";
    let timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-mixed-usd-1",
                "cap-mixed-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp,
                SettlementStatus::Settled,
                "USD",
                4_200,
                "USD",
                false,
                false,
            ))
            .expect("append USD governed receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-mixed-eur-1",
                "cap-mixed-2",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp.saturating_sub(1),
                SettlementStatus::Settled,
                "EUR",
                3_100,
                "EUR",
                false,
                false,
            ))
            .expect("append EUR governed receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-mixed-currency-token";
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

    let issue_response = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("issue underwriting decision");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);
    let decision: SignedUnderwritingDecision = issue_response
        .json()
        .expect("parse signed underwriting decision");
    assert_eq!(
        decision.body.premium.state,
        chio_core::underwriting::UnderwritingPremiumState::Withheld
    );
    assert!(decision.body.premium.quoted_amount.is_none());
    assert!(decision
        .body
        .premium
        .rationale
        .contains("multiple currencies"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_decision_list_partitions_premium_totals_by_currency() {
    skip_when_loopback_denied!(
        test_underwriting_decision_list_partitions_premium_totals_by_currency
    );
    let dir = unique_dir("chio-underwriting-premium-currencies");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-premium-usd-1",
                "cap-premium-usd-1",
                "subject-underwrite-usd-1",
                "issuer-underwrite-usd-1",
                "ledger",
                "transfer",
                unix_now_secs().saturating_sub(60),
                SettlementStatus::Settled,
                "USD",
                4_200,
                "USD",
                false,
                false,
            ))
            .expect("append USD receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-premium-eur-1",
                "cap-premium-eur-1",
                "subject-underwrite-eur-1",
                "issuer-underwrite-eur-1",
                "ledger",
                "transfer",
                unix_now_secs().saturating_sub(61),
                SettlementStatus::Settled,
                "EUR",
                3_100,
                "EUR",
                false,
                false,
            ))
            .expect("append EUR receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-premium-currency-token";
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

    for subject_key in ["subject-underwrite-usd-1", "subject-underwrite-eur-1"] {
        let response = client
            .post(format!("{base_url}/v1/underwriting/decisions/issue"))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {service_token}"),
            )
            .json(&serde_json::json!({
                "query": {
                    "agentSubject": subject_key,
                    "receiptLimit": 10
                }
            }))
            .send()
            .expect("issue underwriting decision");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    let list_response = client
        .get(format!("{base_url}/v1/reports/underwriting-decisions"))
        .query(&[("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list underwriting decisions");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingDecisionListReport = list_response
        .json()
        .expect("parse underwriting decision list");
    assert_eq!(report.summary.total_quoted_premium_units, 0);
    assert!(report.summary.total_quoted_premium_currency.is_none());
    assert_eq!(
        report
            .summary
            .quoted_premium_totals_by_currency
            .get("USD")
            .copied(),
        Some(105)
    );
    assert_eq!(
        report
            .summary
            .quoted_premium_totals_by_currency
            .get("EUR")
            .copied(),
        Some(78)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_appeal_and_supersession_lifecycle() {
    skip_when_loopback_denied!(test_underwriting_appeal_and_supersession_lifecycle);
    let dir = unique_dir("chio-underwriting-appeal");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-appeal-1";
    let issuer_key = "issuer-underwrite-appeal-1";
    let timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-appeal-1",
                "cap-appeal-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp,
            ))
            .expect("append governed underwriting appeal receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-appeal-token";
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

    let initial_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("issue initial underwriting decision");
    assert_eq!(initial_issue.status(), reqwest::StatusCode::OK);
    let initial_decision: SignedUnderwritingDecision =
        initial_issue.json().expect("parse initial decision");

    let appeal_response = client
        .post(format!("{base_url}/v1/underwriting/appeals"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "decisionId": initial_decision.body.decision_id,
            "requestedBy": "ops-reviewer",
            "reason": "need superseding review"
        }))
        .send()
        .expect("create underwriting appeal");
    assert_eq!(appeal_response.status(), reqwest::StatusCode::OK);
    let appeal: UnderwritingAppealRecord =
        appeal_response.json().expect("parse underwriting appeal");
    assert_eq!(
        appeal.status,
        chio_core::underwriting::UnderwritingAppealStatus::Open
    );

    let superseding_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            },
            "supersedesDecisionId": initial_decision.body.decision_id
        }))
        .send()
        .expect("issue superseding underwriting decision");
    assert_eq!(superseding_issue.status(), reqwest::StatusCode::OK);
    let replacement_decision: SignedUnderwritingDecision = superseding_issue
        .json()
        .expect("parse superseding decision");

    let resolve_response = client
        .post(format!("{base_url}/v1/underwriting/appeals/resolve"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "appealId": appeal.appeal_id,
            "resolution": "accepted",
            "resolvedBy": "ops-reviewer",
            "replacementDecisionId": replacement_decision.body.decision_id
        }))
        .send()
        .expect("resolve underwriting appeal");
    assert_eq!(resolve_response.status(), reqwest::StatusCode::OK);
    let resolved_appeal: UnderwritingAppealRecord =
        resolve_response.json().expect("parse resolved appeal");
    assert_eq!(
        resolved_appeal.status,
        chio_core::underwriting::UnderwritingAppealStatus::Accepted
    );
    assert_eq!(
        resolved_appeal.replacement_decision_id.as_deref(),
        Some(replacement_decision.body.decision_id.as_str())
    );

    let second_resolve = client
        .post(format!("{base_url}/v1/underwriting/appeals/resolve"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "appealId": appeal.appeal_id,
            "resolution": "rejected",
            "resolvedBy": "ops-reviewer"
        }))
        .send()
        .expect("resolve underwriting appeal twice");
    assert_eq!(second_resolve.status(), reqwest::StatusCode::CONFLICT);

    let list_response = client
        .get(format!("{base_url}/v1/reports/underwriting-decisions"))
        .query(&[("agentSubject", subject_key), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list underwriting decisions after appeal");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingDecisionListReport = list_response
        .json()
        .expect("parse underwriting decision lifecycle list");
    assert_eq!(report.summary.matching_decisions, 2);
    let initial_row = report
        .decisions
        .iter()
        .find(|row| row.decision.body.decision_id == initial_decision.body.decision_id)
        .expect("initial decision row");
    let replacement_row = report
        .decisions
        .iter()
        .find(|row| row.decision.body.decision_id == replacement_decision.body.decision_id)
        .expect("replacement decision row");
    assert_eq!(
        initial_row.lifecycle_state,
        chio_core::underwriting::UnderwritingDecisionLifecycleState::Superseded
    );
    assert_eq!(
        replacement_row.lifecycle_state,
        chio_core::underwriting::UnderwritingDecisionLifecycleState::Active
    );
    assert_eq!(
        initial_row.latest_appeal_status,
        Some(chio_core::underwriting::UnderwritingAppealStatus::Accepted)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_rejected_appeal_cannot_link_replacement_decision() {
    skip_when_loopback_denied!(test_underwriting_rejected_appeal_cannot_link_replacement_decision);
    let dir = unique_dir("chio-underwriting-appeal-rejected-replacement");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-appeal-2";
    let issuer_key = "issuer-underwrite-appeal-2";
    let timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-appeal-2",
                "cap-appeal-2",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp,
            ))
            .expect("append governed underwriting appeal receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-appeal-rejected-replacement-token";
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

    let initial_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("issue initial underwriting decision");
    assert_eq!(initial_issue.status(), reqwest::StatusCode::OK);
    let initial_decision: SignedUnderwritingDecision =
        initial_issue.json().expect("parse initial decision");

    let appeal_response = client
        .post(format!("{base_url}/v1/underwriting/appeals"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "decisionId": initial_decision.body.decision_id,
            "requestedBy": "ops-reviewer",
            "reason": "need superseding review"
        }))
        .send()
        .expect("create underwriting appeal");
    assert_eq!(appeal_response.status(), reqwest::StatusCode::OK);
    let appeal: UnderwritingAppealRecord =
        appeal_response.json().expect("parse underwriting appeal");

    let superseding_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            },
            "supersedesDecisionId": initial_decision.body.decision_id
        }))
        .send()
        .expect("issue superseding underwriting decision");
    assert_eq!(superseding_issue.status(), reqwest::StatusCode::OK);
    let replacement_decision: SignedUnderwritingDecision = superseding_issue
        .json()
        .expect("parse superseding decision");

    let resolve_response = client
        .post(format!("{base_url}/v1/underwriting/appeals/resolve"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "appealId": appeal.appeal_id,
            "resolution": "rejected",
            "resolvedBy": "ops-reviewer",
            "replacementDecisionId": replacement_decision.body.decision_id
        }))
        .send()
        .expect("resolve underwriting appeal with rejected replacement");
    assert_eq!(resolve_response.status(), reqwest::StatusCode::CONFLICT);
    let body: serde_json::Value = resolve_response
        .json()
        .expect("parse rejected appeal conflict");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("may only be linked"));

    let _ = std::fs::remove_dir_all(&dir);
}
