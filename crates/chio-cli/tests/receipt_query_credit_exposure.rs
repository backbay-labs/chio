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
fn test_exposure_ledger_report_surfaces() {
    skip_when_loopback_denied!(test_exposure_ledger_report_surfaces);
    let dir = unique_dir("chio-exposure-ledger");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-exposure-1";
    let issuer_key = "issuer-exposure-1";
    let timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-exposure-settled-1",
                "cap-exposure-1",
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
            .expect("append settled exposure receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-exposure-pending-1",
                "cap-exposure-2",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp.saturating_sub(1),
                SettlementStatus::Pending,
                "USD",
                1_800,
                "USD",
                false,
                false,
            ))
            .expect("append pending exposure receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-exposure-failed-1",
                "cap-exposure-3",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp.saturating_sub(2),
                SettlementStatus::Failed,
                "USD",
                1_200,
                "USD",
                false,
                false,
            ))
            .expect("append failed exposure receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "exposure-ledger-token";
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
                "since": timestamp,
                "until": timestamp,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("issue underwriting decision for exposure ledger");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);
    let decision: SignedUnderwritingDecision = issue_response
        .json()
        .expect("parse exposure underwriting decision");
    let quoted_premium_units = decision
        .body
        .premium
        .quoted_amount
        .as_ref()
        .map(|amount| amount.units)
        .expect("quoted premium amount");

    let response = client
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
        .expect("send exposure ledger request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: SignedExposureLedgerReport = response.json().expect("parse signed exposure ledger");
    assert!(report
        .verify_signature()
        .expect("verify exposure ledger signature"));
    assert_eq!(report.body.schema, "chio.credit.exposure-ledger.v1");
    assert_eq!(report.body.summary.matching_receipts, 3);
    assert_eq!(report.body.summary.returned_receipts, 3);
    assert_eq!(report.body.summary.matching_decisions, 1);
    assert_eq!(report.body.summary.returned_decisions, 1);
    assert_eq!(report.body.summary.active_decisions, 1);
    assert_eq!(report.body.summary.superseded_decisions, 0);
    assert_eq!(report.body.summary.actionable_receipts, 2);
    assert_eq!(report.body.summary.pending_settlement_receipts, 1);
    assert_eq!(report.body.summary.failed_settlement_receipts, 1);
    assert_eq!(report.body.summary.currencies, vec!["USD"]);
    assert!(!report.body.summary.mixed_currency_book);
    assert_eq!(report.body.positions.len(), 1);
    let position = &report.body.positions[0];
    assert_eq!(position.currency, "USD");
    assert_eq!(position.governed_max_exposure_units, 7_200);
    assert_eq!(position.reserved_units, 3_000);
    assert_eq!(position.settled_units, 4_200);
    assert_eq!(position.pending_units, 1_800);
    assert_eq!(position.failed_units, 1_200);
    assert_eq!(position.provisional_loss_units, 1_200);
    assert_eq!(position.recovered_units, 0);
    assert_eq!(position.quoted_premium_units, quoted_premium_units);
    assert_eq!(position.active_quoted_premium_units, quoted_premium_units);
    assert_eq!(report.body.receipts.len(), 3);
    assert!(report
        .body
        .receipts
        .iter()
        .all(|row| !row.evidence_refs.is_empty()));
    assert_eq!(report.body.decisions.len(), 1);
    assert_eq!(
        report.body.decisions[0]
            .quoted_premium_amount
            .as_ref()
            .map(|amount| amount.units),
        Some(quoted_premium_units)
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "exposure-ledger",
            "export",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "10",
            "--decision-limit",
            "10",
        ])
        .output()
        .expect("run exposure ledger CLI");
    assert!(
        cli_output.status.success(),
        "exposure ledger CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: SignedExposureLedgerReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse exposure ledger CLI json");
    assert!(cli_report
        .verify_signature()
        .expect("verify exposure ledger CLI signature"));
    assert_eq!(cli_report.body.summary.matching_receipts, 3);
    assert_eq!(cli_report.body.summary.matching_decisions, 1);
    assert_eq!(cli_report.body.positions[0].reserved_units, 3_000);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_exposure_ledger_requires_anchor() {
    skip_when_loopback_denied!(test_exposure_ledger_requires_anchor);
    let dir = unique_dir("chio-exposure-ledger-anchor");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "exposure-ledger-anchor-token";
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
        .get(format!("{base_url}/v1/reports/exposure-ledger"))
        .query(&[("receiptLimit", "10"), ("decisionLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send exposure ledger request without anchor");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response
        .json()
        .expect("parse exposure ledger anchor failure");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("require at least one anchor"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_exposure_ledger_rejects_contradictory_currency_row() {
    skip_when_loopback_denied!(test_exposure_ledger_rejects_contradictory_currency_row);
    let dir = unique_dir("chio-exposure-ledger-currency-conflict");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-exposure-conflict-1";
    let issuer_key = "issuer-exposure-conflict-1";
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-exposure-conflict-1",
                "cap-exposure-conflict-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                unix_now_secs().saturating_sub(60),
                SettlementStatus::Settled,
                "USD",
                2_000,
                "EUR",
                false,
                false,
            ))
            .expect("append contradictory currency receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "exposure-ledger-currency-conflict-token";
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
        .get(format!("{base_url}/v1/reports/exposure-ledger"))
        .query(&[
            ("agentSubject", subject_key),
            ("toolServer", "ledger"),
            ("toolName", "transfer"),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send contradictory exposure ledger request");
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let body: serde_json::Value = response
        .json()
        .expect("parse contradictory exposure ledger error");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("cannot project one exposure row across multiple currencies"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_scorecard_report_surfaces() {
    skip_when_loopback_denied!(test_credit_scorecard_report_surfaces);
    let dir = unique_dir("chio-credit-scorecard");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-1";
    let issuer_key = "issuer-credit-1";
    let now = unix_now_secs();
    let settled_at = now.saturating_sub(3 * 86_400);
    let pending_at = now.saturating_sub(2 * 86_400);
    let failed_at = now.saturating_sub(86_400);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-credit-settled-1",
                "cap-credit-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                settled_at,
                SettlementStatus::Settled,
                "USD",
                5_000,
                "USD",
                false,
                false,
            ))
            .expect("append settled credit receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-credit-pending-1",
                "cap-credit-2",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                pending_at,
                SettlementStatus::Pending,
                "USD",
                2_000,
                "USD",
                false,
                false,
            ))
            .expect("append pending credit receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-credit-failed-1",
                "cap-credit-3",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                failed_at,
                SettlementStatus::Failed,
                "USD",
                1_500,
                "USD",
                false,
                false,
            ))
            .expect("append failed credit receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-scorecard-token";
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
                "since": settled_at,
                "until": settled_at,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("issue underwriting decision for credit scorecard");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);

    let response = client
        .get(format!("{base_url}/v1/reports/credit-scorecard"))
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
        .expect("send credit scorecard request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: SignedCreditScorecardReport =
        response.json().expect("parse signed credit scorecard");
    assert!(report
        .verify_signature()
        .expect("verify credit scorecard signature"));
    assert_eq!(report.body.schema, "chio.credit.scorecard.v1");
    assert_eq!(report.body.summary.matching_receipts, 3);
    assert_eq!(report.body.summary.matching_decisions, 1);
    assert_eq!(report.body.summary.currencies, vec!["USD"]);
    assert!(report.body.summary.probationary);
    assert_eq!(
        report.body.summary.confidence,
        chio_core::credit::CreditScorecardConfidence::Low
    );
    assert_eq!(
        report.body.summary.band,
        chio_core::credit::CreditScorecardBand::Probationary
    );
    assert_eq!(report.body.positions.len(), 1);
    assert_eq!(report.body.dimensions.len(), 4);
    assert!(report.body.summary.overall_score >= 0.0 && report.body.summary.overall_score <= 1.0);
    assert!(report.body.anomalies.iter().any(|anomaly| {
        anomaly.code == chio_core::credit::CreditScorecardReasonCode::PendingSettlementBacklog
    }));
    assert!(report.body.anomalies.iter().any(|anomaly| {
        anomaly.code == chio_core::credit::CreditScorecardReasonCode::FailedSettlementBacklog
    }));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "credit-scorecard",
            "export",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "10",
            "--decision-limit",
            "10",
        ])
        .output()
        .expect("run credit scorecard CLI");
    assert!(
        cli_output.status.success(),
        "credit scorecard CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: SignedCreditScorecardReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse credit scorecard CLI json");
    assert!(cli_report
        .verify_signature()
        .expect("verify credit scorecard CLI signature"));
    assert_eq!(cli_report.body.summary.matching_receipts, 3);
    assert!(cli_report.body.summary.probationary);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_scorecard_requires_agent_subject() {
    skip_when_loopback_denied!(test_credit_scorecard_requires_agent_subject);
    let dir = unique_dir("chio-credit-scorecard-anchor");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "credit-scorecard-anchor-token";
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
        .get(format!("{base_url}/v1/reports/credit-scorecard"))
        .query(&[("toolServer", "ledger"), ("receiptLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit scorecard request without subject");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response
        .json()
        .expect("parse credit scorecard anchor failure");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("require --agent-subject"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_scorecard_requires_matching_history() {
    skip_when_loopback_denied!(test_credit_scorecard_requires_matching_history);
    let dir = unique_dir("chio-credit-scorecard-history");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "credit-scorecard-history-token";
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
        .get(format!("{base_url}/v1/reports/credit-scorecard"))
        .query(&[("agentSubject", "missing-subject"), ("receiptLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit scorecard request without history");
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let body: serde_json::Value = response
        .json()
        .expect("parse credit scorecard history failure");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("at least one matching governed receipt"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_facility_report_issue_and_list_surfaces() {
    skip_when_loopback_denied!(test_credit_facility_report_issue_and_list_surfaces);
    let dir = unique_dir("chio-credit-facility-grant");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-facility-grant-1";
    let issuer_key = "issuer-facility-grant-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-facility-grant-{day}"),
                    &format!("cap-facility-grant-{day}"),
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
                .expect("append facility grant receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-facility-grant-token";
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

    let evaluate_response = client
        .get(format!("{base_url}/v1/reports/facility-policy"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit facility evaluate request");
    assert_eq!(evaluate_response.status(), reqwest::StatusCode::OK);
    let evaluate_report: CreditFacilityReport = evaluate_response
        .json()
        .expect("parse credit facility evaluate report");
    assert_eq!(evaluate_report.schema, "chio.credit.facility-report.v1");
    assert_eq!(
        evaluate_report.disposition,
        chio_core::credit::CreditFacilityDisposition::Grant
    );
    assert!(evaluate_report.prerequisites.runtime_assurance_met);
    assert!(!evaluate_report.prerequisites.certification_required);
    assert!(evaluate_report.terms.is_some());

    let remote_issue = client
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
        .expect("send facility issue request");
    assert_eq!(remote_issue.status(), reqwest::StatusCode::OK);
    let first_facility: SignedCreditFacility = remote_issue
        .json()
        .expect("parse first signed credit facility");
    assert_eq!(first_facility.body.schema, "chio.credit.facility.v1");
    assert_eq!(
        first_facility.body.report.disposition,
        chio_core::credit::CreditFacilityDisposition::Grant
    );
    assert_eq!(
        first_facility.body.lifecycle_state,
        chio_core::credit::CreditFacilityLifecycleState::Active
    );

    let remote_supersede = client
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
            },
            "supersedesFacilityId": first_facility.body.facility_id
        }))
        .send()
        .expect("send superseding facility issue request");
    assert_eq!(remote_supersede.status(), reqwest::StatusCode::OK);
    let second_facility: SignedCreditFacility = remote_supersede
        .json()
        .expect("parse second signed credit facility");
    assert_eq!(
        second_facility.body.supersedes_facility_id.as_deref(),
        Some(first_facility.body.facility_id.as_str())
    );

    let remote_list = client
        .get(format!("{base_url}/v1/reports/facilities"))
        .query(&[("agentSubject", subject_key), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit facility list request");
    assert_eq!(remote_list.status(), reqwest::StatusCode::OK);
    let list_report: CreditFacilityListReport = remote_list
        .json()
        .expect("parse credit facility list report");
    assert_eq!(list_report.schema, "chio.credit.facility-list.v1");
    assert_eq!(list_report.summary.matching_facilities, 2);
    assert_eq!(list_report.summary.active_facilities, 1);
    assert_eq!(list_report.summary.superseded_facilities, 1);
    assert_eq!(list_report.summary.granted_facilities, 2);
    let first_row = list_report
        .facilities
        .iter()
        .find(|row| row.facility.body.facility_id == first_facility.body.facility_id)
        .expect("first facility row");
    assert_eq!(
        first_row.lifecycle_state,
        chio_core::credit::CreditFacilityLifecycleState::Superseded
    );
    let second_row = list_report
        .facilities
        .iter()
        .find(|row| row.facility.body.facility_id == second_facility.body.facility_id)
        .expect("second facility row");
    assert_eq!(
        second_row.lifecycle_state,
        chio_core::credit::CreditFacilityLifecycleState::Active
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "facility",
            "list",
            "--agent-subject",
            subject_key,
            "--limit",
            "10",
        ])
        .output()
        .expect("run credit facility list CLI");
    assert!(
        cli_output.status.success(),
        "credit facility list CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: CreditFacilityListReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse credit facility CLI list");
    assert_eq!(cli_report.summary.matching_facilities, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_issue_endpoints_require_service_auth() {
    skip_when_loopback_denied!(test_credit_issue_endpoints_require_service_auth);
    let dir = unique_dir("chio-credit-issue-auth");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "credit-issue-auth-token";
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

    let facility_response = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .json(&serde_json::json!({
            "query": {
                "agentSubject": "missing-auth-facility",
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send unauthenticated facility issue request");
    assert_eq!(
        facility_response.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        facility_response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer")
    );
    let facility_body: serde_json::Value = facility_response
        .json()
        .expect("parse unauthenticated facility issue error");
    assert!(facility_body["error"]
        .as_str()
        .expect("facility error string")
        .contains("missing or invalid control bearer token"));

    let bond_response = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .json(&serde_json::json!({
            "query": {
                "agentSubject": "missing-auth-bond",
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send unauthenticated bond issue request");
    assert_eq!(bond_response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        bond_response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer")
    );
    let bond_body: serde_json::Value = bond_response
        .json()
        .expect("parse unauthenticated bond issue error");
    assert!(bond_body["error"]
        .as_str()
        .expect("bond error string")
        .contains("missing or invalid control bearer token"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_issue_endpoints_require_receipt_db_configuration() {
    skip_when_loopback_denied!(test_credit_issue_endpoints_require_receipt_db_configuration);
    let dir = unique_dir("chio-credit-issue-missing-receipt-db");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "credit-issue-receipt-db-token";
    let _service = spawn_trust_service_without_receipt_db(
        listen,
        service_token,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_response = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": "missing-receipt-db-facility",
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send facility issue request without receipt db");
    assert_eq!(facility_response.status(), reqwest::StatusCode::CONFLICT);
    let facility_body: serde_json::Value = facility_response
        .json()
        .expect("parse missing receipt db facility error");
    assert!(facility_body["error"]
        .as_str()
        .expect("facility error string")
        .contains("credit facility issuance requires --receipt-db"));

    let bond_response = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": "missing-receipt-db-bond",
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send bond issue request without receipt db");
    assert_eq!(bond_response.status(), reqwest::StatusCode::CONFLICT);
    let bond_body: serde_json::Value = bond_response
        .json()
        .expect("parse missing receipt db bond error");
    assert!(bond_body["error"]
        .as_str()
        .expect("bond error string")
        .contains("credit bond issuance requires --receipt-db"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_trust_control_report_endpoints_require_service_auth() {
    skip_when_loopback_denied!(test_trust_control_report_endpoints_require_service_auth);
    let dir = unique_dir("chio-trust-report-auth");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "trust-report-auth-token";
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

    for path in [
        "/v1/reports/capital-book?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/facility-policy?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/facilities?agentSubject=auth-matrix&limit=10",
        "/v1/reports/bond-policy?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/bonds?agentSubject=auth-matrix&limit=10",
        "/v1/reports/credit-backtest?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/provider-risk-package?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/liability-providers?limit=10",
        "/v1/reports/liability-market?agentSubject=auth-matrix&limit=10",
        "/v1/reports/underwriting-input?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/underwriting-decision?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/underwriting-decisions?agentSubject=auth-matrix&limit=10",
    ] {
        assert_trust_service_auth_required(&client, &base_url, path);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_trust_control_report_endpoints_require_receipt_db_configuration() {
    skip_when_loopback_denied!(
        test_trust_control_report_endpoints_require_receipt_db_configuration
    );
    let dir = unique_dir("chio-trust-report-missing-receipt-db");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "trust-report-receipt-db-token";
    let _service = spawn_trust_service_without_receipt_db(
        listen,
        service_token,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    for (path, status, expected_error_fragment) in [
        (
            "/v1/reports/capital-book?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
        (
            "/v1/reports/facility-policy?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::CONFLICT,
            "credit facility evaluation requires --receipt-db on the trust-control service",
        ),
        (
            "/v1/reports/facilities?agentSubject=missing-receipt-db&limit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
        (
            "/v1/reports/bond-policy?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::CONFLICT,
            "credit bond evaluation requires --receipt-db on the trust-control service",
        ),
        (
            "/v1/reports/bonds?agentSubject=missing-receipt-db&limit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
        (
            "/v1/reports/credit-backtest?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::CONFLICT,
            "credit backtests require --receipt-db on the trust-control service",
        ),
        (
            "/v1/reports/provider-risk-package?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::CONFLICT,
            "provider risk package export requires --receipt-db on the trust-control service",
        ),
        (
            "/v1/reports/liability-providers?limit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
        (
            "/v1/reports/liability-market?agentSubject=missing-receipt-db&limit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
        (
            "/v1/reports/underwriting-input?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "trust service is missing receipt_db_path for underwriting input queries",
        ),
        (
            "/v1/reports/underwriting-decision?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "trust service is missing receipt_db_path for underwriting decision queries",
        ),
        (
            "/v1/reports/underwriting-decisions?agentSubject=missing-receipt-db&limit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
    ] {
        assert_trust_service_get_error(
            &client,
            &base_url,
            service_token,
            path,
            status,
            expected_error_fragment,
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_facility_report_denies_missing_prerequisites() {
    skip_when_loopback_denied!(test_credit_facility_report_denies_missing_prerequisites);
    let dir = unique_dir("chio-credit-facility-prerequisites");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(
                &make_governed_authorization_receipt_without_runtime_assurance(
                    "rc-facility-prereq-1",
                    "cap-facility-prereq-1",
                    "subject-facility-prereq-1",
                    "issuer-facility-prereq-1",
                    "ledger",
                    "transfer",
                    unix_now_secs().saturating_sub(60),
                    "USD",
                    4_200,
                ),
            )
            .expect("append credit facility prerequisite receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-facility-prereq-token";
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
        .get(format!("{base_url}/v1/reports/facility-policy"))
        .query(&[
            ("agentSubject", "subject-facility-prereq-1"),
            ("toolServer", "ledger"),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit facility prerequisite request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: CreditFacilityReport = response
        .json()
        .expect("parse credit facility prerequisite report");
    assert_eq!(
        report.disposition,
        chio_core::credit::CreditFacilityDisposition::Deny
    );
    assert!(report.terms.is_none());
    assert_eq!(
        report.prerequisites.minimum_runtime_assurance_tier,
        RuntimeAssuranceTier::Verified
    );
    assert!(!report.prerequisites.runtime_assurance_met);
    assert!(report.prerequisites.certification_required);
    assert!(!report.prerequisites.certification_met);
    let finding_codes = report
        .findings
        .iter()
        .map(|finding| finding.code)
        .collect::<Vec<_>>();
    assert!(finding_codes
        .contains(&chio_core::credit::CreditFacilityReasonCode::MissingRuntimeAssurance));
    assert!(finding_codes
        .contains(&chio_core::credit::CreditFacilityReasonCode::CertificationNotActive));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_facility_report_manual_review_for_mixed_currency_book() {
    skip_when_loopback_denied!(test_credit_facility_report_manual_review_for_mixed_currency_book);
    let dir = unique_dir("chio-credit-facility-mixed-currency");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-facility-mixed-1";
    let issuer_key = "issuer-facility-mixed-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..15_u64 {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-facility-mixed-usd-{day}"),
                    &format!("cap-facility-mixed-usd-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub(day * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append usd facility receipt");
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-facility-mixed-eur-{day}"),
                    &format!("cap-facility-mixed-eur-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 15) * 86_400),
                    SettlementStatus::Settled,
                    "EUR",
                    5_000,
                    "EUR",
                    false,
                    false,
                ))
                .expect("append eur facility receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-facility-mixed-token";
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
        .get(format!("{base_url}/v1/reports/facility-policy"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "100"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send mixed-currency facility request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: CreditFacilityReport = response
        .json()
        .expect("parse mixed-currency facility report");
    assert_eq!(
        report.disposition,
        chio_core::credit::CreditFacilityDisposition::ManualReview
    );
    assert!(report.terms.is_none());
    assert!(report.scorecard.mixed_currency_book);
    assert!(report.findings.iter().any(|finding| {
        finding.code == chio_core::credit::CreditFacilityReasonCode::MixedCurrencyBook
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_facility_report_manual_review_for_mixed_runtime_assurance_provenance() {
    skip_when_loopback_denied!(
        test_credit_facility_report_manual_review_for_mixed_runtime_assurance_provenance
    );
    let dir = unique_dir("chio-credit-facility-mixed-runtime-provenance");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-facility-mixed-runtime-1";
    let issuer_key = "issuer-facility-mixed-runtime-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..30_u64 {
            let (schema, family, verifier, evidence_sha) = if day % 2 == 0 {
                (
                    AZURE_MAA_ATTESTATION_SCHEMA,
                    Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
                    "https://maa.chio.example",
                    "sha256-mixed-runtime-azure",
                )
            } else {
                (
                    GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA,
                    Some(chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation),
                    "https://confidentialcomputing.googleapis.com",
                    "sha256-mixed-runtime-google",
                )
            };
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_runtime_profile(
                    &format!("rc-facility-mixed-runtime-{day}"),
                    &format!("cap-facility-mixed-runtime-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub(day * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    4_500,
                    "USD",
                    false,
                    false,
                    schema,
                    family,
                    RuntimeAssuranceTier::Verified,
                    verifier,
                    evidence_sha,
                ))
                .expect("append mixed runtime provenance receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-facility-mixed-runtime-token";
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
        .get(format!("{base_url}/v1/reports/facility-policy"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "100"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send mixed-runtime-provenance facility request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: CreditFacilityReport = response
        .json()
        .expect("parse mixed-runtime-provenance facility report");
    assert_eq!(
        report.disposition,
        chio_core::credit::CreditFacilityDisposition::ManualReview
    );
    assert!(report.terms.is_none());
    assert!(report.findings.iter().any(|finding| {
        finding.code == chio_core::credit::CreditFacilityReasonCode::MixedRuntimeAssuranceProvenance
    }));

    let _ = std::fs::remove_dir_all(&dir);
}
