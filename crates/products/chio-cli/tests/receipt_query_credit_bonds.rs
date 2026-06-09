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
fn test_credit_backtest_report_surfaces_drift_and_failure_modes() {
    skip_when_loopback_denied!(test_credit_backtest_report_surfaces_drift_and_failure_modes);
    let dir = unique_dir("chio-credit-backtest");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-backtest-1";
    let issuer_key = "issuer-credit-backtest-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 46..=59_u64 {
            store
                .append_chio_receipt(&make_credit_history_receipt(
                    &format!("rc-backtest-good-{day}"),
                    &format!("cap-backtest-good-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub(day * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    4_000,
                    "USD",
                    true,
                ))
                .expect("append good backtest receipt");
        }
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-backtest-pending-no-runtime-1",
                "cap-backtest-pending-no-runtime-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(35 * 86_400),
                SettlementStatus::Pending,
                "USD",
                20_000,
                "USD",
                false,
            ))
            .expect("append first pending backtest receipt");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-backtest-pending-no-runtime-2",
                "cap-backtest-pending-no-runtime-2",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(34 * 86_400),
                SettlementStatus::Pending,
                "USD",
                20_000,
                "USD",
                false,
            ))
            .expect("append second pending backtest receipt");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-backtest-mixed-usd",
                "cap-backtest-mixed-usd",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(23 * 86_400),
                SettlementStatus::Settled,
                "USD",
                4_000,
                "USD",
                true,
            ))
            .expect("append mixed usd receipt");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-backtest-mixed-eur",
                "cap-backtest-mixed-eur",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(22 * 86_400),
                SettlementStatus::Settled,
                "EUR",
                4_000,
                "EUR",
                true,
            ))
            .expect("append mixed eur receipt");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-backtest-stale",
                "cap-backtest-stale",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(10 * 86_400),
                SettlementStatus::Settled,
                "USD",
                4_000,
                "USD",
                true,
            ))
            .expect("append stale backtest receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-backtest-token";
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
        .get(format!("{base_url}/v1/reports/credit-backtest"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
            ("windowSeconds", "1296000"),
            ("windowCount", "4"),
            ("staleAfterSeconds", "432000"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit backtest request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: CreditBacktestReport = response.json().expect("parse credit backtest report");
    assert_eq!(report.schema, "chio.credit.backtest-report.v1");
    assert_eq!(report.summary.windows_evaluated, 4);
    assert!(report.summary.stale_evidence_windows >= 1);
    assert!(report.summary.mixed_currency_windows >= 1);
    assert!(report.summary.over_utilized_windows >= 1);
    let reason_codes = report
        .windows
        .iter()
        .flat_map(|window| window.reason_codes.iter().copied())
        .collect::<Vec<_>>();
    assert!(reason_codes.contains(&chio_kernel::CreditBacktestReasonCode::MissingRuntimeAssurance));
    assert!(reason_codes.contains(&chio_kernel::CreditBacktestReasonCode::MixedCurrencyBook));
    assert!(reason_codes.contains(&chio_kernel::CreditBacktestReasonCode::StaleEvidence));
    assert!(reason_codes.contains(&chio_kernel::CreditBacktestReasonCode::FacilityOverUtilization));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "credit-backtest",
            "export",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "200",
            "--decision-limit",
            "50",
            "--window-seconds",
            "1296000",
            "--window-count",
            "4",
            "--stale-after-seconds",
            "432000",
        ])
        .output()
        .expect("run credit backtest CLI");
    assert!(
        cli_output.status.success(),
        "credit backtest CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: CreditBacktestReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse credit backtest CLI");
    assert_eq!(cli_report.summary.windows_evaluated, 4);
    assert!(cli_report.summary.drift_windows >= 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_bond_issue_and_list_surfaces() {
    skip_when_loopback_denied!(test_credit_bond_issue_and_list_surfaces);
    let dir = unique_dir("chio-credit-bond-lock");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-bond-lock-1";
    let issuer_key = "issuer-credit-bond-lock-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-lock-good-{day}"),
                    &format!("cap-bond-lock-good-{day}"),
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
                .expect("append good bond receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-bond-lock-token";
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
        .expect("issue bond backing facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let issued_facility: SignedCreditFacility = facility_issue
        .json()
        .expect("parse issued bond backing facility");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-bond-lock-pending-1",
                "cap-bond-lock-pending-1",
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
            .expect("append pending bond receipt");
    }

    let evaluate_response = client
        .get(format!("{base_url}/v1/reports/bond-policy"))
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
        .expect("send credit bond evaluate request");
    assert_eq!(evaluate_response.status(), reqwest::StatusCode::OK);
    let evaluate_report: CreditBondReport = evaluate_response
        .json()
        .expect("parse credit bond evaluate report");
    assert_eq!(evaluate_report.schema, "chio.credit.bond-report.v1");
    assert_eq!(
        evaluate_report.disposition,
        chio_core::credit::CreditBondDisposition::Lock
    );
    assert_eq!(
        evaluate_report.latest_facility_id.as_deref(),
        Some(issued_facility.body.facility_id.as_str())
    );
    assert!(evaluate_report.terms.is_some());
    assert!(evaluate_report
        .findings
        .iter()
        .any(|finding| { finding.code == chio_core::credit::CreditBondReasonCode::ReserveLocked }));

    let first_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
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
        .expect("issue first bond");
    assert_eq!(first_issue.status(), reqwest::StatusCode::OK);
    let first_bond: SignedCreditBond = first_issue.json().expect("parse first bond");
    assert_eq!(first_bond.body.schema, "chio.credit.bond.v1");
    assert_eq!(
        first_bond.body.report.disposition,
        chio_core::credit::CreditBondDisposition::Lock
    );
    assert_eq!(
        first_bond.body.lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Active
    );

    let second_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
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
            "supersedesBondId": first_bond.body.bond_id
        }))
        .send()
        .expect("issue superseding bond");
    assert_eq!(second_issue.status(), reqwest::StatusCode::OK);
    let second_bond: SignedCreditBond = second_issue.json().expect("parse second bond");
    assert_eq!(
        second_bond.body.supersedes_bond_id.as_deref(),
        Some(first_bond.body.bond_id.as_str())
    );

    let list_response = client
        .get(format!("{base_url}/v1/reports/bonds"))
        .query(&[("agentSubject", subject_key), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit bond list request");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_report: CreditBondListReport =
        list_response.json().expect("parse credit bond list report");
    assert_eq!(list_report.schema, "chio.credit.bond-list.v1");
    assert_eq!(list_report.summary.matching_bonds, 2);
    assert_eq!(list_report.summary.active_bonds, 1);
    assert_eq!(list_report.summary.superseded_bonds, 1);
    assert_eq!(list_report.summary.locked_bonds, 2);
    let first_row = list_report
        .bonds
        .iter()
        .find(|row| row.bond.body.bond_id == first_bond.body.bond_id)
        .expect("first bond row");
    assert_eq!(
        first_row.lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Superseded
    );
    let second_row = list_report
        .bonds
        .iter()
        .find(|row| row.bond.body.bond_id == second_bond.body.bond_id)
        .expect("second bond row");
    assert_eq!(
        second_row.lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Active
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "bond",
            "list",
            "--agent-subject",
            subject_key,
            "--limit",
            "10",
        ])
        .output()
        .expect("run credit bond list CLI");
    assert!(
        cli_output.status.success(),
        "credit bond list CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: CreditBondListReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse credit bond CLI list");
    assert_eq!(cli_report.summary.matching_bonds, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_bond_report_hold_and_release_semantics() {
    skip_when_loopback_denied!(test_credit_bond_report_hold_and_release_semantics);
    let dir = unique_dir("chio-credit-bond-hold-release");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let hold_subject = "subject-credit-bond-hold-1";
    let release_subject = "subject-credit-bond-release-1";
    let issuer_key = "issuer-credit-bond-hold-release-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-hold-{day}"),
                    &format!("cap-bond-hold-{day}"),
                    hold_subject,
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
                .expect("append hold history");
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-release-{day}"),
                    &format!("cap-bond-release-{day}"),
                    release_subject,
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
                .expect("append release history");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-bond-hold-release-token";
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
                "agentSubject": hold_subject,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue hold facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    let hold_response = client
        .get(format!("{base_url}/v1/reports/bond-policy"))
        .query(&[
            ("agentSubject", hold_subject),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send hold bond request");
    assert_eq!(hold_response.status(), reqwest::StatusCode::OK);
    let hold_report: CreditBondReport = hold_response.json().expect("parse hold bond report");
    assert_eq!(
        hold_report.disposition,
        chio_core::credit::CreditBondDisposition::Hold
    );
    assert!(hold_report
        .findings
        .iter()
        .any(|finding| { finding.code == chio_core::credit::CreditBondReasonCode::ReserveHeld }));

    let release_response = client
        .get(format!("{base_url}/v1/reports/bond-policy"))
        .query(&[
            ("agentSubject", release_subject),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send release bond request");
    assert_eq!(release_response.status(), reqwest::StatusCode::OK);
    let release_report: CreditBondReport =
        release_response.json().expect("parse release bond report");
    assert_eq!(
        release_report.disposition,
        chio_core::credit::CreditBondDisposition::Release
    );
    assert!(release_report.latest_facility_id.is_none());
    assert!(release_report.findings.iter().any(|finding| {
        finding.code == chio_core::credit::CreditBondReasonCode::ReserveReleased
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_bond_report_impairs_and_fails_closed_on_mixed_currency() {
    skip_when_loopback_denied!(test_credit_bond_report_impairs_and_fails_closed_on_mixed_currency);
    let dir = unique_dir("chio-credit-bond-impair-mixed");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let impair_subject = "subject-credit-bond-impair-1";
    let mixed_subject = "subject-credit-bond-mixed-1";
    let issuer_key = "issuer-credit-bond-impair-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-impair-good-{day}"),
                    &format!("cap-bond-impair-good-{day}"),
                    impair_subject,
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
                .expect("append impair good history");
        }
        for day in 0..15_u64 {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-mixed-usd-{day}"),
                    &format!("cap-bond-mixed-usd-{day}"),
                    mixed_subject,
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
                .expect("append mixed usd history");
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-mixed-eur-{day}"),
                    &format!("cap-bond-mixed-eur-{day}"),
                    mixed_subject,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 20) * 86_400),
                    SettlementStatus::Settled,
                    "EUR",
                    4_000,
                    "EUR",
                    false,
                    false,
                ))
                .expect("append mixed eur history");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-bond-impair-token";
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
                "agentSubject": impair_subject,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue impair backing facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-bond-impair-failed-1",
                "cap-bond-impair-failed-1",
                impair_subject,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Failed,
                "USD",
                8_500,
                "USD",
                true,
            ))
            .expect("append failed impair receipt");
    }

    let impair_response = client
        .get(format!("{base_url}/v1/reports/bond-policy"))
        .query(&[
            ("agentSubject", impair_subject),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send impair bond request");
    assert_eq!(impair_response.status(), reqwest::StatusCode::OK);
    let impair_report: CreditBondReport = impair_response.json().expect("parse impair bond report");
    assert_eq!(
        impair_report.disposition,
        chio_core::credit::CreditBondDisposition::Impair
    );
    let impair_codes = impair_report
        .findings
        .iter()
        .map(|finding| finding.code)
        .collect::<Vec<_>>();
    assert!(
        impair_codes.contains(&chio_core::credit::CreditBondReasonCode::FailedSettlementBacklog)
    );
    assert!(
        impair_codes.contains(&chio_core::credit::CreditBondReasonCode::ProvisionalLossOutstanding)
    );

    let mixed_response = client
        .get(format!("{base_url}/v1/reports/bond-policy"))
        .query(&[
            ("agentSubject", mixed_subject),
            ("receiptLimit", "100"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send mixed-currency bond request");
    assert_eq!(mixed_response.status(), reqwest::StatusCode::CONFLICT);
    let mixed_body: serde_json::Value = mixed_response
        .json()
        .expect("parse mixed-currency bond error");
    assert!(mixed_body["error"]
        .as_str()
        .expect("mixed currency error string")
        .contains("does not auto-net reserve accounting across currencies"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_bonded_execution_simulation_report_surfaces() {
    skip_when_loopback_denied!(test_credit_bonded_execution_simulation_report_surfaces);
    let dir = unique_dir("chio-credit-bonded-execution-simulation");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let kill_switch_policy_file = dir.join("bonded-execution-kill-switch.yaml");

    let subject_key = "subject-credit-bonded-execution-1";
    let issuer_key = "issuer-credit-bonded-execution-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bonded-execution-good-{day}"),
                    &format!("cap-bonded-execution-good-{day}"),
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
                ))
                .expect("append bonded execution history");
        }
    }

    let kill_switch_policy = chio_kernel::CreditBondedExecutionControlPolicy {
        version: "chio.credit.bonded-execution-control-policy.kill-switch.v1".to_string(),
        kill_switch: true,
        maximum_autonomy_tier: Some(GovernedAutonomyTier::Delegated),
        minimum_runtime_assurance_tier: Some(RuntimeAssuranceTier::Attested),
        require_delegated_call_chain: true,
        require_locked_reserve: false,
        deny_if_bond_not_active: true,
        deny_if_outstanding_delinquency: true,
    };
    std::fs::write(
        &kill_switch_policy_file,
        serde_yml::to_string(&kill_switch_policy).expect("serialize kill switch policy"),
    )
    .expect("write kill switch policy");

    let listen = reserve_listen_addr();
    let service_token = "credit-bonded-execution-token";
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
        .expect("issue bonded execution facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-bonded-execution-pending-1",
                "cap-bonded-execution-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Pending,
                "USD",
                6_500,
                "USD",
                true,
            ))
            .expect("append pending bonded execution receipt");
    }

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
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
        .expect("issue bonded execution bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse bonded execution bond");
    let bond_id = bond.body.bond_id.clone();

    let simulation_response = client
        .post(format!("{base_url}/v1/reports/bonded-execution-simulation"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "autonomyTier": "delegated",
                "runtimeAssuranceTier": "attested",
                "callChainPresent": true
            },
            "policy": kill_switch_policy
        }))
        .send()
        .expect("send bonded execution simulation request");
    assert_eq!(simulation_response.status(), reqwest::StatusCode::OK);
    let simulation_report: CreditBondedExecutionSimulationReport = simulation_response
        .json()
        .expect("parse bonded execution simulation report");
    assert_eq!(
        simulation_report.schema,
        "chio.credit.bonded-execution-simulation-report.v1"
    );
    assert_eq!(
        simulation_report.default_evaluation.decision,
        chio_kernel::CreditBondedExecutionDecision::Allow
    );
    assert!(
        simulation_report
            .default_evaluation
            .sandbox_integration_ready
    );
    assert_eq!(
        simulation_report.simulated_evaluation.decision,
        chio_kernel::CreditBondedExecutionDecision::Deny
    );
    assert!(simulation_report.delta.decision_changed);
    assert!(simulation_report
        .delta
        .added_reasons
        .contains(&"kill_switch_enabled".to_string()));
    assert!(simulation_report
        .simulated_evaluation
        .findings
        .iter()
        .any(|finding| {
            finding.code == chio_kernel::CreditBondedExecutionFindingCode::KillSwitchEnabled
        }));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "bond",
            "simulate",
            "--bond-id",
            bond_id.as_str(),
            "--autonomy-tier",
            "delegated",
            "--runtime-assurance-tier",
            "attested",
            "--call-chain-present",
            "--policy-file",
            kill_switch_policy_file
                .to_str()
                .expect("kill switch policy path"),
        ])
        .output()
        .expect("run bonded execution simulation CLI");
    assert!(
        cli_output.status.success(),
        "bonded execution simulation CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: CreditBondedExecutionSimulationReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse bonded execution CLI report");
    assert_eq!(
        cli_report.simulated_evaluation.decision,
        chio_kernel::CreditBondedExecutionDecision::Deny
    );

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-bonded-execution-failed-1",
                "cap-bonded-execution-failed-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(30),
                SettlementStatus::Failed,
                "USD",
                8_500,
                "USD",
                true,
            ))
            .expect("append failed bonded execution receipt");
    }

    let delinquency_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "delinquency"
            }
        }))
        .send()
        .expect("issue bonded execution delinquency");
    assert_eq!(delinquency_issue.status(), reqwest::StatusCode::OK);
    let delinquency_event: SignedCreditLossLifecycle = delinquency_issue
        .json()
        .expect("parse bonded execution delinquency");

    let impaired_response = client
        .post(format!("{base_url}/v1/reports/bonded-execution-simulation"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "autonomyTier": "delegated",
                "runtimeAssuranceTier": "attested",
                "callChainPresent": true
            },
            "policy": chio_kernel::CreditBondedExecutionControlPolicy::default()
        }))
        .send()
        .expect("send impaired bonded execution simulation request");
    assert_eq!(impaired_response.status(), reqwest::StatusCode::OK);
    let impaired_report: CreditBondedExecutionSimulationReport = impaired_response
        .json()
        .expect("parse impaired bonded execution simulation report");
    assert_eq!(
        impaired_report.simulated_evaluation.decision,
        chio_kernel::CreditBondedExecutionDecision::Deny
    );
    assert_eq!(
        impaired_report
            .simulated_evaluation
            .outstanding_delinquency_amount
            .as_ref()
            .expect("outstanding delinquency amount")
            .units,
        8_500
    );
    let delinquency_finding = impaired_report
        .simulated_evaluation
        .findings
        .iter()
        .find(|finding| {
            finding.code == chio_kernel::CreditBondedExecutionFindingCode::OutstandingDelinquency
        })
        .expect("outstanding delinquency finding");
    assert!(delinquency_finding
        .evidence_refs
        .iter()
        .any(|reference| { reference.reference_id == delinquency_event.body.event_id }));

    let _ = std::fs::remove_dir_all(&dir);
}
