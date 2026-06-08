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
fn test_capital_book_report_export_surfaces() {
    skip_when_loopback_denied!(test_capital_book_report_export_surfaces);
    let dir = unique_dir("chio-capital-book");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-capital-book-1";
    let issuer_key = "issuer-capital-book-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-good-{day}"),
                    &format!("cap-capital-good-{day}"),
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
                .expect("append capital history receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-book-token";
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
                "receiptLimit": 1000,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue capital facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let issued_facility: SignedCreditFacility = facility_issue
        .json()
        .expect("parse issued capital facility");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-capital-pending-1",
                "cap-capital-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(120),
                SettlementStatus::Pending,
                "USD",
                8_000,
                "USD",
                true,
            ))
            .expect("append pending capital receipt");
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
                "receiptLimit": 1000,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue capital bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let issued_bond: SignedCreditBond = bond_issue.json().expect("parse issued capital bond");
    assert_eq!(
        issued_bond.body.report.disposition,
        chio_core::credit::CreditBondDisposition::Lock
    );

    let delinquency = record_test_credit_loss_event_with_kind(
        &receipt_db_path,
        &issued_bond,
        "cll-capital-delinquency-1",
        CreditLossLifecycleEventKind::Delinquency,
        500,
        CreditBondLifecycleState::Impaired,
        CreditLossLifecycleReasonCode::DelinquencyRecorded,
        "capital delinquency event",
    );
    let recovery = record_test_credit_loss_event_with_kind(
        &receipt_db_path,
        &issued_bond,
        "cll-capital-recovery-1",
        CreditLossLifecycleEventKind::Recovery,
        200,
        CreditBondLifecycleState::Impaired,
        CreditLossLifecycleReasonCode::RecoveryRecorded,
        "capital recovery event",
    );
    let reserve_release = record_test_credit_loss_event_with_kind(
        &receipt_db_path,
        &issued_bond,
        "cll-capital-release-1",
        CreditLossLifecycleEventKind::ReserveRelease,
        50,
        CreditBondLifecycleState::Released,
        CreditLossLifecycleReasonCode::ReserveReleased,
        "capital reserve release event",
    );

    let response = client
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
        .expect("send capital book request");
    let status = response.status();
    let response_body = response.text().expect("read capital book response body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "capital book export failed with body: {response_body}"
    );
    let report: SignedCapitalBookReport =
        serde_json::from_str(&response_body).expect("parse signed capital book");
    assert!(report
        .verify_signature()
        .expect("verify capital book signature"));
    assert_eq!(report.body.schema, "chio.credit.capital-book.v1");
    assert_eq!(report.body.subject_key, subject_key);
    assert_eq!(report.body.summary.funding_sources, 2);
    assert_eq!(report.body.summary.matching_loss_events, 3);
    assert_eq!(report.body.summary.currencies, vec!["USD".to_string()]);

    let facility_source = report
        .body
        .sources
        .iter()
        .find(|source| {
            source.facility_id.as_deref() == Some(issued_facility.body.facility_id.as_str())
        })
        .expect("facility source");
    assert_eq!(
        facility_source.kind,
        chio_core::credit::CapitalBookSourceKind::FacilityCommitment
    );
    assert_eq!(
        facility_source.owner_role,
        chio_core::credit::CapitalBookRole::OperatorTreasury
    );
    assert!(facility_source
        .committed_amount
        .as_ref()
        .is_some_and(|amount| amount.units > 0));
    assert!(facility_source
        .drawn_amount
        .as_ref()
        .is_some_and(|amount| amount.units > 0));
    assert!(facility_source
        .disbursed_amount
        .as_ref()
        .is_some_and(|amount| amount.units > 0));

    let reserve_source = report
        .body
        .sources
        .iter()
        .find(|source| {
            source.kind == chio_core::credit::CapitalBookSourceKind::ReserveBook
                && source.bond_id.as_deref() == Some(issued_bond.body.bond_id.as_str())
        })
        .expect("reserve source");
    assert_eq!(
        reserve_source.kind,
        chio_core::credit::CapitalBookSourceKind::ReserveBook
    );
    assert!(reserve_source
        .held_amount
        .as_ref()
        .is_some_and(|amount| amount.units > 0));
    assert_eq!(
        reserve_source
            .released_amount
            .as_ref()
            .expect("released amount")
            .units,
        50
    );
    assert_eq!(
        reserve_source
            .repaid_amount
            .as_ref()
            .expect("repaid amount")
            .units,
        200
    );
    assert_eq!(
        reserve_source
            .impaired_amount
            .as_ref()
            .expect("impaired amount")
            .units,
        300
    );

    let event_kinds = report
        .body
        .events
        .iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Commit));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Hold));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Draw));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Disburse));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Impair));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Repay));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Release));
    assert!(report
        .body
        .events
        .iter()
        .any(|event| event.loss_event_id.as_deref() == Some(delinquency.body.event_id.as_str())));
    assert!(report
        .body
        .events
        .iter()
        .any(|event| event.loss_event_id.as_deref() == Some(recovery.body.event_id.as_str())));
    assert!(report.body.events.iter().any(
        |event| event.loss_event_id.as_deref() == Some(reserve_release.body.event_id.as_str())
    ));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "capital-book",
            "export",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "200",
            "--facility-limit",
            "10",
            "--bond-limit",
            "10",
            "--loss-event-limit",
            "10",
        ])
        .output()
        .expect("run capital book CLI");
    assert!(
        cli_output.status.success(),
        "capital book CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: SignedCapitalBookReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse capital book CLI");
    assert!(cli_report
        .verify_signature()
        .expect("verify capital book CLI signature"));
    assert_eq!(cli_report.body.summary.funding_sources, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_capital_book_report_rejects_mixed_currency_and_missing_counterparty() {
    skip_when_loopback_denied!(
        test_capital_book_report_rejects_mixed_currency_and_missing_counterparty
    );
    let dir = unique_dir("chio-capital-book-negative");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-capital-book-negative-1";
    let issuer_key = "issuer-capital-book-negative-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..15_u64 {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-negative-usd-{day}"),
                    &format!("cap-capital-negative-usd-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub(day * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    4_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append usd negative capital receipt");
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-negative-eur-{day}"),
                    &format!("cap-capital-negative-eur-{day}"),
                    subject_key,
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
                .expect("append eur negative capital receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-book-negative-token";
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

    let mixed_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "100"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send mixed-currency capital book request");
    assert_eq!(mixed_response.status(), reqwest::StatusCode::CONFLICT);
    let mixed_body: serde_json::Value = mixed_response
        .json()
        .expect("parse mixed-currency capital book response");
    assert!(mixed_body["error"]
        .as_str()
        .expect("mixed-currency error")
        .contains("one coherent currency"));

    let missing_counterparty = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[("receiptLimit", "100")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send missing-counterparty capital book request");
    assert_eq!(
        missing_counterparty.status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let missing_body: serde_json::Value = missing_counterparty
        .json()
        .expect("parse missing-counterparty capital book response");
    assert!(missing_body["error"]
        .as_str()
        .expect("missing-counterparty error")
        .contains("--agent-subject"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_capital_instruction_issue_surfaces() {
    skip_when_loopback_denied!(test_capital_instruction_issue_surfaces);
    let dir = unique_dir("chio-capital-instruction");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let input_file = dir.join("capital-instruction.json");

    let subject_key = "subject-capital-instruction-1";
    let issuer_key = "issuer-capital-instruction-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-instruction-good-{day}"),
                    &format!("cap-capital-instruction-good-{day}"),
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
                .expect("append capital instruction history receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-instruction-token";
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

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-capital-instruction-pending-1",
                "cap-capital-instruction-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(120),
                SettlementStatus::Pending,
                "USD",
                8_000,
                "USD",
                true,
            ))
            .expect("append pending capital receipt");
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
        .expect("issue bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let issued_bond: SignedCreditBond = bond_issue.json().expect("parse issued bond");
    let reserve_amount = issued_bond
        .body
        .report
        .terms
        .as_ref()
        .expect("bond terms")
        .reserve_requirement_amount
        .clone();

    let (authority_chain, custodian_id) = signed_capital_authority_chain(
        CapitalExecutionRole::OperatorTreasury,
        now.saturating_sub(30),
        now.saturating_add(3_600),
        now.saturating_sub(20),
        now.saturating_add(3_600),
    );
    let request_json = serde_json::json!({
        "query": {
            "agentSubject": subject_key,
            "receiptLimit": 200,
            "facilityLimit": 10,
            "bondLimit": 10,
            "lossEventLimit": 10
        },
        "sourceKind": "reserve_book",
        "action": "lock_reserve",
        "amount": reserve_amount.clone(),
        "authorityChain": authority_chain,
        "executionWindow": {
            "notBefore": now.saturating_sub(60),
            "notAfter": now.saturating_add(3_600)
        },
        "rail": {
            "kind": "manual",
            "railId": "reserve-manual-1",
            "custodyProviderId": custodian_id,
            "sourceAccountRef": "reserve-book-main"
        },
        "observedExecution": {
            "observedAt": now,
            "externalReferenceId": "wire-1",
            "amount": reserve_amount.clone()
        }
    });

    let response = client
        .post(format!("{base_url}/v1/capital/instructions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&request_json)
        .send()
        .expect("issue capital instruction");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let instruction: SignedCapitalExecutionInstruction =
        response.json().expect("parse capital instruction");
    assert!(instruction
        .verify_signature()
        .expect("verify capital instruction signature"));
    assert_eq!(
        instruction.body.schema,
        "chio.credit.capital-instruction.v1"
    );
    assert_eq!(instruction.body.subject_key, subject_key);
    assert_eq!(
        instruction.body.action,
        CapitalExecutionInstructionAction::LockReserve
    );
    assert_eq!(
        instruction.body.source_kind,
        chio_core::credit::CapitalBookSourceKind::ReserveBook
    );
    assert_eq!(
        instruction.body.intended_state,
        CapitalExecutionIntendedState::PendingExecution
    );
    assert_eq!(
        instruction.body.reconciled_state,
        CapitalExecutionReconciledState::Matched
    );
    assert_eq!(instruction.body.authority_chain.len(), 2);
    assert!(instruction
        .body
        .evidence_refs
        .iter()
        .any(|evidence| evidence.reference_id == issued_bond.body.bond_id));

    std::fs::write(
        &input_file,
        serde_json::to_vec_pretty(&request_json).expect("serialize capital instruction request"),
    )
    .expect("write capital instruction request");
    // Build the reserve book against the trusted bond/scorecard by scoring with
    // the same authority the trust service uses.
    let authority_seed_path = trust_service_authority_seed_path(&receipt_db_path);
    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
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
            input_file.to_str().expect("capital instruction input file"),
        ])
        .output()
        .expect("run capital instruction CLI");
    assert!(
        cli_output.status.success(),
        "capital instruction CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_instruction: SignedCapitalExecutionInstruction =
        serde_json::from_slice(&cli_output.stdout).expect("parse capital instruction CLI");
    assert!(cli_instruction
        .verify_signature()
        .expect("verify capital instruction CLI signature"));
    assert_eq!(
        cli_instruction.body.action,
        CapitalExecutionInstructionAction::LockReserve
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_capital_instruction_issue_rejects_stale_authority_and_mismatch() {
    skip_when_loopback_denied!(test_capital_instruction_issue_rejects_stale_authority_and_mismatch);
    let dir = unique_dir("chio-capital-instruction-negative");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-capital-instruction-negative-1";
    let issuer_key = "issuer-capital-instruction-negative-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-instruction-negative-{day}"),
                    &format!("cap-capital-instruction-negative-{day}"),
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
                .expect("append negative capital instruction history receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-instruction-negative-token";
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

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-capital-instruction-negative-pending-1",
                "cap-capital-instruction-negative-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(120),
                SettlementStatus::Pending,
                "USD",
                8_000,
                "USD",
                true,
            ))
            .expect("append pending negative capital receipt");
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
        .expect("issue bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let issued_bond: SignedCreditBond = bond_issue.json().expect("parse issued bond");
    let reserve_amount = issued_bond
        .body
        .report
        .terms
        .as_ref()
        .expect("bond terms")
        .reserve_requirement_amount
        .clone();

    let (stale_authority_chain, stale_custodian_id) = signed_capital_authority_chain(
        CapitalExecutionRole::OperatorTreasury,
        now.saturating_sub(100),
        now.saturating_sub(10),
        now.saturating_sub(100),
        now.saturating_sub(10),
    );
    let stale_response = client
        .post(format!("{base_url}/v1/capital/instructions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "sourceKind": "reserve_book",
            "action": "release_reserve",
            "amount": reserve_amount.clone(),
            "authorityChain": stale_authority_chain,
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "reserve-manual-1",
                "custodyProviderId": stale_custodian_id
            }
        }))
        .send()
        .expect("send stale capital instruction");
    assert_eq!(stale_response.status(), reqwest::StatusCode::CONFLICT);
    let stale_body: serde_json::Value = stale_response
        .json()
        .expect("parse stale capital instruction response");
    assert!(stale_body["error"]
        .as_str()
        .expect("stale capital instruction error")
        .contains("stale"));

    let (mismatch_authority_chain, mismatch_custodian_id) = signed_capital_authority_chain(
        CapitalExecutionRole::OperatorTreasury,
        now.saturating_sub(30),
        now.saturating_add(3_600),
        now.saturating_sub(20),
        now.saturating_add(3_600),
    );
    let mismatch_response = client
        .post(format!("{base_url}/v1/capital/instructions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "sourceKind": "reserve_book",
            "action": "lock_reserve",
            "amount": reserve_amount.clone(),
            "authorityChain": mismatch_authority_chain,
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "reserve-manual-1",
                "custodyProviderId": mismatch_custodian_id
            },
            "observedExecution": {
                "observedAt": now,
                "externalReferenceId": "wire-mismatch-1",
                "amount": {
                    "units": reserve_amount.units + 1,
                    "currency": reserve_amount.currency.clone()
                }
            }
        }))
        .send()
        .expect("send mismatched capital instruction");
    assert_eq!(mismatch_response.status(), reqwest::StatusCode::CONFLICT);
    let mismatch_body: serde_json::Value = mismatch_response
        .json()
        .expect("parse mismatched capital instruction response");
    assert!(mismatch_body["error"]
        .as_str()
        .expect("mismatched capital instruction error")
        .contains("does not match intended amount"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_capital_allocation_issue_surfaces() {
    skip_when_loopback_denied!(test_capital_allocation_issue_surfaces);
    let dir = unique_dir("chio-capital-allocation");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let input_file = dir.join("capital-allocation.json");

    let subject_key = "subject-capital-allocation-1";
    let issuer_key = "issuer-capital-allocation-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-allocation-good-{day}"),
                    &format!("cap-capital-allocation-good-{day}"),
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
                .expect("append capital allocation history receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-allocation-token";
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
    let issued_facility: SignedCreditFacility = facility_issue
        .json()
        .expect("parse issued capital allocation facility");

    let rc_capital_allocation_pending_1 = make_governed_authorization_receipt_with_options(
        "rc-capital-allocation-pending-1",
        "cap-capital-allocation-pending-1",
        subject_key,
        issuer_key,
        "ledger",
        "transfer",
        now.saturating_sub(120),
        SettlementStatus::Pending,
        "USD",
        30_000,
        "USD",
        false,
        false,
    );
    let governed_receipt_id = rc_capital_allocation_pending_1.id.as_str();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&rc_capital_allocation_pending_1)
            .expect("append governed pending receipt");
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
        .expect("issue bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let issued_bond: SignedCreditBond = bond_issue.json().expect("parse issued bond");

    let (authority_chain, custodian_id) = signed_capital_authority_chain(
        CapitalExecutionRole::OperatorTreasury,
        now.saturating_sub(30),
        now.saturating_add(3_600),
        now.saturating_sub(20),
        now.saturating_add(3_600),
    );
    let request_json = serde_json::json!({
        "query": {
            "agentSubject": subject_key,
            "receiptLimit": 200,
            "facilityLimit": 10,
            "bondLimit": 10,
            "lossEventLimit": 10
        },
        "receiptId": governed_receipt_id,
        "authorityChain": authority_chain,
        "executionWindow": {
            "notBefore": now.saturating_sub(60),
            "notAfter": now.saturating_add(3_600)
        },
        "rail": {
            "kind": "manual",
            "railId": "capital-allocation-manual-1",
            "custodyProviderId": custodian_id,
            "sourceAccountRef": "operator-capital-main"
        },
        "description": "allocate governed capital for the selected receipt"
    });

    let response = client
        .post(format!("{base_url}/v1/capital/allocations/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&request_json)
        .send()
        .expect("issue capital allocation");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let allocation: SignedCapitalAllocationDecision =
        response.json().expect("parse capital allocation");
    assert!(allocation
        .verify_signature()
        .expect("verify capital allocation signature"));
    assert_eq!(allocation.body.schema, "chio.credit.capital-allocation.v1");
    assert_eq!(allocation.body.subject_key, subject_key);
    assert_eq!(allocation.body.governed_receipt_id, governed_receipt_id);
    assert_eq!(
        allocation.body.outcome,
        CapitalAllocationDecisionOutcome::Allocate
    );
    assert_eq!(
        allocation.body.source_kind,
        Some(CapitalBookSourceKind::FacilityCommitment)
    );
    assert_eq!(
        allocation.body.facility_id.as_deref(),
        Some(issued_facility.body.facility_id.as_str())
    );
    assert_eq!(
        allocation.body.bond_id.as_deref(),
        Some(issued_bond.body.bond_id.as_str())
    );
    assert!(allocation.body.source_id.is_some());
    assert!(allocation.body.reserve_source_id.is_some());
    assert!(allocation.body.findings.is_empty());
    assert!(allocation.body.instruction_drafts.iter().any(|draft| {
        draft.action == CapitalExecutionInstructionAction::TransferFunds
            && draft.amount.units == 30_000
            && draft.amount.currency == "USD"
    }));

    std::fs::write(
        &input_file,
        serde_json::to_vec_pretty(&request_json).expect("serialize capital allocation request"),
    )
    .expect("write capital allocation request");
    // Score and sign the CLI allocation with the same authority the trust
    // service uses so seeded receipts pass reputation integrity validation and
    // the signer key matches.
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
            "capital-allocation",
            "issue",
            "--input-file",
            input_file.to_str().expect("capital allocation input file"),
        ])
        .output()
        .expect("run capital allocation CLI");
    assert!(
        cli_output.status.success(),
        "capital allocation CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_allocation: SignedCapitalAllocationDecision =
        serde_json::from_slice(&cli_output.stdout).expect("parse capital allocation CLI");
    assert!(cli_allocation
        .verify_signature()
        .expect("verify capital allocation CLI signature"));
    assert_eq!(
        cli_allocation.body.outcome,
        CapitalAllocationDecisionOutcome::Allocate
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_capital_allocation_issue_fail_closed_and_boundary_outcomes() {
    skip_when_loopback_denied!(test_capital_allocation_issue_fail_closed_and_boundary_outcomes);
    let dir = unique_dir("chio-capital-allocation-boundaries");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let manual_subject = "subject-capital-allocation-manual-1";
    let queue_subject = "subject-capital-allocation-queue-1";
    let issuer_key = "issuer-capital-allocation-boundaries-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-allocation-manual-good-{day}"),
                    &format!("cap-capital-allocation-manual-good-{day}"),
                    manual_subject,
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
                .expect("append manual allocation history");
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-allocation-queue-good-{day}"),
                    &format!("cap-capital-allocation-queue-good-{day}"),
                    queue_subject,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    100,
                    "USD",
                    false,
                    false,
                ))
                .expect("append queue allocation history");
        }
        // Preserve queue-depth boundary coverage without making every large-history fixture pay
        // for the full reserve-depth dataset.
        for day in LARGE_RECEIPT_HISTORY_LEN..CAPITAL_ALLOCATION_QUEUE_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-allocation-queue-good-{day}"),
                    &format!("cap-capital-allocation-queue-good-{day}"),
                    queue_subject,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    100,
                    "USD",
                    false,
                    false,
                ))
                .expect("append queue allocation reserve depth");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-allocation-boundaries-token";
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

    for subject_key in [manual_subject, queue_subject] {
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
            .expect("issue facility for subject");
        assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    }

    let rc_capital_allocation_manual_pending_1 = make_governed_authorization_receipt_with_options(
        "rc-capital-allocation-manual-pending-1",
        "cap-capital-allocation-manual-pending-1",
        manual_subject,
        issuer_key,
        "ledger",
        "transfer",
        now.saturating_sub(120),
        SettlementStatus::Pending,
        "USD",
        30_000,
        "USD",
        false,
        false,
    );
    let rc_capital_allocation_queue_pending_2 = make_governed_authorization_receipt_with_options(
        "rc-capital-allocation-queue-pending-2",
        "cap-capital-allocation-queue-pending-2",
        queue_subject,
        issuer_key,
        "ledger",
        "transfer",
        now.saturating_sub(60),
        SettlementStatus::Pending,
        "USD",
        5_000,
        "USD",
        false,
        false,
    );
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&rc_capital_allocation_manual_pending_1)
            .expect("append manual pending governed receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-capital-allocation-queue-pending-1",
                "cap-capital-allocation-queue-pending-1",
                queue_subject,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(120),
                SettlementStatus::Pending,
                "USD",
                50_000,
                "USD",
                false,
                false,
            ))
            .expect("append first queue pending receipt");
        store
            .append_chio_receipt(&rc_capital_allocation_queue_pending_2)
            .expect("append second queue pending receipt");
    }

    let queue_bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": queue_subject,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue queue bond");
    assert_eq!(queue_bond_issue.status(), reqwest::StatusCode::OK);

    let (manual_authority_chain, manual_custodian_id) = signed_capital_authority_chain(
        CapitalExecutionRole::OperatorTreasury,
        now.saturating_sub(30),
        now.saturating_add(3_600),
        now.saturating_sub(20),
        now.saturating_add(3_600),
    );
    let manual_review_response = client
        .post(format!("{base_url}/v1/capital/allocations/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": manual_subject,
                "receiptLimit": 200,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "receiptId": rc_capital_allocation_manual_pending_1.id.as_str(),
            "authorityChain": manual_authority_chain,
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "capital-allocation-manual-boundary-1",
                "custodyProviderId": manual_custodian_id,
                "sourceAccountRef": "operator-capital-main"
            }
        }))
        .send()
        .expect("issue manual-review capital allocation");
    assert_eq!(manual_review_response.status(), reqwest::StatusCode::OK);
    let manual_review: SignedCapitalAllocationDecision = manual_review_response
        .json()
        .expect("parse manual-review capital allocation");
    assert_eq!(
        manual_review.body.outcome,
        CapitalAllocationDecisionOutcome::ManualReview
    );
    assert!(manual_review.body.instruction_drafts.is_empty());
    assert!(manual_review.body.findings.iter().any(|finding| {
        finding.code == CapitalAllocationDecisionReasonCode::ReserveBookMissing
    }));

    let (ambiguous_authority_chain, ambiguous_custodian_id) = signed_capital_authority_chain(
        CapitalExecutionRole::OperatorTreasury,
        now.saturating_sub(30),
        now.saturating_add(3_600),
        now.saturating_sub(20),
        now.saturating_add(3_600),
    );
    let ambiguous_response = client
        .post(format!("{base_url}/v1/capital/allocations/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": queue_subject,
                "receiptLimit": 200,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "authorityChain": ambiguous_authority_chain,
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "capital-allocation-queue-boundary-1",
                "custodyProviderId": ambiguous_custodian_id,
                "sourceAccountRef": "operator-capital-main"
            }
        }))
        .send()
        .expect("issue ambiguous capital allocation");
    assert_eq!(ambiguous_response.status(), reqwest::StatusCode::CONFLICT);
    let ambiguous_body: serde_json::Value = ambiguous_response
        .json()
        .expect("parse ambiguous capital allocation body");
    assert!(ambiguous_body["error"]
        .as_str()
        .expect("ambiguous capital allocation error")
        .contains("multiple approved actionable governed receipts"));

    let (queue_authority_chain, queue_custodian_id) = signed_capital_authority_chain(
        CapitalExecutionRole::OperatorTreasury,
        now.saturating_sub(30),
        now.saturating_add(3_600),
        now.saturating_sub(20),
        now.saturating_add(3_600),
    );
    let queue_response = client
        .post(format!("{base_url}/v1/capital/allocations/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": queue_subject,
                "receiptLimit": 200,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "receiptId": rc_capital_allocation_queue_pending_2.id.as_str(),
            "authorityChain": queue_authority_chain,
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "capital-allocation-queue-boundary-1",
                "custodyProviderId": queue_custodian_id,
                "sourceAccountRef": "operator-capital-main"
            }
        }))
        .send()
        .expect("issue queued capital allocation");
    assert_eq!(queue_response.status(), reqwest::StatusCode::OK);
    let queued: SignedCapitalAllocationDecision = queue_response
        .json()
        .expect("parse queued capital allocation");
    assert_eq!(queued.body.outcome, CapitalAllocationDecisionOutcome::Queue);
    assert!(queued.body.instruction_drafts.is_empty());
    assert!(queued.body.findings.iter().any(|finding| {
        finding.code == CapitalAllocationDecisionReasonCode::UtilizationCeilingExceeded
    }));

    let _ = std::fs::remove_dir_all(&dir);
}
