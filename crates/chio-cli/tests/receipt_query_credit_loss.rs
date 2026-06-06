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
fn test_credit_loss_lifecycle_issue_and_list_surfaces() {
    skip_when_loopback_denied!(test_credit_loss_lifecycle_issue_and_list_surfaces);
    let dir = unique_dir("chio-credit-loss-lifecycle");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-loss-1";
    let issuer_key = "issuer-credit-loss-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-loss-good-{day}"),
                    &format!("cap-loss-good-{day}"),
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
                .expect("append good loss history");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-loss-lifecycle-token";
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
        .expect("issue loss backing facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

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
        .expect("issue active bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse active bond");
    let bond_id = bond.body.bond_id.clone();

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-loss-failed-1",
                "cap-loss-failed-1",
                subject_key,
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
            .expect("append failed loss receipt");
    }

    let evaluate_response = client
        .get(format!("{base_url}/v1/reports/bond-loss-policy"))
        .query(&[("bondId", bond_id.as_str()), ("eventKind", "delinquency")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send loss lifecycle evaluate request");
    let evaluate_status = evaluate_response.status();
    let evaluate_body = evaluate_response.text().expect("read loss lifecycle body");
    assert_eq!(
        evaluate_status,
        reqwest::StatusCode::OK,
        "loss lifecycle evaluate failed: {evaluate_body}"
    );
    let evaluate_report: CreditLossLifecycleReport =
        serde_json::from_str(&evaluate_body).expect("parse loss lifecycle report");
    assert_eq!(
        evaluate_report.schema,
        "chio.credit.loss-lifecycle-report.v1"
    );
    assert_eq!(
        evaluate_report.query.event_kind,
        chio_core::credit::CreditLossLifecycleEventKind::Delinquency
    );
    assert_eq!(
        evaluate_report.summary.projected_bond_lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Impaired
    );
    assert_eq!(
        evaluate_report
            .summary
            .event_amount
            .as_ref()
            .expect("delinquency amount")
            .units,
        8_500
    );

    let issue_response = client
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
        .expect("issue delinquency lifecycle event");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);
    let event: SignedCreditLossLifecycle =
        issue_response.json().expect("parse loss lifecycle event");
    assert_eq!(event.body.schema, "chio.credit.loss-lifecycle.v1");
    assert_eq!(
        event.body.event_kind,
        chio_core::credit::CreditLossLifecycleEventKind::Delinquency
    );
    assert_eq!(
        event.body.projected_bond_lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Impaired
    );

    let bond_list = client
        .get(format!("{base_url}/v1/reports/bonds"))
        .query(&[("bondId", event.body.bond_id.as_str()), ("limit", "5")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list bond after delinquency");
    assert_eq!(bond_list.status(), reqwest::StatusCode::OK);
    let bond_report: CreditBondListReport = bond_list.json().expect("parse bond list");
    assert_eq!(bond_report.summary.matching_bonds, 1);
    assert_eq!(
        bond_report.bonds[0].lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Impaired
    );

    let list_response = client
        .get(format!("{base_url}/v1/reports/bond-losses"))
        .query(&[("bondId", event.body.bond_id.as_str()), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send loss lifecycle list request");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_report: CreditLossLifecycleListReport =
        list_response.json().expect("parse loss lifecycle list");
    assert_eq!(list_report.schema, "chio.credit.loss-lifecycle-list.v1");
    assert_eq!(list_report.summary.matching_events, 1);
    assert_eq!(list_report.summary.delinquency_events, 1);
    assert_eq!(
        list_report.events[0].event.body.event_id,
        event.body.event_id
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "loss",
            "list",
            "--bond-id",
            event.body.bond_id.as_str(),
            "--limit",
            "10",
        ])
        .output()
        .expect("run credit loss lifecycle list CLI");
    assert!(
        cli_output.status.success(),
        "credit loss lifecycle list CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: CreditLossLifecycleListReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse credit loss lifecycle CLI list");
    assert_eq!(cli_report.summary.matching_events, 1);
    assert_eq!(cli_report.summary.reserve_slash_events, 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_loss_lifecycle_recovery_write_off_and_release_fail_closed() {
    skip_when_loopback_denied!(
        test_credit_loss_lifecycle_recovery_write_off_and_release_fail_closed
    );
    let dir = unique_dir("chio-credit-loss-lifecycle-release");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-loss-release-1";
    let issuer_key = "issuer-credit-loss-release-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-loss-release-good-{day}"),
                    &format!("cap-loss-release-good-{day}"),
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
                .expect("append good release history");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-loss-release-token";
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

    let _facility_issue = client
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
        .expect("issue release backing facility");

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
        .expect("issue release bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse release bond");
    let bond_id = bond.body.bond_id.clone();
    let reserve_amount = bond
        .body
        .report
        .terms
        .as_ref()
        .expect("release bond terms")
        .reserve_requirement_amount
        .clone();

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-loss-release-failed-1",
                "cap-loss-release-failed-1",
                subject_key,
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
            .expect("append failed release receipt");
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
        .expect("issue delinquency before release");
    let delinquency_status = delinquency_issue.status();
    let delinquency_body = delinquency_issue
        .text()
        .expect("read delinquency lifecycle body");
    assert_eq!(
        delinquency_status,
        reqwest::StatusCode::OK,
        "delinquency issue failed: {delinquency_body}"
    );

    let premature_release = client
        .get(format!("{base_url}/v1/reports/bond-loss-policy"))
        .query(&[
            ("bondId", bond_id.as_str()),
            ("eventKind", "reserve_release"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("evaluate premature reserve release");
    assert_eq!(premature_release.status(), reqwest::StatusCode::CONFLICT);
    let premature_release_body: serde_json::Value = premature_release
        .json()
        .expect("parse premature reserve release error");
    assert!(premature_release_body["error"]
        .as_str()
        .expect("premature reserve release error string")
        .contains("cleared first"));

    let recovery_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "recovery",
                "amount": {
                    "units": 3_500,
                    "currency": "USD"
                }
            }
        }))
        .send()
        .expect("issue recovery event");
    assert_eq!(recovery_issue.status(), reqwest::StatusCode::OK);

    let excessive_write_off = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "write_off",
                "amount": {
                    "units": 6_000,
                    "currency": "USD"
                }
            }
        }))
        .send()
        .expect("issue excessive write-off");
    assert_eq!(excessive_write_off.status(), reqwest::StatusCode::CONFLICT);

    let write_off_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "write_off",
                "amount": {
                    "units": 5_000,
                    "currency": "USD"
                }
            }
        }))
        .send()
        .expect("issue write-off event");
    assert_eq!(write_off_issue.status(), reqwest::StatusCode::OK);
    let write_off_event: SignedCreditLossLifecycle =
        write_off_issue.json().expect("parse write-off event");
    assert_eq!(
        write_off_event.body.event_kind,
        chio_core::credit::CreditLossLifecycleEventKind::WriteOff
    );

    let release_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "reserve_release"
            }
        }))
        .send()
        .expect("issue reserve release event without execution metadata");
    assert_eq!(release_issue.status(), reqwest::StatusCode::BAD_REQUEST);
    let release_issue_body: serde_json::Value = release_issue
        .json()
        .expect("parse reserve release metadata error");
    assert!(release_issue_body["error"]
        .as_str()
        .expect("reserve release metadata error")
        .contains("requires executionWindow"));

    let release_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "reserve_release"
            },
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-1",
                    "approvedAt": now.saturating_sub(30),
                    "expiresAt": now.saturating_add(3_600)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-1",
                    "approvedAt": now.saturating_sub(20),
                    "expiresAt": now.saturating_add(3_600)
                }
            ],
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "reserve-release-manual-1",
                "custodyProviderId": "custodian-1",
                "sourceAccountRef": "reserve-book-main"
            },
            "observedExecution": {
                "observedAt": now,
                "externalReferenceId": "reserve-release-wire-1",
                "amount": reserve_amount.clone()
            },
            "appealWindowEndsAt": now.saturating_add(1_800),
            "description": "operator reserve release after cleared delinquency"
        }))
        .send()
        .expect("issue reserve release event");
    assert_eq!(release_issue.status(), reqwest::StatusCode::OK);
    let release_event: SignedCreditLossLifecycle =
        release_issue.json().expect("parse reserve release event");
    assert_eq!(
        release_event.body.event_kind,
        chio_core::credit::CreditLossLifecycleEventKind::ReserveRelease
    );
    assert_eq!(
        release_event.body.projected_bond_lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Released
    );
    assert_eq!(
        release_event.body.reserve_control_source_id.as_deref(),
        Some(format!("capital-source:bond:{bond_id}").as_str())
    );
    assert_eq!(
        release_event.body.execution_state,
        Some(chio_core::credit::CreditReserveControlExecutionState::Executed)
    );
    assert_eq!(
        release_event.body.reconciled_state,
        Some(CapitalExecutionReconciledState::Matched)
    );
    assert_eq!(
        release_event.body.appeal_state,
        Some(chio_core::credit::CreditReserveControlAppealState::Open)
    );
    assert_eq!(
        release_event.body.appeal_window_ends_at,
        Some(now.saturating_add(1_800))
    );
    assert_eq!(release_event.body.authority_chain.len(), 2);
    assert_eq!(
        release_event
            .body
            .rail
            .as_ref()
            .map(|rail| rail.custody_provider_id.as_str()),
        Some("custodian-1")
    );
    assert_eq!(
        release_event.body.description.as_deref(),
        Some("operator reserve release after cleared delinquency")
    );

    let list_response = client
        .get(format!("{base_url}/v1/reports/bond-losses"))
        .query(&[("bondId", bond_id.as_str()), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list release lifecycle events");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_report: CreditLossLifecycleListReport =
        list_response.json().expect("parse release lifecycle list");
    assert_eq!(list_report.summary.matching_events, 4);
    assert_eq!(list_report.summary.delinquency_events, 1);
    assert_eq!(list_report.summary.recovery_events, 1);
    assert_eq!(list_report.summary.write_off_events, 1);
    assert_eq!(list_report.summary.reserve_release_events, 1);
    assert_eq!(list_report.summary.reserve_slash_events, 0);

    let bond_list = client
        .get(format!("{base_url}/v1/reports/bonds"))
        .query(&[("bondId", bond_id.as_str()), ("limit", "5")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list bond after reserve release");
    assert_eq!(bond_list.status(), reqwest::StatusCode::OK);
    let bond_report: CreditBondListReport = bond_list.json().expect("parse released bond list");
    assert_eq!(
        bond_report.bonds[0].lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Released
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_loss_lifecycle_reserve_slash_requires_valid_execution_metadata() {
    skip_when_loopback_denied!(
        test_credit_loss_lifecycle_reserve_slash_requires_valid_execution_metadata
    );
    let dir = unique_dir("chio-credit-loss-lifecycle-slash");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-loss-slash-1";
    let issuer_key = "issuer-credit-loss-slash-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-loss-slash-good-{day}"),
                    &format!("cap-loss-slash-good-{day}"),
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
                .expect("append good slash history");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-loss-slash-token";
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
        .expect("issue slash backing facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

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
        .expect("issue slash bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse slash bond");
    let bond_id = bond.body.bond_id.clone();

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-loss-slash-failed-1",
                "cap-loss-slash-failed-1",
                subject_key,
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
            .expect("append failed slash receipt");
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
        .expect("issue slash delinquency");
    assert_eq!(delinquency_issue.status(), reqwest::StatusCode::OK);

    let missing_metadata = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "reserve_slash"
            }
        }))
        .send()
        .expect("issue reserve slash without metadata");
    assert_eq!(missing_metadata.status(), reqwest::StatusCode::BAD_REQUEST);
    let missing_metadata_body: serde_json::Value = missing_metadata
        .json()
        .expect("parse reserve slash metadata error");
    assert!(missing_metadata_body["error"]
        .as_str()
        .expect("reserve slash metadata error")
        .contains("requires executionWindow"));

    let stale_authority = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "reserve_slash"
            },
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-1",
                    "approvedAt": now.saturating_sub(100),
                    "expiresAt": now.saturating_sub(10)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-1",
                    "approvedAt": now.saturating_sub(100),
                    "expiresAt": now.saturating_sub(10)
                }
            ],
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "reserve-slash-manual-1",
                "custodyProviderId": "custodian-1",
                "sourceAccountRef": "reserve-book-main"
            }
        }))
        .send()
        .expect("issue reserve slash with stale authority");
    assert_eq!(stale_authority.status(), reqwest::StatusCode::CONFLICT);
    let stale_authority_body: serde_json::Value = stale_authority
        .json()
        .expect("parse stale reserve slash response");
    assert!(stale_authority_body["error"]
        .as_str()
        .expect("stale reserve slash error")
        .contains("stale"));

    let slash_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "reserve_slash",
                "amount": {
                    "units": 500,
                    "currency": "USD"
                }
            },
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-1",
                    "approvedAt": now.saturating_sub(30),
                    "expiresAt": now.saturating_add(3_600)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-1",
                    "approvedAt": now.saturating_sub(20),
                    "expiresAt": now.saturating_add(3_600)
                }
            ],
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "reserve-slash-manual-1",
                "custodyProviderId": "custodian-1",
                "sourceAccountRef": "reserve-book-main"
            },
            "appealWindowEndsAt": now.saturating_add(1_800),
            "description": "operator reserve slash against outstanding delinquency"
        }))
        .send()
        .expect("issue reserve slash event");
    assert_eq!(slash_issue.status(), reqwest::StatusCode::OK);
    let slash_event: SignedCreditLossLifecycle =
        slash_issue.json().expect("parse reserve slash event");
    assert_eq!(
        slash_event.body.event_kind,
        chio_core::credit::CreditLossLifecycleEventKind::ReserveSlash
    );
    assert_eq!(
        slash_event
            .body
            .report
            .summary
            .event_amount
            .as_ref()
            .expect("slash amount")
            .units,
        500
    );
    assert_eq!(
        slash_event.body.execution_state,
        Some(chio_core::credit::CreditReserveControlExecutionState::PendingExecution)
    );
    assert_eq!(
        slash_event.body.reconciled_state,
        Some(CapitalExecutionReconciledState::NotObserved)
    );
    assert_eq!(
        slash_event.body.appeal_state,
        Some(chio_core::credit::CreditReserveControlAppealState::Open)
    );
    assert_eq!(
        slash_event.body.reserve_control_source_id.as_deref(),
        Some(format!("capital-source:bond:{bond_id}").as_str())
    );
    assert_eq!(slash_event.body.authority_chain.len(), 2);
    assert_eq!(
        slash_event.body.description.as_deref(),
        Some("operator reserve slash against outstanding delinquency")
    );

    let list_response = client
        .get(format!("{base_url}/v1/reports/bond-losses"))
        .query(&[("bondId", bond_id.as_str()), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list slash lifecycle events");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_report: CreditLossLifecycleListReport =
        list_response.json().expect("parse slash lifecycle list");
    assert_eq!(list_report.summary.matching_events, 2);
    assert_eq!(list_report.summary.delinquency_events, 1);
    assert_eq!(list_report.summary.reserve_slash_events, 1);
    assert_eq!(list_report.summary.reserve_release_events, 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_provider_risk_package_export_surfaces() {
    skip_when_loopback_denied!(test_provider_risk_package_export_surfaces);
    let dir = unique_dir("chio-provider-risk-package");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-provider-risk-1";
    let issuer_key = "issuer-provider-risk-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_credit_history_receipt(
                    &format!("rc-risk-good-{day}"),
                    &format!("cap-risk-good-{day}"),
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
                .expect("append provider risk receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "provider-risk-package-token";
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
        .expect("issue provider facility");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);
    let issued_facility: SignedCreditFacility = issue_response
        .json()
        .expect("parse issued provider facility");

    let rc_risk_loss_1 = make_credit_history_receipt(
        "rc-risk-loss-1",
        "cap-risk-loss-1",
        subject_key,
        issuer_key,
        "ledger",
        "transfer",
        now.saturating_sub(60),
        SettlementStatus::Failed,
        "USD",
        8_500,
        "USD",
        true,
    );
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&rc_risk_loss_1)
            .expect("append provider risk loss receipt");
    }

    let response = client
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
        .expect("send provider risk package request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: SignedCreditProviderRiskPackage =
        response.json().expect("parse signed provider risk package");
    assert!(report
        .verify_signature()
        .expect("verify provider risk package signature"));
    assert_eq!(report.body.schema, "chio.credit.provider-risk-package.v1");
    assert_eq!(report.body.subject_key, subject_key);
    assert!(report
        .body
        .exposure
        .verify_signature()
        .expect("verify nested exposure signature"));
    assert!(report
        .body
        .scorecard
        .verify_signature()
        .expect("verify nested scorecard signature"));
    assert!(report.body.recent_loss_history.summary.returned_loss_events >= 1);
    assert_eq!(
        report.body.recent_loss_history.entries[0].receipt_id,
        rc_risk_loss_1.id
    );
    assert_eq!(
        report.body.recent_loss_history.entries[0].settlement_status,
        SettlementStatus::Failed
    );
    assert!(!report.body.evidence_refs.is_empty());
    let latest_facility = report
        .body
        .latest_facility
        .as_ref()
        .expect("latest facility snapshot");
    assert_eq!(
        latest_facility.facility_id,
        issued_facility.body.facility_id
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
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
            "provider-risk-package",
            "export",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "200",
            "--decision-limit",
            "50",
            "--recent-loss-limit",
            "5",
        ])
        .output()
        .expect("run provider risk package CLI");
    assert!(
        cli_output.status.success(),
        "provider risk package CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: SignedCreditProviderRiskPackage =
        serde_json::from_slice(&cli_output.stdout).expect("parse provider risk package CLI");
    assert!(cli_report
        .verify_signature()
        .expect("verify provider risk package CLI signature"));
    assert!(
        cli_report
            .body
            .recent_loss_history
            .summary
            .returned_loss_events
            >= 1
    );

    let _ = std::fs::remove_dir_all(&dir);
}
