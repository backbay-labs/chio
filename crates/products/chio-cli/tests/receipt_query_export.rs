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
fn test_receipt_analytics_endpoint() {
    skip_when_loopback_denied!(test_receipt_analytics_endpoint);
    let setup = setup_with_receipts("chio-receipt-analytics");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/analytics", setup.base_url))
        .query(&[("timeBucket", "day"), ("groupLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send analytics request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for analytics"
    );
    let body: serde_json::Value = response.json().expect("parse analytics json");
    assert_eq!(body["summary"]["totalReceipts"].as_u64(), Some(5));
    assert_eq!(body["summary"]["allowCount"].as_u64(), Some(4));
    assert_eq!(body["summary"]["denyCount"].as_u64(), Some(1));

    let by_tool = body["byTool"].as_array().expect("byTool array");
    assert!(
        by_tool.iter().any(|row| {
            row["toolServer"].as_str() == Some("shell")
                && row["toolName"].as_str() == Some("bash")
                && row["metrics"]["totalReceipts"].as_u64() == Some(4)
        }),
        "shell/bash aggregate should be present"
    );

    let by_time = body["byTime"].as_array().expect("byTime array");
    assert_eq!(
        by_time.len(),
        1,
        "all fixture receipts fall into one day bucket"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_operator_report_endpoint() {
    skip_when_loopback_denied!(test_operator_report_endpoint);
    let dir = unique_dir("chio-operator-report");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "shell".to_string(),
            tool_name: "bash".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(5),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-op-root".to_string(),
            issuer: issuer_kp.public_key(),
            subject: root_kp.public_key(),
            scope: scope.clone(),
            issued_at: 1_000,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .expect("sign root capability");
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-op-child".to_string(),
            issuer: issuer_kp.public_key(),
            subject: leaf_kp.public_key(),
            scope,
            issued_at: 1_100,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .expect("sign child capability");

    let rc_op_1 = make_financial_receipt_signed_by(
        &checkpoint_kp,
        "rc-op-1",
        "cap-op-child",
        Some(&leaf_hex),
        &issuer_hex,
        "shell",
        "bash",
        Decision::Allow,
        3_000,
        850,
        None,
        &root_hex,
        1,
    );
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&root, None)
            .expect("record root lineage");
        store
            .record_capability_snapshot(&child, Some("cap-op-root"))
            .expect("record child lineage");

        let seq = store
            .append_chio_receipt_returning_seq(&rc_op_1)
            .expect("append checkpointed receipt");
        store
            .append_chio_receipt(&make_financial_receipt(
                "rc-op-2",
                "cap-op-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                3_001,
                0,
                Some(100),
                &root_hex,
                1,
            ))
            .expect("append uncheckpointed receipt");

        let bytes = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("load canonical receipt bytes")
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint =
            build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    {
        let budgets = SqliteBudgetStore::open(&budget_db_path).expect("open budget store");
        budgets
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-op-child".to_string(),
                grant_index: 0,
                invocation_count: 2,
                updated_at: 3_100,
                seq: 1,
                total_cost_exposed: 850,
                total_cost_realized_spend: 0,
            })
            .expect("upsert budget usage");
    }

    let listen = reserve_listen_addr();
    let service_token = "operator-report-token";
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
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[
            ("agentSubject", leaf_hex.as_str()),
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("budgetLimit", "10"),
            ("attributionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for operator report"
    );
    let body: serde_json::Value = response.json().expect("parse operator report json");

    assert_eq!(
        body["activity"]["summary"]["totalReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(body["activity"]["summary"]["allowCount"].as_u64(), Some(1));
    assert_eq!(body["activity"]["summary"]["denyCount"].as_u64(), Some(1));
    assert_eq!(
        body["budgetUtilization"]["summary"]["matchingGrants"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["budgetUtilization"]["summary"]["nearLimitCount"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["toolServer"].as_str(),
        Some("shell")
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["toolName"].as_str(),
        Some("bash")
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["remainingCostUnits"].as_u64(),
        Some(150)
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["dimensions"]["invocations"]["limit"].as_u64(),
        Some(5)
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["dimensions"]["invocations"]["remaining"].as_u64(),
        Some(3)
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["dimensions"]["money"]["limit"].as_u64(),
        Some(1000)
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["dimensions"]["money"]["remaining"].as_u64(),
        Some(150)
    );
    assert_eq!(
        body["compliance"]["evidenceReadyReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["compliance"]["uncheckpointedReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["compliance"]["pendingSettlementReceipts"].as_u64(),
        Some(0)
    );
    assert_eq!(
        body["compliance"]["failedSettlementReceipts"].as_u64(),
        Some(0)
    );
    assert_eq!(
        body["compliance"]["directEvidenceExportSupported"].as_bool(),
        Some(false)
    );
    assert_eq!(
        body["compliance"]["childReceiptScope"].as_str(),
        Some("omitted_no_join_path")
    );
    assert!(body["compliance"]["exportScopeNote"]
        .as_str()
        .expect("export scope note")
        .contains("tool filters narrow the operator report only"));
    assert_eq!(
        body["settlementReconciliation"]["summary"]["matchingReceipts"].as_u64(),
        Some(0)
    );
    let attribution_row = body["costAttribution"]["receipts"]
        .as_array()
        .expect("cost attribution receipts")
        .iter()
        .find(|row| row["receiptId"] == rc_op_1.id.as_str())
        .expect("operator attribution row");
    assert_eq!(
        attribution_row["budgetAuthority"]["guarantee_level"].as_str(),
        Some("ha_quorum_commit")
    );
    assert_eq!(
        attribution_row["budgetAuthority"]["hold_id"].as_str(),
        Some("budget-hold:rc-op-1:capability:0")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_settlement_reconciliation_report_and_action_endpoint() {
    skip_when_loopback_denied!(test_settlement_reconciliation_report_and_action_endpoint);
    let dir = unique_dir("chio-settlement-reconciliation");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let rc_settle_pending = make_financial_receipt_with_settlement_status(
        "rc-settle-pending",
        "cap-settlement-1",
        "payments",
        "checkout",
        4_000,
        125,
        SettlementStatus::Pending,
        Some("hold-pending-1"),
    );
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&rc_settle_pending)
            .expect("append pending settlement receipt");
        store
            .append_chio_receipt(&make_financial_receipt_with_settlement_status(
                "rc-settle-failed",
                "cap-settlement-1",
                "payments",
                "checkout",
                4_001,
                200,
                SettlementStatus::Failed,
                Some("hold-failed-1"),
            ))
            .expect("append failed settlement receipt");
        store
            .append_chio_receipt(&make_financial_receipt_with_settlement_status(
                "rc-settle-settled",
                "cap-settlement-1",
                "payments",
                "checkout",
                4_002,
                250,
                SettlementStatus::Settled,
                Some("hold-settled-1"),
            ))
            .expect("append settled receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "settlement-report-token";
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

    let initial = client
        .get(format!("{base_url}/v1/reports/settlements"))
        .query(&[
            ("capabilityId", "cap-settlement-1"),
            ("settlementLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send settlement report request");

    assert_eq!(initial.status(), reqwest::StatusCode::OK);
    let initial_body: serde_json::Value = initial.json().expect("parse initial report");
    assert_eq!(
        initial_body["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(initial_body["summary"]["pendingReceipts"].as_u64(), Some(1));
    assert_eq!(initial_body["summary"]["failedReceipts"].as_u64(), Some(1));
    assert_eq!(
        initial_body["summary"]["actionableReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        initial_body["receipts"][0]["reconciliationState"].as_str(),
        Some("open")
    );

    let reconcile = client
        .post(format!("{base_url}/v1/settlements/reconcile"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "receiptId": rc_settle_pending.id.as_str(),
            "reconciliationState": "reconciled",
            "note": "confirmed externally"
        }))
        .send()
        .expect("send settlement reconciliation update");

    assert_eq!(reconcile.status(), reqwest::StatusCode::OK);
    let reconcile_body: serde_json::Value = reconcile.json().expect("parse reconcile response");
    assert_eq!(reconcile_body["receiptId"], rc_settle_pending.id.as_str());
    assert_eq!(reconcile_body["reconciliationState"], "reconciled");
    assert_eq!(reconcile_body["note"], "confirmed externally");
    assert!(reconcile_body["updatedAt"].as_u64().is_some());

    let updated = client
        .get(format!("{base_url}/v1/reports/settlements"))
        .query(&[
            ("capabilityId", "cap-settlement-1"),
            ("settlementLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send updated settlement report request");

    assert_eq!(updated.status(), reqwest::StatusCode::OK);
    let updated_body: serde_json::Value = updated.json().expect("parse updated report");
    assert_eq!(
        updated_body["summary"]["reconciledReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["actionableReceipts"].as_u64(),
        Some(1)
    );
    let reconciled_row = updated_body["receipts"]
        .as_array()
        .expect("settlement receipts array")
        .iter()
        .find(|row| row["receiptId"] == rc_settle_pending.id.as_str())
        .expect("pending receipt should still be present");
    assert_eq!(reconciled_row["reconciliationState"], "reconciled");
    assert_eq!(reconciled_row["note"], "confirmed externally");
    assert_eq!(
        reconciled_row["budgetAuthority"]["guarantee_level"].as_str(),
        Some("ha_quorum_commit")
    );
    assert_eq!(
        reconciled_row["budgetAuthority"]["hold_id"].as_str(),
        Some("budget-hold:rc-settle-pending:capability:0")
    );

    let operator = client
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[
            ("capabilityId", "cap-settlement-1"),
            ("settlementLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");

    assert_eq!(operator.status(), reqwest::StatusCode::OK);
    let operator_body: serde_json::Value = operator.json().expect("parse operator report");
    assert_eq!(
        operator_body["settlementReconciliation"]["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["settlementReconciliation"]["summary"]["reconciledReceipts"].as_u64(),
        Some(1)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_metered_billing_reconciliation_report_and_action_endpoint() {
    skip_when_loopback_denied!(test_metered_billing_reconciliation_report_and_action_endpoint);
    let dir = unique_dir("chio-metered-billing-reconciliation");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();

    let rc_metered_1 =
        make_governed_receipt("rc-metered-1", "cap-metered-1", "shell", "bash", 6_000);
    let rc_metered_2 =
        make_governed_receipt("rc-metered-2", "cap-metered-1", "shell", "bash", 6_001);
    let rc_metered_non_governed = make_governed_x402_receipt(
        "rc-metered-non-governed",
        "cap-metered-2",
        "shell",
        "bash",
        6_002,
    );
    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-metered-1",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        store
            .append_chio_receipt(&rc_metered_1)
            .expect("append first metered governed receipt");
        store
            .append_chio_receipt(&rc_metered_2)
            .expect("append second metered governed receipt");
        store
            .append_chio_receipt(&rc_metered_non_governed)
            .expect("append non-metered governed receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "metered-billing-token";
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

    let initial = client
        .get(format!("{base_url}/v1/reports/metered-billing"))
        .query(&[("capabilityId", "cap-metered-1"), ("meteredLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send metered billing report request");
    let initial_status = initial.status();
    let initial_text = initial.text().expect("read initial metered report body");
    assert_eq!(
        initial_status,
        reqwest::StatusCode::OK,
        "metered billing report body: {initial_text}"
    );
    let initial_body: serde_json::Value =
        serde_json::from_str(&initial_text).expect("parse initial metered report");
    assert_eq!(
        initial_body["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        initial_body["summary"]["missingEvidenceReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        initial_body["summary"]["actionableReceipts"].as_u64(),
        Some(2)
    );

    let reconcile = client
        .post(format!("{base_url}/v1/metered-billing/reconcile"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "receiptId": rc_metered_1.id.as_str(),
            "adapterKind": "manual_meter",
            "evidenceId": "usage-chio-1",
            "observedUnits": 17,
            "billedCost": {
                "units": 4200,
                "currency": "USD"
            },
            "evidenceSha256": "sha256-metered-1",
            "recordedAt": 6100,
            "reconciliationState": "reconciled",
            "note": "approved quote overrun after review"
        }))
        .send()
        .expect("send metered billing reconciliation update");

    assert_eq!(reconcile.status(), reqwest::StatusCode::OK);
    let reconcile_body: serde_json::Value = reconcile.json().expect("parse metered response");
    assert_eq!(reconcile_body["receiptId"], rc_metered_1.id.as_str());
    assert_eq!(reconcile_body["reconciliationState"], "reconciled");
    assert_eq!(
        reconcile_body["evidence"]["usageEvidence"]["evidenceKind"],
        "manual_meter"
    );
    assert_eq!(
        reconcile_body["evidence"]["usageEvidence"]["observedUnits"],
        17
    );
    assert_eq!(reconcile_body["evidence"]["billedCost"]["units"], 4200);

    let replay = client
        .post(format!("{base_url}/v1/metered-billing/reconcile"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "receiptId": rc_metered_2.id.as_str(),
            "adapterKind": "manual_meter",
            "evidenceId": "usage-chio-1",
            "observedUnits": 10,
            "billedCost": {
                "units": 3200,
                "currency": "USD"
            },
            "recordedAt": 6101,
            "reconciliationState": "open"
        }))
        .send()
        .expect("send replay metered billing update");
    assert_eq!(replay.status(), reqwest::StatusCode::CONFLICT);

    let non_metered = client
        .post(format!("{base_url}/v1/metered-billing/reconcile"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "receiptId": rc_metered_non_governed.id.as_str(),
            "adapterKind": "manual_meter",
            "evidenceId": "usage-chio-2",
            "observedUnits": 8,
            "billedCost": {
                "units": 4200,
                "currency": "USD"
            },
            "recordedAt": 6102,
            "reconciliationState": "open"
        }))
        .send()
        .expect("send non-metered reconciliation update");
    assert_eq!(non_metered.status(), reqwest::StatusCode::CONFLICT);

    let updated = client
        .get(format!("{base_url}/v1/reports/metered-billing"))
        .query(&[("capabilityId", "cap-metered-1"), ("meteredLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send updated metered billing report request");
    assert_eq!(updated.status(), reqwest::StatusCode::OK);
    let updated_body: serde_json::Value = updated.json().expect("parse updated metered report");
    assert_eq!(
        updated_body["summary"]["evidenceAttachedReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["missingEvidenceReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["overQuotedUnitsReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["overQuotedCostReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["reconciledReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["actionableReceipts"].as_u64(),
        Some(1)
    );
    let reconciled_row = updated_body["receipts"]
        .as_array()
        .expect("metered billing receipts array")
        .iter()
        .find(|row| row["receiptId"] == rc_metered_1.id.as_str())
        .expect("first metered receipt row");
    assert_eq!(
        reconciled_row["evidence"]["usageEvidence"]["evidenceId"],
        "usage-chio-1"
    );
    assert_eq!(reconciled_row["evidenceMissing"], false);
    assert_eq!(reconciled_row["exceedsQuotedUnits"], true);
    assert_eq!(reconciled_row["exceedsQuotedCost"], true);
    assert_eq!(reconciled_row["financialMismatch"], false);
    assert_eq!(reconciled_row["actionRequired"], false);

    let operator = client
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[("capabilityId", "cap-metered-1"), ("meteredLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");
    let operator_status = operator.status();
    let operator_body_text = operator.text().expect("read operator report body");
    assert_eq!(
        operator_status,
        reqwest::StatusCode::OK,
        "operator report body: {operator_body_text}"
    );
    let operator_body: serde_json::Value =
        serde_json::from_str(&operator_body_text).expect("parse operator report");
    assert_eq!(
        operator_body["meteredBillingReconciliation"]["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["meteredBillingReconciliation"]["summary"]["reconciledReceipts"].as_u64(),
        Some(1)
    );

    let feed = client
        .get(format!("{base_url}/v1/reports/behavioral-feed"))
        .query(&[
            ("capabilityId", "cap-metered-1"),
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("receiptLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send behavioral feed request");
    assert_eq!(feed.status(), reqwest::StatusCode::OK);
    let feed: SignedBehavioralFeed = feed.json().expect("parse signed behavioral feed");
    assert!(feed
        .verify_signature()
        .expect("verify metered behavioral feed signature"));
    assert_eq!(feed.body.metered_billing.metered_receipts, 2);
    assert_eq!(feed.body.metered_billing.evidence_attached_receipts, 1);
    assert_eq!(feed.body.metered_billing.missing_evidence_receipts, 1);
    let metered_feed_row = feed
        .body
        .receipts
        .iter()
        .find(|row| row.receipt_id == rc_metered_1.id)
        .expect("metered feed row");
    assert!(metered_feed_row.governed.is_some());
    assert_eq!(
        metered_feed_row
            .governed
            .as_ref()
            .expect("governed metadata")
            .metered_billing
            .as_ref()
            .expect("metered billing metadata")
            .usage_evidence,
        None
    );
    assert_eq!(
        metered_feed_row
            .metered_reconciliation
            .as_ref()
            .expect("metered reconciliation row")
            .evidence
            .as_ref()
            .expect("evidence")
            .usage_evidence
            .evidence_id,
        "usage-chio-1"
    );

    let receipt_query = client
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("capabilityId", "cap-metered-1"), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send receipt query request");
    assert_eq!(receipt_query.status(), reqwest::StatusCode::OK);
    let receipt_query_body: serde_json::Value =
        receipt_query.json().expect("parse receipt query response");
    let queried_receipt = receipt_query_body["receipts"]
        .as_array()
        .expect("receipts array")
        .iter()
        .find(|row| row["id"] == rc_metered_1.id.as_str())
        .expect("queried metered receipt");
    assert!(
        queried_receipt["metadata"]["governed_transaction"]["metered_billing"]["usageEvidence"]
            .is_null()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_comptroller_surface_report_endpoint() {
    skip_when_loopback_denied!(test_comptroller_surface_report_endpoint);
    let dir = unique_dir("chio-comptroller-surface");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "shell".to_string(),
            tool_name: "bash".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(5),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-cs-root".to_string(),
            issuer: issuer_kp.public_key(),
            subject: root_kp.public_key(),
            scope: scope.clone(),
            issued_at: 1_000,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .expect("sign root capability");
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-cs-child".to_string(),
            issuer: issuer_kp.public_key(),
            subject: leaf_kp.public_key(),
            scope,
            issued_at: 1_100,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .expect("sign child capability");

    let rc_cs_1 = make_financial_receipt_signed_by(
        &checkpoint_kp,
        "rc-cs-1",
        "cap-cs-child",
        Some(&leaf_hex),
        &issuer_hex,
        "shell",
        "bash",
        Decision::Allow,
        3_000,
        850,
        None,
        &root_hex,
        1,
    );
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&root, None)
            .expect("record root lineage");
        store
            .record_capability_snapshot(&child, Some("cap-cs-root"))
            .expect("record child lineage");

        let seq = store
            .append_chio_receipt_returning_seq(&rc_cs_1)
            .expect("append checkpointed receipt");
        store
            .append_chio_receipt(&make_financial_receipt(
                "rc-cs-2",
                "cap-cs-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                3_001,
                0,
                Some(100),
                &root_hex,
                1,
            ))
            .expect("append uncheckpointed receipt");

        let bytes = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("load canonical receipt bytes")
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint =
            build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    {
        let budgets = SqliteBudgetStore::open(&budget_db_path).expect("open budget store");
        budgets
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-cs-child".to_string(),
                grant_index: 0,
                invocation_count: 2,
                updated_at: 3_100,
                seq: 1,
                total_cost_exposed: 850,
                total_cost_realized_spend: 0,
            })
            .expect("upsert budget usage");
    }

    let listen = reserve_listen_addr();
    let service_token = "comptroller-surface-token";
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
        .get(format!("{base_url}/v1/reports/comptroller-surface"))
        .query(&[
            ("agentSubject", leaf_hex.as_str()),
            ("toolServer", "shell"),
            ("toolName", "bash"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send comptroller surface request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for comptroller surface"
    );
    let body: serde_json::Value = response.json().expect("parse comptroller surface json");

    assert_eq!(
        body["schema"].as_str(),
        Some("chio.comptroller.surface-report.v1")
    );
    assert_eq!(body["decisionSummary"]["allowCount"].as_u64(), Some(1));
    assert_eq!(body["decisionSummary"]["denyCount"].as_u64(), Some(1));
    assert!(
        body["exposurePositions"].is_array(),
        "exposurePositions present"
    );
    assert!(body.get("executionNonceRef").is_none());
    assert!(body.get("holdRef").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}
