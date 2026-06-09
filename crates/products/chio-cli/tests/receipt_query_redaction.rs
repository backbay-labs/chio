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
fn test_receipt_query_surfaces_governed_transaction_metadata() {
    skip_when_loopback_denied!(test_receipt_query_surfaces_governed_transaction_metadata);
    let dir = unique_dir("chio-rq-governed");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_receipt(
                "r-governed-1",
                "cap-governed-1",
                "payments",
                "submit_wire",
                2_000,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "test-governed-secret-token".to_string();
    let mut service = spawn_trust_service(
        listen,
        &service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service_result(&client, &base_url, &mut service)
        .expect("wait for trust service");

    let response = client
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("capabilityId", "cap-governed-1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts is array");
    assert_eq!(receipts.len(), 1, "expected one governed receipt");

    let governed = &receipts[0]["metadata"]["governed_transaction"];
    assert_eq!(governed["intent_id"], "intent-ops-1");
    assert_eq!(governed["purpose"], "approve vendor payout");
    assert_eq!(governed["server_id"], "payments");
    assert_eq!(governed["tool_name"], "submit_wire");
    assert_eq!(governed["max_amount"]["units"].as_u64(), Some(4200));
    assert_eq!(
        governed["metered_billing"]["settlementMode"],
        "allow_then_settle"
    );
    assert_eq!(
        governed["metered_billing"]["quote"]["quoteId"],
        "quote-ops-1"
    );
    assert_eq!(
        governed["metered_billing"]["quote"]["quotedCost"]["units"].as_u64(),
        Some(3800)
    );
    assert_eq!(
        governed["metered_billing"]["maxBilledUnits"].as_u64(),
        Some(18)
    );
    assert_eq!(governed["approval"]["token_id"], "approval-ops-1");
    assert_eq!(governed["approval"]["approved"], true);

    let financial = &receipts[0]["metadata"]["financial"];
    assert_eq!(financial["cost_charged"].as_u64(), Some(4200));
    assert_eq!(financial["payment_reference"], "pi_governed_1");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_receipt_query_surfaces_x402_payment_metadata() {
    skip_when_loopback_denied!(test_receipt_query_surfaces_x402_payment_metadata);
    let dir = unique_dir("chio-rq-x402");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_x402_receipt(
                "r-x402-1",
                "cap-x402-1",
                "payments",
                "fetch_dataset",
                2_100,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "test-x402-secret-token".to_string();
    let mut service = spawn_trust_service(
        listen,
        &service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service_result(&client, &base_url, &mut service)
        .expect("wait for trust service");

    let response = client
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("capabilityId", "cap-x402-1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts is array");
    assert_eq!(receipts.len(), 1, "expected one x402 receipt");

    let financial = &receipts[0]["metadata"]["financial"];
    assert_eq!(financial["payment_reference"], "x402_txn_ops_1");
    assert_eq!(
        financial["cost_breakdown"]["payment"]["authorization_id"],
        "x402_txn_ops_1"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["adapter"],
        "x402"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["mode"],
        "prepaid"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["network"],
        "base"
    );

    let governed = &receipts[0]["metadata"]["governed_transaction"];
    assert_eq!(governed["intent_id"], "intent-x402-ops-1");
    assert_eq!(governed["approval"]["token_id"], "approval-x402-ops-1");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_receipt_query_surfaces_acp_payment_metadata() {
    skip_when_loopback_denied!(test_receipt_query_surfaces_acp_payment_metadata);
    let dir = unique_dir("chio-rq-acp");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_acp_receipt(
                "r-acp-1",
                "cap-acp-1",
                "commerce",
                "checkout",
                2_200,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "test-acp-secret-token".to_string();
    let mut service = spawn_trust_service(
        listen,
        &service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service_result(&client, &base_url, &mut service)
        .expect("wait for trust service");

    let response = client
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("capabilityId", "cap-acp-1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts is array");
    assert_eq!(receipts.len(), 1, "expected one acp receipt");

    let financial = &receipts[0]["metadata"]["financial"];
    assert_eq!(financial["payment_reference"], "acp_hold_ops_1");
    assert_eq!(
        financial["cost_breakdown"]["payment"]["authorization_id"],
        "acp_hold_ops_1"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["adapter"],
        "acp"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["mode"],
        "shared_payment_token_hold"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["seller"],
        "merchant.example"
    );

    let governed = &receipts[0]["metadata"]["governed_transaction"];
    assert_eq!(governed["intent_id"], "intent-acp-ops-1");
    assert_eq!(governed["commerce"]["seller"], "merchant.example");
    assert_eq!(
        governed["commerce"]["shared_payment_token_id"],
        "spt_live_ops_1"
    );
    assert_eq!(governed["approval"]["token_id"], "approval-acp-ops-1");

    let _ = std::fs::remove_dir_all(&dir);
}
