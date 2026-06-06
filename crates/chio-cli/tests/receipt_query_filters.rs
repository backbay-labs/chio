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
fn test_receipt_query_filter_capability() {
    skip_when_loopback_denied!(test_receipt_query_filter_capability);
    let setup = setup_with_receipts("chio-rq-filter-cap");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("capabilityId", "cap-1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let total_count = body["totalCount"].as_u64().expect("totalCount is u64");
    let receipts = body["receipts"].as_array().expect("receipts is array");

    assert_eq!(total_count, 4, "4 receipts have cap-1");
    assert_eq!(receipts.len(), 4);

    for receipt in receipts {
        assert_eq!(
            receipt["capability_id"].as_str().expect("capability_id"),
            "cap-1",
            "all returned receipts must have capability_id == cap-1"
        );
    }

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_receipt_query_cursor_pagination() {
    skip_when_loopback_denied!(test_receipt_query_cursor_pagination);
    let setup = setup_with_receipts("chio-rq-cursor");

    // First page: limit=2
    let response1 = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("limit", "2")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send first request");

    assert_eq!(response1.status(), reqwest::StatusCode::OK);
    let body1: serde_json::Value = response1.json().expect("parse json page 1");
    let receipts1 = body1["receipts"].as_array().expect("receipts page 1");
    assert_eq!(receipts1.len(), 2, "first page should have 2 receipts");

    let next_cursor = body1["nextCursor"]
        .as_u64()
        .expect("nextCursor should be present after page 1");

    // Second page: use cursor
    let response2 = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("limit", "2"), ("cursor", &next_cursor.to_string())])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send second request");

    assert_eq!(response2.status(), reqwest::StatusCode::OK);
    let body2: serde_json::Value = response2.json().expect("parse json page 2");
    let receipts2 = body2["receipts"].as_array().expect("receipts page 2");
    assert_eq!(receipts2.len(), 2, "second page should have 2 receipts");

    // The two pages must not overlap (receipts have unique ids).
    let ids1: Vec<&str> = receipts1
        .iter()
        .map(|r| r["id"].as_str().expect("receipt id"))
        .collect();
    let ids2: Vec<&str> = receipts2
        .iter()
        .map(|r| r["id"].as_str().expect("receipt id"))
        .collect();
    for id in &ids1 {
        assert!(
            !ids2.contains(id),
            "receipt {id} appeared on both page 1 and page 2"
        );
    }

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_receipt_query_total_count() {
    skip_when_loopback_denied!(test_receipt_query_total_count);
    let setup = setup_with_receipts("chio-rq-total-count");

    // Fetch only 1 receipt but total should be 5.
    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("limit", "1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let total_count = body["totalCount"].as_u64().expect("totalCount is u64");
    let receipts = body["receipts"].as_array().expect("receipts is array");

    assert_eq!(receipts.len(), 1, "only 1 receipt on this page");
    assert_eq!(total_count, 5, "totalCount should reflect full set of 5");

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_agent_subject_filter_via_http() {
    skip_when_loopback_denied!(test_agent_subject_filter_via_http);
    let dir = unique_dir("chio-agent-filter");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let agent1_kp = Keypair::generate();
    let agent2_kp = Keypair::generate();
    let agent1_hex = agent1_kp.public_key().to_hex();

    // Two capability tokens, one per agent
    let cap1 = make_capability_token("cap-agent1", &agent1_kp, &issuer_kp);
    let cap2 = make_capability_token("cap-agent2", &agent2_kp, &issuer_kp);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open store");
        store
            .record_capability_snapshot(&cap1, None)
            .expect("record cap1");
        store
            .record_capability_snapshot(&cap2, None)
            .expect("record cap2");

        // 2 receipts for agent1, 1 for agent2
        store
            .append_chio_receipt(&make_receipt(
                "ra-1",
                "cap-agent1",
                "shell",
                "bash",
                Decision::Allow,
                1000,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "ra-2",
                "cap-agent1",
                "files",
                "read",
                Decision::Allow,
                1001,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "ra-3",
                "cap-agent2",
                "shell",
                "bash",
                Decision::Allow,
                1002,
                None,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "agent-filter-token";
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
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("agentSubject", agent1_hex.as_str())])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send agent filter request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for agent filter"
    );
    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts array");
    assert_eq!(
        receipts.len(),
        2,
        "only agent1's 2 receipts should be returned"
    );
    for r in receipts {
        assert_eq!(
            r["capability_id"].as_str().expect("capability_id"),
            "cap-agent1",
            "all returned receipts must belong to agent1"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_agent_receipts_endpoint() {
    skip_when_loopback_denied!(test_agent_receipts_endpoint);
    let dir = unique_dir("chio-agent-receipts");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let agent1_kp = Keypair::generate();
    let agent2_kp = Keypair::generate();
    let agent1_hex = agent1_kp.public_key().to_hex();

    let cap1 = make_capability_token("cap-ar-agent1", &agent1_kp, &issuer_kp);
    let cap2 = make_capability_token("cap-ar-agent2", &agent2_kp, &issuer_kp);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open store");
        store
            .record_capability_snapshot(&cap1, None)
            .expect("record cap1");
        store
            .record_capability_snapshot(&cap2, None)
            .expect("record cap2");

        store
            .append_chio_receipt(&make_receipt(
                "rb-1",
                "cap-ar-agent1",
                "shell",
                "bash",
                Decision::Allow,
                1000,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "rb-2",
                "cap-ar-agent1",
                "files",
                "read",
                Decision::Allow,
                1001,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "rb-3",
                "cap-ar-agent2",
                "shell",
                "bash",
                Decision::Allow,
                1002,
                None,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "agent-receipts-token";
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
        .get(format!("{base_url}/v1/agents/{agent1_hex}/receipts"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send agent receipts request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for agent receipts"
    );
    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts array");
    assert_eq!(
        receipts.len(),
        2,
        "only agent1's 2 receipts should be returned"
    );
    for r in receipts {
        assert_eq!(
            r["capability_id"].as_str().expect("capability_id"),
            "cap-ar-agent1",
            "all returned receipts must belong to agent1"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
