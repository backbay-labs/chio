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
fn receipt_query_surfaces_financial_hold_lineage_and_guarantee_level() {
    skip_when_loopback_denied!(receipt_query_surfaces_financial_hold_lineage_and_guarantee_level);
    let dir = unique_dir("chio-rq-budget-lineage");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_financial_receipt_with_budget_authority(
                "r-budget-lineage-1",
                "cap-budget-lineage-1",
                "payments",
                "charge",
                2_250,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "test-budget-lineage-secret-token".to_string();
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
        .query(&[("capabilityId", "cap-budget-lineage-1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts is array");
    assert_eq!(receipts.len(), 1, "expected one financial receipt");

    let financial = &receipts[0]["metadata"]["financial"];
    assert_eq!(financial["cost_charged"].as_u64(), Some(75));
    assert_eq!(financial["settlement_status"].as_str(), Some("settled"));

    let budget_authority = &receipts[0]["metadata"]["budget_authority"];
    assert_eq!(
        budget_authority["guarantee_level"].as_str(),
        Some("ha_quorum_commit")
    );
    assert_eq!(
        budget_authority["hold_id"].as_str(),
        Some("budget-hold:req-query-1:cap-budget-lineage:0")
    );
    assert_eq!(
        budget_authority["budget_term"].as_str(),
        Some("http://leader-a:7")
    );
    assert_eq!(
        budget_authority["authority"]["authority_id"].as_str(),
        Some("http://leader-a")
    );
    assert_eq!(
        budget_authority["authority"]["lease_id"].as_str(),
        Some("http://leader-a#term-7")
    );
    assert_eq!(
        budget_authority["authority"]["lease_epoch"].as_u64(),
        Some(7)
    );
    assert_eq!(
        budget_authority["authorize"]["event_id"].as_str(),
        Some("budget-hold:req-query-1:cap-budget-lineage:0:authorize")
    );
    assert_eq!(
        budget_authority["authorize"]["budget_commit_index"].as_u64(),
        Some(41)
    );
    assert_eq!(
        budget_authority["terminal"]["disposition"].as_str(),
        Some("reconciled")
    );
    assert_eq!(
        budget_authority["terminal"]["event_id"].as_str(),
        Some("budget-hold:req-query-1:cap-budget-lineage:0:reconcile")
    );
    assert_eq!(
        budget_authority["terminal"]["budget_commit_index"].as_u64(),
        Some(42)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_lineage_get_capability_snapshot() {
    skip_when_loopback_denied!(test_lineage_get_capability_snapshot);
    let dir = unique_dir("chio-lineage-get");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let subject_kp = Keypair::generate();
    let token = make_capability_token("cap-lineage-1", &subject_kp, &issuer_kp);
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    prepopulate_lineage(&receipt_db_path, &[(&token, None)]);

    let listen = reserve_listen_addr();
    let service_token = "lineage-get-token";
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
        .get(format!("{base_url}/v1/lineage/cap-lineage-1"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send lineage request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for lineage GET"
    );
    let body: serde_json::Value = response.json().expect("parse lineage json");
    assert_eq!(
        body["capability_id"].as_str().expect("capability_id"),
        "cap-lineage-1"
    );
    assert_eq!(
        body["subject_key"].as_str().expect("subject_key"),
        subject_hex
    );
    assert_eq!(body["issuer_key"].as_str().expect("issuer_key"), issuer_hex);
    assert_eq!(
        body["delegation_depth"].as_u64().expect("delegation_depth"),
        0
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_lineage_get_delegation_chain() {
    skip_when_loopback_denied!(test_lineage_get_delegation_chain);
    let dir = unique_dir("chio-lineage-chain");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let parent_kp = Keypair::generate();
    let child_kp = Keypair::generate();

    // 3-level chain: root -> parent -> child
    let root = make_capability_token("chain-root", &root_kp, &issuer_kp);
    let parent = make_delegated_capability_token("chain-parent", &parent_kp, &root_kp, &root);
    let child = make_delegated_capability_token("chain-child", &child_kp, &parent_kp, &parent);

    prepopulate_lineage(
        &receipt_db_path,
        &[
            (&root, None),
            (&parent, Some("chain-root")),
            (&child, Some("chain-parent")),
        ],
    );

    let listen = reserve_listen_addr();
    let service_token = "chain-token";
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
        .get(format!("{base_url}/v1/lineage/chain-child/chain"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send chain request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for chain GET"
    );
    let chain: Vec<serde_json::Value> = response.json().expect("parse chain json");
    assert_eq!(chain.len(), 3, "chain should have 3 entries");

    // Root-first ordering: delegation_depth 0, 1, 2
    assert_eq!(
        chain[0]["capability_id"].as_str().expect("id"),
        "chain-root"
    );
    assert_eq!(chain[0]["delegation_depth"].as_u64().expect("depth"), 0);
    assert_eq!(
        chain[1]["capability_id"].as_str().expect("id"),
        "chain-parent"
    );
    assert_eq!(chain[1]["delegation_depth"].as_u64().expect("depth"), 1);
    assert_eq!(
        chain[2]["capability_id"].as_str().expect("id"),
        "chain-child"
    );
    assert_eq!(chain[2]["delegation_depth"].as_u64().expect("depth"), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_lineage_not_found() {
    skip_when_loopback_denied!(test_lineage_not_found);
    let setup = setup_with_receipts("chio-lineage-404");

    let response = setup
        .client
        .get(format!("{}/v1/lineage/nonexistent-cap-id", setup.base_url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send lineage 404 request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "unknown capability_id should return 404"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_lineage_requires_auth() {
    skip_when_loopback_denied!(test_lineage_requires_auth);
    let setup = setup_with_receipts("chio-lineage-auth");

    let response = setup
        .client
        .get(format!("{}/v1/lineage/any-cap-id", setup.base_url))
        .send()
        .expect("send unauthenticated lineage request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "lineage endpoint without auth should return 401"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_cost_attribution_report_endpoint() {
    skip_when_loopback_denied!(test_cost_attribution_report_endpoint);
    let dir = unique_dir("chio-cost-attribution");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let root = make_capability_token("cap-cost-root", &root_kp, &issuer_kp);
    let child = make_delegated_capability_token("cap-cost-child", &leaf_kp, &root_kp, &root);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open store");
        store
            .record_capability_snapshot(&root, None)
            .expect("record root");
        store
            .record_capability_snapshot(&child, Some("cap-cost-root"))
            .expect("record child");

        store
            .append_chio_receipt(&make_financial_receipt(
                "rc-cost-1",
                "cap-cost-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Allow,
                2_000,
                150,
                None,
                &root_hex,
                1,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_financial_receipt(
                "rc-cost-2",
                "cap-cost-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                2_001,
                0,
                Some(50),
                &root_hex,
                1,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "cost-attribution-token";
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
        .get(format!("{base_url}/v1/reports/cost-attribution"))
        .query(&[
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("limit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send cost attribution request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for cost attribution report"
    );
    let body: serde_json::Value = response.json().expect("parse cost attribution json");
    assert_eq!(body["summary"]["matchingReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["returnedReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["totalCostCharged"].as_u64(), Some(150));
    assert_eq!(body["summary"]["totalAttemptedCost"].as_u64(), Some(50));
    assert_eq!(body["summary"]["lineageGapCount"].as_u64(), Some(0));

    let by_root = body["byRoot"].as_array().expect("byRoot array");
    assert_eq!(by_root.len(), 1);
    assert_eq!(
        by_root[0]["rootSubjectKey"].as_str(),
        Some(root_hex.as_str())
    );
    assert_eq!(by_root[0]["receiptCount"].as_u64(), Some(2));

    let by_leaf = body["byLeaf"].as_array().expect("byLeaf array");
    assert_eq!(by_leaf.len(), 1);
    assert_eq!(
        by_leaf[0]["rootSubjectKey"].as_str(),
        Some(root_hex.as_str())
    );
    assert_eq!(
        by_leaf[0]["leafSubjectKey"].as_str(),
        Some(leaf_hex.as_str())
    );
    assert_eq!(by_leaf[0]["totalCostCharged"].as_u64(), Some(150));
    assert_eq!(by_leaf[0]["totalAttemptedCost"].as_u64(), Some(50));

    let receipts = body["receipts"].as_array().expect("receipts array");
    assert_eq!(receipts.len(), 2);
    assert!(receipts
        .iter()
        .all(|row| row["lineageComplete"].as_bool() == Some(true)));
    assert!(receipts.iter().all(|row| row["chain"]
        .as_array()
        .is_some_and(|chain| chain.len() == 2)));

    let _ = std::fs::remove_dir_all(&dir);
}
