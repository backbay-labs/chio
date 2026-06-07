use super::*;
use axum::body::to_bytes;
use chio_openapi::PolicyDecision;

use chio_test_support::prelude::*;

fn strict_nonce_state(routes: Vec<RouteEntry>) -> Arc<ProxyState> {
    let keypair = Keypair::generate();
    let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
    let signer_public_key = keypair.public_key();
    let trusted_capability_issuers = vec![signer_public_key.clone()];
    let trusted_receipt_signers = vec![signer_public_key];
    let mut evaluator = RequestEvaluator::new_with_approval_store(
        routes,
        keypair.clone(),
        "test-policy".to_string(),
        Arc::clone(&approval_store),
    );
    evaluator.enable_strict_execution_nonce_for_tests();
    let upstream = "http://127.0.0.1:1".to_string();
    let egress_contract = default_upstream_egress_contract(&upstream).test_unwrap();
    let http_client = client_builder_with_contract(&egress_contract)
        .build()
        .test_unwrap();

    Arc::new(ProxyState {
        evaluator,
        signer_keypair: keypair,
        upstream,
        http_client,
        egress_contract,
        approval_admin: ApprovalAdmin::new(approval_store),
        receipt_log: Mutex::new(ReceiptLog {
            receipts: Vec::new(),
        }),
        tool_receipt_log: Mutex::new(ToolReceiptLog {
            receipts: Vec::new(),
        }),
        receipt_store: None,
        revoked_capability_ids: Mutex::new(HashSet::new()),
        trusted_capability_issuers,
        trusted_receipt_signers,
        sidecar_control_token: None,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sidecar_evaluate_returns_strict_execution_nonce_for_retry() {
    let state = strict_nonce_state(vec![RouteEntry {
        pattern: "/pets".to_string(),
        method: HttpMethod::Post,
        operation_id: Some("createPet".to_string()),
        policy: PolicyDecision::SessionAllow,
    }]);
    let mut body = ChioHttpRequest::new(
        "req-sidecar-nonce-preflight".to_string(),
        HttpMethod::Post,
        "/pets".to_string(),
        "/pets".to_string(),
        chio_http_core::CallerIdentity::anonymous(),
    );
    body.body_hash = Some("abc".to_string());
    body.body_length = 3;
    let request = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
        .test_unwrap();

    let response = sidecar_evaluate_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let preflight: EvaluateResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(matches!(preflight.verdict, Verdict::Incomplete { .. }));
    assert!(!preflight.receipt.is_allowed());
    let nonce = preflight
        .execution_nonce
        .clone()
        .test_expect("strict sidecar preflight should return retry nonce");

    let mut retry_body = body;
    retry_body.request_id = "req-sidecar-nonce-retry".to_string();
    retry_body.execution_nonce = Some(nonce);
    let retry_request = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&retry_body).test_unwrap()))
        .test_unwrap();

    let retry_response = sidecar_evaluate_handler(State(Arc::clone(&state)), retry_request).await;
    assert_eq!(retry_response.status(), StatusCode::OK);
    let retry_bytes = to_bytes(retry_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let allowed: EvaluateResponse = serde_json::from_slice(&retry_bytes).test_unwrap();
    assert!(allowed.verdict.is_allowed());
    assert!(allowed.receipt.is_allowed());
    assert!(allowed.execution_nonce.is_none());
}
