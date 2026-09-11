//! Exercise the deployed HTTP authority bridge over a real loopback connection.
#![cfg(feature = "runtime")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chio_core_types::{
    crypto::Keypair,
    receipt::kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
};
use chio_envoy_ext_authz::{runtime::HttpAuthorityKernel, EnvoyKernel, ToolCallRequest, Verdict};
use chio_http_core::{ChioHttpRequest, HttpReceipt, HttpReceiptBody};
use serde_json::json;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
struct Authority {
    key: Arc<Keypair>,
    behavior: &'static str,
}
async fn evaluate(
    State(state): State<Authority>,
    headers: HeaderMap,
    Json(mut request): Json<ChioHttpRequest>,
) -> Response {
    assert_eq!(
        headers.get("x-chio-capability").unwrap(),
        "signed-test-credential"
    );
    assert_eq!(
        request.headers.get("content-type").unwrap(),
        "application/json"
    );
    match state.behavior {
        "timeout" => tokio::time::sleep(Duration::from_secs(1)).await,
        "malformed" => return (StatusCode::OK, "not JSON").into_response(),
        "oversized" => return (StatusCode::OK, "x".repeat(1_048_577)).into_response(),
        "redirect" => {
            return (
                StatusCode::TEMPORARY_REDIRECT,
                [("location", "/chio/evaluate")],
            )
                .into_response()
        }
        "unavailable" => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        _ => {}
    }
    if state.behavior == "wrong-body" {
        request.body_hash = Some("different-body".into());
    }
    let verdict = if state.behavior == "deny" {
        chio_http_core::Verdict::deny("grant revoked", "revocation")
    } else {
        chio_http_core::Verdict::Allow
    };
    let body = HttpReceiptBody {
        id: String::new(),
        request_id: if state.behavior == "replay" {
            "previous-request".into()
        } else {
            request.request_id.clone()
        },
        route_pattern: request.route_pattern.clone(),
        method: request.method,
        caller_identity_hash: request.caller.identity_hash().unwrap(),
        session_id: request.session_id.clone(),
        verdict: verdict.clone(),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: vec![],
        evidence: vec![],
        response_status: 200,
        timestamp: request.timestamp,
        content_hash: request.content_hash().unwrap(),
        policy_hash: "test-policy".into(),
        trust_level: TrustLevel::Mediated,
        capability_id: request.capability_id.clone(),
        metadata: None,
        kernel_key: state.key.public_key(),
    };
    let mut receipt = serde_json::to_value(HttpReceipt::sign(body, &state.key).unwrap()).unwrap();
    if state.behavior == "tampered" {
        receipt["content_hash"] = json!("tampered");
    }
    if state.behavior == "advisory" {
        receipt["receipt_kind"] = json!("advisory");
    }
    Json(json!({"verdict": verdict, "receipt": receipt})).into_response()
}
fn call() -> ToolCallRequest {
    ToolCallRequest {
        request_id: "caller-controlled-id".into(),
        tool: "http.post.notes".into(),
        server_id: "envoy".into(),
        method: "POST".into(),
        path: "/notes".into(),
        query: String::new(),
        headers: [("content-type".into(), "application/json".into())].into(),
        caller: Default::default(),
        body_hash: Some("body-digest".into()),
        body_length: 11,
        session_id: Some("session-1".into()),
        capability_id: None,
        capability_token: Some("signed-test-credential".into()),
    }
}
async fn exercise(behavior: &'static str) {
    let key = Arc::new(Keypair::generate());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/chio/evaluate", post(evaluate))
        .with_state(Authority {
            key: key.clone(),
            behavior,
        });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let signer = if behavior == "untrusted" {
        Keypair::generate().public_key()
    } else {
        key.public_key()
    };
    let bridge = HttpAuthorityKernel::new(&origin, signer, Duration::from_millis(200)).unwrap();
    let result = bridge.evaluate_with_receipt(call()).await;
    server.abort();
    match behavior {
        "allow" => {
            let (verdict, id) = result.unwrap();
            assert_eq!(verdict, Verdict::Allow);
            assert!(!id.unwrap().is_empty());
        }
        "deny" => {
            let (verdict, id) = result.unwrap();
            assert!(!verdict.is_allowed());
            assert!(!id.unwrap().is_empty());
        }
        "unavailable" | "timeout" => assert!(matches!(
            result,
            Err(chio_envoy_ext_authz::KernelError::Unavailable(_))
        )),
        _ => assert!(
            matches!(
                result,
                Err(chio_envoy_ext_authz::KernelError::Evaluation(_))
            ),
            "{behavior} unexpectedly authorized a request"
        ),
    }
}
#[tokio::test]
async fn trusted_bound_receipt_authorizes() {
    exercise("allow").await;
}
#[tokio::test]
async fn refusal_retains_receipt_association() {
    exercise("deny").await;
}
#[tokio::test]
async fn invalid_authority_outcomes_fail_closed() {
    for behavior in [
        "untrusted",
        "replay",
        "wrong-body",
        "tampered",
        "advisory",
        "malformed",
        "oversized",
        "redirect",
        "unavailable",
        "timeout",
    ] {
        exercise(behavior).await;
    }
}
#[test]
fn credentials_are_redacted_and_unsafe_origins_rejected() {
    assert!(!format!("{:?}", call()).contains("signed-test-credential"));
    for origin in [
        "file:///tmp/authority",
        "https://user:secret@example.com",
        "https://example.com/path",
        "https://example.com?token=secret",
    ] {
        assert!(HttpAuthorityKernel::new(
            origin,
            Keypair::generate().public_key(),
            Duration::from_secs(1)
        )
        .is_err());
    }
}
