//! Integration test: Chio tower middleware on a bytes-backed Tower/HTTP2 path
//! that approximates unary gRPC traffic.
//!
//! This exercises the middleware with `Full<Bytes>` request bodies and gRPC-ish
//! HTTP/2 headers. It does not prove replay support for real
//! `tonic::body::Body`, so the test remains an approximation rather than a
//! full Tonic runtime qualification.

use bytes::Bytes;
use chio_core_types::capability::{CapabilityToken, CapabilityTokenBody, ChioScope};
use chio_core_types::crypto::Keypair;
use chio_http_core::{http_status_scope, HttpReceipt, CHIO_HTTP_STATUS_SCOPE_FINAL};
use chio_tower::ChioLayer;
use http::Request;
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt};

type TestBody = Full<Bytes>;

fn valid_capability_token_json(id: &str, issuer: &Keypair) -> String {
    let now = chrono::Utc::now().timestamp() as u64;
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: issuer.public_key(),
            scope: ChioScope::default(),
            issued_at: now.saturating_sub(60),
            expires_at: now + 3600,
            delegation_chain: Vec::new(),
        },
        issuer,
    )
    .unwrap_or_else(|e| panic!("token sign failed: {e}"));
    serde_json::to_string(&token).unwrap_or_else(|e| panic!("token serialize failed: {e}"))
}

/// Simulate a gRPC unary call (POST with application/grpc content type).
/// gRPC calls are always POST, so they require a capability token.
#[tokio::test]
async fn grpc_post_denied_without_capability() {
    let keypair = Keypair::generate();
    let layer = ChioLayer::new(keypair, "test-policy-grpc".to_string());

    let inner = tower::service_fn(|_req: Request<TestBody>| async {
        panic!("inner should not be called");
        #[allow(unreachable_code)]
        Ok::<http::Response<()>, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(()))
    });

    let mut service = layer.layer(inner);

    // gRPC requests are always POST.
    let req = Request::builder()
        .method("POST")
        .uri("http://localhost/my.service.MyService/GetItem")
        .header("content-type", "application/grpc")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build failed: {e}"));

    let resp: http::Response<()> = service
        .ready()
        .await
        .unwrap_or_else(|e| panic!("ready failed: {e}"))
        .call(req)
        .await
        .unwrap_or_else(|e| panic!("call failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    assert!(resp.headers().contains_key("x-chio-receipt-id"));
    let receipt = resp
        .extensions()
        .get::<HttpReceipt>()
        .unwrap_or_else(|| panic!("missing receipt extension"));
    assert_eq!(receipt.response_status, 403);
    assert_eq!(
        http_status_scope(receipt.metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
}

/// gRPC call with capability token should be allowed.
#[tokio::test]
async fn grpc_post_allowed_with_capability() {
    let keypair = Keypair::generate();
    let layer = ChioLayer::new(keypair.clone(), "test-policy-grpc".to_string());

    let inner = tower::service_fn(|_req: Request<TestBody>| async {
        let mut resp = http::Response::new(());
        resp.headers_mut().insert(
            "content-type",
            http::HeaderValue::from_static("application/grpc"),
        );
        Ok::<http::Response<()>, Box<dyn std::error::Error + Send + Sync>>(resp)
    });

    let mut service = layer.layer(inner);

    let req = Request::builder()
        .method("POST")
        .uri("http://localhost/my.service.MyService/CreateItem")
        .header("content-type", "application/grpc")
        .header(
            "x-chio-capability",
            valid_capability_token_json("grpc-cap-1", &keypair),
        )
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build failed: {e}"));

    let resp: http::Response<()> = service
        .ready()
        .await
        .unwrap_or_else(|e| panic!("ready failed: {e}"))
        .call(req)
        .await
        .unwrap_or_else(|e| panic!("call failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::OK);
    assert!(resp.headers().contains_key("x-chio-receipt-id"));
    let receipt = resp
        .extensions()
        .get::<HttpReceipt>()
        .unwrap_or_else(|| panic!("missing receipt extension"));
    assert_eq!(receipt.response_status, 200);
    assert_eq!(
        http_status_scope(receipt.metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
}

/// Verify that the receipt ID is a valid UUIDv7 format.
#[tokio::test]
async fn grpc_receipt_id_format() {
    let keypair = Keypair::generate();
    let layer = ChioLayer::new(keypair.clone(), "test-policy-grpc".to_string());

    let inner = tower::service_fn(|_req: Request<TestBody>| async {
        Ok::<http::Response<()>, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(()))
    });

    let mut service = layer.layer(inner);

    let req = Request::builder()
        .method("POST")
        .uri("http://localhost/my.service.MyService/ListItems")
        .header("content-type", "application/grpc")
        .header(
            "x-chio-capability",
            valid_capability_token_json("grpc-cap-2", &keypair),
        )
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build failed: {e}"));

    let resp: http::Response<()> = service
        .ready()
        .await
        .unwrap_or_else(|e| panic!("ready failed: {e}"))
        .call(req)
        .await
        .unwrap_or_else(|e| panic!("call failed: {e}"));

    let receipt_id = resp
        .headers()
        .get("x-chio-receipt-id")
        .unwrap_or_else(|| panic!("missing receipt id"))
        .to_str()
        .unwrap_or_else(|e| panic!("invalid header value: {e}"));

    // UUIDv7 format: 8-4-4-4-12 hex chars.
    assert_eq!(receipt_id.len(), 36);
    assert_eq!(receipt_id.chars().filter(|c| *c == '-').count(), 4);
    let receipt = resp
        .extensions()
        .get::<HttpReceipt>()
        .unwrap_or_else(|| panic!("missing receipt extension"));
    assert_eq!(receipt.response_status, 200);
}

/// gRPC call with bearer token for identity extraction.
#[tokio::test]
async fn grpc_bearer_identity() {
    let keypair = Keypair::generate();
    let layer = ChioLayer::new(keypair.clone(), "test-policy-grpc".to_string());

    let inner = tower::service_fn(|_req: Request<TestBody>| async {
        Ok::<http::Response<()>, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(()))
    });

    let mut service = layer.layer(inner);

    let req = Request::builder()
        .method("POST")
        .uri("http://localhost/my.service.MyService/GetItem")
        .header("content-type", "application/grpc")
        .header("authorization", "Bearer grpc-secret-token")
        .header(
            "x-chio-capability",
            valid_capability_token_json("grpc-cap-3", &keypair),
        )
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|e| panic!("build failed: {e}"));

    let resp: http::Response<()> = service
        .ready()
        .await
        .unwrap_or_else(|e| panic!("ready failed: {e}"))
        .call(req)
        .await
        .unwrap_or_else(|e| panic!("call failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::OK);
    assert!(resp.headers().contains_key("x-chio-receipt-id"));
    let receipt = resp
        .extensions()
        .get::<HttpReceipt>()
        .unwrap_or_else(|| panic!("missing receipt extension"));
    assert_eq!(receipt.response_status, 200);
}
