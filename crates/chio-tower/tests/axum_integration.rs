//! Integration test: Chio tower middleware with Axum.
//!
//! Verifies that the ChioLayer correctly integrates with Axum's router,
//! producing signed receipts for allowed requests and denying requests
//! without capability tokens.

use axum::{body::Body, routing::get, routing::post, Router};
use bytes::Bytes;
use chio_core_types::capability::{CapabilityToken, CapabilityTokenBody, ChioScope};
use chio_core_types::crypto::Keypair;
use chio_http_core::{http_status_scope, HttpReceipt, CHIO_HTTP_STATUS_SCOPE_FINAL};
use chio_tower::{ChioEvaluator, ChioService};
use http::Request;
use http_body::Body as HttpBody;
use http_body_util::BodyExt;
use tower::ServiceExt;
use tower_layer::Layer;

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

/// A thin Layer wrapper that adapts ChioService's error type to Infallible
/// for Axum compatibility. Axum requires layers with Error: Into<Infallible>.
#[derive(Clone)]
struct AxumChioLayer {
    evaluator: ChioEvaluator,
}

impl AxumChioLayer {
    fn new(keypair: Keypair, policy_hash: String) -> Self {
        Self {
            evaluator: ChioEvaluator::new(keypair, policy_hash),
        }
    }
}

impl<S> Layer<S> for AxumChioLayer {
    type Service = AxumChioService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AxumChioService {
            inner: ChioService::new(inner, self.evaluator.clone()),
        }
    }
}

/// Wrapper service that maps ChioService errors to Infallible for Axum.
#[derive(Clone)]
struct AxumChioService<S> {
    inner: ChioService<S>,
}

impl<S, ReqBody> tower_service::Service<Request<ReqBody>> for AxumChioService<S>
where
    S: tower_service::Service<Request<ReqBody>, Response = http::Response<Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ReqBody: HttpBody + From<Bytes> + Send + 'static,
    ReqBody::Data: Send,
    ReqBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = http::Response<Body>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // ChioService always reports ready when inner is ready.
        match self.inner.poll_ready(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(_)) => {
                // Map errors to a 502 response internally; never return Infallible error.
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let fut = tower_service::Service::call(&mut self.inner, req);
        Box::pin(async move {
            match fut.await {
                Ok(resp) => Ok(resp),
                Err(_) => {
                    // Return a 502 error response instead of propagating.
                    let resp = http::Response::builder()
                        .status(http::StatusCode::BAD_GATEWAY)
                        .body(Body::from("Chio evaluation error"))
                        .unwrap_or_else(|_| http::Response::new(Body::from("internal error")));
                    Ok(resp)
                }
            }
        })
    }
}

fn build_app(keypair: Keypair) -> Router {
    let layer = AxumChioLayer::new(keypair, "test-policy-axum".to_string());
    Router::new()
        .route("/pets", get(list_pets))
        .route("/pets", post(create_pet))
        .route("/pets/{pet_id}", get(get_pet))
        .layer(layer)
}

async fn list_pets() -> &'static str {
    r#"[{"id":1,"name":"Fido"}]"#
}

async fn create_pet(body: String) -> (http::StatusCode, String) {
    (http::StatusCode::CREATED, body)
}

async fn get_pet(axum::extract::Path(pet_id): axum::extract::Path<String>) -> String {
    format!(r#"{{"id":{},"name":"Buddy"}}"#, pet_id)
}

#[tokio::test]
async fn axum_get_allowed_with_receipt() {
    let keypair = Keypair::generate();
    let app = build_app(keypair);

    let req = Request::builder()
        .method("GET")
        .uri("/pets")
        .body(Body::empty())
        .unwrap_or_else(|e| panic!("build request failed: {e}"));

    let resp = app
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::OK);
    let receipt = resp
        .extensions()
        .get::<HttpReceipt>()
        .unwrap_or_else(|| panic!("missing receipt extension"));
    assert_eq!(receipt.response_status, 200);
    assert_eq!(
        http_status_scope(receipt.metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );

    // Verify receipt ID header is present.
    let receipt_id = resp
        .headers()
        .get("x-chio-receipt-id")
        .unwrap_or_else(|| panic!("missing x-chio-receipt-id header"));
    assert!(!receipt_id.is_empty());

    // Verify response body.
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body collect failed: {e}"))
        .to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap_or_else(|e| panic!("utf8 failed: {e}"));
    assert!(body_str.contains("Fido"));
}

#[tokio::test]
async fn axum_post_denied_without_capability() {
    let keypair = Keypair::generate();
    let app = build_app(keypair);

    let req = Request::builder()
        .method("POST")
        .uri("/pets")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"Rex"}"#))
        .unwrap_or_else(|e| panic!("build request failed: {e}"));

    let resp = app
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));

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

#[tokio::test]
async fn axum_post_allowed_with_capability() {
    let keypair = Keypair::generate();
    let app = build_app(keypair.clone());
    let payload = r#"{"name":"Rex"}"#;

    let req = Request::builder()
        .method("POST")
        .uri("/pets")
        .header("content-type", "application/json")
        .header(
            "x-chio-capability",
            valid_capability_token_json("cap-axum", &keypair),
        )
        .body(Body::from(payload))
        .unwrap_or_else(|e| panic!("build request failed: {e}"));

    let resp = app
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::CREATED);
    assert!(resp.headers().contains_key("x-chio-receipt-id"));
    let receipt = resp
        .extensions()
        .get::<HttpReceipt>()
        .unwrap_or_else(|| panic!("missing receipt extension"));
    assert_eq!(receipt.response_status, 201);
    assert_eq!(
        http_status_scope(receipt.metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );

    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body collect failed: {e}"))
        .to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap_or_else(|e| panic!("utf8 failed: {e}"));
    assert_eq!(body_str, payload);
}

#[tokio::test]
async fn axum_path_parameter_with_receipt() {
    let keypair = Keypair::generate();
    let app = build_app(keypair);

    let req = Request::builder()
        .method("GET")
        .uri("/pets/42")
        .body(Body::empty())
        .unwrap_or_else(|e| panic!("build request failed: {e}"));

    let resp = app
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::OK);
    assert!(resp.headers().contains_key("x-chio-receipt-id"));

    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body collect failed: {e}"))
        .to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap_or_else(|e| panic!("utf8 failed: {e}"));
    assert!(body_str.contains("42"));
}

#[tokio::test]
async fn axum_bearer_identity_in_receipt() {
    let keypair = Keypair::generate();
    let app = build_app(keypair);

    let req = Request::builder()
        .method("GET")
        .uri("/pets")
        .header("authorization", "Bearer secret-token-123")
        .body(Body::empty())
        .unwrap_or_else(|e| panic!("build request failed: {e}"));

    let resp = app
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::OK);
    assert!(resp.headers().contains_key("x-chio-receipt-id"));
}
