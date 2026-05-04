//! Chio tower Service implementation.

use std::collections::HashMap;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::Body;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tower_service::Service;

use crate::evaluator::{ChioEvaluator, EvaluationInput};

/// Default upper bound on buffered request body size (8 MiB).
///
/// The middleware needs to inspect request bodies to compute content hashes
/// for receipts; without a cap a single oversized request could exhaust host
/// memory before the inner service ever sees it. Callers can override this
/// via [`ChioService::with_max_body_bytes`] when a deployment expects larger
/// payloads.
pub const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Tower `Service` that evaluates HTTP requests against the Chio kernel.
///
/// For each request, the service:
/// 1. Extracts the caller identity from request headers
/// 2. Evaluates the request against the Chio policy
/// 3. If denied, returns a 403 JSON error response
/// 4. If allowed, forwards to the inner service with receipt ID in response headers
///
/// Request bodies must be replayable after inspection. The current middleware
/// supports body types that implement both `http_body::Body` and `From<Bytes>`.
#[derive(Clone)]
pub struct ChioService<S> {
    inner: S,
    evaluator: ChioEvaluator,
    max_body_bytes: usize,
}

impl<S> ChioService<S> {
    /// Create a new Chio service wrapping the inner service.
    pub fn new(inner: S, evaluator: ChioEvaluator) -> Self {
        Self {
            inner,
            evaluator,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Override the maximum body size buffered for hashing.
    ///
    /// Requests whose advertised or observed body size exceeds this limit are
    /// rejected with `413 Payload Too Large` before reaching the inner
    /// service. Defaults to [`DEFAULT_MAX_BODY_BYTES`].
    #[must_use]
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }
}

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for ChioService<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ReqBody: Body + From<Bytes> + Send + 'static,
    ReqBody::Data: Send,
    ReqBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ResBody: Default + Send + 'static,
{
    type Response = http::Response<ResBody>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        let evaluator = self.evaluator.clone();
        let mut inner = self.inner.clone();
        let max_body_bytes = self.max_body_bytes;

        Box::pin(async move {
            let method = req.method().as_str().to_string();
            let path = req.uri().path().to_string();
            let query: HashMap<String, String> = req
                .uri()
                .query()
                .map(|raw| {
                    url::form_urlencoded::parse(raw.as_bytes())
                        .map(|(key, value)| (key.into_owned(), value.into_owned()))
                        .collect()
                })
                .unwrap_or_default();
            let headers = req.headers().clone();
            let (req, body_hash, body_length) = match buffer_request_body(req, max_body_bytes).await
            {
                Ok(parts) => parts,
                Err(BufferBodyError::TooLarge) => {
                    let mut response = http::Response::new(ResBody::default());
                    *response.status_mut() = http::StatusCode::PAYLOAD_TOO_LARGE;
                    return Ok(response);
                }
                Err(BufferBodyError::Inner(error)) => return Err(error),
            };

            // Extract caller identity.
            let identity_fn = evaluator.identity_extractor();
            let caller = identity_fn(&headers);

            // Evaluate the request.
            let prepared = match evaluator.prepare(EvaluationInput {
                method: &method,
                path: &path,
                query: &query,
                caller,
                headers: &headers,
                body_hash,
                body_length,
            }) {
                Ok(r) => r,
                Err(e) => {
                    if evaluator.is_fail_open() {
                        // Fail-open: pass through to inner service.
                        return inner.call(req).await.map_err(Into::into);
                    }
                    tracing::error!("Chio evaluation failed: {e}");
                    let mut response = http::Response::new(ResBody::default());
                    *response.status_mut() = http::StatusCode::BAD_GATEWAY;
                    return Ok(response);
                }
            };

            // Check verdict.
            if prepared.verdict.is_denied() {
                let status = denied_status(&prepared.verdict);
                let receipt = evaluator
                    .finalize_receipt(&prepared, status.as_u16())
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;

                let mut response = http::Response::new(ResBody::default());
                *response.status_mut() = status;
                response.headers_mut().insert(
                    "x-chio-receipt-id",
                    http::HeaderValue::from_str(&receipt.id)
                        .unwrap_or_else(|_| http::HeaderValue::from_static("unknown")),
                );
                response.extensions_mut().insert(receipt);
                return Ok(response);
            }

            // Forward to inner service.
            let mut response = inner.call(req).await.map_err(Into::into)?;
            let receipt = evaluator
                .finalize_receipt(&prepared, response.status().as_u16())
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;

            // Attach receipt ID to response.
            if let Ok(val) = http::HeaderValue::from_str(&receipt.id) {
                response.headers_mut().insert("x-chio-receipt-id", val);
            }
            response.extensions_mut().insert(receipt);

            Ok(response)
        })
    }
}

fn denied_status(verdict: &chio_http_core::Verdict) -> http::StatusCode {
    if let chio_http_core::Verdict::Deny { http_status, .. } = verdict {
        http::StatusCode::from_u16(*http_status).unwrap_or(http::StatusCode::FORBIDDEN)
    } else {
        http::StatusCode::FORBIDDEN
    }
}

/// Result of a failed body buffer operation.
enum BufferBodyError {
    /// The request body exceeded the configured limit. The middleware reports
    /// this as 413 Payload Too Large rather than passing it to the inner
    /// service.
    TooLarge,
    /// The underlying body or inner service produced an error.
    Inner(Box<dyn std::error::Error + Send + Sync>),
}

async fn buffer_request_body<ReqBody>(
    req: http::Request<ReqBody>,
    max_body_bytes: usize,
) -> Result<(http::Request<ReqBody>, Option<String>, u64), BufferBodyError>
where
    ReqBody: Body + From<Bytes>,
    ReqBody::Data: Send,
    ReqBody::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // Reject early when the body advertises a size beyond the cap. This avoids
    // pulling any bytes for clearly-oversized payloads.
    if let Some(upper) = req.body().size_hint().upper() {
        if upper > max_body_bytes as u64 {
            return Err(BufferBodyError::TooLarge);
        }
    }

    let (parts, body) = req.into_parts();
    let collected = body
        .collect()
        .await
        .map_err(|error| BufferBodyError::Inner(error.into()))?
        .to_bytes();
    if collected.len() > max_body_bytes {
        return Err(BufferBodyError::TooLarge);
    }
    let body_length = collected.len() as u64;
    let body_hash = if collected.is_empty() {
        None
    } else {
        let mut hasher = Sha256::new();
        hasher.update(collected.as_ref());
        Some(hex::encode(hasher.finalize()))
    };
    let replay = http::Request::from_parts(parts, ReqBody::from(collected));
    Ok((replay, body_hash, body_length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluator::ChioEvaluator;
    use bytes::Bytes;
    use chio_core_types::capability::{CapabilityToken, CapabilityTokenBody, ChioScope};
    use chio_core_types::crypto::Keypair;
    use chio_http_core::{http_status_scope, HttpReceipt, CHIO_HTTP_STATUS_SCOPE_FINAL};
    use http_body_util::Full;
    use tower::ServiceExt;

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

    fn make_service() -> (Keypair, ChioEvaluator) {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair.clone(), "test-policy".to_string());
        (keypair, evaluator)
    }

    #[tokio::test]
    async fn service_allows_get() {
        let (_kp, evaluator) = make_service();

        let inner = tower::service_fn(|_req: http::Request<TestBody>| async {
            Ok::<http::Response<TestBody>, Box<dyn std::error::Error + Send + Sync>>(
                http::Response::new(Full::new(Bytes::new())),
            )
        });

        let mut service = ChioService::new(inner, evaluator);

        let req = http::Request::builder()
            .method("GET")
            .uri("/pets")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|e| panic!("build failed: {e}"));

        let resp: http::Response<TestBody> = service
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

    #[tokio::test]
    async fn service_denies_post_without_capability() {
        let (_kp, evaluator) = make_service();

        let inner = tower::service_fn(|_req: http::Request<TestBody>| async {
            panic!("inner should not be called for denied requests");
            #[allow(unreachable_code)]
            Ok::<http::Response<TestBody>, Box<dyn std::error::Error + Send + Sync>>(
                http::Response::new(Full::new(Bytes::new())),
            )
        });

        let mut service = ChioService::new(inner, evaluator);

        let req = http::Request::builder()
            .method("POST")
            .uri("/pets")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|e| panic!("build failed: {e}"));

        let resp: http::Response<TestBody> = service
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

    #[tokio::test]
    async fn service_allows_post_with_capability() {
        let (kp, evaluator) = make_service();

        let inner = tower::service_fn(|_req: http::Request<TestBody>| async {
            let mut response = http::Response::new(Full::new(Bytes::new()));
            *response.status_mut() = http::StatusCode::CREATED;
            Ok::<http::Response<TestBody>, Box<dyn std::error::Error + Send + Sync>>(response)
        });

        let mut service = ChioService::new(inner, evaluator);

        let req = http::Request::builder()
            .method("POST")
            .uri("/pets")
            .header(
                "x-chio-capability",
                valid_capability_token_json("cap-service", &kp),
            )
            .body(Full::new(Bytes::from_static(br#"{"name":"Rex"}"#)))
            .unwrap_or_else(|e| panic!("build failed: {e}"));

        let resp: http::Response<TestBody> = service
            .ready()
            .await
            .unwrap_or_else(|e| panic!("ready failed: {e}"))
            .call(req)
            .await
            .unwrap_or_else(|e| panic!("call failed: {e}"));

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
    }

    #[tokio::test]
    async fn buffer_request_body_hashes_and_replays_raw_bytes() {
        let payload = Bytes::from_static(br#"{"hello":"world","count":2}"#);
        let req = http::Request::builder()
            .method("POST")
            .uri("/echo")
            .body(Full::new(payload.clone()))
            .unwrap_or_else(|e| panic!("build failed: {e}"));

        let (req, body_hash, body_length) =
            match buffer_request_body(req, DEFAULT_MAX_BODY_BYTES).await {
                Ok(parts) => parts,
                Err(BufferBodyError::TooLarge) => panic!("body unexpectedly too large"),
                Err(BufferBodyError::Inner(error)) => panic!("buffer failed: {error}"),
            };

        let replayed = req
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|e| panic!("collect failed: {e}"))
            .to_bytes();

        let mut expected = Sha256::new();
        expected.update(payload.as_ref());

        assert_eq!(body_length, payload.len() as u64);
        assert_eq!(body_hash, Some(hex::encode(expected.finalize())));
        assert_eq!(replayed, payload);
    }

    #[tokio::test]
    async fn buffer_request_body_rejects_oversized_payload() {
        let payload = Bytes::from(vec![b'a'; 32]);
        let req = http::Request::builder()
            .method("POST")
            .uri("/oversized")
            .body(Full::new(payload))
            .unwrap_or_else(|e| panic!("build failed: {e}"));

        let result = buffer_request_body(req, 16).await;
        assert!(matches!(result, Err(BufferBodyError::TooLarge)));
    }

    #[tokio::test]
    async fn service_returns_413_when_body_exceeds_limit() {
        let (_kp, evaluator) = make_service();

        let inner = tower::service_fn(|_req: http::Request<TestBody>| async {
            panic!("inner should not be called for oversized requests");
            #[allow(unreachable_code)]
            Ok::<http::Response<TestBody>, Box<dyn std::error::Error + Send + Sync>>(
                http::Response::new(Full::new(Bytes::new())),
            )
        });

        let mut service = ChioService::new(inner, evaluator).with_max_body_bytes(16);

        let oversized = Bytes::from(vec![b'x'; 64]);
        let req = http::Request::builder()
            .method("POST")
            .uri("/pets")
            .body(Full::new(oversized))
            .unwrap_or_else(|e| panic!("build failed: {e}"));

        let resp: http::Response<TestBody> = service
            .ready()
            .await
            .unwrap_or_else(|e| panic!("ready failed: {e}"))
            .call(req)
            .await
            .unwrap_or_else(|e| panic!("call failed: {e}"));

        assert_eq!(resp.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
    }
}
