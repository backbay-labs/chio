//! Chio tower Service implementation.

use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use http_body::Body;
use sha2::{Digest, Sha256};
use tower_service::Service;

use crate::evaluator::{ChioEvaluator, EvaluationInput};
use crate::request_metadata::RequestMetadata;

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
        crate::metrics::seed_fail_open_series();
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
    ResBody: Default + From<Bytes> + Send + 'static,
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
            let request_metadata = RequestMetadata::parse(req.uri().query());
            let headers = req.headers().clone();

            // Extract caller identity up front. The transport-layer body-size
            // guard signs a deny receipt that records the caller's identity
            // hash even if buffering aborts before the kernel ever runs, so
            // we resolve the identity before pulling any body bytes.
            let identity_fn = evaluator.identity_extractor();
            let caller = identity_fn(&headers);

            let (req, body_hash, body_length) = match buffer_request_body(req, max_body_bytes).await
            {
                Ok(parts) => parts,
                Err(BufferBodyError::TooLarge) => {
                    return Ok(build_payload_too_large_response::<ResBody>(
                        &evaluator,
                        &method,
                        &path,
                        &caller,
                        max_body_bytes,
                    ));
                }
                Err(BufferBodyError::Inner(error)) => return Err(error),
            };

            // Evaluate the request.
            let evaluation_input = EvaluationInput {
                method: &method,
                path: &path,
                query: request_metadata.query(),
                caller,
                headers: &headers,
                body_hash,
                body_length,
            };
            let prepared = match request_metadata.presented_capability_override() {
                Some(presented_capability) => evaluator.prepare_with_presented_capability(
                    evaluation_input,
                    Some(presented_capability),
                ),
                None => evaluator.prepare(evaluation_input),
            };

            let prepared = match prepared {
                Ok(r) => r,
                Err(e) => {
                    if evaluator.is_fail_open() {
                        crate::metrics::record_fail_open_suspected("tower");
                        // Fail-open: pass through to inner service. Record the
                        // skipped enforcement so the bypass is auditable.
                        tracing::warn!(
                            error = %e,
                            "Chio evaluation failed; fail-open enabled, forwarding request WITHOUT enforcement"
                        );
                        return inner.call(req).await.map_err(Into::into);
                    }
                    tracing::error!("Chio evaluation failed: {e}");
                    let mut response = http::Response::new(ResBody::default());
                    *response.status_mut() = http::StatusCode::BAD_GATEWAY;
                    return Ok(response);
                }
            };

            if prepared.verdict.is_denied() {
                let status = denied_status(&prepared.verdict);
                let receipt = evaluator
                    .finalize_receipt(&prepared, status.as_u16())
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
                // Fail closed on a durable append error: a denial's audit record
                // must be as durable as an allow's, so a configured store that
                // cannot record the deny receipt surfaces an error instead of a
                // 403 whose evidence was silently lost.
                evaluator
                    .persist_http_receipt(&receipt)
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

            // Durable-by-default: when a durable receipt store is configured,
            // record the authorization decision before the protected effect
            // runs. Signing and appending the decision receipt up front means an
            // allowed request cannot reach the inner service unless its audit
            // record is durably persisted; a store append failure denies the
            // request rather than letting the effect complete unaudited. With no
            // durable sink this is skipped so the ephemeral hot path avoids the
            // extra signing.
            if evaluator.has_durable_receipt_sink() {
                let decision_receipt = evaluator
                    .sign_decision_receipt(&prepared)
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
                evaluator
                    .persist_http_receipt(&decision_receipt)
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            }

            // Forward to inner service.
            let mut response = inner.call(req).await.map_err(Into::into)?;
            let receipt = evaluator
                .finalize_receipt(&prepared, response.status().as_u16())
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            evaluator
                .persist_http_receipt(&receipt)
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

/// Guard name attached to the deny verdict the middleware emits when a
/// request body exceeds the configured `max_body_bytes` limit.
const TRANSPORT_BODY_SIZE_GUARD: &str = "chio_tower_request_body_limit_guard";

/// Build the `413 Payload Too Large` response that fronts an oversized
/// request body. The response carries:
///
/// - A signed [`HttpReceipt`] (in the response extensions and as the JSON
///   body) so an auditor can verify the rejection was a Chio decision and
///   not a stray network-layer 413.
/// - The receipt id in the `x-chio-receipt-id` header.
///
/// If signing fails (which shouldn't happen for a well-formed kernel
/// keypair), the function falls back to an empty body so the deny path is
/// never blocked by a signing error.
fn build_payload_too_large_response<ResBody>(
    evaluator: &ChioEvaluator,
    method: &str,
    path: &str,
    caller: &chio_http_core::CallerIdentity,
    max_body_bytes: usize,
) -> http::Response<ResBody>
where
    ResBody: Default + From<Bytes>,
{
    use chio_http_core::TransportDenyInput;

    // Route the transport-level denial through the same durability gate as the
    // normal request path. When the evaluator has neither a durable receipt sink
    // nor an explicit ephemeral opt-in, `prepare` denies normal requests with a
    // durable-persistence error (surfaced as a 502 by the service), so an
    // oversized body must not slip past that gate with a signed 413 whose audit
    // record cannot be recorded. Fail closed with the same server error.
    if !evaluator.receipts_are_audited() {
        tracing::error!(
            target: "chio::tower",
            "refusing to sign a transport-deny receipt without durable receipt storage; failing closed"
        );
        let mut response = http::Response::new(ResBody::default());
        *response.status_mut() = http::StatusCode::BAD_GATEWAY;
        return response;
    }

    let status = http::StatusCode::PAYLOAD_TOO_LARGE;
    let caller_identity_hash = caller.identity_hash().ok();

    let receipt = match (
        crate::evaluator::parse_method(method),
        caller_identity_hash.as_deref(),
    ) {
        (Ok(http_method), Some(caller_hash)) => {
            let route_pattern = (evaluator.route_resolver())(method, path);
            let verdict = chio_http_core::Verdict::deny_with_status(
                format!("request body exceeds {max_body_bytes}-byte limit for chio_tower"),
                TRANSPORT_BODY_SIZE_GUARD,
                status.as_u16(),
            );
            let request_id = uuid::Uuid::now_v7().to_string();
            evaluator
                .sign_transport_deny_receipt(TransportDenyInput {
                    request_id: &request_id,
                    route_pattern: &route_pattern,
                    method: http_method,
                    caller_identity_hash: caller_hash,
                    content_hash: None,
                    verdict,
                })
                .ok()
        }
        _ => None,
    };

    let mut response = http::Response::new(ResBody::default());
    *response.status_mut() = status;

    if let Some(receipt) = receipt {
        // Fail closed on a durable append error: the signed 413 must not go out
        // while its audit record was dropped by the configured store. Return the
        // same server error the durability gate uses above.
        if let Err(error) = evaluator.persist_http_receipt(&receipt) {
            tracing::error!(
                target: "chio::tower",
                %error,
                "failed to persist transport-deny receipt to durable store; failing closed"
            );
            let mut response = http::Response::new(ResBody::default());
            *response.status_mut() = http::StatusCode::BAD_GATEWAY;
            return response;
        }
        if let Ok(val) = http::HeaderValue::from_str(&receipt.id) {
            response.headers_mut().insert("x-chio-receipt-id", val);
        }
        if let Ok(body_bytes) = serde_json::to_vec(&receipt) {
            *response.body_mut() = ResBody::from(Bytes::from(body_bytes));
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
        }
        response.extensions_mut().insert(receipt);
    }

    response
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

    // Pull frames one at a time and abort as soon as the running buffer would
    // exceed `max_body_bytes`. Buffering the whole body first (e.g.
    // `body.collect()`) would let an attacker exhaust host memory with a
    // single oversized POST whose declared size hint hid the true length.
    // Streaming the frames bounds peak buffer use to `max_body_bytes` plus
    // the size of one in-flight frame.
    let (parts, body) = req.into_parts();
    let mut body = std::pin::pin!(body);
    let mut buffer = BytesMut::new();
    let limit = max_body_bytes;

    loop {
        let frame = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await;
        let frame = match frame {
            Some(Ok(frame)) => frame,
            Some(Err(error)) => return Err(BufferBodyError::Inner(error.into())),
            None => break,
        };
        let mut data = match frame.into_data() {
            Ok(data) => data,
            // Trailers and other non-data frames carry no body bytes and are
            // dropped: the kernel's content hash and length only cover the
            // request payload, not HTTP/2 trailers.
            Err(_non_data) => continue,
        };
        let chunk_len = data.remaining();
        if buffer.len().saturating_add(chunk_len) > limit {
            return Err(BufferBodyError::TooLarge);
        }
        // `ReqBody::Data: Buf` may expose the chunk as multiple slices, so
        // drain the buffer slice-by-slice rather than relying on a single
        // contiguous `chunk()` view.
        while data.has_remaining() {
            let slice = data.chunk();
            let slice_len = slice.len();
            buffer.extend_from_slice(slice);
            data.advance(slice_len);
        }
    }

    let collected = buffer.freeze();
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
    use chio_core_types::capability::{
        scope::ChioScope,
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core_types::crypto::Keypair;
    use chio_http_core::{
        http_authority_tool_grant, http_status_scope, HttpReceipt, CHIO_HTTP_STATUS_SCOPE_FINAL,
    };
    use http_body_util::{BodyExt, Full};
    use tower::ServiceExt;

    type TestBody = Full<Bytes>;

    fn valid_capability_token_json(id: &str, issuer: &Keypair) -> String {
        let now = chrono::Utc::now().timestamp() as u64;
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope: ChioScope {
                    grants: vec![http_authority_tool_grant()],
                    ..ChioScope::default()
                },
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
        let evaluator = ChioEvaluator::new_ephemeral(keypair.clone(), "test-policy".to_string());
        (keypair, evaluator)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fail_open_branch_increments_suspected_counter() {
        let (_kp, evaluator) = make_service();
        // An unsupported HTTP method makes prepare() return Err (parse_method
        // rejects it); with fail-open enabled the request forwards unenforced
        // through the fail-open branch.
        let evaluator = evaluator.with_fail_open(true);
        let inner = tower::service_fn(|_req: http::Request<TestBody>| async {
            Ok::<http::Response<TestBody>, Box<dyn std::error::Error + Send + Sync>>(
                http::Response::new(Full::new(Bytes::new())),
            )
        });
        let mut service = ChioService::new(inner, evaluator);

        let before = {
            let mut body = String::new();
            chio_metrics_spec::runtime::families::FAIL_OPEN_SUSPECTED.render(&mut body);
            body
        };

        let request = http::Request::builder()
            .method("FOOBAR")
            .uri("/anything")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|e| panic!("request build failed: {e}"));
        let response = service
            .ready()
            .await
            .unwrap_or_else(|e| panic!("ready failed: {e}"))
            .call(request)
            .await;
        assert!(response.is_ok(), "fail-open forwards to inner");

        let mut after = String::new();
        chio_metrics_spec::runtime::families::FAIL_OPEN_SUSPECTED.render(&mut after);
        // The tower surface counter advanced by at least one and the series
        // exists (seeded at zero) even before any event.
        assert!(
            after.contains("chio_fail_open_suspected_total{surface=\"tower\"}"),
            "series must exist: {after}"
        );
        assert_ne!(before, after, "the fail-open counter must advance");
    }

    // Chio's sync tool-dispatch bridge requires a multi-thread runtime (the
    // documented host requirement); the default current-thread test runtime
    // cannot drive the async tool server.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_denies_duplicate_query_capability_even_when_one_value_is_valid() {
        let (kp, evaluator) = make_service();

        let inner = tower::service_fn(|_req: http::Request<TestBody>| async {
            Ok::<http::Response<TestBody>, Box<dyn std::error::Error + Send + Sync>>(
                http::Response::new(Full::new(Bytes::new())),
            )
        });

        let mut service = ChioService::new(inner, evaluator);
        let valid_capability = url::form_urlencoded::byte_serialize(
            valid_capability_token_json("cap-query", &kp).as_bytes(),
        )
        .collect::<String>();
        let req = http::Request::builder()
            .method("GET")
            .uri(format!(
                "/pets?chio_capability=not-json&chio_capability={valid_capability}"
            ))
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
        assert!(receipt.is_denied());
        assert_eq!(receipt.response_status, 403);
        assert_eq!(
            http_status_scope(receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    /// Regression for enforcing body limits during collection: a streaming
    /// body whose size hint hides its true length must abort as soon as the
    /// running buffer crosses the configured cap, so an attacker cannot
    /// exhaust host RAM by streaming chunks one at a time.
    #[tokio::test]
    async fn buffer_request_body_aborts_streaming_body_during_collection() {
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct StreamingBody {
            chunks: Vec<Bytes>,
        }

        impl Body for StreamingBody {
            type Data = Bytes;
            type Error = std::convert::Infallible;

            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                if self.chunks.is_empty() {
                    Poll::Ready(None)
                } else {
                    let chunk = self.chunks.remove(0);
                    Poll::Ready(Some(Ok(http_body::Frame::data(chunk))))
                }
            }

            // Deliberately advertise no upper bound so the size_hint short
            // circuit cannot reject the request before the streaming loop runs.
            fn size_hint(&self) -> http_body::SizeHint {
                http_body::SizeHint::default()
            }
        }

        // Wrapper that satisfies `From<Bytes>` for the replay path; the call must abort before this conversion runs.
        struct AdaptedBody(StreamingBody);
        impl Body for AdaptedBody {
            type Data = Bytes;
            type Error = std::convert::Infallible;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                Pin::new(&mut self.0).poll_frame(cx)
            }
            fn size_hint(&self) -> http_body::SizeHint {
                self.0.size_hint()
            }
        }
        impl From<Bytes> for AdaptedBody {
            fn from(_value: Bytes) -> Self {
                AdaptedBody(StreamingBody { chunks: Vec::new() })
            }
        }

        let chunks = vec![
            Bytes::from(vec![b'x'; 8]),
            Bytes::from(vec![b'x'; 8]),
            Bytes::from(vec![b'x'; 8]),
            Bytes::from(vec![b'x'; 8]),
        ];
        let req = http::Request::builder()
            .method("POST")
            .uri("/streaming-oversized")
            .body(AdaptedBody(StreamingBody {
                chunks: chunks.clone(),
            }))
            .unwrap_or_else(|e| panic!("build failed: {e}"));

        // Cap at 16 bytes, total payload is 32 bytes split across four frames.
        // The streaming loop should reject the third frame (running total 24),
        // before the fourth chunk is ever pulled.
        let result = buffer_request_body(req, 16).await;
        assert!(
            matches!(result, Err(BufferBodyError::TooLarge)),
            "streaming body exceeding the cap during collection must abort"
        );
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
            .unwrap_or_else(|e| panic!("call failed: {e}"))
            .call(req)
            .await
            .unwrap_or_else(|e| panic!("call failed: {e}"));

        assert_eq!(resp.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Regression for signed oversized-body deny receipts: the 413 response
    /// must carry a Chio-signed deny receipt as its JSON body (and as an
    /// extension), so an auditor can verify the rejection was a Chio decision
    /// rather than a stray network 413.
    #[tokio::test]
    async fn service_413_response_has_signed_receipt_body() {
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

        // The Chio receipt must be present in extensions for in-process
        // consumers (auditors, the upstream layer that records receipts).
        let receipt = resp
            .extensions()
            .get::<HttpReceipt>()
            .unwrap_or_else(|| panic!("missing receipt extension on 413"))
            .clone();
        assert_eq!(receipt.response_status, 413);
        assert!(
            receipt.is_denied(),
            "413 receipt must record a Deny verdict"
        );
        assert!(
            receipt
                .verify_signature()
                .unwrap_or_else(|e| panic!("verify failed: {e}")),
            "413 receipt signature must verify under embedded kernel key"
        );

        // The receipt id header must mirror the body so out-of-band auditors
        // can correlate without parsing the body.
        let header_id = resp
            .headers()
            .get("x-chio-receipt-id")
            .unwrap_or_else(|| panic!("missing x-chio-receipt-id header on 413"))
            .to_str()
            .unwrap_or_else(|e| panic!("header was not utf-8: {e}"))
            .to_string();
        assert_eq!(header_id, receipt.id);

        // The response body must carry the same signed receipt as JSON.
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_TYPE)
                .map(|v| v.to_str().unwrap_or_else(|e| panic!("ctype utf8: {e}"))),
            Some("application/json"),
        );
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|e| panic!("collect failed: {e}"))
            .to_bytes();
        assert!(
            !body_bytes.is_empty(),
            "413 response body must not be empty"
        );
        let parsed: HttpReceipt = serde_json::from_slice(&body_bytes)
            .unwrap_or_else(|e| panic!("response body must be a serialised HttpReceipt: {e}"));
        assert_eq!(parsed.id, receipt.id);
        assert_eq!(parsed.response_status, 413);
        assert!(
            parsed
                .verify_signature()
                .unwrap_or_else(|e| panic!("verify failed: {e}")),
            "deserialised receipt body must verify under the embedded kernel key"
        );
    }

    /// Durability parity for the transport-deny path: an evaluator with neither
    /// a durable receipt store nor an explicit ephemeral opt-in is fail-closed,
    /// so an oversized body must not receive a signed 413 whose audit record is
    /// silently dropped. It fails closed with the same server error the normal
    /// request path returns for a missing durable store.
    #[tokio::test]
    async fn service_413_fails_closed_without_durable_receipts() {
        let keypair = Keypair::generate();
        // `ChioEvaluator::new` attaches no durable store and does not opt into
        // ephemeral receipts, matching a misconfigured production deployment.
        let evaluator = ChioEvaluator::new(keypair, "fail-closed-policy".to_string());

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

        // Fail closed exactly like the normal path's durability denial: a server
        // error, and no signed receipt implying an audit trail that never landed.
        assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
        assert!(resp.extensions().get::<HttpReceipt>().is_none());
        assert!(resp.headers().get("x-chio-receipt-id").is_none());
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|e| panic!("collect failed: {e}"))
            .to_bytes();
        assert!(body_bytes.is_empty());
    }

    #[tokio::test]
    async fn service_413_without_receipt_body_omits_json_content_type() {
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
            .method("BREW")
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
        assert!(resp.extensions().get::<HttpReceipt>().is_none());
        assert!(resp.headers().get(http::header::CONTENT_TYPE).is_none());
        assert!(resp.headers().get("x-chio-receipt-id").is_none());

        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|e| panic!("collect failed: {e}"))
            .to_bytes();
        assert!(body_bytes.is_empty());
    }

    #[tokio::test]
    async fn service_413_unsupported_method_rejects_before_route_resolver() {
        fn route_resolver(_method: &str, _path: &str) -> String {
            panic!("route resolver must not run for unsupported HTTP methods");
        }

        let (_kp, evaluator) = make_service();
        let evaluator = evaluator.with_route_resolver(route_resolver);

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
            .method("BREW")
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
        assert!(resp.extensions().get::<HttpReceipt>().is_none());
        assert!(resp.headers().get(http::header::CONTENT_TYPE).is_none());
        assert!(resp.headers().get("x-chio-receipt-id").is_none());
    }

    #[tokio::test]
    async fn service_413_receipt_uses_route_resolver_pattern() {
        fn route_resolver(_method: &str, path: &str) -> String {
            if path.starts_with("/pets/") {
                "/pets/{petId}".to_string()
            } else {
                path.to_string()
            }
        }

        let (_kp, evaluator) = make_service();
        let evaluator = evaluator.with_route_resolver(route_resolver);

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
            .uri("/pets/secret-id")
            .body(Full::new(oversized))
            .unwrap_or_else(|e| panic!("build failed: {e}"));

        let resp: http::Response<TestBody> = service
            .ready()
            .await
            .unwrap_or_else(|e| panic!("ready failed: {e}"))
            .call(req)
            .await
            .unwrap_or_else(|e| panic!("call failed: {e}"));

        let receipt = resp
            .extensions()
            .get::<HttpReceipt>()
            .unwrap_or_else(|| panic!("missing receipt extension on 413"));
        assert_eq!(receipt.route_pattern, "/pets/{petId}");
    }

    /// A recording receipt store that captures every appended core receipt, used
    /// to assert the tower service persists its outer HTTP receipts to a durable
    /// store rather than leaving them only in the response extensions.
    #[derive(Default)]
    struct RecordingReceiptStore {
        receipts: std::sync::Mutex<Vec<chio_core_types::receipt::body::ChioReceipt>>,
    }

    impl RecordingReceiptStore {
        fn stored_ids(&self) -> Vec<String> {
            let receipts = match self.receipts.lock() {
                Ok(receipts) => receipts,
                Err(poisoned) => poisoned.into_inner(),
            };
            receipts.iter().map(|receipt| receipt.id.clone()).collect()
        }
    }

    impl chio_kernel::ReceiptStore for RecordingReceiptStore {
        fn append_chio_receipt(
            &self,
            receipt: &chio_core_types::receipt::body::ChioReceipt,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            match self.receipts.lock() {
                Ok(mut receipts) => receipts.push(receipt.clone()),
                Err(poisoned) => poisoned.into_inner().push(receipt.clone()),
            }
            Ok(())
        }

        fn append_child_receipt(
            &self,
            _receipt: &chio_core_types::receipt::lineage::ChildRequestReceipt,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            Ok(())
        }
    }

    /// Durable-by-default for tower embedders: when an evaluator is built with a
    /// durable receipt store, the outer HTTP receipt the service signs for the
    /// HTTP decision must be appended to that store, not just placed in the
    /// response extensions where it vanishes on restart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_persists_http_receipt_to_durable_store() {
        let keypair = Keypair::generate();
        let store = std::sync::Arc::new(RecordingReceiptStore::default());
        let evaluator = ChioEvaluator::builder(keypair.clone(), "durable-policy".to_string())
            .receipt_store(store.clone())
            .allow_ephemeral(true)
            .build()
            .unwrap_or_else(|e| panic!("build failed: {e}"));

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
        let http_receipt = resp
            .extensions()
            .get::<HttpReceipt>()
            .unwrap_or_else(|| panic!("missing receipt extension"))
            .clone();

        // Converting the signed HTTP receipt with the kernel keypair reproduces
        // the exact core receipt the durable sink appended, so its id must be
        // present in the store after the call.
        let expected = http_receipt
            .to_chio_receipt_with_keypair(&keypair)
            .unwrap_or_else(|e| panic!("convert failed: {e}"));
        let stored_ids = store.stored_ids();
        assert!(
            stored_ids.contains(&expected.id),
            "durable store must contain the HTTP decision receipt {}; stored: {stored_ids:?}",
            expected.id
        );
    }

    /// A receipt store that accepts the embedded kernel's own authorization
    /// receipt (the first append during evaluation) but then rejects every
    /// later append, standing in for a volume that fills up (or turns
    /// read-only) after the kernel has recorded its decision but before the
    /// outer HTTP receipt lands.
    #[derive(Default)]
    struct FailAfterFirstAppend {
        appended: std::sync::atomic::AtomicUsize,
    }

    impl chio_kernel::ReceiptStore for FailAfterFirstAppend {
        fn append_chio_receipt(
            &self,
            _receipt: &chio_core_types::receipt::body::ChioReceipt,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            if self
                .appended
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0
            {
                Ok(())
            } else {
                Err(chio_kernel::ReceiptStoreError::Conflict(
                    "durable receipt append failed (volume full)".to_string(),
                ))
            }
        }

        fn append_child_receipt(
            &self,
            _receipt: &chio_core_types::receipt::lineage::ChildRequestReceipt,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            Ok(())
        }
    }

    /// Durable-by-default fail-closed for the outer HTTP receipt: when a durable
    /// receipt store is configured and the append of the HTTP decision receipt
    /// fails, an allowed request must not reach the inner service. The protected
    /// effect must not run while its audit record is silently dropped, so the
    /// request fails closed instead of returning a success.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_fails_closed_when_durable_http_receipt_append_fails() {
        let keypair = Keypair::generate();
        let store = std::sync::Arc::new(FailAfterFirstAppend::default());
        let evaluator = ChioEvaluator::builder(keypair, "durable-policy".to_string())
            .receipt_store(store)
            .allow_ephemeral(true)
            .build()
            .unwrap_or_else(|e| panic!("build failed: {e}"));

        let inner = tower::service_fn(|_req: http::Request<TestBody>| async {
            panic!("inner service must not run when the durable HTTP receipt append fails");
            #[allow(unreachable_code)]
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

        let result = service
            .ready()
            .await
            .unwrap_or_else(|e| panic!("ready failed: {e}"))
            .call(req)
            .await;

        // Fail closed: an error is unambiguously fail-closed, and any response
        // must be a server error, never a 2xx success whose HTTP audit record
        // was dropped by the durable store.
        if let Ok(response) = result {
            assert!(
                response.status().is_server_error(),
                "a durable HTTP receipt append failure must fail closed, got {}",
                response.status()
            );
        }
    }
}
