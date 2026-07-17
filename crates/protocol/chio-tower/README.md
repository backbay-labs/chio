# chio-tower

Tower middleware for Chio capability validation and receipt signing over
HTTP, plus an independent Tower stack for dispatching tool-call requests
straight through the kernel. `ChioLayer`/`ChioService` wrap any
`tower::Service` that speaks `http::Request`/`http::Response`, including
Axum's `axum::body::Body` and other bytes-backed HTTP bodies; real
`tonic::body::Body` replay is not yet covered.

The middleware does not decide authorization itself: it extracts caller
identity, buffers and hashes the request body, and forwards evaluation to
`chio-http-core`'s `HttpAuthority` (backed by `chio-kernel`). It owns the
edge-only trust logic around that call - see Responsibilities.

## Responsibilities

- Wrap an inner service with `ChioLayer`/`ChioService`: evaluate every
  request against `HttpAuthority` and attach a signed `HttpReceipt` to the
  response (`x-chio-receipt-id` header and response extensions).
- Extract caller identity from `Authorization: Bearer`, `X-Api-Key`, or
  `Cookie` headers, hashing the secret before it becomes the identity
  subject; anonymous otherwise.
- Buffer and SHA-256 hash request bodies up to a configurable cap
  (`DEFAULT_MAX_BODY_BYTES`, 8 MiB by default), streamed frame-by-frame so a
  misreported `size_hint` cannot exhaust memory, then replay the exact bytes
  to the inner service.
- Detect duplicate `chio_capability` query parameters as ambiguous
  presentation and force a signed deny rather than trust a collapsed map.
- Persist decision, final, and transport-deny receipts to a durable
  `chio_kernel::ReceiptStore` when one is configured; fail the request closed
  if a configured store cannot record the receipt.
- Dispatch tool-call requests directly through `chio_kernel::ChioKernel` via
  `KernelService`, with tracing, per-tenant concurrency limiting, load
  shedding, and timeout normalization (`build_layered`).
- Expose the fixed WASM host-call metric-label vocabulary used for guard
  observability.

## Public API

HTTP middleware:

- `ChioLayer::{new, new_ephemeral, builder, from_evaluator, with_max_body_bytes}`
  - `tower::Layer` producing `ChioService<S>`.
- `ChioService<S>`, `DEFAULT_MAX_BODY_BYTES` - the `tower::Service` and its
  default body-size cap.
- `ChioEvaluator::{new, new_ephemeral, builder, with_fail_open,
  with_identity_extractor, with_route_resolver}`, `EvaluationResult` - the
  evaluation core `ChioLayer` wraps.
- `extract_identity`, `IdentityExtractor` - default header-based caller
  identity extraction.
- `ChioTowerError` - evaluation, signing, persistence, and identity errors.

Kernel dispatch:

- `KernelService`, `KernelRequest`, `KernelResponse`, `KernelServiceError`,
  `TenantId` - direct tool-call dispatch through `chio_kernel::ChioKernel`.
- `KernelTraceLayer` / `KernelTraceService` - request/response tracing.
- `TenantConcurrencyLimitLayer` / `TenantConcurrencyLimitService` -
  per-tenant concurrency limiting with load shedding.
- `build_layered(kernel, per_tenant_limit, request_timeout)` - composes
  trace, timeout, and per-tenant limiting/shedding around `KernelService`.

Host-call metrics: `HOST_CALL_LOG`, `HOST_CALL_GET_CONFIG`,
`HOST_CALL_GET_TIME_UNIX_SECS`, `HOST_CALL_FETCH_BLOB`,
`HOST_CALL_METRIC_LABEL_VALUES`, `normalize_host_call_metric_label`.

## Usage

```rust
use chio_tower::ChioLayer;
use chio_core_types::crypto::Keypair;
use tower::Layer;

let keypair = Keypair::generate();
let layer = ChioLayer::new(keypair, "policy-hash-abc".to_string());

// Wrap any tower Service with Chio evaluation.
let inner = tower::service_fn(|_req: http::Request<http_body_util::Full<bytes::Bytes>>| async {
    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(()))
});
let _service = layer.layer(inner);
```

`ChioLayer::new` is fail-closed with no durable store attached. Use
`ChioLayer::builder` to wire a `ReceiptStore`/`RevocationStore`, or
`ChioLayer::new_ephemeral` for a local scaffold.

## Testing

`cargo test -p chio-tower`

Tests that drive the kernel's async tool dispatch require a multi-thread
Tokio runtime (`#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`).

## See also

- `chio-http-core` - defines `HttpAuthority`, `HttpReceipt`,
  `CallerIdentity`, `Verdict`; this crate is its Tower/HTTP integration.
- `chio-kernel` - `ChioKernel`, `ReceiptStore`, `RevocationStore` that
  `HttpAuthority` and `KernelService` dispatch through.
- `chio-metrics-spec` - defines `chio_fail_open_suspected_total`,
  incremented here for the `"tower"` surface on every fail-open bypass.
