# chio-tower architecture

## Overview

chio-tower is the Tower and Axum integration surface for Chio's HTTP
enforcement. `ChioLayer`/`ChioService` terminate inbound HTTP requests but
delegate the authorization decision itself to `chio_http_core::HttpAuthority`
(backed by `chio_kernel`) rather than deciding it locally. The crate does own
the edge-only trust logic around that delegation - see Invariants and
failure modes. A second, independent service stack (`KernelService`,
`build_layered`) dispatches tool-call requests straight through `ChioKernel`,
with no HTTP shape at all.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public facade (`#![forbid(unsafe_code)]`). Re-exports the HTTP middleware, evaluator, identity extraction, kernel dispatch stack, and host-call metric labels. |
| `src/layer.rs` | `ChioLayer` / `ChioLayerBuilder`: the `tower_layer::Layer` entry point; a thin configuration wrapper that builds `ChioService`. |
| `src/service.rs` | `ChioService`: the `tower_service::Service`. Buffers and hashes request bodies, dispatches evaluation, signs and persists receipts, attaches them to the response. |
| `src/evaluator.rs` | `ChioEvaluator` / `ChioEvaluatorBuilder`: bridges Tower request data into `HttpAuthority`, and durably persists the outer HTTP receipts `ChioService` signs. |
| `src/identity.rs` | `extract_identity`: the default `IdentityExtractor`. Hashes bearer tokens, API keys, and cookie values into a `CallerIdentity`. |
| `src/request_metadata.rs` | `RequestMetadata` (crate-private): query-string parsing and duplicate-`chio_capability` detection, kept out of `service.rs`'s control flow. |
| `src/kernel_service.rs` | `KernelService` plus the tracing, timeout, and per-tenant concurrency/load-shed layers around it: an independent stack for direct tool-call dispatch through `ChioKernel`. |
| `src/metrics.rs` | Fail-open-suspected counter emission (crate-private), seeded to zero on `ChioService::new` so the alerting backstop does not fire on a deployment that has never failed open. |
| `src/host_call.rs` | Fixed metric-label vocabulary for WASM host-call observability. |
| `src/error.rs` | `ChioTowerError`, the crate's error type. |

## Request lifecycle

`ChioService::call` runs one request through:

1. Parse the query string and extract caller identity from headers before
   touching the body (`RequestMetadata::parse`, `IdentityExtractor`).
2. Buffer the body up to `max_body_bytes`, one frame at a time, aborting as
   soon as the running total would exceed the cap; compute its SHA-256 hash.
   An oversized body short-circuits to a signed `413`.
3. Build the evaluation input and call `ChioEvaluator::prepare` (or
   `prepare_with_presented_capability` when `RequestMetadata` found a
   duplicate `chio_capability` query parameter), which delegates to
   `HttpAuthority::prepare`.
4. A `prepare` error is fail-open (forward unenforced, increment
   `chio_fail_open_suspected_total{surface="tower"}`) or fail-closed
   (`502 Bad Gateway`), per `ChioEvaluator::is_fail_open`.
5. A deny verdict signs and persists a final receipt and returns the
   verdict's HTTP status with `x-chio-receipt-id` and the receipt in the
   response extensions; the inner service is never called.
6. An allow verdict with a durable receipt store signs and persists the
   decision receipt before the inner service runs.
7. The inner service runs; the response status finalizes the receipt, which
   is signed, persisted, and attached to the response.

## Kernel dispatch stack

`build_layered(kernel, per_tenant_limit, request_timeout)` composes, outermost
first: `KernelTraceLayer`, an internal timeout-error normalizer,
`tower::timeout::TimeoutLayer`, `TenantConcurrencyLimitLayer`, then
`KernelService`.

- `KernelService::call` dispatches straight to
  `ChioKernel::evaluate_tool_call`; capability validation and receipt
  signing happen inside the kernel, not in this stack.
- `TenantConcurrencyLimitService` gives each `TenantId` its own
  `LoadShed<ConcurrencyLimit<S>>` bucket, bounded by `max_tenants` (default
  `DEFAULT_MAX_TENANT_CONCURRENCY_BUCKETS` = 1024). It never waits for
  capacity: a saturated bucket returns `KernelServiceError::Overloaded`
  immediately. A bucket idle past `tenant_idle_reap_secs` (default 3600s)
  with no in-flight calls may be reaped to admit a new tenant when the table
  is full; a bucket with an in-flight call is never reaped, since recreating
  its semaphore would let that tenant exceed `per_tenant_limit`.
- `map_kernel_error` routes `KernelError::Overloaded` to the same
  `KernelServiceError::Overloaded` variant tower-side load shedding
  produces, instead of the blanket `Kernel(..)` wrap, so kernel-side (RSS)
  shedding and tower-side shedding are equally retryable to callers.

## Invariants and failure modes

- Fail-closed by default; fail-open is opt-in per evaluator
  (`with_fail_open`), and every bypass increments the fail-open-suspected
  counter for the `"tower"` surface.
- Durable-by-default: with a receipt store configured, every receipt
  (decision, final, deny, transport-deny) must append successfully before or
  instead of the protected effect completing; a store append failure fails
  the request closed. Without a store attached, the evaluator must opt into
  ephemeral receipts (`allow_ephemeral(true)` or `new_ephemeral`), or every
  receipt-emitting path - including the transport-level body-size deny -
  fails closed (`ChioEvaluator::receipts_are_audited`).
- An HTTP receipt that cannot convert into a verifiable core receipt under
  the durable sink's keypair (signed under a different kernel key) is
  skipped rather than appended or failing the request.
- A duplicate `chio_capability` query parameter is ambiguous presentation;
  `RequestMetadata` forces deny evaluation rather than letting a collapsed
  `HashMap` silently pick one value.
- Request bodies replay byte-identical to the inner service after hashing;
  trailers and other non-data frames are excluded from the hash and length.
- Safe methods (GET/HEAD/OPTIONS) default to
  `HttpAuthorityPolicy::SessionAllow`; all other methods default to
  `DenyByDefault` and require a presented capability.
- `#![forbid(unsafe_code)]` at the crate root.

## Dependencies

Internal: `chio-http-core` supplies `HttpAuthority`, `HttpReceipt`,
`CallerIdentity`, and `Verdict`, the evaluation core `ChioEvaluator` wraps.
`chio-kernel` supplies `ChioKernel`, `ToolCallRequest`/`ToolCallResponse`,
`KernelError`, and the `ReceiptStore`/`RevocationStore` traits used by both
the durable-receipt path and `KernelService`. `chio-core-types` supplies
`Keypair` and the capability/receipt metadata types. `chio-metrics-spec`
supplies the `chio_fail_open_suspected_total` counter family. No dependency
aliasing.

External: `tower` / `tower-layer` / `tower-service` for the `Layer`/`Service`
traits and the `ConcurrencyLimit`/`LoadShed`/`Timeout` combinators; `http` /
`http-body` / `http-body-util` / `bytes` for request and response bodies;
`sha2` / `hex` for content hashing; `uuid` (`v7`) for request ids; `url` for
capability query-parameter parsing; `thiserror` for `KernelServiceError`.

## Extension points

- `IdentityExtractor` (`fn(&http::HeaderMap) -> CallerIdentity`) - override
  via `ChioEvaluator::with_identity_extractor` to source caller identity
  from a custom scheme.
- Route pattern resolution (`fn(&str, &str) -> String`) - override via
  `ChioEvaluator::with_route_resolver` to normalize a path into a route
  pattern (for example collapsing path parameters) before evaluation.
