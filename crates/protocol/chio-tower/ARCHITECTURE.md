# chio-tower Architecture Note

## Module Boundaries

- `lib.rs` is the public facade. It reexports the Tower HTTP middleware, the HTTP evaluator, identity extraction, kernel dispatch services, and host-call metric labels.
- `layer.rs` owns the `tower_layer::Layer` entrypoint and stays a thin configuration wrapper over `ChioService`.
- `service.rs` owns HTTP request interception: body buffering, receipt-bound content hashing, evaluation dispatch, signed deny responses, and response receipt attachment.
- `evaluator.rs` owns the bridge from Tower request metadata into `chio-http-core::HttpAuthority`. It maps methods, route patterns, caller identity, capability presentation, policy mode, and receipt finalization.
- `identity.rs` owns caller extraction from HTTP headers. It must hash secrets and never propagate raw bearer tokens, API keys, or cookie values.
- `kernel_service.rs` owns Tower services for tool-call dispatch through `chio-kernel`, including tracing, timeout normalization, and per-tenant load shedding.
- `host_call.rs` owns the fixed metric-label vocabulary for WASM host-call observability.

## Capability Presentation Boundary

A request-metadata boundary parses the raw query string before it is collapsed
to `HashMap<String, String>`. A duplicated `chio_capability` query parameter is
an ambiguous capability presentation, so the boundary detects duplicates and
forces that request through the normal signed-deny evaluation path rather than
letting a surviving map value decide capability presentation. Security-sensitive
transport parsing stays out of the service control flow.

## Security And API Constraints

- The middleware is fail-closed by default.
- Every enforcement denial that reaches HTTP evaluation carries a signed receipt through the `HttpAuthority` path.
- Request bodies stay byte-stable for downstream replay after hashing.
- Raw secrets are never logged or echoed into documentation, receipts, errors, or tests.
- Existing public exports and builder methods stay compatible.

## Affected Dependents

- Axum and generic Tower/HTTP2 tests exercise `ChioService` and `ChioLayer`.
- `chio-api-protect` and cross-protocol runtime qualification scripts include `cargo test -p chio-tower`.
- `chio-http-core` is the authority for receipt construction and capability validation; its public request schema is unchanged.
