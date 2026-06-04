# chio-tower Architecture Note

## Current Boundaries

- `lib.rs` is the public facade. It reexports the Tower HTTP middleware, the HTTP evaluator, identity extraction, kernel dispatch services, and host-call metric labels.
- `layer.rs` owns the `tower_layer::Layer` entrypoint and should stay a thin configuration wrapper over `ChioService`.
- `service.rs` owns HTTP request interception: body buffering, receipt-bound content hashing, evaluation dispatch, signed deny responses, and response receipt attachment.
- `evaluator.rs` owns the bridge from Tower request metadata into `chio-http-core::HttpAuthority`. It maps methods, route patterns, caller identity, capability presentation, policy mode, and receipt finalization.
- `identity.rs` owns caller extraction from HTTP headers. It must hash secrets and never propagate raw bearer tokens, API keys, or cookie values.
- `kernel_service.rs` owns Tower services for tool-call dispatch through `chio-kernel`, including tracing, timeout normalization, and per-tenant load shedding.
- `host_call.rs` owns the fixed metric-label vocabulary for WASM host-call observability.

## Pain Points

- `service.rs` still mixes three jobs: HTTP transport mechanics, request metadata normalization, and enforcement response construction. That makes it easier for subtle transport parsing behavior to bypass the security model.
- Query parameters are parsed directly into `HashMap<String, String>` inside `service.rs`. That matches `chio-http-core`'s current normalized request model, but it loses duplicate key information before capability presentation is interpreted.
- A duplicated `chio_capability` query parameter is an ambiguous capability presentation. Treating whichever value survives collection as authoritative is too weak for a fail-closed middleware boundary.
- The public surface should not grow a new query model until `chio-http-core` changes its substrate contract. This slice should harden the Tower boundary without forcing downstream API churn.

## Security And API Constraints

- The middleware must remain fail-closed by default.
- Every enforcement denial that reaches HTTP evaluation should carry a signed receipt through the existing `HttpAuthority` path.
- Request bodies must stay byte-stable for downstream replay after hashing.
- Raw secrets must not be logged or echoed into documentation, receipts, errors, or tests.
- Existing public exports and builder methods must remain compatible.

## Affected Dependents

- Axum and generic Tower/HTTP2 tests exercise `ChioService` and `ChioLayer`; they should continue to pass without API changes.
- `chio-api-protect` and cross-protocol runtime qualification scripts include `cargo test -p chio-tower`; no generated artifacts should be edited.
- `chio-http-core` remains the authority for receipt construction and capability validation. This slice should not change its public request schema.

## Planned Material Improvement

Introduce a small request-metadata boundary inside `chio-tower` that parses the raw query string before it is collapsed to `HashMap<String, String>`. The boundary will detect duplicate `chio_capability` query parameters and force that request through the normal signed-deny evaluation path instead of letting a surviving map value decide capability presentation. This is architectural, not cosmetic, because it moves security-sensitive transport parsing out of the service control flow and strengthens the capability boundary while preserving the external API.
