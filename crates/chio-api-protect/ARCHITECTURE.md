# chio-api-protect Architecture

`chio-api-protect` owns the zero-code HTTP sidecar product behind
`chio api protect` and `chio start`. It translates inbound HTTP requests into
Chio HTTP authority inputs, signs decision and final receipts, persists local
receipt and revocation state when configured, and exposes sidecar control routes
for capability minting, release, receipt submission, receipt verification, and
human approval workflows.

## Module Boundaries

- `src/lib.rs` is the public crate boundary: `ProtectConfig`, `ProtectProxy`,
  `RequestEvaluator`, `EvaluationResult`, `RouteEntry`, `ProtectError`, and spec
  loading helpers.
- `src/evaluator.rs` owns OpenAPI route matching, caller identity extraction,
  capability extraction, policy-mode mapping, and the call into
  `chio_http_core::HttpAuthority`.
- `src/proxy.rs` is the product router and test harness container. The
  implementation is split through `src/proxy/*` for approval routes, HTTP
  utilities, receipt helpers, router assembly, sidecar endpoints, scope checks,
  and state/storage.
- `src/spec_discovery.rs` owns OpenAPI discovery/loading and the upstream egress
  contract. It must not weaken outbound host, scheme, redirect, or loopback
  constraints.
- `src/error.rs` is the product error surface. It maps library failures into
  operator-visible errors without exposing secrets.

## Pain Points

- Caller identity extraction exists in both `evaluator.rs` and
  `proxy/http_util.rs`. Divergence here changes signed receipt caller hashes
  depending on which product path handled the request.
- `proxy.rs` still acts as a large integration-test container. That is
  acceptable for now because the tests exercise product routes end to end, but
  new code should stay in the focused `src/proxy/*` modules.
- Sidecar compatibility routes serve multiple SDK shapes. Tight validation is
  preferable to silently normalizing malformed authorization material.

## Security And API Constraints

- Side-effect HTTP methods and routes marked approval-required must fail closed
  before upstream forwarding unless a valid capability authorizes the request.
- Chio transport credentials, including `x-chio-capability` and
  `chio_capability`, must not be forwarded upstream.
- Control endpoints are loopback-only unless a configured bearer token matches
  in constant time.
- Receipt signatures, caller identity hashes, response-status rebinding, and
  durable revocation semantics must remain stable across restarts.
- Public API compatibility is preserved. Internal helper movement can occur, but
  exported `ProtectConfig`, `ProtectProxy`, `RequestEvaluator`, and discovery
  helpers must keep their existing signatures unless separately approved.

## Affected Dependents

- `chio-cli` invokes this crate for `chio api protect` and `chio start`.
- SDK compatibility routes are exercised by Python and controller integrations
  that call `/v1/capabilities`, `/v1/evaluate`, and `/v1/receipts`.
- `chio-http-core`, `chio-kernel`, `chio-openapi`, and `chio-store-sqlite`
  remain the owners of authority evaluation, approval store semantics, OpenAPI
  parsing, and durable stores. This crate should adapt to them, not duplicate
  their protocol logic.

## Planned Improvement

The caller identity helper is now shared by proxy and evaluator paths, but the
underlying header map lookups still recognize only selected spellings such as
`Authorization`, `authorization`, `X-Chio-Capability`, and
`x-chio-capability`. HTTP header names are case-insensitive, so this product
boundary must use one case-insensitive lookup for caller credentials,
capability transport, revocation preflight, and upstream header scrubbing.

Planned improvement for this slice: introduce a shared case-insensitive header
lookup inside the evaluator/proxy boundary and route all Chio authorization
header decisions through it. This is architectural rather than cosmetic because
header spelling currently changes whether a side-effect request is authorized,
which caller identity hash is signed into the receipt, and whether Chio
transport credentials can be recognized consistently before forwarding.
