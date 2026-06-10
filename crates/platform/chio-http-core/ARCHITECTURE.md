# chio-http-core Architecture

## Boundary

`chio-http-core` owns the transport-neutral HTTP security model used by proxy,
sidecar, and framework adapters. Its public surface is deliberately DTO-heavy:
request and identity models, HTTP authority evaluation, HTTP receipts, verdict
wire shapes, route registrations, and substrate-independent admin handlers.

The crate depends on `chio-core-types` for canonical JSON, capabilities,
receipts, and key material; on `chio-kernel` for kernel-backed authority
projection and execution nonces; and on `chio-egress-contract` for typed
outbound HTTP egress policy. HTTP adapters and products depend on this crate
for stable wire shapes, so public API compatibility matters.

## Module Boundaries

- `request`, `identity`, `method`, `session`, `verdict`, and `receipt` define
  serializable HTTP-facing primitives and receipt bindings.
- `authority` owns kernel-backed HTTP request authorization and signed HTTP
  decision/final receipts.
- `egress` re-exports the leaf egress contract so adapters can depend on one
  HTTP-facing crate.
- `approvals`, `emergency`, `plan`, `compliance`, and `regulatory_api` expose
  handler-level admin and audit workflows without embedding a web framework.
- `routes` centralizes route and header constants consumed by adapters.

## Authority Boundary

- `authority.rs` owns kernel invocation, receipt signing, and capability
  validation. Authority regression tests live in `authority/tests.rs`, and the
  reserved path binding plus kernel projection payload live in
  `authority_projection`, separating the most sensitive binding decision from
  receipt signing and kernel orchestration.
- The reserved `/chio/tools/{server}/{tool}` path is security-sensitive because
  path-derived identity must override spoofable request fields and must fail
  closed on malformed path identity.
- The kernel projection payload is an internal wire contract between
  `HttpAuthority` and its private `HttpProjectionGuard`. Keeping that payload
  close to binding logic keeps the authority boundary auditable.
- The emergency admin handler stores its configured token as raw `String` state
  and compares it at request time. A blank or malformed configured token fails
  closed because the spec requires operator-level authentication for kill-switch
  routes.

## Security And API Constraints

- Public DTO and route wire shapes must remain backward compatible.
- HTTP receipt signing must preserve canonical JSON byte stability, receipt id
  validation, signed metadata semantics, and decision/final status metadata.
- Deny-by-default routes must continue requiring a valid capability unless the
  route is explicitly session-allow.
- Reserved `/chio/tools` paths must bind to the decoded path identity, not to
  request fields supplied by an adapter.
- Malformed reserved tool paths must deny before a wildcard or HTTP-authority
  grant can accidentally authorize the request.
- Emergency kill-switch routes must require a non-empty operator credential. A
  missing, blank, or control-character-bearing configured token must not turn an
  empty incoming header into operator authority.

## Affected Dependents

Direct dependents include `chio-api-protect`, `chio-envoy-ext-authz`,
`chio-openapi`, `chio-config`, `chio-conformance`, SDK middleware crates, and
tests that import HTTP DTOs and route constants. `EmergencyAdmin::new` returns
`Self`, and the shared handler refuses unusable configured admin tokens at
authorization time. Dependent behavior is covered by `chio-http-core` emergency
endpoint tests and by the crate-level test and clippy gates.
