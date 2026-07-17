# chio-http-core architecture

## Overview

`chio-http-core` is the protocol-agnostic HTTP security model that every HTTP
substrate adapter (`chio-tower`, `chio-api-protect`, hosted sidecars,
framework middleware) builds on. It ships no HTTP server: adapters extract a
`ChioHttpRequest` from their own framework and hand it to this crate's types
and handlers.

`HttpAuthority` does not reimplement guard or capability logic. It embeds a
`ChioKernel` whose only registered tool server exposes a synthetic
`authorize_http_request` tool and projects each HTTP request into a
`ToolCallRequest` against it, so the same guard/capability/receipt pipeline
that mediates native tool calls also mediates HTTP requests. Most of the
crate is trust-neutral DTOs and wire logic; `authority.rs` and
`authority_projection.rs` are the actual trust boundary.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Module declarations and the public re-export surface, including selected `chio-kernel` and `chio-core-types` types. |
| `src/request.rs` | `ChioHttpRequest`: the shared evaluation input and its content-hash binding. |
| `src/identity.rs`, `src/method.rs`, `src/session.rs` | `CallerIdentity`/`AuthMethod`, `HttpMethod`, `SessionContext`: caller, method, and per-session primitives the request and authority types build on. |
| `src/verdict.rs` | `Verdict`/`DenyDetails`: the allow/deny/cancel/incomplete outcome type and structured deny context. |
| `src/receipt.rs` | `HttpReceipt`/`HttpReceiptBody`: signed receipt type, authority-semantics validation, decision/final status metadata helpers. |
| `src/authority.rs` (+ `authority/tests.rs`) | `HttpAuthority`: kernel-backed evaluation, capability token validation, decision/final receipt signing. |
| `src/authority_projection.rs` | Reserved `/chio/tools/{server}/{tool}` path binding and the `HttpKernelAuthorizationRequest` projection sent to the embedded kernel. |
| `src/evaluation.rs` | `EvaluateResponse`, `HealthResponse`, `SidecarStatus`, `VerifyReceiptResponse`: sidecar-facing response shapes. |
| `src/egress.rs` | Re-exports `chio-egress-contract` types (and, under `reqwest-egress`, its reqwest helpers) so adapters depend on one crate for outbound egress policy. |
| `src/metrics.rs` | Guard-evaluation counters and decision-latency histogram for the HTTP authority, rendered as Prometheus text. |
| `src/routes.rs` | Route path and header constants plus route-registration descriptors shared by every substrate adapter. |
| `src/approvals.rs`, `src/emergency.rs`, `src/plan.rs`, `src/compliance.rs`, `src/regulatory_api.rs` | Substrate-agnostic handlers for HITL approvals, the kill switch, plan pre-flight evaluation, compliance scoring, and signed regulatory export (see README for the per-path table). |

## Request lifecycle

1. An adapter decodes its request into `HttpAuthorityInput` (method, route
   pattern, path, `CallerIdentity`, body hash/length, optional presented
   capability, optional execution nonce, `HttpAuthorityPolicy`) and calls
   `HttpAuthority::evaluate` (or `prepare`, to sign the receipt separately).
2. `authority_projection::capability_binding` derives the tool-server/
   tool-name binding. A reserved `/chio/tools/{server}/{tool}` path always
   wins, decoding server and tool identity from the path and forcing
   `DenyByDefault`; a malformed path denies immediately. Otherwise the
   binding follows the caller-supplied policy and tool fields.
3. A presented capability token is verified for issuer trust, signature,
   time bounds, tool/scope match, and non-revocation across the delegation
   chain; any failure forces a deny.
4. `prepare` content-hashes a `ChioHttpRequest` and dispatches it as a
   `ToolCallRequest` through the embedded kernel.
5. The kernel's verdict is cross-checked against the HTTP-projected verdict
   (disagreement is an `HttpAuthorityError`). `PendingApproval` surfaces as
   `HttpAuthorityError::PendingApproval` for the adapter to map to `409` and
   `/approvals/*`; a fail-closed durability denial also surfaces as an error
   rather than a routine deny receipt.
6. `evaluate` signs a decision receipt and records guard-evaluation/latency
   metrics. Once the adapter has an upstream response, `finalize_receipt`
   signs a second receipt carrying the real `response_status`.

## Invariants and failure modes

- Reserved `/chio/tools/{server}/{tool}` paths bind capability identity from
  the decoded path segments, not adapter-supplied fields; a missing tool
  segment, nested segments, an empty segment, or incomplete/non-UTF-8
  percent-encoding denies (`DenyByDefault`) before any session-allow or
  wildcard policy can authorize the request.
- Every `HttpAuthority` constructor (and `HttpAuthorityBuilder`, by default)
  is fail-closed: no receipt or revocation store is attached and both
  ephemeral opt-ins default `false`, so the first mediated call denies with
  a durability error (kernel guard `kernel.receipt_persistence`) until a
  durable store is wired through `HttpAuthority::builder`. Only the
  `_ephemeral` constructors, or `allow_ephemeral_*(true)` on the builder,
  opt into in-memory state.
- A presented capability's revocation check fails closed: an unavailable
  revocation store rejects the capability instead of treating it as valid.
- `HttpReceipt::sign` and `verify_signature` both enforce fixed authority
  semantics (`receipt_kind = MediatedDecision`, `boundary_class = Prevent`,
  `observation_outcome = None`, `trust_level = Mediated`); a receipt that
  drifts from this shape refuses to sign or fails verification.
- `EmergencyAdmin` treats a blank or control-character-bearing configured
  admin token as permanently unusable, so an empty or missing caller header
  can never match it.
- The embedded HTTP-mediation kernel disables sampling, sampling-tool-use,
  elicitation, and Web3-evidence requirements; only the receipt-store,
  revocation-store, and ephemeral flags vary per `HttpAuthority` instance.
- `#![forbid(unsafe_code)]` at the crate root.

## Dependencies

`chio-kernel` supplies the embedded `ChioKernel` (capability issuance, guard
evaluation, receipt/revocation durability gates) `HttpAuthority` wraps.
`chio-core-types` supplies canonical JSON, capability/crypto/receipt
primitives, and the plan-evaluation types re-exported for the plan endpoint.
`chio-egress-contract` supplies the typed egress contract re-exported under
`egress`; it stays a leaf crate so callers such as `chio-link` (itself a
`chio-kernel` dependency) can consume it without forming a cycle.
`chio-cross-protocol` supplies the route-planning types `authority.rs` uses
for route-selection metadata. `chio-metrics-spec` supplies the metric-name
constants `metrics.rs` renders, including `chio_dispatch_failure_total`.
`chrono`, `sha2`/`hex`, `uuid` (`v7`), and `thiserror` support timestamps,
hashing, ids, and typed handler errors.

## Extension points

- `ComplianceSource` (`compliance.rs`) - backing store for
  `/compliance/score`; adapters supply an implementation (typically
  `chio-store-sqlite`-backed) to `handle_compliance_score`.
- `RegulatoryReceiptSource` (`regulatory_api.rs`) - backing store for
  `/regulatory/receipts`; adapters supply an implementation to
  `handle_regulatory_receipts_signed`.
