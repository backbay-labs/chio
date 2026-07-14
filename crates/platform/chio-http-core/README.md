# chio-http-core

`chio-http-core` defines the protocol-agnostic HTTP security types shared by
every Chio HTTP substrate adapter: the request model, caller identity, session
context, verdicts, and signed HTTP receipts. It also owns `HttpAuthority`, the
kernel-backed authorizer that turns a decoded HTTP request into an allow/deny
verdict and a signed receipt. The crate ships no HTTP server; substrate
adapters (`chio-tower`, `chio-api-protect`, hosted sidecars, framework
middleware) wire these types and handlers into their own routing layer.

## Responsibilities

- Define the shared wire types every substrate adapter needs: `ChioHttpRequest`,
  `CallerIdentity`/`AuthMethod`, `HttpMethod`, `SessionContext`,
  `Verdict`/`DenyDetails`, `HttpReceipt`/`HttpReceiptBody`.
- Own `HttpAuthority`: kernel-backed HTTP request authorization, presented-
  capability validation, reserved `/chio/tools/{server}/{tool}` path binding,
  and decision/final receipt signing.
- Expose substrate-agnostic handler functions for HITL approvals, the
  emergency kill switch, plan-level pre-flight evaluation, compliance
  scoring, and signed regulatory receipt export, so each adapter maps its own
  framework's request/response types onto one shared handler.
- Centralize route path and header constants (`routes`) so every adapter
  serves the same paths.
- Re-export the execution-nonce types (`chio-kernel`) and the canonical
  JSON/crypto/plan types (`chio-core-types`) that HTTP adapters commonly
  need, plus the typed HTTP egress contract (`chio-egress-contract`), so
  adapters depend on one HTTP-facing crate.

## Public API

Core types:

- `request::ChioHttpRequest` - the shared evaluation input.
- `identity::{CallerIdentity, AuthMethod}`, `method::HttpMethod`,
  `session::SessionContext`.
- `verdict::{Verdict, DenyDetails}` - allow/deny/cancel/incomplete outcome.
- `receipt::{HttpReceipt, HttpReceiptBody}`, plus
  `http_status_metadata_decision`/`http_status_metadata_final`/`http_status_scope`.
- `authority::{HttpAuthority, HttpAuthorityBuilder, HttpAuthorityInput,
  HttpAuthorityPolicy, HttpAuthorityEvaluation, PreparedHttpEvaluation,
  TransportDenyInput, HttpAuthorityError, http_authority_tool_grant}`.
- `evaluation::{EvaluateResponse, HealthResponse, SidecarStatus,
  VerifyReceiptResponse}` - sidecar response shapes.

Endpoint handlers (substrate-agnostic: each takes parsed input and returns a
typed response or a typed error exposing `status()`):

| Method | Path | Handler | Auth |
|--------|------|---------|------|
| GET | `/approvals/pending` | `handle_list_pending` | adapter-defined |
| GET | `/approvals/{id}` | `handle_get_approval` | adapter-defined |
| POST | `/approvals/{id}/respond` | `handle_respond` | adapter-defined |
| POST | `/approvals/batch/respond` | `handle_batch_respond` | adapter-defined |
| POST | `/emergency-stop` | `handle_emergency_stop` | `X-Admin-Token` |
| POST | `/emergency-resume` | `handle_emergency_resume` | `X-Admin-Token` |
| GET | `/emergency-status` | `handle_emergency_status` | `X-Admin-Token` |
| POST | `/evaluate-plan` | `handle_evaluate_plan` | capability token in body |
| POST | `/compliance/score` | `handle_compliance_score` | adapter-defined |
| GET | `/regulatory/receipts` | `handle_regulatory_receipts_signed` | `X-Regulatory-Token` (adapter-resolved) |

Path and header constants live in `routes`; Prometheus metrics helpers live
in `metrics`.

## Feature flags

| Flag | Effect |
|------|--------|
| `reqwest-egress` | Re-exports `chio-egress-contract`'s `client_builder_with_contract` and `send_with_contract` through `chio_http_core::*`, for callers that already depend on `reqwest`. |

## Testing

`cargo test -p chio-http-core`

## See also

- `chio-http-session` - a separate, hash-chained per-session journal (request
  history, cumulative data flow, tool sequence); `SessionContext` here is a
  plain DTO and is not backed by that journal.
- `chio-kernel` - supplies the kernel `HttpAuthority` embeds for capability
  validation and receipt signing.
- `chio-egress-contract` - defines the egress contract re-exported under `egress`.
- `chio-api-protect`, `chio-openapi`, `chio-tower`, `chio-conformance` -
  consume these HTTP DTOs and route constants.
