# chio-a2a-adapter architecture

## Overview

`chio-a2a-adapter` bridges one external A2A (Agent-to-Agent) server into Chio
as a governed tool server. It is an untrusted edge component: it speaks A2A
JSON-RPC or HTTP+JSON to a remote, potentially adversarial agent on one side,
and the Chio `ToolServerConnection` contract to the kernel on the other, so
the kernel mediates and issues signed receipts for every wrapped call. The
crate consumes an external agent; the opposite direction, serving Chio tools
out as A2A skills, is `chio-a2a-edge`. Task-lifecycle correlation (`GetTask`,
`SubscribeToTask`, `CancelTask`, push-notification config) is treated as a
security boundary: a durable, file-backed registry binds each observed task
id to the tool, server, interface, binding, tenant, and partner that first
saw it, and denies any later follow-up that disagrees.

## Module map

All files below except `loaded_weights.rs` are `include!`d from `lib.rs` into
the crate-root scope rather than declared as `mod`, so their public items
resolve as `chio_a2a_adapter::*` directly (for example
`chio_a2a_adapter::A2aAdapterConfig`, not a per-file path). `fuzz.rs` is the
one included file that declares its own nested `pub mod fuzz`.

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root: shared constants, `pub mod loaded_weights`, and `include!`s of the files below into the crate-root scope. |
| `src/config.rs` | `A2aAdapterConfig` builder: agent-card URL and manifest public key, request auth (bearer/basic/header/query/cookie), OAuth client credentials and scopes, TLS root CAs and mutual-TLS identity, timeout, server id/version, partner policy, task-registry path, egress contract. Validates auth material before discovery. |
| `src/partner_policy.rs` | `A2aPartnerPolicy` builder: required tenant, required skills, required security-scheme names, allowed interface origins. |
| `src/protocol.rs` | Local serde model for A2A Agent Cards, skills, interfaces, JSON-RPC envelopes, and `SendMessage`/`GetTask`/`CancelTask`/push-notification-config requests and responses. |
| `src/invoke.rs` | `A2aAdapter`: `discover`, per-skill request-auth resolution (security-scheme negotiation, OAuth/OpenID token acquisition and caching), `SendMessage`/`GetTask`/`CancelTask`/push-notification-config dispatch over JSON-RPC or HTTP+JSON, streaming dispatch, task-registry binding checks, and the `ToolServerConnection` impl. |
| `src/mapping.rs` | Tool-input parsing and mutual-exclusion rules (`A2aToolInvocation`); input-mode-to-`A2aSkillInputSurface` classification; `AdapterError`; `ToolManifest`/`ToolDefinition` projection from Agent Card skills; interface selection and partner-policy admission. |
| `src/discovery.rs` | Security-scheme and security-requirement parsing from the Agent Card; request-auth header/query/cookie lookup, dedup, and upsert; skill-routing metadata merge; `SendMessage`, task, and stream-event response validation; agent-card and task/push-notification-config URL construction. |
| `src/auth.rs` | HTTP dispatch: agent construction, TLS config (root CAs, mutual TLS, PEM parsing), egress-contract enforcement and manual redirect-chain validation, OAuth2 client-credentials token requests, and the `fetch_json`/`post_json`/`post_sse_json`/`post_form_json`/`get_sse`/`delete_empty` request helpers. |
| `src/transport.rs` | SSE stream parsing and framing limits (per-line, per-event, total-response, chunk-count); request header/cookie/query application and redirect-origin checks; egress-contract response-size enforcement; `ureq` error-to-`AdapterError` mapping. |
| `src/task_registry.rs` | `A2aTaskRegistry`: durable JSON file-backed task-binding store, `validate_follow_up` binding checks, and classified record/rebind-conflict handling. |
| `src/loaded_weights.rs` | `LoadedWeights` impl for `A2aAdapter` reporting model bytes unavailable. A true Rust submodule (`pub mod loaded_weights`), not `include!`d. |
| `src/fuzz.rs` | `fuzz::fuzz_a2a_envelope_decode`, the libFuzzer entry point exercising the SSE parser and JSON-RPC/HTTP+JSON envelope decode paths. Compiled only under the `fuzz` feature. |
| `src/tests.rs` (+ `src/tests/`) | `#[cfg(test)] mod tests`, including 7 files: support fixtures, protocol, discovery/registry, invoke/manifest, streaming lifecycle, auth, and end-to-end kernel-receipt tests. |

## Discovery and dispatch lifecycle

1. `A2aAdapterConfig` builds the agent-card URL, manifest public key, request
   auth, TLS material, timeout, an optional `A2aPartnerPolicy`, an optional
   task-registry file, and the `HttpEgressContract`.
2. `A2aAdapter::discover` validates the configured auth material and fetches
   the Agent Card (defaults to `/.well-known/agent-card.json` when the
   configured URL has no explicit `.json` path), rejecting a card with zero
   skills. `select_supported_interface` then scans interfaces for the first
   whose protocol version starts with `1.` and whose binding is `JSONRPC` or
   `HTTP+JSON` (non-matches are skipped); that interface's URL must be
   https, or http on localhost, or discovery fails outright, and only a
   partner-policy origin mismatch skips ahead to the next candidate.
3. Discovery projects every Chio-projectable skill into a `ToolDefinition`
   named after the skill id and validates the assembled `ToolManifest`.
   Because A2A's `SendMessage` is skill-agnostic, routing back to a specific
   skill flows through injected `metadata.chio.targetSkillId` /
   `targetSkillName` on the outbound request rather than a distinct RPC
   method.
4. The kernel drives the adapter through `ToolServerConnection::invoke` /
   `invoke_stream`. Each call parses the JSON tool input into an
   `A2aToolInvocation` (`SendMessage` or one of six mutually exclusive
   follow-up operations), resolves per-skill request auth against the Agent
   Card's declared security schemes, and dispatches over the selected
   binding.
5. Task-bearing follow-ups are checked against the task registry before
   dispatch; task-bearing responses (`task`, `statusUpdate`,
   `artifactUpdate`) are recorded into the registry after dispatch.
   Streaming calls parse the upstream SSE body chunk by chunk and record
   every task-bearing chunk through the same registry path as blocking
   calls.

## Invariants and failure modes

- Configured auth material (headers, query params, cookies, OAuth
  credentials, bearer/basic tokens) is validated at config-build or discover
  time: empty, padded, control-character-bearing, or (for cookies)
  `;`-bearing values are rejected before any request is built.
- Discovery fails closed on zero advertised skills (`NoSkillsAdvertised`) and
  on skills with no Chio-projectable input mode
  (`NoProjectableSkillsAdvertised`). `A2aSkillInputSurface::from_modes` strips
  MIME parameters before matching only `text`/`text/plain` and
  `json`/`application/json` essences; every other media type is
  non-projectable.
- Every outbound HTTP dispatch requires an `HttpEgressContract`; a missing
  contract fails closed before a request is sent. Redirects are followed
  manually (`redirects(0)` on the `ureq` agent) so every hop is validated
  against the contract; cross-origin redirects strip `Authorization`,
  `Cookie`, and `Proxy-Authorization`, and are rejected outright for
  body-bearing (non-GET) requests.
- `SendMessage` responses must contain exactly one of `task` or `message`;
  stream events must contain exactly one of `task`, `message`,
  `statusUpdate`, or `artifactUpdate`; task and status-update payloads must
  carry non-empty `id`/`taskId` and `status.state`.
- The task registry is a trust boundary, not a cache: `validate_follow_up`
  denies an operation whose recorded tool, server id, interface URL,
  protocol binding, tenant, or partner differs from the current adapter, and
  a rebind conflict on write is reported without widening the existing
  binding.
- SSE parsing enforces per-line (16 KiB), per-event (256 KiB), total-response
  (1 MiB, further capped by the egress contract), and per-stream chunk-count
  (1024) ceilings before a chunk reaches the kernel.
- Generated tool input schemas are closed (`additionalProperties: false`) at
  the top level and inside every follow-up operation object; the
  corresponding Rust input structs use `#[serde(deny_unknown_fields)]`, so
  unknown fields fail parsing before a remote request is assembled.
- Every projected tool is marked `has_side_effects: true` with
  `LatencyHint::Moderate` (the A2A Agent Card schema carries no per-skill
  safety or latency hints to preserve), and `invoke`'s `NestedFlowBridge`
  parameter is accepted but unused: this crate does not bridge nested Chio
  flows through the wrapped call.

## Dependencies

Internal: `chio-kernel` supplies `ToolServerConnection`, `NestedFlowBridge`,
`KernelError`, and the streaming result/chunk types the adapter implements
against. `chio-manifest` supplies `ToolManifest`, `ToolDefinition`,
`LatencyHint`, and `validate_manifest`. `chio-egress-contract` supplies
`HttpEgressContract`, enforced on every outbound call. The `chio-core`
dependency is aliased to `chio-core-types` (`sha256_hex` for deriving server
ids, `LoadedWeights`/`LoadedWeightsUnavailable`, and `crypto::Keypair` in
tests).

External: `ureq` (with its `rustls` backend) is the blocking HTTP client;
`rustls-pemfile` and `webpki-roots` parse PEM material and seed TLS root
stores for mutual TLS; `base64` encodes HTTP Basic and OAuth
client-credential headers; `url` parses and rewrites request URLs;
`async-trait` provides the `ToolServerConnection` trait's async methods;
`thiserror` derives `AdapterError`. Dev-only: `tokio` (async tests), `rcgen`
(test TLS certificates).
