# chio-ag-ui-proxy architecture

## Overview

The proxy is an edge component called directly by an embedding runtime, not
through the Chio kernel's tool-server contract: `AgUiProxy::evaluate` is a
synchronous, in-process call over a caller-supplied `AgUiEvent` and
`Transport`, with no async runtime and no SSE or WebSocket implementation of
its own; `Transport` only tracks per-connection identity and forwarded/blocked
counts. It performs full capability verification through
`verify_capability_full`, the same entry point chio-kernel-core reserves for
production kernels, and signs its own receipts with a keypair supplied at
construction. Capability grants authorize AG-UI actions through Chio's
ordinary scope-grant model, mapping each event classification to a tool name
on a synthetic `ag-ui` server id rather than a bespoke AG-UI grant schema.
Receipts are observational only: `AgUiReceiptVerification::authorized` is
always `false`, and blocked events are receipted, not silently dropped.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public facade; re-exports the event, proxy, receipt, and transport modules' key types. |
| `src/event.rs` | `AgUiEvent`, `EventType`, `EventClassification`, `TargetComponent`, and `validate_boundary` (event identity checks). |
| `src/proxy.rs` | Declares the `proxy` submodules, re-exports their public types, and owns `AG_UI_SERVER_ID`. Its `#[cfg(test)]` block is a large integration suite covering capability trust, delegation, sibling-budget, and payload-spoofing scenarios. |
| `src/proxy/core.rs` | `AgUiProxy`: `evaluate`, capability decision, budget admission, receipt construction. |
| `src/proxy/config.rs` | `AgUiProxyConfig`, `ParentBudgetSnapshot`, `AdmittedChildBudget`, and their defaults. |
| `src/proxy/decision.rs` | `ProxyDecision`, `AgUiProxyError`. |
| `src/proxy/classify.rs` | `derive_server_classification`: maps `EventType` (and, for `Lifecycle`, the payload's action) to `EventClassification`. |
| `src/proxy/helpers.rs` | Scope-argument construction, grant-to-event binding (`grant_binds_event`), capability error message mapping. |
| `src/proxy/budget.rs` | Builds and seeds an `InMemoryBudgetRegistry` from `ParentBudgetSnapshot`s. |
| `src/proxy/clock.rs` | `SystemClock`, a `chio_kernel_core::Clock` backed by `SystemTime`. |
| `src/receipt.rs` | `AgUiReceipt`, `AgUiReceiptBody`: signing, embedded-signature verification, `verify_with_trusted_kernel_keys`, payload hashing. |
| `src/transport.rs` | `Transport`, `TransportKind`: connection identity and forwarded/blocked counters. No network code. |

## Event evaluation

1. `AgUiProxy::evaluate` calls `event.validate_boundary()` first: `event_id`,
   `agent_id`, and any present `session_id`/`target.component_type`/
   `target.component_id` must be non-empty, unpadded, and free of control
   characters. Failure returns `AgUiProxyError::InvalidEvent` before
   classification, capability checks, transport counters, or receipt signing
   run.
2. `derive_server_classification` recomputes `EventClassification` from
   `event_type` (for `Lifecycle`, from the payload's `action`/`lifecycle`/
   `event` field). A mismatch against the caller-supplied classification, or
   an unclassifiable `EventType::Custom`, blocks immediately.
3. `decide` routes capability-bearing events to
   `decide_capability_bound_event`; capability-less events forward only if
   `allow_display_without_capability` is set and the classification is not in
   `restricted_classifications`.
4. `decide_capability_bound_event` rejects IDs in `revoked_capability_ids`,
   runs `verify_capability_full` with a `NoopBudgetRegistry` (budget
   admission is deferred), then matches scope grants with
   `resolve_capability_grants` and `grant_binds_event`. A matching, binding
   grant proceeds to `admit_capability_budget` against the proxy's persistent
   registry; a budget rejection blocks even a scope-valid capability.
5. `build_receipt` always runs, forward or block: it hashes the payload
   (`AgUiReceipt::hash_payload`, canonical JSON plus SHA-256), builds an
   `AgUiReceiptBody` (`id: "agui-{event_id}"`), and signs it with the proxy's
   keypair.
6. `transport.record_forwarded()` or `record_blocked()` updates the counters
   and a `tracing` event is logged.

## Invariants and failure modes

- Restricted classifications (`Mutate`, `Navigate`, `Create`, `Destroy`,
  `Submit` by default) always require a capability; `Display` requires one
  only when `allow_display_without_capability` is unset.
- `grant_binds_event` checks a matched grant's `Constraint::Custom` entries
  for `event_id`, `session_id`, `target_component_type`, and
  `target_component_id` against the event's own fields, not its payload, so a
  scope grant cannot be satisfied by spoofing those values inside the opaque
  JSON payload.
- Sibling-sum budget admission runs only after verification and scope
  matching succeed, against the proxy's persistent `InMemoryBudgetRegistry`;
  a denied event never consumes sibling budget.
- `AgUiProxy::new` falls back to an empty budget registry and logs a warning
  on an invalid `parent_budget_snapshots` config instead of failing
  construction; `try_new` rejects the same config immediately. Either way,
  delegated events still fail closed at the sibling-sum check.
- The crypto floor passed to `verify_capability_full` is hardcoded to
  `CapabilityCryptoFloor::AllowClassical` and is not exposed through
  `AgUiProxyConfig`, so a classical Ed25519 signature alone satisfies
  verification.
- `AgUiReceiptVerification::authorized` is always `false`; receipts record
  `receipt_kind: "trace_observation"` and `boundary_class: "detect_only"` and
  never themselves grant Chio authorization, allowed or not.

## Dependencies

Internal: `chio-core` (workspace dependency, not aliased) supplies capability,
crypto, and error types (`capability::{token, scope, attenuation,
crypto_floor, features}`, `crypto::{Keypair, PublicKey, Signature,
canonical_json_bytes, sha256_hex}`, `Error`). `chio-kernel-core` (path
dependency, `default-features = false`) supplies `verify_capability_full`,
`resolve_capability_grants`, `ScopeMatchError`, `CapabilityError`, `Clock`,
and the budget-registry family (`BudgetRegistry`, `InMemoryBudgetRegistry`,
`NoopBudgetRegistry`, `BudgetSplitError`, `MAX_BUDGET_SHARE_BPS`). Disabling
default features drops `chio-kernel-core`'s `revocation-view` feature, so this
crate carries no live revocation-oracle view; `AgUiProxyConfig`'s
`revoked_capability_ids` is how an embedder feeds revocation in instead.
External: `serde`/`serde_json` for wire types, `thiserror` for
`AgUiProxyError`, `tracing` for forward/block logging. No async runtime.
