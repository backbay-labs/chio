# chio-cross-protocol architecture

## Overview

`chio-cross-protocol` is a shared library crate, not an edge itself: no
transport, no server loop, no protocol wire format. It sits between the
outward protocol edges (A2A, ACP, MCP, OpenAI-shaped bridges) and
`chio-kernel`, giving them one orchestrator (`CrossProtocolOrchestrator`) and
one set of signed-lineage types so capability, scope, route, and trace are
computed the same way regardless of which edge originated the request.
Execution is synchronous: the orchestrator and every `TargetProtocolExecutor`
call the kernel's blocking evaluation entry point directly; edges on an async
runtime cross back in through `sync_bridge_shared::block_on_tool_server_invoke`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Declares the public modules. No root-level re-exports; callers import the owning module. |
| `src/capability_bridge.rs` | `CrossProtocolCapabilityRef`, `CrossProtocolCapabilityEnvelope`, trace types, the `CapabilityBridge` trait, and the parent-hash/scope-attenuation helpers the orchestrator uses. |
| `src/discovery.rs` | `DiscoveryProtocol` enum, its parser and `Display`, and `TargetProtocolRegistry` (executor lookup, default-target resolution). |
| `src/error.rs` | `BridgeError`, the crate's error type. |
| `src/execution.rs` | `CrossProtocolExecutionRequest`/`CrossProtocolTargetRequest`, the `TargetProtocolExecutor` trait, and the built-in `OpenAiTargetExecutor`. |
| `src/lifecycle.rs` | `RuntimeLifecycleSurface`/`RuntimeLifecycleContract`: entrypoint and delivery-mode metadata for claim-eligible vs. compatibility-only bridge surfaces. |
| `src/orchestrator.rs` | `CrossProtocolOrchestrator::execute`, deny-path signing, trace-context construction, and `OrchestratedToolCall` (including its receipt-metadata rendering). |
| `src/routing.rs` | Route-candidate evidence, `plan_authoritative_route`, and signed `RouteSelectionEvidence`. |
| `src/semantic_hints.rs` | `BridgeFidelity` and `BridgeSemanticHints`, derived from `x-chio-*` tool schema extensions. |
| `src/sync_bridge_shared.rs` | `block_on_tool_server_invoke`: shared synchronous-bridge shim for compatibility-surface edges, mirroring the kernel's runtime-flavor gate. |
| `src/validation.rs` | Private (`mod validation`, not `pub`). Request-identity validation and capability-ref cross-checks used by the orchestrator; schema-extension accessors used by `discovery` and `semantic_hints`. |
| `src/tests.rs` | `#[cfg(test)]` unit tests: mock `CapabilityBridge`/`TargetProtocolExecutor`/`ToolServerConnection`, orchestrator lineage checks, and route-planning behavior. |

## Bridged call lifecycle

`CrossProtocolOrchestrator::execute` runs one bridged call end to end:

1. `validate_execution_request_boundary` rejects empty, padded, or
   control-character identity fields before any lineage is built.
2. `CapabilityBridge::extract_capability_ref` reads an existing ref from the
   source envelope; if present, `validate_provided_capability_ref` checks it
   against the active capability's id, parent hash, and `source_protocol`. If
   absent, a fresh ref is built from the capability.
3. `CapabilityBridge::inject_capability_ref` projects the ref into a clone of
   the source envelope (`projected_request`).
4. `attenuate_scope_for_tool` narrows the parent capability's grants to the
   concrete target server/tool; the orchestrator rejects
   (`BridgeError::InvalidAttenuation`) if the result is not a subset of the
   parent scope.
5. `plan_authoritative_route` decides `Select`, `Attenuate`, or `Deny` from
   governed-intent control-plane hints and route availability.
6. On `Deny`, the kernel signs a deny response (`sign_planned_deny_response`);
   route and trace evidence are still built, so denied attempts get full
   signed lineage too.
7. On `Select`/`Attenuate`, a `Native` target dispatches straight to
   `ChioKernel::evaluate_tool_call_blocking_with_metadata`; any other target
   dispatches to the registered `TargetProtocolExecutor`.
8. Route/trace evidence assemble from the returned hops (trace id and session
   fingerprint are `sha256` over canonical JSON). `OrchestratedToolCall::metadata()`
   renders the final `chio.*` metadata object callers attach to their own
   protocol response.

## Invariants and failure modes

- Request-identity fields (`origin_request_id`, `kernel_request_id`,
  `target_server_id`, `target_tool_name`, `agent_id`) must be non-empty,
  unpadded, and control-character-free, and are not trimmed: signed lineage
  must describe exactly what the caller submitted.
- A caller-supplied capability ref is rejected if its `originProtocol` does
  not match the bridge's `source_protocol`, even with a valid id and parent
  hash.
- `plan_authoritative_route` never selects a non-`Native` target with no
  registered executor, even if marked available, and fails closed to `Deny`
  when no candidate route is available.
- Route-selection evidence and any caller-supplied `receipt_context` are
  threaded into the kernel call and land inside the signed receipt metadata,
  not just this crate's return type.
- `block_on_tool_server_invoke` fails closed with
  `SyncBridgeIncompatibleWithCurrentThreadRuntime` under a current-thread
  Tokio runtime rather than risking a deadlock; it uses `block_in_place` on a
  multi-thread runtime and `futures::executor::block_on` with none active.
- `#![forbid(unsafe_code)]` at the crate root.

## Dependencies

Internal: `chio-kernel` supplies `ChioKernel`, tool-call evaluation,
deny-signing, and kernel error types. The `chio-core` dependency is aliased
to `chio-core-types` (`chio-core = { package = "chio-core-types", ... }`) and
supplies `CapabilityToken`, `ChioScope`, governance types, canonical JSON,
and `sha256_hex`. `chio-manifest` supplies `ToolDefinition` and
`LatencyHint` for target-protocol and semantic-hint resolution.

External: `serde`/`serde_json` for every wire type, `thiserror` for
`BridgeError`, `tokio` and `futures` for the runtime-flavor detection and
non-Tokio fallback in `sync_bridge_shared`. `async-trait` is a declared
dependency but is exercised only by the crate's own `#[cfg(test)]` mock
`ToolServerConnection`; the crate's own traits (`CapabilityBridge`,
`TargetProtocolExecutor`) are synchronous.

## Extension points

- `CapabilityBridge` - implement to extract/inject a
  `CrossProtocolCapabilityRef` and protocol context for a new source
  protocol's request-envelope shape.
- `TargetProtocolExecutor` - implement and register with
  `TargetProtocolRegistry` / `CrossProtocolOrchestrator::with_executor` to
  add a non-native bridge target beyond the built-in `OpenAiTargetExecutor`.
