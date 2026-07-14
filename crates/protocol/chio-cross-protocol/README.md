# chio-cross-protocol

Shared substrate for Chio's outward protocol edges (A2A, ACP, MCP, and
OpenAI-shaped bridges). It owns one definition of cross-protocol capability
lineage, scope attenuation, route selection, and receipt tracing, run through
one orchestrator, so edge crates do not reimplement that logic against
`chio-kernel` independently. Edge crates plug in a `CapabilityBridge` for
their envelope shape and, for non-native targets, a `TargetProtocolExecutor`;
this crate holds no transport and speaks no protocol wire format itself.

## Responsibilities

- Define `discovery::DiscoveryProtocol`, the protocol-family enum (`Native`,
  `Http`, `Mcp`, `A2a`, `Acp`, `OpenAi`) read from `x-chio-target-protocol`
  schema extensions, plus the `TargetProtocolRegistry` that resolves a tool's
  target against registered executors.
- Build and validate signed capability lineage across a protocol hop
  (`CrossProtocolCapabilityRef`, `CrossProtocolCapabilityEnvelope`) and
  attenuate a parent capability's scope to the concrete target server/tool.
- Run the shared orchestration path, `CrossProtocolOrchestrator::execute`:
  validate request identity, resolve a capability reference via the caller's
  `CapabilityBridge`, plan a route, and dispatch to `chio-kernel` or a
  registered `TargetProtocolExecutor`.
- Plan and sign route selection (`routing::plan_authoritative_route`) from
  governed-intent control-plane hints and per-protocol route availability.
- Declare the lifecycle contract that claim-eligible and compatibility-only
  A2A/ACP surfaces publish, and derive publication fidelity and semantic
  hints from `x-chio-*` tool schema extensions.
- Provide `sync_bridge_shared::block_on_tool_server_invoke`, a synchronous
  bridge shim shared by compatibility-surface edges that fails closed under a
  current-thread Tokio runtime instead of deadlocking.

## Public API

- `capability_bridge::{CapabilityBridge, CrossProtocolCapabilityRef,
  CrossProtocolCapabilityEnvelope}` - capability-lineage trait and the signed
  types it produces.
- `discovery::{DiscoveryProtocol, TargetProtocolRegistry,
  target_protocol_for_tool}` - protocol-family enum and its executor
  registry.
- `orchestrator::{CrossProtocolOrchestrator, OrchestratedToolCall}` - the
  shared `execute` entry point and its signed result/metadata.
- `execution::{TargetProtocolExecutor, CrossProtocolExecutionRequest,
  OpenAiTargetExecutor}` - the pluggable executor trait and the built-in
  OpenAI-shaped executor.
- `routing::{plan_authoritative_route, RouteSelectionEvidence,
  RouteAvailabilityStatus}` - route planning and its signed evidence.
- `lifecycle::{RuntimeLifecycleSurface, RuntimeLifecycleContract,
  runtime_lifecycle_contract}` - claim-eligible vs. compatibility-only
  lifecycle contracts.
- `semantic_hints::{BridgeFidelity, BridgeSemanticHints,
  semantic_hints_for_tool}` - publication fidelity and semantic-hint
  derivation from tool schemas.
- `sync_bridge_shared::block_on_tool_server_invoke` - shared sync-bridge shim
  for compatibility-surface edges.
- `error::BridgeError` - the crate's error type.

## Testing

`cargo test -p chio-cross-protocol`

## See also

- `chio-kernel` - supplies `ChioKernel`, tool-call evaluation, deny-signing,
  and receipt issuance that the orchestrator drives.
- `chio-core-types` (depended on here under the `chio-core` name) - supplies
  `CapabilityToken`, `ChioScope`, governance types, and canonical
  JSON/hashing used for capability lineage.
- `chio-manifest` - supplies `ToolDefinition` used for target-protocol and
  semantic-hint resolution.
- `chio-a2a-edge`, `chio-acp-edge`, `chio-acp-proxy`, `chio-mcp-edge`,
  `chio-openai-adapter`, `chio-http-core` - consume this crate's orchestrator
  and shared types.
