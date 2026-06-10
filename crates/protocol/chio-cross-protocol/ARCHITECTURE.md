# chio-cross-protocol Architecture Notes

## Module Boundaries

`lib.rs` declares the public cross-protocol modules and does not flatten their
APIs at the crate root.

- `discovery.rs`: target protocol enum, parser, display implementation, schema
  target-protocol lookup, and `TargetProtocolRegistry`.
- `lifecycle.rs`: runtime lifecycle surfaces and metadata contracts.
- `semantic_hints.rs`: bridge fidelity and tool semantic-hint extraction.
- `routing.rs`: route availability, candidate evidence, route-selection
  evidence, planner decisions, and route metadata.
- `execution.rs`: kernel-bound execution request, target request/response
  handoff, target executor trait, and OpenAI-shaped target executor.
- `capability_bridge.rs`: capability references, capability envelopes, protocol
  trace data, bridge trait, and attenuation/hash helpers.
- `orchestrator.rs`: shared orchestration runtime and signed metadata assembly.
- `validation.rs`: request-boundary validation and schema extension helpers.
- `error.rs`: cross-protocol bridge error type.

The crate is intentionally a shared substrate for protocol edge crates rather
than a product surface. Callers import the owning module for each domain instead
of relying on root-level aliases.

## Orchestrator Boundary Validation

The orchestrator builds signed receipt metadata from request identity fields and
caller-provided capability references. An orchestrator-owned validation step runs
before capability reference injection, route planning, trace construction,
target execution, or receipt signing, turning lineage data from trusted caller
metadata into a checked shared invariant:

- `origin_request_id`, `kernel_request_id`, `target_server_id`,
  `target_tool_name`, and `agent_id` must be non-empty, unpadded, and
  control-free. Values are not trimmed, because signed lineage must describe
  exactly what the caller submitted. `origin_request_id` becomes the source hop
  id and bridge id suffix; the others cross from protocol edges into native
  kernel execution.
- A supplied `CrossProtocolCapabilityRef` must match the active capability id,
  the deterministic parent capability hash, and the `CapabilityBridge`
  `source_protocol`. A request entering through one protocol cannot carry a
  capability reference whose `originProtocol` belongs to another, even when its
  id and parent hash are otherwise valid; protocol-edge metadata is not trusted
  when it disagrees with the bridge object the caller selected.

Malformed requests fail closed with `BridgeError::InvalidRequest` at the shared
orchestrator boundary rather than reaching route planning or kernel execution.

## Security and API Constraints

The orchestrator fails closed before signing or forwarding misleading lineage.
Route selection evidence, trace ids, receipt metadata, and capability envelope
fields stay canonical and byte-stable for valid requests. Public type names,
trait methods, struct fields, and serialized field names stay source-compatible.
Native and registered target execution continues to route through the kernel.

## Affected Dependents

No transitive crate edits are expected. `chio-a2a-edge`, `chio-acp-edge`,
`chio-acp-proxy`, `chio-mcp-edge`, and other crates using
`CrossProtocolOrchestrator`, `CapabilityBridge`, `TargetProtocolExecutor`, and
`CrossProtocolExecutionRequest` keep the same API. Malformed requests change
from kernel/routing behavior to `BridgeError::InvalidRequest`.

## Verification Focus

Tests cover identity-field rejection before route planning, capability id and
parent-hash mismatch rejection, source-protocol drift rejection, metadata byte
stability for valid bridge requests, and kernel handoff parity for native and
registered executors. Edge-crate smoke tests prove that A2A, ACP, MCP, and
OpenAPI callers inherit the shared orchestrator boundary without reimplementing
lineage validation.
