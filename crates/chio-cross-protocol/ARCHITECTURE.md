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

## Pain Points

The orchestrator builds signed receipt metadata from request identity fields
and caller-provided capability references before enforcing a local lineage
boundary. Empty `origin_request_id`, `kernel_request_id`, `target_server_id`,
`target_tool_name`, or `agent_id` values can flow into bridge ids, route
selection ids, trace contexts, and kernel requests. A source envelope can also
provide a `capabilityRef` whose `chioCapabilityId` matches the active
capability but whose `parentCapabilityHash` does not match the actual
capability lineage.

## Security and API Constraints

The orchestrator must fail closed before signing or forwarding misleading
lineage. Route selection evidence, trace ids, receipt metadata, and capability
envelope fields must remain canonical and byte-stable for valid requests.
Public type names, trait methods, and struct fields should remain
source-compatible. Native and registered target execution must continue to
route through the kernel as before.

## Affected Dependents

No transitive crate edits are expected. Edge crates using
`CrossProtocolOrchestrator`, `CapabilityBridge`, `TargetProtocolExecutor`, and
`CrossProtocolExecutionRequest` keep the same API. Malformed requests change
from kernel/routing behavior to `BridgeError::InvalidRequest` at the shared
orchestrator boundary.

## Completed Boundary Validation Baseline

Added an orchestrator-owned execution boundary validation step before capability
reference injection, route planning, trace construction, or kernel execution.
Required non-empty request identity fields and verified any supplied
`CrossProtocolCapabilityRef` against both the active capability id and the
deterministic parent capability hash. This turns lineage data from trusted
caller metadata into a checked shared invariant.

## Source Protocol Continuity Slice

### Current Boundary

- `CapabilityBridge::source_protocol` is the authoritative protocol family for
  the inbound edge executing through the shared orchestrator.
- `CrossProtocolCapabilityRef::origin_protocol` is deserialized from inbound
  request metadata when a protocol edge supplies a prior bridge reference.
- `OrchestratedToolCall::metadata` signs both `sourceProtocol` and the
  accepted `capabilityRef` into bridge metadata.

### Pain Point

The existing capability-reference validation checks the active capability id
and deterministic parent capability hash, but it does not check that a
supplied `capabilityRef.originProtocol` matches the actual
`CapabilityBridge::source_protocol`. A request entering through A2A can
therefore carry an ACP-origin capability reference whose id and parent hash are
otherwise valid. That creates contradictory signed bridge metadata and weakens
receipt lineage even though the orchestrator knows the real inbound protocol.

### Security And API Constraints

- Preserve public structs, trait methods, serialized field names, and valid
  receipt metadata bytes for correctly labeled inbound requests.
- Reject source-protocol drift before capability reference injection, route
  planning, trace construction, target execution, or receipt signing.
- Keep existing capability-id and parent-hash mismatch errors stable.
- Do not trust protocol-edge metadata when it disagrees with the bridge object
  selected by the caller.

### Affected Dependents

- `chio-a2a-edge`, `chio-acp-edge`, and `chio-acp-proxy` keep the same public
  API and valid request behavior.
- Malformed bridged requests with a valid capability id/hash but drifted
  `originProtocol` now fail closed with `BridgeError::InvalidRequest` at the
  shared orchestrator boundary.

### Completed Material Improvement

Extended the orchestrator-owned capability-reference validation so supplied
`CrossProtocolCapabilityRef` values must match the active bridge source
protocol as well as the capability id and parent hash, with a focused
regression proving mismatched source-protocol metadata fails before signed
lineage construction.

## Execution Identity Normalization Slice

### Current Boundary

- `CrossProtocolExecutionRequest` identity fields feed bridge ids, route
  selection ids, trace ids, receipt metadata, and kernel-bound
  `ToolCallRequest` values.
- `origin_request_id` becomes the source hop id and bridge id suffix.
- `kernel_request_id`, `target_server_id`, `target_tool_name`, and `agent_id`
  cross from protocol edges into native kernel execution.

### Pain Point

The boundary validation rejects whitespace-only identity fields, but it does
not reject padded or control-bearing values. A malformed protocol edge request
can therefore create signed bridge metadata, route evidence, trace hops, or
kernel requests with ambiguous identifiers even though the orchestrator is the
shared authority for this cross-protocol hop.

### Security And API Constraints

- Preserve valid request behavior, public struct fields, and serialized field
  names.
- Keep the existing empty-field error stable for whitespace-only values.
- Reject padded or control-bearing request identity values before capability
  reference injection, route planning, trace construction, target execution, or
  receipt signing.
- Do not normalize by trimming because signed lineage should describe exactly
  what the caller submitted.

### Affected Dependents

`chio-a2a-edge`, `chio-acp-edge`, `chio-acp-proxy`, `chio-mcp-edge`, and other
orchestrator callers keep the same API. Valid requests are byte-stable.
Malformed requests now fail at the shared orchestrator boundary instead of
reaching route planning or kernel execution.

### Completed Material Improvement

Replaced non-empty-only request field checks with orchestrator-owned identity
validation that requires non-empty, unpadded, control-free execution identity
fields, with a regression proving padded and control-bearing values fail before
signed lineage construction.

## Verification Focus

Tests should cover identity-field rejection before route planning, capability
id and parent-hash mismatch rejection, source-protocol drift rejection,
metadata byte stability for valid bridge requests, and kernel handoff parity
for native and registered executors. Edge-crate smoke tests should continue to
prove that A2A, ACP, MCP, and OpenAPI callers inherit the shared orchestrator
boundary without reimplementing lineage validation.
