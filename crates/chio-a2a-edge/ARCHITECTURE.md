# chio-a2a-edge Architecture Note

## Current Boundaries

- `lib.rs` is the public facade. It exposes the A2A edge types and includes focused source fragments into one crate-root module.
- `config.rs` owns the advertised Agent Card settings: agent identity, endpoint URL, and protocol binding.
- `types.rs` owns the public A2A wire structs and the kernel execution context required for authoritative calls.
- `bridge.rs` owns cross-protocol bridge selection, target executor registration, bridge fidelity, skill candidate construction, and orchestration.
- `conversion.rs` owns A2A message-to-argument extraction, kernel output projection, and Chio metadata envelope construction.
- `edge.rs` owns the server object, skill publication, JSON-RPC dispatch, compatibility wrapper, and deferred task lifecycle.
- `metrics.rs` and `otel.rs` own edge-specific receipt metrics and optional GenAI span helpers.

## Pain Points

- `edge.rs` still owns multiple trust-boundary responsibilities: manifest-to-skill publication, JSON-RPC dispatch, target-skill routing, kernel execution, and deferred task lifecycle.
- JSON-RPC request-boundary parsing now lives in `jsonrpc.rs`, including
  non-empty and unpadded `metadata.chio.targetSkillId` and `params.taskId`
  checks before skill resolution or task lookup.
- `ChioA2aEdge::new` now validates every manifest with
  `chio_manifest::validate_manifest` before Agent Card skill publication,
  bridge-fidelity classification, or authoritative skill binding construction.
- `jsonrpc.rs` now owns a centralized known-method params-object gate used by
  both authoritative and compatibility dispatch. Missing params remain
  compatible as `{}`, unknown methods still return method-not-found, and
  non-object params for known A2A methods fail with `-32602` before message
  parsing, task lookup, or deferred lifecycle mutation can observe malformed
  params.

## Security And API Constraints

- Public API compatibility must be preserved. Public request and response structs should not change.
- Authoritative calls must continue to route through `CrossProtocolOrchestrator` and the Chio kernel.
- Compatibility-surface helpers must remain visibly non-authoritative and feature-gated.
- Deferred task ownership must stay bound to the authenticated `agent_id`.
- Receipt metadata, capability ids, bridge route metadata, and lifecycle metadata must remain stable.
- No generated code is in scope.

## Affected Dependents

- `chio-kernel` sees this crate through kernel-mediated tool execution. No kernel API change is planned.
- `chio-cross-protocol` provides bridge and lifecycle metadata contracts. This slice should preserve those values.
- `chio-mcp-edge` remains a target executor dependency for multi-hop routes. No transitive change is planned.
- Downstream A2A clients may see construction-time manifest errors earlier. Successful Agent Card, JSON-RPC, task lifecycle, and response shapes stay compatible.

## Completed Baseline

Validate every `ToolManifest` with `chio_manifest::validate_manifest` before Agent Card skill publication, bridge-fidelity classification, or authoritative skill binding construction. This is architectural rather than cosmetic because it makes manifest validation the single envelope gate before external A2A discovery and keeps the existing JSON-RPC parser focused on request-boundary inputs.

## Completed Material Improvement

Added a centralized known-method params-object gate for the authoritative and
compatibility JSON-RPC dispatch paths. Missing params remain compatible as `{}`,
unknown methods still return method-not-found, and non-object params for known
A2A methods fail with `-32602` before message parsing, task lookup, or deferred
lifecycle mutation can observe malformed params.

## Deferred Terminal Task Retention Slice

### Current Boundary

- `edge.rs` owns the authoritative `message/stream`, `task/get`, and
  `task/cancel` lifecycle.
- `conversion.rs` owns terminal `TaskResponse` construction and receipt-bearing
  metadata projection.
- `bridge.rs` owns the bounded deferred-task cap and TTL constants.

### Pain Point

The A2A bridge contract says `task/get` executes a working deferred task once
and then persists the terminal result. The current edge updates the stored
response after execution but immediately removes the task record. It also
removes cancelled tasks after returning the cancellation response. That makes a
follow-up `task/get` or idempotent `task/cancel` see `tool not found` instead
of the already-produced terminal task response, and it loses the owner-bound
task state that proves the terminal receipt or cancellation belonged to the
same caller.

Terminal retention also has to count against the deferred task cap. Otherwise
callers can repeatedly create streams, resolve or cancel them, and retain
terminal entries until TTL expiry without consuming pending-task capacity.

### Security And API Constraints

- Preserve public API and wire structs.
- Preserve owner binding for all task states.
- Do not re-execute the kernel-backed deferred request after the first
  successful `task/get`.
- Keep task retention bounded by the existing TTL and deferred-task cap.
- Preserve signed receipt metadata on completed or failed terminal responses
  and cancellation metadata on cancelled responses.

### Affected Dependents

- A2A clients can now repeat `task/get` after completion and receive the same
  terminal response until TTL expiry instead of `tool not found`.
- `task/cancel` remains able to cancel only working tasks; repeated cancel for
  an already cancelled task returns the retained cancelled response.
- `chio-kernel`, `chio-cross-protocol`, and `chio-mcp-edge` APIs are unchanged.

### Completed Material Improvement

Retain terminal deferred-task responses in the internal task map until the
existing TTL expires, while preserving owner checks and bounded capacity.
Update lifecycle tests to prove completed tasks are not re-executed or removed
on the first `task/get`, cancelled tasks remain visible for idempotent
follow-up, and the deferred-task cap applies to all retained task records after
TTL pruning.

## Agent Card Config Validation Slice

### Current Boundary

- `config.rs` defines the public `A2aEdgeConfig` fields that become Agent Card
  identity and interface metadata.
- `edge.rs` owns `ChioA2aEdge::new`, which is the last gate before tool
  manifests are converted into externally discoverable A2A skills.
- `agent_card` publishes config fields without further normalization or
  validation.

### Pain Point

The bridge spec requires at least the advertised Agent Card name to be
non-empty, and the interface entry must be usable by clients. Today callers can
construct an edge with blank identity fields, blank endpoint URLs, or blank
protocol bindings, and those values are published directly in discovery
metadata. That lets malformed operator configuration escape as a valid-looking
A2A Agent Card before any request-boundary or kernel guard can reject it.

### Security And API Constraints

- Preserve `A2aEdgeConfig` as a public struct and preserve `ChioA2aEdge::new`
  as the constructor.
- Fail closed at construction with `A2aEdgeError::InvalidRequest`.
- Do not trim and silently rewrite operator-provided public metadata.
- Keep successful default config and existing Agent Card JSON shape stable.
- No dependent crate API change is planned.

### Affected Dependents

- Downstream A2A clients no longer see malformed Agent Cards from blank edge
  config.
- Existing callers with valid config are unchanged.

### Completed Material Improvement

Add a config publication gate in the owning crate that rejects blank Agent Card
identity and interface fields before manifest validation, skill publication, or
JSON-RPC dispatch can occur. Add focused constructor tests for each rejected
field and a stability test proving valid default Agent Card fields are still
published unchanged.

## Agent Card Config Padding Follow-up

### Current Boundary

- `config.rs` owns the public `A2aEdgeConfig` fields that are published into the
  Agent Card.
- `ChioA2aEdge::new` calls `validate_for_agent_card` before any Agent Card is
  exposed.
- `agent_card` publishes config bytes without trimming or normalization.

### Pain Point

The constructor rejects blank endpoint URLs and protocol bindings but accepts
non-empty values with leading or trailing whitespace. Those raw values are then
published into Agent Cards that downstream clients cannot reliably parse or
match.

### Security And API Constraints

- Preserve public config fields and successful default Agent Card output.
- Fail closed at construction with `A2aEdgeError::InvalidRequest`.
- Do not trim and silently rewrite operator-provided metadata.
- Keep existing blank-field error messages stable.

### Affected Dependents

- Existing callers with exact, valid config are unchanged.
- Padded Agent Card config now fails before discovery publication.

### Planned Material Improvement

Extend the Agent Card config validator to reject leading or trailing whitespace
for non-empty fields and add focused constructor regressions for padded endpoint
URLs and protocol bindings.

## JSON-RPC Identifier Shape Slice

### Current Boundary

- `jsonrpc.rs` owns `metadata.chio.targetSkillId` extraction before A2A
  send/stream requests reach skill resolution.
- `jsonrpc.rs` owns `params.taskId` extraction before `task/get` and
  `task/cancel` reach deferred-task lookup or owner checks.

### Pain Point

The request-boundary checks reject all-whitespace identifiers, but padded
non-empty identifiers currently keep their original bytes. Values such as
`" echo "` and `" task-1 "` can flow into exact skill and task map lookups,
which returns misleading tool-not-found or ownership errors instead of a
JSON-RPC invalid-params response at the boundary.

### Security And API Constraints

- Preserve public request/response structs and successful identifier bytes.
- Do not silently trim or rewrite identifiers.
- Reject malformed identifiers before skill resolution, task lookup, owner
  checks, lifecycle mutation, or kernel dispatch.
- Keep all-whitespace identifier error messages stable.

### Affected Dependents

- A2A clients that send padded identifiers now receive `-32602` invalid-params
  errors instead of downstream lookup errors.
- Clients that send exact identifiers are unchanged.

### Completed Material Improvement

Extend the JSON-RPC identifier parser so `metadata.chio.targetSkillId` and
`params.taskId` reject leading or trailing whitespace after the existing
non-empty checks. Add tests proving padded target-skill ids and task ids fail
closed before lookup.

## Data Part Argument Shape Slice

### Current Boundary

- `types.rs` models A2A message parts, including structured `data` parts, as
  protocol-facing wire values.
- `conversion.rs` owns extraction of A2A message parts into Chio tool
  arguments before authoritative kernel dispatch or compatibility passthrough.
- `bridge.rs` and `edge.rs` assume the extracted value is the target tool
  argument payload carried into `CrossProtocolExecutionRequest`.

### Pain Point

The edge publishes Chio tools with object-shaped input schemas, and the bridge
spec describes an A2A `data` part as the arguments object. Runtime extraction
currently accepts any JSON value as a data part, including scalars and arrays,
and forwards it as tool arguments. That lets malformed A2A data reach kernel
dispatch or compatibility passthrough before the edge request boundary rejects
it.

### Security And API Constraints

- Preserve public wire structs and valid text-message behavior.
- Preserve valid object-shaped `data` part behavior.
- Preserve the existing one-data-part maximum and text-plus-data precedence.
- Fail closed before kernel dispatch, receipt construction, deferred task
  creation, or compatibility passthrough when a data part is not an object.

### Affected Dependents

- Downstream A2A clients that send object-shaped arguments are unchanged.
- Clients that send scalar or array data parts now receive
  `A2aEdgeError::InvalidRequest` through the existing JSON-RPC `-32602`
  mapping.
- `chio-kernel`, `chio-cross-protocol`, and `chio-mcp-edge` APIs are
  unchanged.

### Completed Material Improvement

Made the message-to-arguments boundary reject non-object data parts and added
focused regressions proving scalar and array data fail before dispatch.

## Execution Context Agent Identity Slice

### Current Boundary

- `types.rs` exposes `A2aKernelExecutionContext`, including the authenticated
  caller `agent_id` used for kernel execution and deferred-task ownership.
- `edge.rs` copies `execution.agent_id` into `CrossProtocolExecutionRequest`
  and into retained `DeferredA2aTask.owner_agent_id`.
- `chio-cross-protocol` rejects all-whitespace `agent_id` values at
  orchestration time, but `message/stream` can retain a task before
  orchestration, and padded values can still become owner keys.

### Pain Point

The edge treats `agent_id` as already authenticated caller metadata but does
not validate its shape before dispatch or task retention. Blank IDs depend on a
downstream cross-protocol error on blocking sends, while padded IDs can be
stored as distinct task owners in the deferred lifecycle and later produce
misleading ownership errors.

### Security And API Constraints

- Preserve `A2aKernelExecutionContext` as a public struct.
- Reject malformed execution context before skill resolution, kernel dispatch,
  deferred task allocation, owner checks, or lifecycle mutation.
- Do not trim or normalize the authenticated identifier.
- Preserve successful exact agent-id behavior and existing task ownership
  semantics.
- No dependent crate API change is planned.

### Affected Dependents

- Callers with exact authenticated agent ids are unchanged.
- Callers that pass blank, padded, or control-bearing execution agent ids now
  receive `A2aEdgeError::InvalidRequest` through direct APIs or JSON-RPC
  `-32602` before side effects.

### Completed Material Improvement

Add an A2A edge execution-context validator and call it from blocking send,
deferred stream creation, deferred task resolution, cancellation, and test-only
pending projection. Add focused regressions proving malformed agent ids fail
closed before dispatch or task retention.
