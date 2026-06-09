# chio-acp-edge Architecture Note

## Current Boundaries

- `lib.rs` is the public facade. It exposes ACP edge types and includes focused source fragments into one crate-root module.
- `config.rs` owns permission defaults and the fallback ACP category for discovered tools.
- `types.rs` owns public ACP capability, permission, invocation, deferred-task, and kernel execution-context structs.
- `bridge.rs` owns cross-protocol bridge selection, ACP category inference, bridge fidelity, target bindings, deferred-task limits, and orchestration.
- `conversion.rs` owns kernel-output projection, ACP source envelopes, surface metadata, lifecycle metadata, and permission-preview metadata.
- `edge.rs` owns the server object, capability publication, JSON-RPC dispatch, permission preview, invocation, compatibility wrapper, and deferred task lifecycle.
- `fuzz.rs` owns the optional fuzz-only JSON-RPC decode pipeline behind the `fuzz` feature.

## Pain Points

- `edge.rs` still owns multiple trust-boundary responsibilities: manifest-to-capability publication, JSON-RPC dispatch, permission preview, kernel execution, and deferred task lifecycle.
- Kernel-backed ACP permission preview now uses the kernel-owned stateless DPoP verifier, so preview and invoke agree on installed DPoP TTL, skew, and store/config presence without consuming the nonce.
- `ChioAcpEdge::new` now validates every manifest with
  `chio_manifest::validate_manifest` before ACP capability publication,
  bridge-fidelity classification, or authoritative capability binding
  construction.
- The remaining request-boundary gap is JSON-RPC params shape. The envelope
  parser defaults missing params to `{}`, but non-object params are preserved.
  Known ACP methods then fall through into method-specific parsers or no-params
  responses, producing deeper errors or successful responses instead of
  rejecting malformed request params at the JSON-RPC boundary.

## Security And API Constraints

- Public Rust structs and method signatures must remain compatible.
- Authoritative invocation must continue through `CrossProtocolOrchestrator` and the Chio kernel.
- Permission preview remains preview-only, must not imply receipt-bearing execution, and must not consume the DPoP nonce that invoke will later spend.
- Compatibility-surface helpers must remain visibly non-authoritative and feature-gated.
- Deferred task ownership must stay bound to the authenticated `agent_id`.
- Receipt metadata, bridge route metadata, and lifecycle metadata must remain stable for valid requests.
- The `fuzz` feature must keep exercising the JSON-RPC handler without pulling fuzz dependencies into default builds.

## Affected Dependents

- `chio-kernel` remains the execution authority and DPoP preview verifier.
- `chio-cross-protocol` supplies bridge and lifecycle metadata. This slice should preserve those contracts.
- `chio-mcp-edge` remains a target executor dependency for multi-hop routes. No transitive edit is planned.
- ACP clients may see construction-time manifest errors earlier. Valid capability, permission, invocation, and deferred-task response shapes stay compatible.

## Completed Baseline

Validate every `ToolManifest` with `chio_manifest::validate_manifest` before ACP capability publication, bridge-fidelity classification, or authoritative capability binding construction. This is architectural because it makes manifest validation the single envelope gate before external ACP discovery and keeps permission preview focused on request-time admission.

## Completed Material Improvement

Added a centralized known-method params-object gate for authoritative and
compatibility JSON-RPC dispatch. Missing params remain compatible as `{}`,
unknown methods still return method-not-found, and non-object params for known
ACP methods fail with `-32602` before permission preview, invocation parsing,
task lifecycle lookup, or capability listing can observe malformed params.

## Deferred Terminal Task Retention Slice

### Current Boundary

- `edge.rs` owns the authoritative `tool/stream`, `tool/resume`, and
  `tool/cancel` lifecycle.
- `conversion.rs` owns receipt-bearing `AcpInvocationResult` construction and
  pending/cancelled lifecycle metadata.
- `bridge.rs` owns the bounded deferred-task cap and TTL constants.

### Pain Point

The ACP lifecycle contract advertises deferred `tool/stream` tasks resolved by
`tool/resume` with `resumed_terminal_payload` delivery. The edge now retains
completed, failed, and cancelled task records until TTL expiry so repeated
`tool/resume` or idempotent `tool/cancel` can return owner-bound terminal task
state.

The remaining capacity bug is that the deferred-task cap currently counts only
working tasks. Retained completed or cancelled task records can accumulate until
TTL expiry without consuming capacity, even though they still occupy the
owner-bound task registry.

### Security And API Constraints

- Preserve public Rust structs, JSON-RPC methods, and response shapes.
- Preserve owner binding for working, completed, failed, and cancelled tasks.
- Do not execute the deferred kernel request more than once.
- Keep all retained task records bounded by the existing TTL and deferred-task
  cap.
- Preserve signed receipt metadata on completed or failed resumed results and
  cancellation metadata on cancelled tasks.

### Affected Dependents

- ACP clients can repeat `tool/resume` after terminal resolution and receive
  the same retained task and result until TTL expiry.
- Repeated `tool/cancel` on an already cancelled task returns the retained
  cancelled task.
- `chio-kernel`, `chio-cross-protocol`, and `chio-mcp-edge` APIs are unchanged.

### Completed Terminal Retention Baseline

Retain terminal deferred-task records until the existing TTL expires, while
preserving owner checks. Lifecycle tests prove resume does not re-execute or
remove a terminal task, and cancel remains idempotent for retained cancelled
tasks.

### Completed Capacity Accounting Improvement

Make the deferred-task capacity gate count every retained task record after TTL
pruning, not just `working` tasks. Update lifecycle tests so retained cancelled
tasks at the cap reject a new `tool/stream`, proving terminal retention cannot
grow without bound until TTL expiry.

## JSON-RPC Identifier Shape Slice

### Current Boundary

- `jsonrpc.rs` owns ACP request-boundary extraction for
  `params.capabilityId` before permission preview, `tool/invoke`, and
  `tool/stream`.
- `jsonrpc.rs` owns `params.taskId` extraction before `tool/cancel` and
  `tool/resume` reach deferred-task lookup or owner checks.
- `bridge.rs` records the accepted capability id into ACP protocol context for
  cross-protocol receipt metadata.

### Pain Point

The request-boundary parsers reject missing, non-string, and all-whitespace
identifiers, but padded non-empty identifiers keep their original bytes and
flow into exact capability or task lookup. Values such as `" read_file "` and
`" acp-task-1 "` therefore produce misleading deny, tool-not-found, or
lifecycle errors instead of an ACP JSON-RPC invalid-params response at the
boundary.

### Security And API Constraints

- Preserve public Rust structs and successful exact identifier bytes.
- Do not trim or silently rewrite client-supplied identifiers.
- Reject malformed identifiers before permission preview, capability binding
  lookup, task lookup, owner checks, lifecycle mutation, kernel dispatch, or
  bridge protocol-context metadata construction.
- Keep existing missing, non-string, and empty identifier errors stable.

### Affected Dependents

- ACP clients that send exact identifiers are unchanged.
- Clients that send padded `capabilityId` or `taskId` values now receive
  JSON-RPC `-32602` invalid-params errors instead of downstream lookup or deny
  behavior.
- `chio-kernel`, `chio-cross-protocol`, and `chio-mcp-edge` APIs are
  unchanged.

### Completed Material Improvement

Extended ACP JSON-RPC identifier parsing so `params.capabilityId` and
`params.taskId` reject leading or trailing whitespace, with focused
regressions proving padded capability and task identifiers fail before
downstream lookup.

## Execution Context Agent Identity Slice

### Current Boundary

- `types.rs` exposes `AcpKernelExecutionContext`, including authenticated
  caller `agent_id` for permission preview, kernel execution, and deferred-task
  ownership.
- `edge.rs` copies `execution.agent_id` into `CrossProtocolExecutionRequest`
  and retained `DeferredAcpTask.owner_agent_id`.
- Direct permission preview returns `Deny` for subject mismatches, but JSON-RPC
  permission preview, invocation, and lifecycle handling do not reject malformed
  authenticated identity at the ACP edge boundary.

### Pain Point

Blank agent ids depend on downstream cross-protocol validation during blocking
invocation, while padded non-empty ids can be stored as distinct deferred-task
owners before any kernel execution occurs. JSON-RPC permission preview also
turns malformed authenticated caller metadata into a normal denial instead of
an invalid-params boundary error.

### Security And API Constraints

- Preserve `AcpKernelExecutionContext` as a public struct.
- Preserve direct permission-preview return type; malformed execution context
  should continue to fail closed as `Deny` there.
- Reject malformed JSON-RPC execution context with `-32602` before permission
  preview, invocation, deferred task allocation, owner checks, lifecycle
  mutation, or kernel dispatch.
- Do not trim or normalize authenticated caller metadata.
- Preserve successful exact agent-id behavior and existing owner checks.

### Affected Dependents

- Callers with exact authenticated agent ids are unchanged.
- Callers that pass blank, padded, or control-bearing execution agent ids now
  receive `AcpEdgeError::InvalidRequest` through direct invocation/lifecycle
  APIs or JSON-RPC `-32602` where a JSON-RPC method uses the execution context.

### Completed Material Improvement

Add an ACP edge execution-context validator and apply it to permission preview,
blocking invocation, MCP-target invocation, deferred stream creation,
cancellation, resume, and test-only pending projection. Add focused regressions
proving malformed agent ids fail closed before dispatch, preview, or task
retention.
