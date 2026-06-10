# chio-acp-edge Architecture Note

## Module Boundaries

- `lib.rs` is the public facade. It includes focused source fragments into one crate-root module and exposes the ACP edge types.
- `config.rs` owns permission defaults and the fallback ACP category for discovered tools.
- `types.rs` owns public ACP capability, permission, invocation, deferred-task, and kernel execution-context structs.
- `bridge.rs` owns cross-protocol bridge selection, ACP category inference, bridge fidelity, target bindings, deferred-task limits, and orchestration. It owns the bounded deferred-task cap and TTL constants.
- `conversion.rs` owns kernel-output projection, ACP source envelopes, surface metadata, lifecycle metadata, and permission-preview metadata.
- `edge.rs` owns the server object, capability publication, JSON-RPC dispatch, permission preview, invocation, the compatibility wrapper, and deferred task lifecycle.
- `jsonrpc.rs` owns JSON-RPC request-boundary parsing.
- `fuzz.rs` owns the optional fuzz-only JSON-RPC decode pipeline behind the `fuzz` feature.

## Request-Boundary Gates

`ChioAcpEdge::new` validates every `ToolManifest` with
`chio_manifest::validate_manifest` before ACP capability publication,
bridge-fidelity classification, or authoritative capability binding
construction. Manifest validation is the single envelope gate before external
ACP discovery.

A centralized known-method params-object gate serves both authoritative and
compatibility dispatch: missing params remain compatible as `{}`, unknown
methods return method-not-found, and non-object params for known ACP methods
fail with `-32602` before permission preview, invocation parsing, task lifecycle
lookup, or capability listing.

`params.capabilityId` and `params.taskId` reject missing, non-string,
all-whitespace, and padded identifiers, returning `-32602`, before permission
preview, capability binding lookup, task lookup, owner checks, lifecycle
mutation, kernel dispatch, or bridge protocol-context metadata construction.
Client-supplied identifiers are not trimmed or rewritten.

`AcpKernelExecutionContext.agent_id` is validated for non-empty, unpadded,
control-free shape and applied to permission preview, blocking invocation,
MCP-target invocation, deferred stream creation, cancellation, and resume.
Direct permission preview returns `Deny` for malformed execution context;
JSON-RPC paths return `-32602` before preview, invocation, deferred task
allocation, owner checks, lifecycle mutation, or kernel dispatch. The
authenticated identifier is not trimmed or normalized.

Kernel-backed ACP permission preview uses the kernel-owned stateless DPoP
verifier, so preview and invoke agree on installed DPoP TTL, skew, and
store/config presence without consuming the nonce that invoke will later spend.

## Deferred Task Lifecycle

The ACP lifecycle advertises deferred `tool/stream` tasks resolved by
`tool/resume` with `resumed_terminal_payload` delivery. Completed, failed, and
cancelled task records are retained until TTL expiry so repeated `tool/resume`
or idempotent `tool/cancel` returns owner-bound terminal task state. The deferred
kernel request is never executed more than once. The deferred-task capacity gate
counts every retained task record after TTL pruning, not only working tasks, so
terminal retention cannot grow without bound. Signed receipt metadata is
preserved on completed or failed resumed results and cancellation metadata on
cancelled tasks.

## Security And API Constraints

- Public Rust structs and method signatures stay compatible.
- Authoritative invocation continues through `CrossProtocolOrchestrator` and the Chio kernel.
- Permission preview stays preview-only, must not imply receipt-bearing execution, and must not consume the DPoP nonce that invoke will spend.
- Compatibility-surface helpers stay visibly non-authoritative and feature-gated.
- Deferred task ownership stays bound to the authenticated `agent_id`.
- Receipt metadata, bridge route metadata, and lifecycle metadata stay byte-stable for valid requests.
- The `fuzz` feature exercises the JSON-RPC handler without pulling fuzz dependencies into default builds.

## Affected Dependents

- `chio-kernel` is the execution authority and DPoP preview verifier.
- `chio-cross-protocol` supplies bridge and lifecycle metadata contracts, preserved here.
- `chio-mcp-edge` remains a target executor dependency for multi-hop routes.
- ACP clients may see construction-time manifest errors earlier; valid capability, permission, invocation, and deferred-task response shapes stay compatible.
