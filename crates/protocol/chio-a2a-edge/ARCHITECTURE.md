# chio-a2a-edge Architecture Note

## Module Boundaries

- `lib.rs` is the public facade. It includes focused source fragments into one crate-root module and exposes the A2A edge types.
- `config.rs` owns the advertised Agent Card settings: agent identity, endpoint URL, and protocol binding.
- `types.rs` owns the public A2A wire structs and the kernel execution context required for authoritative calls.
- `bridge.rs` owns cross-protocol bridge selection, target executor registration, bridge fidelity, skill candidate construction, and orchestration. It owns the bounded deferred-task cap and TTL constants.
- `conversion.rs` owns A2A message-to-argument extraction, kernel output projection, terminal `TaskResponse` construction, and Chio metadata envelope construction.
- `edge.rs` owns the server object, skill publication, JSON-RPC dispatch, target-skill routing, kernel execution, the compatibility wrapper, and deferred task lifecycle.
- `jsonrpc.rs` owns JSON-RPC request-boundary parsing.
- `metrics.rs` and `otel.rs` own edge-specific receipt metrics and optional GenAI span helpers.

## Request-Boundary Gates

`ChioA2aEdge::new` validates every `ToolManifest` with `chio_manifest::validate_manifest` before Agent Card skill publication, bridge-fidelity classification, or authoritative skill binding construction. Manifest validation is the single envelope gate before external A2A discovery.

`config.rs` rejects blank Agent Card identity, endpoint, and protocol-binding fields, and rejects leading or trailing whitespace on non-empty fields, at construction with `A2aEdgeError::InvalidRequest`. Operator-provided metadata is not silently trimmed or rewritten.

`jsonrpc.rs` is the trust boundary for inbound JSON-RPC. A centralized known-method params-object gate serves both authoritative and compatibility dispatch: missing params remain compatible as `{}`, unknown methods return method-not-found, and non-object params for known A2A methods fail with `-32602` before message parsing, task lookup, or deferred lifecycle mutation. `metadata.chio.targetSkillId` and `params.taskId` reject missing, non-string, all-whitespace, and padded identifiers before skill resolution or task lookup.

`conversion.rs` rejects non-object `data` parts before kernel dispatch, receipt construction, deferred task creation, or compatibility passthrough; the one-data-part maximum and text-plus-data precedence are preserved.

`A2aKernelExecutionContext.agent_id` is validated for non-empty, unpadded, control-free shape before skill resolution, kernel dispatch, deferred task allocation, owner checks, or lifecycle mutation. The authenticated identifier is not trimmed or normalized.

## Deferred Task Lifecycle

`task/get` executes a working deferred task once and then persists the terminal result. Terminal deferred-task responses (completed, failed, cancelled) are retained in the internal task map until the TTL expires, so a follow-up `task/get` or idempotent `task/cancel` returns the same owner-bound terminal response rather than `tool not found`. The kernel-backed deferred request is never re-executed after the first successful `task/get`. The deferred-task cap counts every retained task record after TTL pruning, not only working tasks, so terminal retention cannot grow without bound. Signed receipt metadata is preserved on completed or failed terminal responses and cancellation metadata on cancelled responses.

## Security And API Constraints

- Public request and response structs do not change.
- Authoritative calls route through `CrossProtocolOrchestrator` and the Chio kernel.
- Compatibility-surface helpers stay visibly non-authoritative and feature-gated.
- Deferred task ownership stays bound to the authenticated `agent_id` across all task states.
- Receipt metadata, capability ids, bridge route metadata, and lifecycle metadata stay byte-stable for valid requests.
- No generated code is in scope.

## Affected Dependents

- `chio-kernel` is reached through kernel-mediated tool execution; the kernel API is unchanged.
- `chio-cross-protocol` provides bridge and lifecycle metadata contracts, preserved here.
- `chio-mcp-edge` remains a target executor dependency for multi-hop routes.
- Downstream A2A clients may see construction-time manifest errors earlier; successful Agent Card, JSON-RPC, task lifecycle, and response shapes stay compatible.
