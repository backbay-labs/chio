# chio-acp-proxy Architecture Notes

## Module Boundaries

`lib.rs` currently flattens the crate with `include!` so public ACP wire types,
guards, kernel integration traits, telemetry helpers, transport, and tests all
share one crate-root namespace. The practical boundaries are still visible:
`protocol.rs` owns ACP JSON-RPC wire shapes and method discrimination,
`interceptor.rs` owns request routing and fail-closed policy decisions,
`fs_guard.rs` and `terminal_guard.rs` own built-in local guards,
`kernel_checker.rs` and `kernel_signer.rs` adapt live ACP operations into
kernel-backed authorization and receipt flows, and `transport.rs` plus
`proxy.rs` own subprocess stdio orchestration.

## Completed Permission Boundary Slice

The guarded fs, terminal, lifecycle, receipt-producing session-update, and
permission paths now validate boundary identifiers before they become
capability, pending-context, receipt, or user-decision correlation keys.
Earlier versions treated malformed `session/request_permission` params as
best-effort logging input and forwarded the request, so empty `sessionId` or
option ids could cross into the editor/user decision boundary without a
trustworthy ACP correlation key.

## Security and API Constraints

The public root exports must remain source-compatible because downstream crates
consume the flattened ACP proxy types directly. The proxy must keep fail-closed
guard ordering: live capability checker first when present, then built-in path
or command guard, then forwarding. Canonical JSON hashes for authorization
params and ACP audit entries must remain byte-stable. Standalone unsigned mode
must remain available, but it cannot silently treat malformed session or tool
identifiers as useful compliance evidence.

## Affected Dependents

`chio-kernel` and tests using `KernelCapabilityChecker`, `KernelReceiptSigner`,
`AcpCapabilityRequest`, `AcpToolCallAuditEntry`, and `MessageInterceptor` rely
on the existing public type names. No transitive crate edits are planned unless
focused gates reveal downstream breakage from stricter malformed-message
handling.

## Completed Material Improvement

Extend the existing ACP boundary identifier validation in `protocol.rs` to
`session/request_permission` and have `MessageInterceptor` require valid params
whenever the request supplies them. Non-empty `sessionId` remains required for
guarded operations, non-empty `toolCallId` remains required before ACP
`session/update` can generate a receipt-bearing audit entry, and permission
requests with option lists must carry non-empty option ids before they cross the
user decision boundary. This keeps no-params compatibility while rejecting
malformed permission correlation evidence without changing the public root API
shape.

## Session Update Params Boundary Slice

### Current Boundary

`session/update` is the agent-to-client notification path that can produce ACP
tool-call audit entries and signed Chio receipts. `interceptor.rs` parses it
into `SessionUpdateNotification`, validates the `sessionId`, then parses
security-relevant `toolCall` and `toolCallUpdate` updates before receipt
generation.

### Pain Point

The interceptor currently treats missing or malformed `session/update` params as
an uninteresting update and forwards the message unchanged. That is too weak for
a receipt boundary: a recognized method with invalid params should not cross the
proxy as unaudited traffic just because parsing failed.

### Security and API Constraints

The public flattened root API and ACP wire structs must remain unchanged.
Unknown methods can still forward for forward compatibility. Recognized
`session/update` messages must fail closed when their params are absent or do not
decode into the ACP notification shape, while valid non-tool updates continue to
forward without receipts.

### Affected Dependents

Only the owning crate tests are expected to change. Downstream crates observe the
same `AcpProxyError::Protocol` error shape already used by guarded ACP methods
with missing or invalid params.

### Completed Material Improvement

Route `session/update` through the same params-required decoding boundary used
by guarded fs, terminal, and permission methods. Missing params and malformed
params should return protocol errors before forwarding; valid non-tool updates
should still pass through, and valid tool updates should preserve the existing
receipt behavior.

## Blocked Request Context Isolation Slice

### Current Boundary

`interceptor.rs` is the trust boundary between ACP JSON-RPC traffic and Chio
authorization evidence. It captures live capability contexts after successful
kernel checks, stores pending contexts for ACP requests that do not yet carry a
`toolCallId`, and later attaches those contexts to `session/update` receipts.

### Pain Point

Guard-denied or checker-denied fs and terminal-create requests currently call
`clear_capability_context(session_id)`. That clears every live and pending
authorization context in the session, not just any context associated with the
blocked request. A denied unrelated operation can therefore downgrade later
receipts for already-authorized tool calls to `AuditOnly` or discard pending
evidence for authorized requests that have not emitted their ACP `toolCallId`
yet.

### Security and API Constraints

The public flattened root API, `InterceptResult` variants, ACP wire structs,
canonical parameter hashes, and receipt field semantics must remain unchanged.
Denied requests must still fail closed and must not leave behind a context for
the denied request. The fix must preserve guard ordering: capability checker
first when installed, then built-in guard, then forwarding.

### Affected Dependents

`chio-cli` depends on `chio-acp-proxy`, but no transitive public API change is
planned. The expected compatibility proof is the owning crate test suite plus a
targeted `chio-cli` check if the crate compiles cleanly.

### Completed Material Improvement

Replace session-wide context clearing on blocked fs and terminal-create paths
with request-scoped cleanup. If the blocked request carried a `toolCallId`, only
that live context is removed; requests without a `toolCallId` have not been
buffered yet and require no cleanup. Add regression tests proving that a denied
request cannot erase unrelated live or pending authorization evidence.

## Session Cancel Params Boundary Slice

### Current Boundary

`session/cancel` is the lifecycle cleanup path for live and pending ACP
authorization contexts. It clears the per-session pending FIFO and the
`tool:<session>:*` live context index so cancelled sessions do not retain
authorization material.

### Pain Point

The interceptor currently treats `session/cancel` params as optional. Missing,
non-object, or blank `sessionId` values are forwarded unchanged and do not drain
any context. That is weaker than the rest of the recognized ACP lifecycle
surface: malformed cancel messages can cross the proxy as if they were valid
control messages while leaving captured authorization evidence alive.

### Security and API Constraints

The public flattened root API must remain source-compatible. Valid
`session/cancel` messages should still forward unchanged after context cleanup.
Malformed `session/cancel` messages should fail closed with the existing
`AcpProxyError::Protocol` shape used by guarded ACP methods. Unknown ACP
methods still forward for forward compatibility.

### Affected Dependents

Only owning-crate tests are expected to change. No downstream API or wire shape
change is planned for valid cancel messages.

### Completed Material Improvement

Add typed `session/cancel` params validation and route the method through the
same params-required decode boundary as guarded fs, terminal, permission, and
session-update methods. Add regression coverage proving malformed cancel
messages fail before forwarding and do not drain unrelated pending contexts.

## Capability Checker Evidence Boundary Slice

### Current Boundary

`interceptor.rs` accepts `AcpVerdict` values from any injected
`CapabilityChecker` implementation. When a verdict is allowed, the interceptor
promotes its `capability_id`, authorization receipt id, and authorization
request id into `AcpCapabilityAuditContext`; later ACP `session/update` traffic
can copy that evidence into audit entries or signed receipts.

### Pain Point

The proxy previously checked only that allowed verdict evidence existed. Padded
or control-bearing capability and receipt identifiers could therefore cross the
checker boundary and be stored as authorization metadata. The kernel-backed
checker emits normalized values, but the trait is public and other
implementations can be injected.

### Security and API Constraints

The public `CapabilityChecker` trait and ACP wire shape must remain unchanged.
The interceptor must keep failing closed, preserve existing missing-evidence
errors, and avoid changing canonical ACP parameter hashes. Valid checker
verdicts should still forward exactly as before.

### Affected Dependents

No downstream API change is expected. `chio-cli` is the direct workspace
dependent to recheck after the owning crate passes.

### Completed Material Improvement

Reject allowed checker verdicts whose `capability_id`, authorization receipt
id, or authorization request id is empty after trimming, padded, or contains
ASCII or Unicode control characters. Add regression coverage proving malformed
evidence blocks before the ACP request is forwarded.
