# chio-acp-proxy Architecture Notes

## Module Boundaries

`lib.rs` flattens the crate with `include!` so public ACP wire types,
guards, kernel integration traits, telemetry helpers, transport, and tests all
share one crate-root namespace. The practical boundaries are still distinct:
`protocol.rs` owns ACP JSON-RPC wire shapes, method discrimination, and
boundary identifier validation; `interceptor.rs` owns request routing and
fail-closed policy decisions; `fs_guard.rs` and `terminal_guard.rs` own built-in
local guards; `kernel_checker.rs` and `kernel_signer.rs` adapt live ACP
operations into kernel-backed authorization and receipt flows; and
`transport.rs` plus `proxy.rs` own subprocess stdio orchestration.

## Params Boundary

Recognized ACP methods fail closed on absent or malformed params. `fs`,
`terminal`, `session/request_permission`, `session/update`, and `session/cancel`
route through the same params-required decode boundary in `protocol.rs`:

- Non-empty `sessionId` is required for guarded operations.
- Non-empty `toolCallId` is required before `session/update` can generate a
  receipt-bearing audit entry.
- Permission requests carrying option lists require non-empty option ids before
  they cross the user-decision boundary.
- `session/update` and `session/cancel` with absent or non-decoding params fail
  with `AcpProxyError::Protocol` before forwarding; valid non-tool updates still
  forward without receipts, and valid tool updates preserve receipt behavior.

Unknown methods still forward for forward compatibility. No-params requests stay
compatible where the ACP method permits them.

## Authorization Context Isolation

`interceptor.rs` is the trust boundary between ACP JSON-RPC traffic and Chio
authorization evidence. It captures live capability contexts after successful
kernel checks, stores pending contexts for ACP requests that do not yet carry a
`toolCallId`, and attaches those contexts to `session/update` receipts.

- Guard-denied or checker-denied fs and terminal-create requests use
  request-scoped cleanup: a blocked request that carried a `toolCallId` removes
  only that live context; a request without a `toolCallId` has not been buffered
  and requires no cleanup. A denied request cannot erase unrelated live or
  pending authorization evidence.
- `session/cancel` drains the per-session pending FIFO and the
  `tool:<session>:*` live context index for cancelled sessions.
- Allowed `CapabilityChecker` verdicts are admitted only when `capability_id`,
  authorization receipt id, and authorization request id are non-empty after
  trimming, unpadded, and free of ASCII or Unicode control characters. The
  `CapabilityChecker` trait is public, so the interceptor revalidates evidence
  from any injected implementation before storing it as authorization metadata.

## Security and API Constraints

The public root exports must remain source-compatible; downstream crates consume
the flattened ACP proxy types directly. The proxy keeps fail-closed guard
ordering: live capability checker first when present, then built-in path or
command guard, then forwarding. Canonical JSON hashes for authorization params
and ACP audit entries stay byte-stable. Standalone unsigned mode remains
available, but it does not treat malformed session or tool identifiers as useful
compliance evidence.

## Affected Dependents

`chio-cli` and tests using `KernelCapabilityChecker`, `KernelReceiptSigner`,
`AcpCapabilityRequest`, `AcpToolCallAuditEntry`, and `MessageInterceptor` rely
on the existing public type names. No transitive crate edits are planned unless
focused gates reveal downstream breakage from stricter malformed-message
handling.
