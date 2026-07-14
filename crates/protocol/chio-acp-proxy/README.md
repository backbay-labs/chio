# chio-acp-proxy

Security proxy for the Agent Client Protocol (ACP). Sits between an editor or
IDE client and a third-party ACP coding agent subprocess, intercepting
JSON-RPC messages to enforce Chio capability-based access control on the
agent's filesystem and terminal requests. Unsigned audit entries are
generated for every observed tool call and, when a signer is installed,
promoted to signed Chio receipts.

This crate governs an external ACP agent from the outside. It does not expose
Chio's own tools over ACP; that direction is `chio-acp-edge`.

## Responsibilities

- Spawn an ACP agent as a subprocess over stdio and forward JSON-RPC messages
  bidirectionally between it and the client (`AcpTransport`, `AcpProxy`).
- Gate agent-initiated `fs/read_text_file`, `fs/write_text_file`, and
  `terminal/create` requests through an optional `CapabilityChecker` and the
  built-in `FsGuard` / `TerminalGuard` allowlists; a denial from either blocks
  the request.
- Gate `terminal/kill` and `terminal/release` on a `CapabilityChecker` alone
  and deny them outright when none is installed, since no built-in guard
  covers process lifecycle.
- Bind capability context captured before a `toolCallId` exists (fs and
  terminal-create requests) to the `toolCallId` that arrives later on
  `session/update`, through a per-session FIFO that only binds on an
  unambiguous match.
- Turn observed `tool_call` / `tool_call_update` events into unsigned
  `AcpToolCallAuditEntry` records, promoted to signed `ChioReceipt`s through
  the `ReceiptSigner` trait (`KernelReceiptSigner`).
- Map `session/request_permission` ACP permission kinds to Chio capability
  decisions for audit logging; the editor's own UI makes the actual decision.
- Generate and verify session compliance certificates over a receipt log:
  signatures, chain continuity, scope, budget, guard evidence.
- Convert signed receipts into OTel-shaped spans through the
  `ReceiptSpanExporter` trait.

## Public API

- `AcpProxy` - top-level orchestrator; `start` (built-in guards only) or
  `start_with_kernel` (kernel-backed signer and checker).
- `AcpProxyConfig` - builder for agent command, allowlists, public key, server id.
- `MessageInterceptor`, `Direction`, `InterceptResult` - the interception core.
- `FsGuard`, `TerminalGuard` - built-in fail-closed guards.
- `ReceiptSigner`, `CapabilityChecker` - kernel integration traits, implemented
  by `KernelReceiptSigner` and `KernelCapabilityChecker`.
- `ReceiptLogger`, `AcpToolCallAuditEntry`, `AcpEnforcementMode` - unsigned
  audit trail.
- `generate_compliance_certificate`, `verify_compliance_certificate`,
  `ComplianceConfig` - post-hoc session compliance evidence.
- `receipt_to_span`, `ReceiptSpanExporter`, `TelemetryConfig` - OTel span
  export.
- `AcpProxyError` - `Protocol`, `AccessDenied`, `PathTraversal`, `Transport`.

## Feature flags

| Flag | Effect |
|------|--------|
| `otel` | Enables `chio-kernel/otel` and the `otel` module: re-exports `chio_kernel::otel`'s GenAI span builder and adds `acp_tool_call_span` for ACP tool calls. |

## Testing

`cargo test -p chio-acp-proxy`

## See also

- `chio-acp-edge` - the inverse direction: exposes Chio's own tools as ACP
  capabilities instead of governing an external agent.
- `chio-kernel` - supplies the guard pipeline, receipt store, and (behind
  `otel`) the span builder consumed by the kernel-backed signer and checker.
- `chio-cross-protocol` - supplies the capability bridge and orchestrator
  `KernelCapabilityChecker` routes ACP operations through.
- `chio-cli` - wires this proxy into the Chio CLI.
