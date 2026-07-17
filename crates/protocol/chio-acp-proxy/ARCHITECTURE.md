# chio-acp-proxy architecture

## Overview

`chio-acp-proxy` is the enforcement point between an ACP client (editor or
IDE) and a third-party ACP coding agent subprocess. It runs in two modes: a
standalone mode backed only by local fail-closed allowlists, and a
kernel-backed mode where an installed `CapabilityChecker` and `ReceiptSigner`
route filesystem and terminal requests through `chio-kernel`'s guard pipeline
and sign the resulting receipts. Every file under `src/` is pulled into the
crate root with `include!` rather than declared as a Rust module, so the
public surface lives in one flat `chio_acp_proxy::*` namespace; the module map
below groups by file, not by `mod`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/protocol.rs` | ACP JSON-RPC wire types (`JsonRpcMessage`, per-method param structs), `AcpMethod` discrimination, `session/update` payload parsing, boundary-identifier validation. |
| `src/config.rs` | `AcpProxyConfig`: agent command/args/env, path and command allowlists, public key, server id. Builder pattern; allowlists start empty. |
| `src/fs_guard.rs` | `FsGuard`: path-prefix allowlist, traversal rejection, filesystem-backed symlink resolution. |
| `src/terminal_guard.rs` | `TerminalGuard`: command allowlist, shell-metacharacter rejection on arguments. |
| `src/permission.rs` | `PermissionMapper`: ACP permission-option kinds to Chio `PermissionDecision`, for audit only. |
| `src/receipt.rs` | `ReceiptLogger`: builds unsigned `AcpToolCallAuditEntry` records with a canonical-JSON content hash over explicit wire fields only. |
| `src/attestation.rs` | `ReceiptSigner` and `CapabilityChecker` traits, their request/verdict/error types, `AcpAttestationMode`. |
| `src/kernel_signer.rs` | `KernelReceiptSigner`: the kernel-backed `ReceiptSigner`. Verifies the referenced live authorization receipt, signs a `ChioReceipt`, appends it to a `ReceiptStore`, batches Merkle checkpoints. |
| `src/kernel_checker.rs` | `KernelCapabilityChecker`: the kernel-backed `CapabilityChecker`. Routes ACP operations through `CrossProtocolOrchestrator` and a guard-only `ToolServerConnection`. |
| `src/compliance.rs` | Session compliance certificates: `generate_compliance_certificate`, `verify_compliance_certificate`, `ComplianceConfig`. |
| `src/telemetry.rs` | `ChioReceipt` to OTel-shaped `ReceiptSpan` conversion, `ReceiptSpanExporter` trait, `LoggingSpanExporter`, `JsonFileExporter`. |
| `src/interceptor.rs` | `MessageInterceptor`: routes each message by `AcpMethod` and `Direction`, owns the live and pending capability-context buffers. |
| `src/transport.rs` | `AcpTransport`: subprocess spawn, newline-delimited JSON-RPC over stdio. |
| `src/proxy.rs` | `AcpProxy`: wires config, transport, and interceptor into the public entry point. |
| `src/otel.rs` | Feature-gated (`otel`). Re-exports `chio_kernel::otel`'s GenAI span builder and adds `acp_tool_call_span`. |
| `src/tests.rs` (+ `src/tests/`) | `#[cfg(test)]` only: aggregates the unit test suite. |

## Message lifecycle

1. `AcpProxy::start` or `start_with_kernel` spawns the agent subprocess
   (`AcpTransport::spawn`) with piped stdin/stdout and inherited stderr.
2. Every message read from the agent or client goes to
   `MessageInterceptor::intercept` with a `Direction`. `extract_method` maps
   the JSON-RPC `method` to an `AcpMethod`; unrecognized methods forward
   unchanged for forward compatibility.
3. Agent-to-client `fs/read_text_file`, `fs/write_text_file`, and
   `terminal/create` requests (the agent asking the client to touch the
   filesystem or a terminal) decode their params and validate boundary
   identifiers, then run the optional `CapabilityChecker` gate. A checker
   denial blocks immediately; otherwise the built-in `FsGuard` or
   `TerminalGuard` makes the final call.
4. `terminal/kill` and `terminal/release` skip the built-in guard entirely:
   with no `CapabilityChecker` installed the message is blocked outright.
5. A capability context captured for a request with no `toolCallId` yet is
   buffered per session. When a later `session/update` `ToolCall` event's
   `kind` uniquely matches one buffered operation, the context binds to the
   resolved `toolCallId` and moves into the live index. An ambiguous or
   missing match leaves the eventual receipt at `AuditOnly`.
6. `session/update` notifications carrying `tool_call` / `tool_call_update`
   payloads become `AcpToolCallAuditEntry` records (`ReceiptLogger`), enriched
   with any bound capability context, then passed to the installed
   `ReceiptSigner`, if any (`sign_or_block`, gated by `AcpAttestationMode`).
7. `session/cancel`, in either direction, drains the session's pending and
   live capability-context buffers.
8. The caller (`AcpProxy::process_client_message` / `process_agent_message`)
   gets back `InterceptResult::Forward`, `Block`, or `ForwardWithReceipt` and
   drives the transport (`send_to_agent` / `recv_from_agent`) accordingly.

## Invariants and failure modes

- `FsGuard` and `TerminalGuard` are fail-closed: an empty allowlist denies
  every request, and `..` path segments are rejected before prefix matching.
- `terminal/kill` and `terminal/release` are denied outright with no
  `CapabilityChecker` installed; no built-in guard substitutes for one.
- `MessageInterceptor` re-validates every allowing `CapabilityChecker`
  verdict before trusting it: `capability_id`, authorization receipt id, and
  authorization request id must be non-empty, unpadded, and free of control
  characters, and operations that require a `toolCallId` binding
  (`terminal_kill`, `terminal_release`) are rejected if the checker allowed
  them without one.
- The pending capability-context buffer is capped at 32 entries per session
  with FIFO eviction, so unmatched requests cannot grow it without bound.
- An audit entry's `content_hash` covers only the explicit ACP wire fields
  (`toolCallId`, `title`, `kind`, `status`); the `#[serde(flatten)]` `extra`
  map is excluded so unknown JSON keys cannot silently change the hash. This
  makes the hash incompatible by design with a prior non-canonical digest.
- `KernelReceiptSigner` signs a `CryptographicallyEnforced` entry only after
  re-verifying the referenced live authorization receipt end to end
  (signature, content-addressed id, action hash, kernel-key match, and
  capability / tool-target / session / tool-call / correlation / operation /
  resource / parameter-hash match); the audit entry's own fields are never
  trusted as authorization evidence on their own.
- Receipt-store append is part of the signing boundary and fails closed; a
  Merkle checkpoint failure after a successful append is recorded in
  `KernelSignerCheckpointHealth` and logged, not surfaced as a signing error.
- `AcpAttestationMode::Required` blocks a message when no signer is installed
  or signing fails; `AcpAttestationMode::BestEffort` (default) logs and
  forwards instead.
- Compliance certificate generation and verification fail closed on any
  anomaly (bad signature, id or action-hash mismatch, untrusted kernel key,
  session or tenant mismatch, chain gap, scope/budget/guard violation, mixed
  kernel keys across a session); an empty
  `ComplianceConfig::trusted_kernel_keys` rejects every receipt, logged once
  as a misconfiguration warning.
- `#![forbid(unsafe_code)]` at the crate root.

## Dependencies

- `chio-core` (aliased to `chio-core-types`) - canonical JSON, SHA-256
  hashing, Ed25519 keypairs and signatures, capability tokens, and the
  `ChioReceipt` / `ChioReceiptBody` types this crate signs and verifies.
- `chio-kernel` - `ChioKernel`, the guard pipeline, `ReceiptStore` /
  `AuthorizationReceiptConsumption`, `SignedExecutionNonce`, and (behind the
  `otel` feature) the GenAI span builder re-exported from `src/otel.rs`.
- `chio-cross-protocol` - `CapabilityBridge`, `CrossProtocolOrchestrator`, and
  the discovery/execution types `KernelCapabilityChecker` uses to route ACP
  operations through the kernel as a `Native`-protocol target.
- `async-trait` - the `async fn invoke` on `AcpAuthorityToolServer`'s
  `ToolServerConnection` implementation.
- `sha2` - content hashes and OTel trace/span id derivation.
- `serde` / `serde_json`, `thiserror`, `tracing` - wire (de)serialization,
  typed errors, structured logging.

## Extension points

- `ReceiptSigner` - implement to plug in a signing backend other than
  `KernelReceiptSigner`.
- `CapabilityChecker` - implement to plug in an authorization backend other
  than `KernelCapabilityChecker`.
- `ReceiptSpanExporter` - implement to export `ReceiptSpan`s to a collector
  other than the provided `LoggingSpanExporter` / `JsonFileExporter`.
