# Chio Wire Schemas v1

These files are the machine-readable schema contract for the shipped native Chio
message families defined in [WIRE_PROTOCOL.md](../../../WIRE_PROTOCOL.md).

The JSON Schema documents in this directory are the source of truth for the
Chio v1 wire contract. Any SDK, codegen pipeline, or conformance harness that
needs to validate Chio payloads should resolve types from these files first
and treat hand-typed bindings as derived artifacts.

Directory layout:

- `agent/`
  - `tool_call_request.schema.json`
  - `list_capabilities.schema.json`
  - `heartbeat.schema.json`
- `kernel/`
  - `tool_call_chunk.schema.json`
  - `tool_call_response.schema.json`
  - `capability_list.schema.json`
  - `capability_revoked.schema.json`
  - `heartbeat.schema.json`
- `result/`
  - `ok.schema.json`
  - `stream_complete.schema.json`
  - `cancelled.schema.json`
  - `incomplete.schema.json`
  - `err.schema.json`
- `error/`
  - `capability_denied.schema.json`
  - `capability_expired.schema.json`
  - `capability_revoked.schema.json`
  - `policy_denied.schema.json`
  - `tool_server_error.schema.json`
  - `internal_error.schema.json`
- `capability/` - capability tokens, grants, and revocation envelopes.
- `jsonrpc/` - JSON-RPC framing used by the hosted MCP HTTP edge.
- `provenance/` - provenance and attestation records emitted by the kernel.
- `receipt/` - signed receipts produced after tool calls complete.
- `trust-control/` - trust-control plane messages (policy, allowlist, audit).

Source-of-truth pointers:

- The Rust types backing these schemas live in `crates/chio-core-types`. When
  Rust types and these schemas disagree, fix the schema or the type so they
  match again before shipping.
- Cross-language conformance vectors live under `tests/bindings/vectors/`
  (canonical JSON, capability, hashing, manifest, receipt, signing). SDKs in
  other languages must round-trip those vectors through their generated
  bindings.
