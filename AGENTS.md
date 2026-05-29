# AGENTS.md

## What is Chio?

Chio is a protocol for secure, attested tool access in AI agent systems. It replaces ad-hoc MCP-style wiring with a ground-up design built on capability-based security, cryptographic attestation, and privilege separation. The kernel mediates every tool call: capabilities are time-bounded and verifiable, guards evaluate input and output before anything crosses a trust boundary, and every decision is signed into an append-only receipt log. Policy and guards ship as first-class native components (`chio-policy`, `chio-guards`, `chio-data-guards`, `chio-external-guards`, `chio-wasm-guards`); no external policy engine is required.

## Five Components

1. **Agent** - untrusted LLM-powered process that consumes tools via capability tokens.
2. **Runtime Kernel** - trusted mediator (TCB) that validates capabilities, runs the guard pipeline, and signs receipts.
3. **Tool Servers** - sandboxed processes implementing tools, isolated from each other and from the agent.
4. **Capability Authority** - issues, scopes, and revokes time-bounded capability tokens.
5. **Receipt Log** - append-only Merkle-committed log of signed attestations over every decision and tool call.

## Crate Map

The workspace ships ~105 crates. The table below lists representative crates per group; see `Cargo.toml` for the full list.

| Group | Representative crates | Purpose |
|-------|-----------------------|---------|
| Core protocol | `chio-core`, `chio-core-types` | Shared types: capabilities, scopes, grants, receipts, canonical JSON, signing. |
| Kernel | `chio-kernel`, `chio-kernel-core`, `chio-kernel-browser`, `chio-kernel-mobile` | Capability validation, guard pipeline, receipt signing, platform variants. |
| Guards & Policy | `chio-guards`, `chio-data-guards`, `chio-external-guards`, `chio-wasm-guards`, `chio-policy`, `chio-guard-sdk` | Native guard implementations, policy evaluation, and the guard authoring SDK. |
| Adapters & Edges | `chio-mcp-adapter`, `chio-mcp-edge`, `chio-a2a-adapter`, `chio-a2a-edge`, `chio-acp-edge`, `chio-acp-proxy`, `chio-openapi-mcp-bridge`, `chio-cross-protocol`, `chio-ag-ui-proxy` | Wrap external protocols (MCP, A2A, ACP, OpenAPI, AG-UI) as Chio tool servers. |
| Economics & Settlement | `chio-credit`, `chio-market`, `chio-settle`, `chio-link`, `chio-anchor`, `chio-underwriting`, `chio-appraisal` | Pricing, markets, settlement rails, and anchoring for metered tool access. |
| Identity & Federation | `chio-did`, `chio-credentials`, `chio-federation`, `chio-governance`, `chio-reputation` | DID handling, verifiable credentials, multi-authority federation, governance. |
| Observability | `chio-siem`, `chio-metering` | SIEM event export and metering for billing and audit. |
| Control Plane & Storage | `chio-control-plane`, `chio-store-sqlite`, `chio-manifest` | Runtime wiring, persistent stores, signed tool manifests. |
| HTTP & Session | `chio-http-core`, `chio-http-session` | Shared HTTP primitives and session lifecycle. |
| Products | `chio-cli`, `chio-wall`, `chio-api-protect` | End-user binaries and product surfaces built on the protocol. |

## Build and Test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Conventions

- **Fail-closed**: errors during evaluation deny access. Invalid policies reject at load time.
- **Clippy**: `unwrap_used = "deny"`, `expect_used = "deny"` in all crates.
- **Serialization**: canonical JSON (RFC 8785) for all signed payloads.
- **Commit messages**: conventional commits (`feat:`, `fix:`, `docs:`, `test:`, etc.).
- **No em dashes** in code, comments, or documentation. Use hyphens or parentheses.

## Key Files

- Protocol spec: `spec/PROTOCOL.md`
- Core types: `crates/chio-core/src/lib.rs`
- Kernel: `crates/chio-kernel/src/lib.rs`
- Native guards: `crates/chio-guards/src/lib.rs`
- Policy engine: `crates/chio-policy/src/lib.rs`
- Manifest format: `crates/chio-manifest/src/lib.rs`
- Docs index: `docs/README.md`
- Python adapter primitives (redact, security, receipts, filters): `sdks/python/chio-adapter-base/`; integration overview at `docs/integrations/CHIO-ADAPTER-BASE.md`.
