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

The workspace ships 107 crates, organized into 11 functional subfolders under `crates/`. Every crate lives at `crates/<group>/chio-<name>`; see `Cargo.toml` for the full member list. The table below names each folder, its representative crates, and its purpose.

| Folder (`crates/<group>`) | Representative crates | Purpose |
|---------------------------|-----------------------|---------|
| `core` | `chio-core`, `chio-core-types`, `chio-errors`, `chio-arena`, `chio-adversarial-suite` | Shared types (capabilities, scopes, grants, receipts, canonical JSON, signing), error vocabulary, and the adversarial test arena. |
| `kernel` | `chio-kernel`, `chio-kernel-core`, `chio-kernel-browser`, `chio-kernel-mobile`, `chio-runtime`, `chio-runtime-core`, `chio-runtime-harness` | Capability validation, guard pipeline, receipt signing, platform variants, and runtime wiring/harness. |
| `guards` | `chio-guards`, `chio-data-guards`, `chio-external-guards`, `chio-wasm-guards`, `chio-policy`, `chio-guard-registry` | Native guard implementations, policy evaluation, and the guard registry. |
| `protocol` | `chio-mcp-adapter`, `chio-mcp-edge`, `chio-a2a-adapter`, `chio-acp-edge`, `chio-openai-adapter`, `chio-openapi-mcp-bridge`, `chio-cross-protocol`, `chio-tower` | Wrap external protocols (MCP, A2A, ACP, OpenAPI, AG-UI) and provider tool-call dialects as Chio tool servers (27 crates). |
| `economy` | `chio-credit`, `chio-market`, `chio-settle`, `chio-link`, `chio-anchor`, `chio-underwriting`, `chio-appraisal`, `chio-metering`, `chio-web3` | Pricing, markets, settlement rails, anchoring, metering, and web3 bindings for metered tool access. |
| `trust` | `chio-did`, `chio-credentials`, `chio-federation`, `chio-governance`, `chio-reputation`, `chio-attest-verify`, `chio-pheromone`, `chio-tee`, `chio-weights` | DID handling, verifiable credentials, federation, governance, attestation, TEE, pheromone trust signals (20 crates). |
| `observability` | `chio-siem`, `chio-lineage`, `chio-log-redact`, `chio-metrics-spec`, `chio-otel-receipt-exporter` | SIEM event export, lineage, log redaction, metrics spec, and OTel receipt export. |
| `platform` | `chio-control-plane`, `chio-store-sqlite`, `chio-manifest`, `chio-config`, `chio-workflow`, `chio-http-core`, `chio-http-session` | Runtime wiring, persistent stores, signed tool manifests, config, workflow, and shared HTTP/session primitives. |
| `products` | `chio-cli`, `chio-wall`, `chio-wall-core`, `chio-mercury`, `chio-mercury-core`, `chio-api-protect` | End-user binaries and product surfaces built on the protocol. |
| `sdk` | `chio-guard-sdk`, `chio-guard-sdk-macros`, `chio-binding-helpers`, `chio-bindings-ffi`, `chio-cpp-kernel-ffi`, `chio-eval-receipt` | Guard authoring SDK, FFI bindings, and receipt evaluation helpers. |
| `tooling` | `chio-conformance`, `chio-spec-codegen`, `chio-spec-validate`, `chio-lsp`, `chio-test-support` | Conformance suite, spec codegen/validation, LSP, and shared test support. |

## Build and Test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

### Toolchain prerequisites

- **`wasm32-unknown-unknown` target** (required for `chio-wasm-guards` tests): `rustup target add wasm32-unknown-unknown`. The test harness compiles Rust example guards to WASM on first run.
- **`componentize-py`** (optional, Python guard tests): builds the gitignored `sdks/guard/chio-guard-py/dist/tool-gate.wasm` via `cd sdks/guard/chio-guard-py && ./scripts/build-guard.sh`. Tests skip gracefully when the artifact is absent.
- **TinyGo + wasi-virt** (optional, Go guard tests): builds `sdks/guard/chio-guard-go/dist/tool-gate.wasm` via `cd sdks/guard/chio-guard-go && ./scripts/build-guard.sh`. Tests skip gracefully when the artifact is absent.

## Conventions

- **Fail-closed**: errors during evaluation deny access. Invalid policies reject at load time.
- **Clippy**: `unwrap_used = "deny"`, `expect_used = "deny"` in all crates.
- **Serialization**: canonical JSON (RFC 8785) for all signed payloads.
- **Commit messages**: conventional commits (`feat:`, `fix:`, `docs:`, `test:`, etc.).
- **No em dashes** in code, comments, or documentation. Use hyphens or parentheses.

## Key Files

- Protocol spec: `spec/PROTOCOL.md`
- Core types: `crates/core/chio-core/src/lib.rs`
- Kernel: `crates/kernel/chio-kernel/src/lib.rs`
- Native guards: `crates/guards/chio-guards/src/lib.rs`
- Policy engine: `crates/guards/chio-policy/src/lib.rs`
- Manifest format: `crates/platform/chio-manifest/src/lib.rs`
- Docs index: `docs/README.md`
- Python adapter primitives (redact, security, receipts, filters): `sdks/python/chio-adapter-base/`; integration overview at `docs/integrations/CHIO-ADAPTER-BASE.md`.
