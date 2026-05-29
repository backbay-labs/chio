# chio-cross-protocol

Shared cross-protocol bridge contracts and orchestrator runtime substrate for
Chio.

## What it does

`chio-cross-protocol` centralizes the types that outward protocol edges (A2A,
ACP, MCP, OpenAI, HTTP) share so each edge does not independently re-implement
provenance, attenuation, and receipt-lineage behavior.

The crate provides:

- `DiscoveryProtocol` -- enum of the protocol families Chio can bridge across
  (Native, Http, Mcp, A2a, Acp, OpenAi). Used in `x-chio-target-protocol`
  schema extensions.
- `TargetProtocolRegistry` -- binds `TargetProtocolExecutor` impls to protocol
  families at runtime and resolves which executor handles a given tool
  definition.
- `RuntimeLifecycleSurface` / `RuntimeLifecycleContract` -- canonical lifecycle
  contract for claim-eligible bridge surfaces (entrypoints, stream delivery,
  partial output, cancellation).
- `BridgeFidelity` -- typed publication-gate contract: `Lossless`, `Adapted`
  (with caveats), or `Unsupported`.
- `BridgeSemanticHints` -- semantic flags derived from `x-chio-*` tool schema
  extensions (publish, approval-required, streaming, cancellation,
  partial-output).
- Cross-protocol capability envelope constants (`CROSS_PROTOCOL_AUTHORITY_PATH`,
  `CROSS_PROTOCOL_CAPABILITY_ENVELOPE_SCHEMA`).

## Position in the system

`chio-cross-protocol` is a leaf-level shared library. It depends only on
`chio-core-types`, `chio-kernel`, and `chio-manifest`. The edge crates
(`chio-a2a-edge`, `chio-acp-edge`, `chio-mcp-edge`, `chio-acp-proxy`) depend
on it.

## Building

```bash
cargo build -p chio-cross-protocol
cargo test -p chio-cross-protocol
```

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"` apply.
