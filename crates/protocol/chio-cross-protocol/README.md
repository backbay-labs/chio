# chio-cross-protocol

Shared cross-protocol bridge contracts and orchestrator runtime substrate for
Chio.

## What it does

`chio-cross-protocol` centralizes the types that outward protocol edges (A2A,
ACP, MCP, OpenAI, HTTP) share so each edge does not independently re-implement
provenance, attenuation, and receipt-lineage behavior.

The crate provides:

- `discovery::DiscoveryProtocol` -- enum of the protocol families Chio can
  bridge across (Native, Http, Mcp, A2a, Acp, OpenAi). Used in
  `x-chio-target-protocol` schema extensions.
- `discovery::TargetProtocolRegistry` -- binds
  `execution::TargetProtocolExecutor` impls to protocol families at runtime and
  resolves which executor handles a given tool definition.
- `lifecycle::RuntimeLifecycleSurface` and
  `lifecycle::RuntimeLifecycleContract` -- canonical lifecycle contract for
  claim-eligible bridge surfaces (entrypoints, stream delivery, partial output,
  cancellation).
- `semantic_hints::BridgeFidelity` -- typed publication-gate contract:
  `Lossless`, `Adapted` (with caveats), or `Unsupported`.
- `semantic_hints::BridgeSemanticHints` -- semantic flags derived from
  `x-chio-*` tool schema extensions (publish, approval-required, streaming,
  cancellation, partial-output).
- `capability_bridge::CROSS_PROTOCOL_AUTHORITY_PATH` and
  `capability_bridge::CROSS_PROTOCOL_CAPABILITY_ENVELOPE_SCHEMA` -- constants
  signed into cross-protocol capability envelopes.
- `orchestrator::CrossProtocolOrchestrator` -- shared runtime that validates
  request lineage, plans routes, projects capability references, and hands
  execution to the selected target protocol.

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
