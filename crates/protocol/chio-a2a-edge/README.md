# chio-a2a-edge

Edge crate that exposes Chio-governed tools as A2A (Agent-to-Agent) skills.

## What it does

`chio-a2a-edge` is the outward A2A server surface: it serves Chio tools to
external A2A clients rather than consuming a remote A2A server (that direction
is `chio-a2a-adapter`). Responsibilities:

- Publish an A2A Agent Card at `/.well-known/agent-card.json`.
- Accept `message/send` requests and route them through the Chio kernel.
- Expose a truthful blocking `message/send` surface and a deferred
  receipt-bearing `message/stream` / `task/get` / `task/cancel` lifecycle.
- Evaluate `BridgeFidelity` per tool to signal translation quality.

Kernel-backed entrypoints produce signed Chio receipts. Passthrough
compatibility helpers are available for bounded migration and tests but are not
the authoritative trust path.

The crate exports Prometheus-compatible receipt-write counters via its `metrics`
module (`render_a2a_edge_metrics_prometheus`, `CHIO_RECEIPT_WRITE_TOTAL`).

## Position in the system

```
A2A client (external agent)
        |
  [chio-a2a-edge]  -- Chio kernel dispatch, receipt signing
        |
  chio-kernel
```

Depends on `chio-cross-protocol` for shared bridge contracts and
`BridgeFidelity`.

## Building

```bash
cargo build -p chio-a2a-edge
cargo test -p chio-a2a-edge
```
