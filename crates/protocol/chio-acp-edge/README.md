# chio-acp-edge

Edge crate that exposes Chio-governed tools as ACP (Agent Client Protocol)
capabilities.

## What it does

`chio-acp-edge` is the outward ACP server surface, allowing ACP-compatible
editors and IDEs to invoke Chio tools over ACP-shaped permission and invocation
surfaces. Responsibilities:

- Map Chio tool definitions to ACP capability advertisements.
- Intercept `session/request_permission` calls.
- Expose truthful ACP lifecycle semantics: permission preview, blocking
  `tool/invoke`, and deferred-task `tool/stream` / `tool/cancel` /
  `tool/resume`.
- Route outward invocations through the Chio kernel by default.
- Evaluate `BridgeFidelity` per tool.

Kernel-backed entrypoints emit signed Chio receipts. Passthrough compatibility
helpers are available but are not sufficient for full cross-protocol attestation
claims.

The optional `fuzz` feature exposes the fuzz corpus entry points. The `metrics`
module exports Prometheus-compatible receipt-write counters
(`render_acp_edge_metrics_prometheus`, `CHIO_RECEIPT_WRITE_TOTAL`).

## Position in the system

```
ACP editor / IDE client
        |
  [chio-acp-edge]  -- permission gating, Chio kernel dispatch, receipt signing
        |
  chio-kernel
```

Depends on `chio-cross-protocol` for shared bridge contracts and
`BridgeFidelity`.

## Building

```bash
cargo build -p chio-acp-edge
cargo test -p chio-acp-edge
```
