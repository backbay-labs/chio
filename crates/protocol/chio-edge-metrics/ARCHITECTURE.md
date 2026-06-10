# chio-edge-metrics Architecture

## Boundaries

`chio-edge-metrics` owns the shared receipt-write metrics sink used by protocol
edge crates. The crate exports the registry-backed
`chio_receipt_write_total` metric name, the closed receipt-write outcome
taxonomy, per-edge counter storage, typed snapshots, and Prometheus rendering.

The crate does not own kernel evaluation, receipt signing, edge protocol
translation, HTTP serving, OpenTelemetry export, or the workspace metrics
registry. Edge crates such as `chio-mcp-edge`, `chio-acp-edge`, and
`chio-a2a-edge` each own their own static counter instance and delegate common
recording and rendering behavior here.

## Counter Model

Receipt-write metrics are shared across edges, but counter state is not: each
edge owns its own counter instance so label constants, rendering logic, and
counter handling stay centralized here rather than duplicated per edge, and one
edge cannot drift from the workspace registry or lose per-edge isolation.

`ReceiptWriteSnapshot` exposes a typed sample view, so every exporter consumes
the same closed, stable outcome ordering with counts attached instead of
re-creating outcome ordering or querying totals one label at a time. The
Prometheus renderer uses that sample view.

## Security And API Constraints

- Preserve `CHIO_RECEIPT_WRITE_TOTAL` and the stable `outcome` label values.
- Preserve per-edge isolation: this crate must expose counter instances, not
  module-level global counters.
- Preserve fail-closed error accounting: unknown string labels still record and
  read through the error bucket for compatibility.
- Preserve additive public API compatibility for existing edge crates.
- Keep the crate local and synchronous; metrics recording must not allocate,
  perform I/O, or depend on exporter runtime state.

## Affected Dependents

`chio-mcp-edge`, `chio-acp-edge`, and `chio-a2a-edge` depend on the public
counter and rendering APIs. `chio-conformance` verifies that those edge crates
emit the registry-backed metric and keep per-edge counters isolated. The public
API is additive, so dependents need no transitive code changes.
