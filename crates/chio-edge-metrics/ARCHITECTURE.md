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

## Pain Points

Receipt-write metrics are shared across edges but counter state must not be
shared across edges. Earlier in-tree edge implementations duplicated label
constants, rendering logic, and counter handling, which made it easy for an
edge to drift from the workspace registry or accidentally lose per-edge
isolation.

Before this slice, the counter API exposed typed outcomes and snapshots, but
snapshot consumers still needed to re-create outcome ordering or query totals
one label at a time. That kept the Prometheus renderer correct but left
downstream tests and future non-Prometheus exporters closer to stringly typed
access than they needed to be.

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
emit the registry-backed metric and keep per-edge counters isolated. This slice
did not require transitive code changes because the improvement is additive.

## Material Improvement

`ReceiptWriteSnapshot` now exposes a typed sample view so all exporters can
consume the same closed, stable outcome ordering with counts attached. The
Prometheus renderer uses that sample view, and crate-local tests prove stable
ordering, exact sample totals, and compatibility with existing string-label
recording behavior.
