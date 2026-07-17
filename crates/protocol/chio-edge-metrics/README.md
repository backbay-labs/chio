# chio-edge-metrics

Shared receipt-write metrics sink for Chio's protocol edge crates. Every edge
(MCP, ACP, A2A) surfaces the same `chio_receipt_write_total` counter and the
receipt-writer liveness gauges through identical recorder, accessor, and
Prometheus-rendering logic; that logic lives here once instead of being
copied into each edge.

`chio-metrics-spec` is the workspace-wide registry that declares every Chio
metric's name and shape, including `chio_receipt_write_total`, as data.
`chio-edge-metrics` does not add to that registry; it is the runtime counter
implementation for that one metric family, re-exporting the registered name
rather than redeclaring it. Counter *state* stays per-edge: this crate exposes
a `ReceiptWriteCounters` instance type rather than a module-level global, so
each edge crate declares its own `static` and one edge's dispatches cannot
advance another edge's counter.

## Responsibilities

- Hold the closed four-outcome taxonomy (`allow`, `deny`, `pending_approval`,
  `error`) for `chio_receipt_write_total` as `ReceiptWriteOutcome`.
- Provide `ReceiptWriteCounters`: atomic, saturating, per-instance counter
  storage plus recording, snapshotting, and Prometheus rendering.
- Map a kernel `Verdict` to its receipt-write outcome.
- Render the `chio_receipt_writer_healthy` / `chio_receipt_writer_liveness`
  gauges for the serving store's writer health.
- Fail closed on unrecognized outcome labels by recording and reading them
  through the error bucket instead of dropping them.

## Public API

- `ReceiptWriteCounters` - `new`/`Default`, `record_verdict`, `record_outcome`,
  `record`, `total_outcome`, `total`, `snapshot`, `render_prometheus`.
- `ReceiptWriteOutcome` - `Allow` | `Deny` | `PendingApproval` | `Error`;
  `as_str`, `from_label`.
- `ReceiptWriteSnapshot`, `ReceiptWriteSample`, `RECEIPT_WRITE_OUTCOMES` - typed,
  stably-ordered totals for one counter set.
- `receipt_write_outcome_for_verdict`, `receipt_write_outcome_value_for_verdict`
  - map a `chio_kernel::Verdict` to its outcome label or typed variant.
- `render_receipt_writer_liveness(liveness_label, healthy)` - render the
  writer-health gauges.
- Constants: `CHIO_RECEIPT_WRITE_TOTAL` (re-exported from `chio-metrics-spec`),
  `CHIO_RECEIPT_WRITER_HEALTHY`, `CHIO_RECEIPT_WRITER_LIVENESS`,
  `RECEIPT_WRITE_OUTCOME_ALLOW` / `_DENY` / `_PENDING_APPROVAL` / `_ERROR`.

## Usage

```rust
use chio_edge_metrics::{ReceiptWriteCounters, RECEIPT_WRITE_OUTCOME_ALLOW};

static COUNTERS: ReceiptWriteCounters = ReceiptWriteCounters::new();

COUNTERS.record(RECEIPT_WRITE_OUTCOME_ALLOW);
let body = COUNTERS.render_prometheus();
```

## Testing

`cargo test -p chio-edge-metrics`

## See also

- `chio-metrics-spec` - declares `chio_receipt_write_total`'s name and shape in
  the workspace registry; this crate re-exports the name and implements the
  counter.
- `chio-mcp-edge`, `chio-acp-edge`, `chio-a2a-edge` - each owns a `static
  ReceiptWriteCounters` and delegates recording and rendering here.
- `chio-kernel` - source of the `Verdict` this crate maps to outcomes.
