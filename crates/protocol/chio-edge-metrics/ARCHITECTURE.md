# chio-edge-metrics architecture

## Overview

`chio-edge-metrics` is a pure, synchronous library: no I/O, no async runtime,
no shared global state of its own. It exists to deduplicate one thing across
Chio's protocol edges: the receipt-write counter and its Prometheus rendering.
Each edge (`chio-mcp-edge`, `chio-acp-edge`, `chio-a2a-edge`) sits at an
untrusted boundary and must expose the same `chio_receipt_write_total` series
after every kernel-mediated response; rather than three copies of the same
atomic-counter and rendering code, the logic lives here once and each edge
supplies its own storage.

## Module map

Single-file crate. `src/lib.rs` holds the outcome taxonomy,
`ReceiptWriteCounters`, the snapshot/sample types, the verdict mapping, and
the Prometheus renderers for both the receipt-write counters and the
writer-liveness gauges.

## Recording and rendering path

1. An edge crate declares `static COUNTERS: ReceiptWriteCounters =
   ReceiptWriteCounters::new();` in its own `metrics` module.
2. On each kernel response the edge calls `COUNTERS.record_verdict(verdict)`
   (mapping a `chio_kernel::Verdict`) or `record_outcome`/`record` directly.
   Recording increments one of four `AtomicU64` fields via `fetch_update` with
   `saturating_add`, so a counter caps at `u64::MAX` instead of wrapping.
3. The edge's own metrics endpoint calls `COUNTERS.render_prometheus()` for
   the `chio_receipt_write_total` series, and separately
   `render_receipt_writer_liveness(label, healthy)` for the
   `chio_receipt_writer_healthy` / `chio_receipt_writer_liveness` gauges,
   passing its serving kernel or store's own liveness state.
4. Rendering walks `ReceiptWriteSnapshot::samples()`, which returns all four
   outcomes in the fixed order `[Allow, Deny, PendingApproval, Error]`, so
   exposition output is deterministic across scrapes.

## Invariants and failure modes

- `record` and `total` fail closed on an unrecognized outcome label:
  `ReceiptWriteOutcome::from_label` returns `None`, and both fall back to the
  error bucket rather than silently dropping the sample.
- Counters saturate at `u64::MAX`; they never wrap.
- This crate holds no counter state of its own (no `static`, no global
  registry): per-edge isolation is a property of each edge declaring its own
  `ReceiptWriteCounters` instance. This crate's test suite proves two
  instances stay independent (`counters_are_isolated_per_instance`);
  `chio-conformance`'s `metrics_registry_consumed.rs` proves the same holds
  for real MCP/ACP/A2A dispatches (an ACP or A2A call does not advance the
  MCP counter, and vice versa).
- `#![forbid(unsafe_code)]`.

## Dependencies

`chio-kernel` supplies the `Verdict` enum this crate maps to outcomes.
`chio-metrics-spec` owns `CHIO_RECEIPT_WRITE_TOTAL`'s registered name and
shape; this crate re-exports the constant rather than redeclaring the string.
`chio-metrics-spec` documents receipt-write metrics as declared there for name
and shape only, with the owning crate storing samples; `chio-edge-metrics` is
that owning implementation, shared by the MCP, ACP, and A2A edges instead of
duplicated across them. No other dependencies.
