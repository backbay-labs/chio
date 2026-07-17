# chio-loadgen

Real-stack sustained-load harness for the Chio kernel and its durable receipt
store. This crate replaces the former synthetic `sustained_p99_30min` bench,
which timed a local `VecDeque` loop and constructed no product types.

## What it boots

`StackHarness::boot` starts a live `chio_kernel::ChioKernel` wired to a real
`chio_store_sqlite::SqliteReceiptStore` and a configurable-latency stub tool
server, then drives allow-path dispatches through the unmodified kernel
evaluation pipeline. The gating boot refuses a non-durable in-memory store
(`MemoryStoreRejectedInGate`) so a run cannot claim durability it does not have;
`boot_smoke` relaxes that only for local smoke checks.

## What it asserts

`run_sustained` paces dispatches at the target arrival rate for the configured
duration, measures per-call end-to-end latency (p50/p99) over the allow-verdict
dispatches, and samples resident-set size. `enforce_budget` is the fail-closed
gate: it denies with `P99Exceeded` when measured p99 is over budget and with
`RssGrowthExceeded` when resident-set growth is over budget. Every fallible boot
and dispatch path yields a typed `LoadgenError` and denies; there is no
silent-success path and no `unwrap`/`expect`.

## Env knobs (sustained gate binary)

The gate binary `src/bin/sustained.rs` reads:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CHIO_SUSTAINED_P99_SECONDS` | `30` | sustained-phase duration in seconds |
| `CHIO_LOADGEN_RATE_HZ` | `200` | target dispatch arrival rate |
| `CHIO_LOADGEN_P99_BUDGET_MS` | `50` | p99 end-to-end ceiling |
| `CHIO_LOADGEN_RSS_BUDGET_MB` | `64` | resident-set growth ceiling |

A present-but-unparseable knob denies rather than falling back to the default.

## Run locally

```bash
# Short local run against the real stack (30s default):
cargo run -p chio-loadgen --release --bin sustained

# Longer run with a tighter budget:
CHIO_SUSTAINED_P99_SECONDS=120 CHIO_LOADGEN_P99_BUDGET_MS=40 \
  cargo run -p chio-loadgen --release --bin sustained

# Unit and integration tests (boot rejection, pacer, percentiles):
cargo test -p chio-loadgen
```

The nightly lane `.github/workflows/sustained-p99-nightly.yml` runs this gate
binary (`cargo run -p chio-loadgen --release --bin sustained`) with a longer
`CHIO_SUSTAINED_P99_SECONDS`.

## Scope caveats

- `exporter_queue_high_water` is always `None`. The load generator's dispatch
  path does not traverse the OTLP ingress queue, so there is no live exporter
  queue to snapshot; the field is carried as `None` rather than reporting a
  depth the run did not produce.
- `rss_start_bytes` / `rss_end_bytes` are `None` on platforms without a
  resident-set sampler. They are never fabricated, and an absent sampler cannot
  prove an RSS-growth budget violation.
- The kernel is booted with `DispatchIntentJournalMode::Off`, matching the
  current deployment posture. The measured allow path therefore skips the
  RFC-0003 durable dispatch-intent write and consume; a latency regression
  confined to the journal-on posture is invisible to this lane until a
  journal-on knob is added.
- This is the sustained-lane cutover. A healthcare replay mode and a dedicated
  time-to-first-receipt-hardened measurement mode named in the load-soak-chaos
  plan are not implemented here.
