# Healthcare Pilot Capacity

This crate is the sustained-load capacity harness for the healthcare
design-partner pilot. It is a sibling of `bench/ttfrh`, but the goal is
different: TTFRH measures first-receipt happy path latency, while this harness
records whether the healthcare pilot stays inside BOUNDED_OPERATIONAL_PROFILE
at 1x, 2x, and 5x replayed shadow load.

## Inputs

The planning baseline is 25,000 receipts per day. This number is replaced with
a 24-hour shadow capture when the design-partner tee is available.

Required inputs:

- baseline receipts per day
- p50 mediation latency
- p95 mediation latency
- p99 mediation latency
- receipt-write throughput
- trust-control convergence time
- chio-siem exporter backpressure

## Output

The crate emits a deterministic `CapacityReport` with one row for:

- 1x baseline replay
- 2x replay
- 5x replay

Each row includes p50, p95, p99, receipt-write throughput,
trust-control convergence, exporter backpressure, and whether the row stays
inside the bounded profile.

## Gate

Run the local gate with:

```bash
cargo build -p healthcare-pilot-capacity --quiet
cargo clippy -p healthcare-pilot-capacity -- -D warnings
```

The generated 1x / 2x / 5x report feeds the audit documentation and quota lane
sizing guidance. Spikes beyond 5x are incident material, not a hidden expansion
of the release boundary.
