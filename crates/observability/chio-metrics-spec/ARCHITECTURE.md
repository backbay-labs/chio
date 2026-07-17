# chio-metrics-spec architecture

## Overview

`chio-metrics-spec` is a pure library crate: no I/O, no runtime state beyond
process-local metric storage, and no dependencies beyond `std`. It has two
roles. `src/lib.rs` is the compile-time authority: a sorted registry of
`MetricDescriptor`s, fail-closed shape validation, and a deterministic
snapshot renderer used as a CI gate against taxonomy drift. `src/runtime.rs`
is an optional runtime layer: process-global counter/gauge/histogram storage
for the subset of registered families that a serving surface composes
directly from this crate instead of through its own storage.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `MetricKind`, `MetricDescriptor`, `MetricValidationError`; the `describe!` macro; every `CHIO_*` name and `*_BUCKETS_SECONDS` constant; the sorted `REGISTRY`; `descriptor_for`/`is_registered_metric` lookup; `is_prometheus_metric_name`/`is_prometheus_label_name` predicates; `validate_metric_descriptor`/`validate_registry`; `registry_snapshot`. |
| `src/runtime.rs` | `LabeledCounter`/`LabeledGauge`/`LabeledHistogram`; the `families` module of process-global static instances; `preregister_known_label_sets`; the `render_*_families` functions and `compose_metrics_body`. |

## Declaration and emission paths

Declaring a metric (compile time, reviewed in CI):

1. Add a `CHIO_*` name constant.
2. Add a `describe!()` entry to `REGISTRY` in sorted position.
3. `validate_registry`/`validate_metric_descriptor` enforce shape in tests,
   and `registry_snapshot()` must match `metrics.snapshot` or the golden test
   fails, turning the taxonomy change into a reviewable diff.

Emitting a `runtime`-backed family (process lifetime):

1. A producer crate (`chio-wasm-guards` for the guard families) calls
   `.incr`/`.observe`/`.set` on a `runtime::families` static with an ordered
   label-value tuple.
2. The static resolves the label-keyed cell through a `Mutex<BTreeMap<...>>`;
   each cell is an `Arc` around plain atomics, so the counter increment,
   gauge store, or histogram bucket update on an already-resolved cell is a
   lock-free atomic op.
3. A serving surface calls the matching `render_*_families` function, which
   reads `descriptor_for` for the `# HELP`/`# TYPE` header and renders every
   cell. `chio-kernel` composes the guard, OTEL-drop, and receipt-watchdog
   families (plus the signing-queue-block counter directly); `chio-wall`,
   `chio-api-protect`, `chio-control-plane`, and `chio-mcp-remote` each
   compose the alert pack (`chio-wall` also composes receipt-watchdog).
   `compose_metrics_body` concatenates render sources into one body.

Not every `REGISTRY` descriptor has a `runtime::families` static. Metrics
outside the kernel-composed set (pheromone gossip, federation transport,
receipt writes, decision latency, sidecar requests, and others) are declared
here for their name and shape only; the owning crate stores its own samples,
for example `chio-http-core` and `chio-federation` build their own atomics
keyed off `DECISION_LATENCY_BUCKETS_SECONDS` and
`FEDERATION_HOP_LATENCY_BUCKETS_SECONDS`.

## Invariants and failure modes

- `REGISTRY` stays sorted by name and unique; `validate_registry` checks both
  and the test suite asserts it directly.
- Non-histogram descriptors (`Counter`, `Gauge`) carry no buckets; `Histogram`
  descriptors require at least one bucket, each parseable as a finite `f64`
  and strictly increasing.
- Metric names must start with an ASCII letter, `_`, or `:` and contain only
  ASCII alphanumerics, `_`, or `:`. Label names must start with an ASCII
  letter or `_`, contain only ASCII alphanumerics or `_`, and reject the `__`
  prefix Prometheus reserves internally. Labels are unique within one
  descriptor.
- `runtime` primitives fail closed: a label-arity mismatch or a poisoned
  cell-map mutex drops the sample instead of panicking, so a bad emission
  call never unwinds the caller's hot path.
- Histogram `le` labels render the descriptor's original bucket string, not a
  reparsed `f64`, so a `"1.0"` bucket never collapses to `le="1"` and
  fragments a series between the runtime renderer and anything else keyed on
  the registry string.
- Label values are escaped for backslash, double quote, and line feed before
  rendering, so an embedded newline cannot split one sample into two physical
  lines or forge a second series.
- `preregister_known_label_sets` seeds a fixed set of label combinations at
  zero at startup so `absent_over_time` alerting fires only on a genuine
  scrape gap. Label domains that are deployment-configured (DLQ, SOC export,
  alert-dispatch route) are seeded by the SIEM serve mode instead, not by
  this crate.

## Dependencies

None. `[dependencies]` is empty; `runtime` uses only `std::collections` and
`std::sync`. Staying dependency-free lets nearly any crate in the workspace,
including ones that must stay minimal, depend on it without pulling in an
exporter or an async runtime.
