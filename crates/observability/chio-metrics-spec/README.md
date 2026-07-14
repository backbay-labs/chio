# chio-metrics-spec

Authoritative, workspace-wide registry of Prometheus metric names for Chio's
SRE surfaces. Every emitted metric name is declared here first as a
`MetricDescriptor`, then consumed by other crates as a constant instead of an
inlined string literal, so a metric-taxonomy change goes through one
reviewable place: this crate's `REGISTRY` and its golden `metrics.snapshot`.

The crate has no dependencies, internal or external, beyond `std`, so any
crate in the workspace, including WASM guest code and edge transports, can
depend on it without growing its build graph.

## Responsibilities

- Declare each Chio metric name as a `pub const &str` and its shape (kind,
  help text, labels, histogram buckets) as a `MetricDescriptor` entry in the
  sorted, deduplicated `REGISTRY` slice (57 descriptors).
- Validate descriptor shape fail-closed: Prometheus-safe metric and label
  names, no duplicate labels per descriptor, histogram buckets present,
  finite, and strictly increasing, and non-histogram kinds carrying no
  buckets.
- Render a deterministic text snapshot of `REGISTRY` so a taxonomy change
  shows up as a reviewable diff against `metrics.snapshot` and fails CI
  otherwise.
- Provide `runtime`: process-global counter/gauge/histogram storage that
  renders its `# HELP`/`# TYPE` header straight from the registry
  descriptor, so a family's exposed metadata cannot drift from its
  declaration.

## Public API

- `MetricKind`, `MetricDescriptor`, `MetricValidationError` - the descriptor
  model.
- `describe!` - builds a `MetricDescriptor` from a name constant plus literal
  help/kind/labels/buckets; used to build `REGISTRY`.
- `REGISTRY` - the sorted slice of every registered descriptor.
- `descriptor_for`, `is_registered_metric` - registry lookup.
- `validate_metric_descriptor`, `validate_registry` - shape validation.
- `is_prometheus_metric_name`, `is_prometheus_label_name` - name predicates
  (labels reject the `__` reserved prefix).
- `registry_snapshot` - deterministic `name|kind|labels|buckets|help` dump,
  one line per descriptor, checked against `metrics.snapshot`.
- `CHIO_*` constants - one per registered metric name.
- `*_BUCKETS_SECONDS` constants - 10 named histogram bucket-bound arrays for
  consumers that register their own storage against this crate's shape
  instead of using `runtime`.
- `runtime::{LabeledCounter, LabeledGauge, LabeledHistogram}` - process-global
  emission primitives keyed by an ordered label tuple.
- `runtime::families` - the static instances for the guard, OTEL-drop,
  receipt-watchdog, signing-queue, and alert-pack families.
- `runtime::{render_guard_families, render_otel_drop_families,
  render_receipt_watchdog_gauges, render_alert_pack_families,
  compose_metrics_body, preregister_known_label_sets}`.

## Usage

```rust
use chio_metrics_spec::{is_registered_metric, CHIO_GUARD_EVALUATIONS_TOTAL};
use chio_metrics_spec::runtime::families::GUARD_VERDICT;

assert!(is_registered_metric(CHIO_GUARD_EVALUATIONS_TOTAL));
GUARD_VERDICT.incr(&["policy-guard", "allow"]);
```

## Testing

`cargo test -p chio-metrics-spec`

Changing a descriptor's name, kind, labels, buckets, or help text changes
`registry_snapshot()`'s output and must be reflected in `metrics.snapshot`, or
the golden snapshot test fails.

## See also

- `chio-kernel` - renders the guard, OTEL-drop, and receipt-watchdog families
  and the signing-queue-block counter at its `/metrics` endpoint.
- `chio-wasm-guards` - producer for the guard-family runtime statics.
- `chio-wall`, `chio-api-protect`, `chio-control-plane`, `chio-mcp-remote` -
  render the alert pack at their own `/metrics` endpoints.
- `chio-conformance` - runs the production emission path per edge and fails
  if a registered name is declared but never actually emitted.
