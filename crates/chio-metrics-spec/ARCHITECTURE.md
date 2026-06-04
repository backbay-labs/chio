# chio-metrics-spec Architecture

## Boundary

`chio-metrics-spec` is the workspace authority for Prometheus metric family names and descriptor metadata. Emitters in other crates import names from this crate instead of creating local string literals, which keeps dashboards, alerts, and conformance tests tied to one taxonomy.

The crate owns metric descriptors, validation rules, and snapshot rendering. It does not collect samples, expose HTTP endpoints, or depend on any runtime exporter. Runtime crates can consume the constants without pulling in exporter policy.

## Descriptor Model

The crate has no runtime dependencies. It exposes descriptor constants, lookup helpers, Prometheus name predicates, a deterministic snapshot renderer, and descriptor validation. The snapshot file is the review surface for taxonomy changes; the validator is the semantic gate for data that Prometheus clients cannot safely repair later.

Metric names must be globally sorted and unique. Labels must be valid Prometheus identifiers and unique within a metric. Counters, gauges, and histograms share one descriptor type so validation can reason across the full registry.

## Histogram Policy

Histogram buckets stay as strings because downstream exporters use textual bucket boundaries. Validation still parses them as finite numbers and requires strict ascending order so an updated snapshot cannot bless duplicate, nonsensical, or unsorted SLO buckets.

## Invariants

- Metric family names are added here before use elsewhere.
- The registry snapshot is deterministic and reviewable.
- Non-histogram metrics must not carry buckets.
- Histogram buckets must be finite and strictly increasing.
- The crate must remain dependency-light enough for broad workspace reuse.
