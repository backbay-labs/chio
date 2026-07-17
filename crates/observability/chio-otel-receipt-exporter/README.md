# chio-otel-receipt-exporter

Turns OpenTelemetry trace batches into signed Chio trace-observation receipts.
The crate owns a narrow OTLP trace representation, a bounded ingress queue,
span provenance validation, the Prometheus high-cardinality attribute
deny-list, and the sink that signs and appends receipts to a
`chio_kernel::receipt_store::ReceiptStore`.

## Responsibilities

- Hold OTLP trace batches in a crate-local shape (`OtlpGrpcTraceExport`,
  `OtlpResourceSpans`, `OtlpSpan`, `OtlpAttribute`); protobuf/gRPC decoding is
  the caller's job, not this crate's.
- Queue batches in a bounded, drop-oldest queue limited by batch count, span
  count, and estimated byte size, and drain them with resumable retry on
  transient store failures.
- Validate span provenance before signing: trace/span id shape, a required
  `chio.verdict`, routing attribute overrides, and source `chio.receipt.id`
  correlation shape.
- Strip the high-cardinality attributes (`gen_ai.tool.call.id`,
  `chio.receipt.id`, `chio.replay.run_id`, `chio.tenant.id`) before they reach
  receipt metadata or a Prometheus-shaped sink.
- Sign each accepted span into a `TraceObservation` / `DetectOnly` receipt and
  append it through a pluggable `CanonicalReceiptSink`.

## Public API

- `OtlpGrpcIngress` - synchronous facade over the bounded queue: `export`,
  `enqueue`, `drain`, `snapshot`.
- `BoundedOtlpGrpcIngress` - the queue engine `OtlpGrpcIngress` wraps, for
  callers that need enqueue and drain decoupled from a single `export` call.
- `OtlpGrpcTraceExport`, `OtlpResourceSpans`, `OtlpSpan`, `OtlpAttribute` - the
  OTLP trace shape.
- `OtlpExporterQueueConfig`, `OtlpExporterQueueSnapshot`,
  `OtlpExporterEnqueueSummary`, `BoundedOtlpExportSummary` - queue tuning and
  observability.
- `ReceiptStoreSink`, `ReceiptStoreSinkConfig`, `ReceiptStoreSinkSummary` - the
  validate-sign-append path from one `OtlpSpan` to one signed receipt.
- `CanonicalReceiptSink`, `CanonicalChioReceipt` - the append trait and the
  cached (receipt, canonical bytes) pair passed to it.
- `OTelReceiptExportError` - `InvalidSpan`, `Canonical`, and `Sign` are
  terminal; `Queue` and `ReceiptStore(Pool)` are retryable.
- `denylist::{PROMETHEUS_DENIED_ATTRIBUTES, is_denied_attribute,
  denied_attribute_keys, strip_denied_attributes, strip_denied_span_attributes,
  strip_denied_batch_attributes}`.
- `METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL`, `METRIC_CHIO_OTEL_SINK_DROP_TOTAL` -
  metric name constants re-exported from `chio-kernel`.

## Usage

```rust
use chio_core::crypto::Keypair;
use chio_otel_receipt_exporter::{
    OtlpGrpcIngress, OtlpGrpcTraceExport, OtlpSpan, ReceiptStoreSink, ReceiptStoreSinkConfig,
};

// receipt_store: Arc<dyn chio_kernel::receipt_store::ReceiptStore>
let sink = ReceiptStoreSink::new(receipt_store, ReceiptStoreSinkConfig::new(Keypair::generate()));
let ingress = OtlpGrpcIngress::new(sink);

let span = OtlpSpan::new(trace_id, span_id, "gen_ai.tool.call")
    .with_attribute("chio.verdict", serde_json::json!("allow"));
let summary = ingress.export(&OtlpGrpcTraceExport::from_spans(vec![span]))?;
```

## Testing

`cargo test -p chio-otel-receipt-exporter` runs the unit, integration, and
proptest suites. The bounded-queue concurrency model is loom-only and
excluded by default:

```
RUSTFLAGS="--cfg loom" cargo test -p chio-otel-receipt-exporter --test loom_ring_sender_vs_shutdown
```

`--cfg loom` also drops `chio-core`, `chio-kernel`, `chio-metrics-spec`,
`serde`, `serde_json`, `thiserror`, and `uuid` from the build (see
`[target.'cfg(not(loom))'.dependencies]` in `Cargo.toml`) and makes
`queue_core` a public module so the loom test can reach it directly.

## See also

- `chio-kernel` - owns `ReceiptStore`, the `otel` attribute name constants,
  and the re-exported metric name constants.
- `chio-core` - owns receipt and canonical JSON types, signing, and receipt id
  derivation.
- `chio-metrics-spec` - owns the `chio_otel_ingress_drop_total` and
  `chio_otel_sink_drop_total` counter families this crate increments.
