# chio-otel-receipt-exporter architecture

## Overview

This crate is the boundary where OpenTelemetry trace data, which may
originate outside Chio's trust boundary (an instrumented tool, agent, or
collector), becomes an entry in the signed receipt log. It runs as a separate
ingress path, not inside the kernel process, but it holds a real signing
keypair and the receipts it appends are indistinguishable from any other
receipt once in the store, so it must validate span provenance before
signing. The core design idea is splitting a pure, retry-safe prepare step
(validate and sign once per batch) from an at-least-once, resumable append
step, so a receipt-store outage never re-signs or double-mints a receipt that
was already generated.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Declares the public modules and re-exports the public API; `#![forbid(unsafe_code)]`. |
| `src/denylist.rs` | The Prometheus high-cardinality attribute deny-list and the strip functions applied to attributes, spans, and batches. |
| `src/ingress.rs` | The OTLP trace shape, `OtlpGrpcIngress` facade, `BoundedOtlpGrpcIngress` queue engine, queue config/summary/snapshot types, and byte estimation. |
| `src/queue_core.rs` | `BoundedDropOldestQueue<T: BoundedQueueItem>`: the generic bounded, drop-oldest queue with push/pop/snapshot accounting. `pub` only under `--cfg loom` (so the loom test can reach it); otherwise a private module used by `ingress.rs`. |
| `src/sink.rs` | `ReceiptStoreSink`: span validation, receipt construction, canonicalization, signing, and append; `OTelReceiptExportError`; the `CanonicalReceiptSink` trait. |

## Export lifecycle

1. A caller (an OTLP gRPC listener or offline tooling, outside this crate)
   decodes protobuf into an `OtlpGrpcTraceExport`.
2. `OtlpGrpcIngress::export` takes the `flow_lock` and enqueues the batch into
   `BoundedOtlpGrpcIngress`'s `BoundedDropOldestQueue`. Admission rejects the
   batch outright (`dropped_incoming_*`) if it alone exceeds
   `max_queued_spans` or `max_queued_bytes`, or if `max_queued_batches` is 0;
   otherwise it evicts queued batches from the front (`dropped_oldest_*`)
   until the new batch fits. Defaults: 1024 queued batches, 65,536 queued
   spans, 64 MiB queued bytes, 128 batches per drain (`OtlpExporterQueueConfig::default`).
3. `drain_locked` processes up to `drain_limit` queued batches. For the front
   item, `prepare_front` calls `ReceiptStoreSink::prepare_receipts` once
   (validates batch limits, then per span: id shape, `chio.verdict`, routing
   attributes, and source receipt-id correlation; strips denylisted
   attributes; builds and signs a `ChioReceipt`) and caches the result plus
   its estimated resident size on the queued item.
4. `ReceiptStoreSink::append_from` appends `prepared[appended..]` one at a
   time through the `CanonicalReceiptSink`, advancing the `appended` cursor
   after each success.
5. On full-batch success the batch is popped and counted once. On a retryable
   error (`OTelReceiptExportError::Queue` or `ReceiptStoreError::Pool`) the
   batch, its prepared receipts, and its resume cursor stay queued for the
   next `drain`. On any other error the batch is popped and dropped, and
   `chio_otel_sink_drop_total` increments.
6. `OtlpGrpcIngress::snapshot` / `BoundedOtlpGrpcIngress::snapshot` expose
   queue depth and accepted/dropped/appended/error counters for
   observability.

## Invariants and failure modes

- `trace_id` must be 32, and `span_id` 16, non-zero lowercase hex characters;
  anything else rejects before any receipt is prepared.
- `chio.verdict` is required and must be `allow`, `deny`, or `incomplete`;
  missing, wrong-case, or non-string values reject the span.
- A source `chio.receipt.id` attribute, if present, must be 64 lowercase hex
  characters or the span rejects; this correlates a trace-observation receipt
  back to the receipt that produced the span.
- Routing overrides (`chio.capability.id`, the server id, `gen_ai.tool.name`),
  if present, must be non-empty and unpadded (`value.trim() == value`) or the
  span rejects; absent overrides fall back to `ReceiptStoreSinkConfig`'s
  default capability id, tool server, and tool name.
- Batch limits are checked before any span is processed, so a batch that
  exceeds `RECEIPT_EXPORT_MAX_RESOURCE_SPANS` (4,096), `RECEIPT_EXPORT_MAX_SPANS`
  (65,536), or `RECEIPT_EXPORT_MAX_ESTIMATED_BYTES` (64 MiB) rejects atomically,
  never partially.
- Tenant identity comes only from `ReceiptStoreSinkConfig::tenant_id`. A
  `chio.tenant.id` span attribute is denylisted and never reaches the receipt
  or its metadata, so a span cannot spoof its tenant.
- Every receipt this crate emits has `receipt_kind: TraceObservation`,
  `boundary_class: DetectOnly`, and `decision: None`; it never emits a policy
  decision receipt.
- A batch's pre-signature receipt ids (`otel-<uuidv7>`) are generated once and
  cached; a retryable failure resumes append at the same cursor with the same
  ids rather than re-signing (checked by the `otel_retry_idempotence`
  proptest).
- Mutex poisoning on the queue or flow lock fails closed with
  `OTelReceiptExportError::Queue` rather than panicking; `unwrap_used` and
  `expect_used` are denied crate-wide.

## Dependencies

- `chio-core` - `Keypair` and receipt signing, `canonical::CanonicalBytes`,
  `sha256_hex`, and the `ChioReceipt`/`ChioReceiptBody`/`ToolCallAction`/kind
  types this crate constructs and signs. Owns receipt id derivation.
- `chio-kernel` - the `ReceiptStore`/`ReceiptStoreError` trait this crate
  appends through, the `otel` OTLP attribute name constants, and the metric
  name constants re-exported at the crate root.
- `chio-metrics-spec` - the `OTEL_INGRESS_DROP` and `OTEL_SINK_DROP` counter
  families incremented directly by `ingress.rs`.
- `serde` / `serde_json` - the OTLP shape and attribute values.
- `thiserror` - `OTelReceiptExportError`.
- `uuid` (`v7` feature) - `Uuid::now_v7()` for pre-signature receipt ids.
- All of the above are compiled only `cfg(not(loom))`; the `--cfg loom` build
  depends on nothing but `loom` itself plus `std`.

## Extension points

`CanonicalReceiptSink` is the trait a consumer implements to plug in a custom
receipt destination instead of a `ReceiptStore`. `ReceiptStoreSink::new` /
`from_receipt_store` adapt an `Arc<dyn ReceiptStore>`; `ReceiptStoreSink::new_canonical`
takes an `Arc<dyn CanonicalReceiptSink>` directly, which is how the test
suite substitutes recording and failing sinks.
