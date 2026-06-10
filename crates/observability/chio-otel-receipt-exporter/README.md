# chio-otel-receipt-exporter

`chio-otel-receipt-exporter` is the OpenTelemetry trace ingress and
receipt-store sink for Chio. It accepts OTLP trace batches in a narrow Rust
representation, signs span-derived Chio receipts, appends them to a configured
receipt store, and exposes the high-cardinality attribute deny-list applied
before forwarding span attributes to Prometheus-shaped sinks.

Use this crate to turn OpenTelemetry spans into signed Chio receipts and bridge
trace data into the receipt log.
