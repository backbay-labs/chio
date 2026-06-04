# chio-otel-receipt-exporter Architecture

`chio-otel-receipt-exporter` turns OpenTelemetry trace exports into signed Chio
trace-observation receipts. It owns the crate-local OTLP trace shape, bounded
ingress queue, Prometheus high-cardinality deny-list, and receipt-store sink
adapter used by collectors and offline tests.

## Boundaries

- `chio-kernel` owns the locked OpenTelemetry attribute names, metric constants,
  and receipt-store trait consumed by this crate.
- `chio-core` owns canonical JSON, signing keys, receipt semantics, receipt id
  derivation, and tool-call action hashing.
- `denylist` owns the exact high-cardinality attribute keys stripped before
  Prometheus-shaped sinks or receipt metadata receive span attributes.
- `ingress` owns the narrow OTLP trace representation, byte estimation, bounded
  drop-oldest queue, retryable append failure handling, and queue snapshots.
- `sink` owns batch limit validation, span provenance validation, receipt
  construction, canonicalization, signing, and append calls.
- This crate does not own OTLP wire decoding, trace collection, receipt-store
  persistence, policy evaluation, or metric export transport.

## Trust Invariants

- Trace ids and span ids must be non-zero lowercase hex with OTLP lengths before
  any receipt is signed.
- `chio.verdict` is required and must be one of `allow`, `deny`, or
  `incomplete`; malformed verdict spans reject before appending.
- Source `chio.receipt.id` correlations must match Chio's authoritative
  lowercase 64-hex receipt id shape before metadata records them.
- Routing attributes that override capability id, tool server, or tool name must
  be non-empty unpadded strings.
- Oversized batches reject before span processing so partial appends cannot
  occur inside a single export.
- Retryable receipt-store failures stay queued; nonretryable invalid-span
  failures are counted and dropped.
- Tenant identity is only taken from sink configuration, never from OTLP span
  attributes.

## Testing Focus

Integration tests cover OTLP span to receipt signing, tenant spoofing rejection,
batch atomicity, oversized batch rejection, malformed verdict rejection,
malformed routing rejection, malformed receipt correlation rejection, and
high-cardinality attribute stripping. Unit tests cover canonical receipt bytes,
bounded queue overload behavior, retryable append retention, and nonretryable
invalid-span drops. The loom test models sender and shutdown interleavings for
the bounded queue core when compiled with `--cfg loom`.
