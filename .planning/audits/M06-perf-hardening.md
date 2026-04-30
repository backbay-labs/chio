# M06 Performance Hardening Audit Baseline

This doc captures the starting state for the M06 performance hardening pack.
The milestone is about retiring repeated serialization, unbounded or unaudited
queue behavior, one-transaction-per-insert SQLite writes, and fresh Wasmtime
instantiation on every guard call. It is not a feature milestone.

Source-of-truth: `.planning/trajectory-2/06-performance-hardening-pack.md`.
Snapshot date: 2026-04-29.

## Starting counts

| Surface | Starting count | Audit note | Exit direction |
|---------|---------------:|------------|----------------|
| `canonical_json_bytes` direct serialization sites in the hot-path core-types files | 10 | The milestone narrative lists 8. The current worktree has 10 direct calls in `crates/chio-core-types/src/{receipt,capability,session,crypto}.rs` after excluding imports, function declarations, and the public wrapper body. | P1 should canonicalize once per receipt dispatch and thread `Arc<CanonicalBytes>` through signing, store, and exporter paths. |
| `CanonicalBytes` API surface | 0 | `crates/chio-core-types/src/canonical.rs` exposes `canonical_json_bytes(value: &T) -> Result<Vec<u8>>` and `canonical_json_string(value: &T) -> Result<String>`. No witnessed byte newtype exists yet. | Add `CanonicalBytes` as the witnessed canonical buffer type. |
| `InstancePre` references in `crates/chio-wasm-guards/src/runtime.rs` | 0 | `runtime.rs` is 2688 lines in this worktree. Wasmtime is present, but no `wasmtime::InstancePre` cache exists. | Add an `InstancePre` cache keyed by guard module hash and invalidated by the existing `ArcSwap` reload path. |
| `r2d2` `max_size(8)` file-backed pool defaults | 5 | The current hits are `approval_store.rs`, `encrypted_blob.rs`, `execution_nonce_store.rs`, `memory_provenance_store.rs`, and `receipt_store/bootstrap.rs`. | Replace hard-coded writer contention with configured reader and writer pool bounds. |
| `crates/chio-store-sqlite/src/` Rust files | 21 | The milestone narrative listed 14 files. The larger current source set is the live audit baseline. | P3 should keep group-commit and pool-split work scoped to store surfaces that own receipt, revocation, approval, and adjacent file-backed pools. |
| OTEL receipt exporter Rust files | 4 | `denylist.rs`, `ingress.rs`, `lib.rs`, and `sink.rs`. | P2 should audit ingress and sink bounds before replacing them with bounded drop-oldest rings. |
| OTEL literal channel or send matches | 0 | `rg -n "channel|mpsc|unbounded|Sender::send|send\\(" crates/chio-otel-receipt-exporter/src` returns no matches. The current facade is synchronous: `OtlpGrpcIngress::export` calls `ReceiptStoreSink::export_traces`, which appends directly to the receipt store. | P2 owns the wrapper-level queue design and must emit drop counters where backpressure is introduced. |

## CanonicalBytes API Surface Decision

Decision: `CanonicalBytes` is !Clone. `Arc<CanonicalBytes>` is the sharing
primitive.

Rationale:

- `CanonicalBytes` represents bytes that came from the Chio canonicalizer and
  are suitable for signing, hashing, store persistence, and export. Copying
  that buffer by default would hide the exact allocation class this milestone
  is trying to remove.
- `Arc<CanonicalBytes>` gives cheap sharing across the signing task, SQLite
  store, and OTEL exporter while preserving a single owned canonical buffer.
- Move-only extraction remains explicit through an owned method such as
  `into_vec(self) -> Vec<u8>`. Borrowing remains cheap through
  `as_slice(&self) -> &[u8]` or `AsRef<[u8]>`.
- Constructors must fail closed. If serialization or canonical validation
  fails, no witnessed value is produced.

Expected P1 surface:

```rust
pub struct CanonicalBytes {
    bytes: Vec<u8>,
    _witness: CanonicalJsonWitness,
}

impl CanonicalBytes {
    pub fn from_value<T: serde::Serialize>(value: &T) -> Result<Self>;
    pub fn as_slice(&self) -> &[u8];
    pub fn into_vec(self) -> Vec<u8>;
}
```

Do not derive or implement `Clone` for `CanonicalBytes`. Callers that need
shared ownership must receive or create `Arc<CanonicalBytes>`.

## Reference Runner Contract

M06 bench additions reuse the trajectory-1 M05 reference runner contract:

- 4-core Linux runner.
- Warm cache before measurement.
- In-memory stores for canonical bytes and guard checkout benches unless the
  benchmark specifically measures file-backed SQLite behavior.
- Criterion 100-sample median with 95 percent CI on the diff.
- Existing 10 percent regression tolerance remains the CI comparison policy.
- Sustained p99 lanes must run separately from short Criterion samples and
  must report queue depth, drop counters, and allocation counts when relevant.
- Local laptop numbers are useful for diagnosis only. They are not release
  gates.

## Dhat Allocation-Count Baseline

dhat allocation-count baseline: `dispatch_allow_dhat` is a dhat harness
scaffold for the current placeholder M05 `dispatch_allow` probe. It currently
measures only `std::hint::black_box(0_u64)`, so the 0 total heap allocation
blocks and 0 total heap bytes baseline describes the placeholder probe, not the
real kernel dispatch, canonicalization, receipt signing, or reserialization
path. The M06 allocation-reduction evidence remains incomplete until this bench
exercises the real dispatch/canonicalization path and reports a numeric
allocation-count reduction attributable to reduced reserialization.

Run command:

```bash
cargo bench -p chio-kernel --features dhat-heap --bench dispatch_allow_dhat -- --test
```

The bench target keeps the global allocator swap behind the `dhat-heap` feature
and leaves a source-level `cfg(dhat)` hook so normal production builds and the
existing Criterion dispatch benches continue to use the default allocator.

## OTEL exporter channel audit

The live `chio-otel-receipt-exporter` source does not currently contain an
exporter channel. This matters because the trajectory text describes an
unaudited channel bound, while this worktree still has a synchronous facade
that pushes decoded OTLP trace batches directly into the receipt-store sink.

Current code paths:

- `crates/chio-otel-receipt-exporter/src/ingress.rs`: `OtlpGrpcIngress` owns a
  `ReceiptStoreSink`. `OtlpGrpcIngress::export` synchronously calls
  `self.sink.export_traces(request)`. There is no producer task, receiver
  task, channel handle, retry loop, queue depth counter, or explicit capacity
  in `ingress.rs`.
- `crates/chio-otel-receipt-exporter/src/sink.rs`:
  `ReceiptStoreSink::export_traces` maps every span to a
  `CanonicalChioReceipt`, collects the full batch into `Vec<_>`, and then
  appends receipts serially through
  `CanonicalReceiptSink::append_chio_receipt_canonical`. Validation,
  canonicalization, or signing failure during the collect phase appends zero
  receipts. A store error during the serial append loop can leave a prefix
  already appended because this layer does not wrap the batch in a transaction.

Current bounds and backpressure behavior:

- The literal channel audit remains zero for `channel`, `mpsc`, `unbounded`,
  and `send(` in `crates/chio-otel-receipt-exporter/src`. There is no hidden
  bounded queue in `ingress.rs` or `sink.rs`.
- Backpressure is caller-thread blocking. The network owner that decoded the
  OTLP request stays parked while the sink validates spans, canonicalizes span
  payloads, signs derived Chio receipts, and appends to the receipt store.
  Receipt-store pool contention or disk latency is surfaced as synchronous
  latency or error, not as an exporter queue signal.
- The effective input bound is whatever the upstream network and protobuf
  decode layer accepted before constructing `OtlpGrpcTraceExport`. Inside the
  exporter, one request can allocate decoded vectors, cloned attribute maps,
  sanitized attributes, canonical span bytes, signed receipts, and the
  collected receipt vector before the first append.
- There are no exporter-local span count, byte count, or batch count limits.
  There are also no exporter drop counters, enqueue failure counters, queue
  depth gauges, or sustained-load saturation signals for this path yet.

Next implementation notes:

- Put the lossy boundary in front of `ReceiptStoreSink`, either inside
  `OtlpGrpcIngress` or in a new wrapper exported from `lib.rs`. Keep
  `ReceiptStoreSink` as the deterministic validate, sign, and append worker so
  existing tests can continue to exercise it synchronously.
- Add explicit queue config for max queued batches, max queued spans, max
  queued bytes, and worker drain limit. If the implementation uses
  `tokio::sync::mpsc`, wrap it with drop-oldest ring accounting instead of
  relying on blocking `send`.
- Decide the queue item shape before coding. Prefer decoded span work items or
  bounded mini-batches over cloning whole unbounded `OtlpGrpcTraceExport`
  requests. Count dropped batches and dropped spans separately so one oversized
  batch cannot hide loss behind one event.
- Extend summaries or metrics to report accepted, enqueued, appended,
  dropped-oldest batches, dropped-oldest spans, current queue depth, and append
  errors. The sustained p99 lane should force saturation and prove nonzero
  drop counters plus stable memory under an oversized export request.
- Preserve the current fail-closed validation posture: invalid spans must not
  append derived receipts. Queue overflow is a deliberate exporter-loss path
  and must be observable; it must not be conflated with policy decisions or
  receipt-store durability failure.
- Add tests for empty export, invalid span before append, store append prefix
  failure, queue overflow drop-oldest order, worker shutdown with queued items,
  and metrics increments.

## Dependency Notes

- `wasmtime` is already present for `chio-wasm-guards`; the `InstancePre`
  cache should reuse that pin.
- `r2d2` is already present for `chio-store-sqlite`; M06 should split and
  configure pools rather than add a new pooling crate.
- `Arc<CanonicalBytes>` should avoid introducing a broader byte-buffer
  abstraction unless P1 proves `bytes = "1"` is required.
- The milestone narrative refers to `spec/vectors/canonical_json/`, but that
  directory is absent in this worktree. M06 treats this as a source-of-truth
  discrepancy. Before P1 can claim compliance, the intended corpus must be
  restored or a sanctioned M01 / trajectory amendment must change the
  requirement.

## Reproduction Commands

```bash
rg -n "canonical_json_bytes" crates/chio-core-types/src/{receipt,capability,session,crypto}.rs
rg -n "InstancePre" crates/chio-wasm-guards/src/runtime.rs
rg -n "max_size\\(8\\)" crates/chio-store-sqlite/src
find crates/chio-otel-receipt-exporter/src -maxdepth 1 -type f -name '*.rs' -print | sort
rg -n "channel|mpsc|unbounded|Sender::send|send\\(" crates/chio-otel-receipt-exporter/src
```

## Audit-Local Phase Tracking

- [x] P0.T1: Open this audit doc with starting counts, the reference-runner
  contract, and the `CanonicalBytes` API surface decision.
- [ ] P0.T2: Pin `dhat = "0.3"` and verify dependency resolution.
- [x] P0.T3: Confirm bench reference runner contract during bench scaffold
  wiring.
- [ ] P1: Add and migrate `Arc<CanonicalBytes>` through the hot path.
- [ ] P2: Bound OTEL exporter and signing queues with drop-oldest semantics.
- [ ] P3: Add SQLite group commit, `INSERT ... RETURNING`, and pool splits.
- [ ] P4: Add Wasmtime `InstancePre` cache and warmed-instance rings.
- [ ] P5: Extend allocation, bundle-size, and sustained-load regression gates.
- [x] P5.T1: Add `dispatch_allow_dhat` dhat harness scaffold and placeholder
  allocation-count baseline for the current `dispatch_allow` probe.
- [ ] P5.T1 evidence: Replace the placeholder probe with the real
  dispatch/canonicalization path and report allocation-count reduction
  attributable to reduced reserialization.

## Final after-counts

after-counts snapshot date: 2026-04-30.

| Surface | Starting count | After count | p99 delta note |
|---------|---------------:|------------:|----------------|
| `canonical_json_bytes` direct serialization sites in hot-path core-types files | 10 | 10 | p99 delta is not claimed for canonicalization in this closeout because the P5.T1 dhat harness still measures the placeholder dispatch probe rather than the real dispatch and signing path. |
| `InstancePre` references in `crates/chio-wasm-guards/src/runtime.rs` | 0 | 25 | p99 delta is now feedable through `guard_pool_checkout_p99/warm_tenant_checkout`, which exercises warmed tenant-ring checkout through `WasmtimeBackend::evaluate`. Reference-runner comparison owns the numeric delta. |
| `r2d2` `max_size(8)` file-backed pool defaults | 5 | 4 | p99 delta for SQLite write throughput is feedable through `store_receipt_write_throughput`; this audit pass does not claim a laptop-derived release number. |
| OTEL receipt exporter Rust files | 4 | 5 | p99 delta for exporter saturation remains unclaimed here because P2 introduced the queue boundary after the starting audit and sustained stack evidence needs seven consecutive nightly greens. |

## Final p99 and cache evidence

- `guard_pool_checkout_p99` is the P4.T6 Criterion feed for Wasm guard-pool
  checkout p99. The bench warms a tenant ring, verifies a nonzero warm size,
  then measures warmed checkout through the production evaluate path.
- `sustained_p99_30min` is the P5.T3 nightly lane. The ticket-local gate runs
  the one-second `--test` path; `.github/workflows/m06-sustained-p99-nightly.yml`
  sets `CHIO_M06_SUSTAINED_P99_SECONDS=1800` for the 30-minute scheduled run.
- Current cache hit-rate evidence is structural rather than a final numeric
  release claim: `pool_metrics_snapshot` records checkout totals and retained
  warm entries for the bench tenant before measurement. The numeric cache hit
  rate and p99 delta should be promoted from seven consecutive nightly outputs,
  not from a single local worktree run.
