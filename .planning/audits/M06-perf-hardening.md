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
