# Milestone 06: Performance Hardening Pack

## Lens

Single lens: performance and scale. Bounded backpressure on hot async edges,
amortised SQLite write cost, pre-instantiated WASM guard pool, and a zero-copy
canonical-bytes newtype that shrinks per-receipt allocation by 3-4x. This
milestone is not about new features. It is about taking the surface that
trajectory-1 finished (M05 async kernel, M06 WASM guard platform, M10 OTEL
exporter, M01 canonical-JSON vectors) and removing the four shapes of waste
that show up the moment those surfaces sustain load. Determinism is the gate:
M01 vectors are the byte-equivalence oracle, and no fast path is allowed to
leak nondeterminism into a receipt.

## Why this is on the trajectory

Four trajectory-1 deliverables created the conditions for this milestone, and
each of them now imposes a cost that wants amortising.

- M05 async kernel (commit landed in `crates/chio-kernel/src/kernel/signing_task.rs`)
  introduced the receipt-signing mpsc task. The channel bound is correct in
  shape but the saturation telemetry is not yet wired to `/metrics`, and the
  drop-oldest behaviour the spec assumed is not yet a ring. Producers can
  block on send under sustained load.
- M06 (trajectory-1) shipped atomic guard reload via `ArcSwap` plus a
  Prometheus `/metrics` surface in `crates/chio-wasm-guards/src/metrics.rs`.
  The surface is healthy, but every guard call still walks the
  `wasmtime::Module -> Instance` instantiation cost, which dominates the
  five-guard-pipeline `<400 us` SLO from the M05 bench gate.
- M10 (trajectory-1, commit `3e0f04b52`) shipped the OTEL receipt exporter
  (`crates/chio-otel-receipt-exporter/src/{ingress,sink}.rs`). The current
  ingress and sink were written with adequate channels but no audited bound
  envelope, no drop-oldest ring, and no `chio_signing_queue_block_total`
  counter feeding the dashboard from the trajectory-1 M06.P4.T5 Grafana
  scaffold.
- M01 (trajectory-1) shipped the canonical-JSON vector corpus
  (`spec/vectors/canonical_json/*.json`). Receipt and capability code today
  call `canonical::canonical_json_bytes` 3-4 times per dispatch (see
  `crates/chio-core-types/src/{receipt,capability,session}.rs` grep below).
  Each call reserialises. With M01's vectors as a byte-equivalence oracle we
  can introduce a `CanonicalBytes` newtype, serialise once, and pass an
  `Arc<CanonicalBytes>` through signing, store, and exporter without
  reserialisation.

This milestone consolidates these four wins into one coherent surface.

## Prior-art reckoning

What trajectory-1 shipped that overlaps with M06:

- The bench-regression CI from trajectory-1 M05.P3.T4 already enforces a
  10 percent p99 lower-bound CI gate per Criterion metric on the reference
  4-core Linux runner. Trajectory-2 M06 reuses that gate; it does not re-cut
  it. The new bench files added by P3 (SQLite write throughput) and P4
  (guard pool checkout) feed straight into the existing comparison job.
- The `chio_signing_queue_depth` gauge introduced by trajectory-1 M05.P3.T2
  exists and is scraped. Trajectory-2 M06 ADDS the `*_drop_total` counter
  alongside it, with a saturation alert pinned to the existing dashboard.
  Trajectory-2 M06 does NOT re-cut the metrics endpoint or the scrape config.
- Trajectory-1 M06 shipped atomic guard reload via `ArcSwap` (see
  `crates/chio-wasm-guards/src/hot_reload.rs`). Trajectory-2 M06 ADDS the
  `wasmtime::InstancePre` pool UNDER that reload swap, with cache
  invalidation tied to the existing `ArcSwap` notifier. The reload itself is
  preserved verbatim; only the cache lifetime hangs off it.
- Trajectory-1 M06.P4.T3 capped guard-metric label cardinality at 1024 entries
  per series. Trajectory-2 M06.P4 piggybacks on that cap; new
  per-tenant-warmed-instance metrics use the same cardinality discipline.

What trajectory-2 M06 changes:

- The OTEL exporter ingress and sink channels become explicitly bounded with
  drop-oldest rings. Today they are `tokio::sync::mpsc::channel(N)` with
  unaudited N values; this milestone audits them, pins the bounds in
  `chio-otel-receipt-exporter/src/lib.rs` config, and emits drop counters.
- `chio-store-sqlite` per-store actor coalesces inserts into one
  `BEGIN IMMEDIATE`/`COMMIT`. Today every receipt insert is a single tx; the
  group-commit actor coalesces by count or `flush_us` deadline.
- `r2d2` `max_size(8)` becomes a config value with separate reader and writer
  pools. Today reads and writes contend on the same eight handles.
- `wasmtime::InstancePre` cache and per-tenant warmed-instance ring buffer
  land in `chio-wasm-guards/src/runtime.rs`. Today every guard call
  instantiates fresh.
- `CanonicalBytes` newtype is new in `chio-core-types`. The reserialisation
  cost it eliminates is the single largest opportunity in the per-receipt
  allocation profile.

This milestone is bounded: it does not introduce SIMD canonical JSON,
chain-coalesced signing, Mercury Merkle aggregation, or an edge SDK bundle
budget. Synthesis cut those; some fold into M09 (economic layer) and others
into a future milestone.

## Hard counts (measured 2026-04-29)

Reproduce with the commands in parentheses.

- `crates/chio-otel-receipt-exporter/src/`: 4 files (`denylist.rs`,
  `ingress.rs`, `lib.rs`, `sink.rs`). Total channel call sites referencing
  `mpsc::channel`, `unbounded_channel`, or `Sender::send`: zero matches with
  the literal patterns today (the channels live behind a wrapper); audit P2
  identifies the wrapper and the unaudited bounds. (`grep -rn 'channel\|mpsc\|unbounded' crates/chio-otel-receipt-exporter/src/`)
- `crates/chio-store-sqlite/src/`: 14 files including `receipt_store.rs`,
  `revocation_store.rs`, `approval_store.rs`. `r2d2` pool `max_size(8)` is
  the default in `lib.rs` today. (`ls crates/chio-store-sqlite/src/`)
- `crates/chio-wasm-guards/src/runtime.rs`: 2086 lines. Wasmtime usage gated
  on the `wasmtime-runtime` feature starts at line 616. No `InstancePre`
  reference today. (`grep -n 'InstancePre' crates/chio-wasm-guards/src/runtime.rs`
  returns no hits.)
- `crates/chio-core-types/src/canonical.rs`: 486 lines. Public surface today
  is `canonical_json_bytes(value: &T) -> Result<Vec<u8>>` and
  `canonical_json_string(value: &T) -> Result<String>`. There is no
  newtype wrapping the buffer with a witness for "ran through M01 vectors".
- Per-receipt `canonical_json_bytes` call sites in the receipt and capability
  surface: 8 hits in `crates/chio-core-types/src/{receipt,capability,session,
  crypto}.rs` (`grep -rn 'canonical_json_bytes' crates/chio-core-types/src/`).
  Each hit is a fresh serialise; an `Arc<CanonicalBytes>` flowing through
  signing collapses 3-4 of these into one for the hot dispatch path.
- Trajectory-1 M01 vector corpus location: `spec/vectors/canonical_json/`.
  The byte-equivalence test that M06.P1 reuses lives at
  `crates/chio-core-types/src/canonical.rs:466 fn canonical_bytes_match_string`.
- Receipt-signing task: `crates/chio-kernel/src/kernel/signing_task.rs` and
  the crash-recovery integration test at
  `crates/chio-kernel/tests/signer_crash.rs` already exist. M06.P2 adds the
  drop-oldest semantics and the saturation counter on top of this.

## Workspace dependency state

Pinned in `[workspace.dependencies]` of root `Cargo.toml` already (reuse, do
not re-pin):

- `tokio = { version = "1", features = ["full"] }` (from trajectory-1 M05).
- `dashmap = "6"` (from trajectory-1 M05). Per `EXECUTION-BOARD.md`
  Cargo.lock order (M06 P0.T2 -> M02 P0.T2 -> M01 P0.T1), M06 owns any
  trajectory-2 bump to this pin; M01 and M02 reuse without re-pinning.
- `arc-swap = "1"` (from trajectory-1 M05/M06).
- `loom = "0.7"` dev-dependency, gated on `cfg(loom)` (from trajectory-1 M05).
- `criterion = "0.5"` (from trajectory-1 M05).
- `wasmtime` (current pin in `chio-wasm-guards`; reuse for `InstancePre`).
- `r2d2` (current pin in `chio-store-sqlite`; reuse with reader/writer split).
- `prometheus` (current pin used by `chio-wasm-guards/src/metrics.rs`; reuse
  for `chio_signing_queue_block_total` and pool-checkout metrics).

New pins this milestone introduces (P0 Cargo.lock bump, versions verified
against crates.io on the day P0 opens):

- `dhat = "0.3"` dev-dependency, used by P5 allocation-count regression bench
  (`#[global_allocator]` swap behind a `cfg(dhat)` gate so production builds
  are unaffected).
- `twiggy` is invoked as a CLI in P5; no crate dep needed.
- `bytes = "1"` for `Arc<CanonicalBytes>` zero-copy slicing if needed; if a
  P1 prototype shows a plain `Arc<Vec<u8>>` wrapper suffices, this pin is
  dropped before P0 closes.

## Scope

In:

- `CanonicalBytes` newtype in `crates/chio-core-types/src/canonical.rs` with
  a phantom witness type proving the buffer was produced by the canonicaliser
  and validated against the M01 vector corpus.
- `Arc<CanonicalBytes>` threaded through `chio-core` signing, `chio-kernel`
  receipt-sign step, `chio-store-sqlite` write path, and the
  `chio-otel-receipt-exporter` sink so a receipt is canonicalised once.
- Bounded backpressure on the OTEL exporter ingress and sink channels with
  drop-oldest ring semantics on overload.
- `chio_signing_queue_block_total` Prometheus counter wired to the existing
  `/metrics` endpoint (trajectory-1 M06.P4.T4).
- Saturation alert on the trajectory-1 M06.P4.T5 Grafana dashboard.
- Loom model: sender-vs-shutdown for the bounded ring channel.
- SQLite per-store group-commit actor coalescing inserts into one
  `BEGIN IMMEDIATE`/`COMMIT` flushed by count or `flush_us` deadline.
- `INSERT ... RETURNING` on `receipt_store.rs`, `revocation_store.rs`,
  `approval_store.rs` to remove the post-insert SELECT round-trip.
- Reader / writer pool split in `chio-store-sqlite` with separate config
  bounds.
- Criterion harness `store_receipt_write_throughput` feeding the trajectory-1
  M05.P3.T4 regression gate.
- `wasmtime::InstancePre` cache in `chio-wasm-guards/src/runtime.rs` keyed by
  guard module hash and invalidated by the trajectory-1 M06.P3.T1 `ArcSwap`
  reload swap.
- Per-tenant warmed-instance ring buffer with cardinality-respecting metrics
  piggybacking on the trajectory-1 M06.P4.T3 1024-cap.
- Loom model: reload-vs-checkout race on the InstancePre cache.
- Cross-cutting bench-regression CI extensions: `dhat` allocation count,
  `twiggy` browser-kernel bundle size, sustained 30-minute p99 lane.

Out (and why):

- SIMD canonical JSON. The hot path bottleneck is reserialisation count, not
  cycles per byte. `CanonicalBytes` removes the duplication; SIMD on top is
  a separate project.
- Chain-coalesced signing (signing N receipts under one signature). This is
  a protocol change. M06 stays inside the wire format; coalesced signatures
  fold into M09 economic-layer bundling.
- Mercury Merkle aggregation. Same reasoning: protocol surface change.
- Edge SDK bundle budget for the browser kernel. Tracked via P5's `twiggy`
  job as a CI artifact only; budget enforcement is M07 territory.
- Custom executor. Tokio is the executor. M06 does not relitigate that.
- Cross-process kernel sharding. Single-process only. Same boundary as
  trajectory-1 M05.

## Phases

### P0: wave-opener pins and audit doc

- M06.P0.T1: Open audit doc at `.planning/audits/M06-perf-hardening.md` with
  starting counts (8 `canonical_json_bytes` call sites, 0 `InstancePre`
  references, `r2d2 max_size(8)` default, OTEL channel-wrapper inventory).
- M06.P0.T2: Pin `dhat = "0.3"` dev-dep workspace-wide; bump Cargo.lock and
  verify single-version resolution for `dashmap`, `arc-swap`, `wasmtime`,
  `prometheus`, `r2d2`. `cargo tree -d` must be clean.
- M06.P0.T3: Decide and document the bench reference runner contract for
  M06's new benches in the audit doc (4-core Linux, in-memory stores, warm
  cache, criterion 100-sample median with 95 percent CI). This contract is
  identical to trajectory-1 M05's; the audit doc just pins it.

### P1: CanonicalBytes newtype and signing-path migration

- M06.P1.T1: Add `CanonicalBytes` newtype in `crates/chio-core-types/src/canonical.rs`.
- M06.P1.T2: Property test against `spec/vectors/canonical_json/` corpus
  asserting every vector round-trips byte-identical through the newtype.
- M06.P1.T3: Migrate `chio-core` signing path to `Arc<CanonicalBytes>`.
- M06.P1.T4: Migrate `chio-kernel` receipt-sign step to
  `Arc<CanonicalBytes>`; preserve M04 replay byte-equivalence goldens.
- M06.P1.T5: Migrate `chio-store-sqlite` write path API to take
  `Arc<CanonicalBytes>`; deprecate the bytes-copy variant.
- M06.P1.T6: Migrate `chio-otel-receipt-exporter` sink to
  `Arc<CanonicalBytes>` so the exporter does not reserialise.

### P2: Bounded backpressure on OTEL exporter and signing mpsc

- M06.P2.T1: Audit OTEL exporter ingress and sink channel bounds; document
  current behaviour in audit doc.
- M06.P2.T2: Replace channels with bounded `tokio::sync::mpsc::channel(N)`
  plus drop-oldest ring on overload in `ingress.rs` and `sink.rs`.
- M06.P2.T3: Add `chio_signing_queue_block_total` Prometheus counter wired to
  `/metrics`; add `chio_otel_ingress_drop_total` and
  `chio_otel_sink_drop_total` with the same shape.
- M06.P2.T4: Saturation alert added to the trajectory-1 M06.P4.T5 Grafana
  dashboard JSON.
- M06.P2.T5: Loom model `loom_ring_sender_vs_shutdown` for the bounded
  drop-oldest ring under shutdown race.
- M06.P2.T6: Audit the trajectory-1 M05.P1.T3 signing task (commit
  `c630006c9`); confirm bound is enforced and emit the drop counter alongside
  the existing depth gauge.

### P3: SQLite write path

- M06.P3.T1: Per-store group-commit actor in `crates/chio-store-sqlite/`
  coalescing N inserts into one `BEGIN IMMEDIATE`/`COMMIT` flushed by count
  or `flush_us` deadline.
- M06.P3.T2: Replace post-insert SELECT round-trips with `INSERT ... RETURNING`
  in `receipt_store.rs`.
- M06.P3.T3: Same migration for `revocation_store.rs`.
- M06.P3.T4: Same migration for `approval_store.rs`.
- M06.P3.T5: Bump `r2d2` `max_size(8)` to a config value with separate
  reader and writer pools; document the default in `lib.rs` rustdoc.
- M06.P3.T6: Criterion harness `store_receipt_write_throughput` at
  `crates/chio-store-sqlite/benches/store_receipt_write_throughput.rs`
  feeding the trajectory-1 M05.P3.T4 regression gate.

### P4: Pre-instantiated WASM guard pool

- M06.P4.T1: `wasmtime::InstancePre` cache in
  `crates/chio-wasm-guards/src/runtime.rs` keyed by guard module hash.
- M06.P4.T2: Cache invalidation hook fired by the trajectory-1 M06.P3.T1
  `ArcSwap` reload swap; ensures stale `InstancePre` entries are dropped at
  reload.
- M06.P4.T3: Per-tenant warmed-instance ring buffer with bounded capacity.
- M06.P4.T4: Cardinality-respecting metrics (`chio_guard_pool_checkout_total`,
  `chio_guard_pool_warm_size`, `chio_guard_pool_evict_total`) piggybacking
  on the trajectory-1 M06.P4.T3 1024-cap.
- M06.P4.T5: Loom model `loom_instance_pre_reload_vs_checkout` for the
  reload-vs-checkout race on the cache.
- M06.P4.T6: Criterion harness `guard_pool_checkout_p99` feeding the
  trajectory-1 M05.P3.T4 regression gate.

### P5: Cross-cutting bench-regression CI extensions

- M06.P5.T1: `dhat` allocation-count harness added to the M05 dispatch-allow
  bench; allocation-count baseline pinned in audit doc.
- M06.P5.T2: `twiggy` job for the browser-kernel bundle in CI; output
  artifact uploaded per PR. Budget enforcement is M07; this milestone only
  surfaces the number.
- M06.P5.T3: Sustained 30-minute p99 lane added as a nightly job (not on
  every PR) running the full kernel + store + exporter stack on the
  reference 4-core Linux runner.
- M06.P5.T4: Audit doc final pass with after-counts (canonical_json_bytes
  call sites collapsed, InstancePre cache hit-rate, group-commit batch size
  distribution, p99 deltas per metric).

## Cross-milestone interactions

Hard dependencies (other trajectory-2 tickets):

- M06.P0.T2 must land before any other M06 ticket.
- M06.P1.T1 must land before M06.P1.T2..T6 (newtype shape).
- M06.P1.T6 should land before M06.P2.T2 so the exporter migration sees the
  bounded-ring API and the new bytes shape together.
- M06.P3.T1 must land before M06.P3.T2..T4 (group-commit actor is the
  surface the `INSERT ... RETURNING` migrations bind to).
- M06.P4.T1 must land before M06.P4.T2..T6.

Soft dependencies (cross-trajectory):

- "trajectory-1 M01 canonical-JSON vectors at `spec/vectors/canonical_json/`
  are the byte-equivalence oracle for `CanonicalBytes`."
- "trajectory-1 M05.P3.T4 bench-regression gate consumes the new Criterion
  harnesses; it does not need re-cutting."
- "trajectory-1 M06.P3.T1 atomic guard reload via `ArcSwap` is the
  invalidation source for the `InstancePre` cache."
- "trajectory-1 M06.P4.T3 1024-cap label cardinality discipline applies to
  the new pool metrics."
- "trajectory-1 M06.P4.T5 Grafana dashboard scaffold receives the saturation
  alert."
- "trajectory-1 M10 commit `3e0f04b52` shipped the OTEL exporter; M06.P2
  hardens it without changing the wire format."
- "trajectory-2 M03 PQ signing and trajectory-2 M09 lineage are downstream
  consumers of `Arc<CanonicalBytes>`; soft_deps point reverse-direction
  (M03.P*.* and M09.P*.* will declare M06.P1.T1 as a soft_dep when they
  open)."

## Risks and mitigations

- Risk: a fast path silently leaks nondeterminism into a receipt (e.g. a
  field reorder, a whitespace, a number representation). Mitigation: M06.P1.T2
  property test runs every M01 vector through `CanonicalBytes` and asserts
  byte-identity; the trajectory-1 M04 replay goldens must continue to pass
  on every M06 PR. The audit doc enumerates every receipt path observed by
  trajectory-1 M04 replay and requires green ticks per path before P1
  closes.
- Risk: drop-oldest ring loses receipts that should have been signed.
  Mitigation: M06.P2.T2 only drops at the OTEL exporter boundary (export is
  best-effort by definition); the receipt-signing channel from trajectory-1
  M05 is bounded with backpressure (block on send), not drop-oldest. The
  drop counter distinguishes the two surfaces.
- Risk: SQLite group-commit actor introduces tail-latency spikes on the
  flush boundary. Mitigation: M06.P3.T1 ships with `flush_us` deadline as a
  config knob with a fail-closed default sized so p99 stays inside the
  trajectory-1 M05 receipt-append `<50 us` SLO; bench harness in
  M06.P3.T6 catches regressions.
- Risk: `InstancePre` cache memory growth on reload churn. Mitigation:
  M06.P4.T2 invalidates on every `ArcSwap` swap; the per-tenant ring is
  bounded at construction time; eviction emits a metric so growth is
  observable.
- Risk: `Arc<CanonicalBytes>` migration is wide and produces a long-running
  PR series. Mitigation: P1 is six tickets, each scoped to one crate
  surface; each ticket independently passes `cargo test --workspace` and
  `cargo clippy --workspace -- -D warnings` and preserves M04 replay
  byte-equivalence.
- Risk: `dhat` allocator swap in P5 is a global-allocator change that
  conflicts with other crates' allocator opinions. Mitigation: gate behind
  `cfg(dhat)` so the allocator is only swapped when running the dhat bench;
  production builds are unaffected.
- Risk: bench-regression gate becomes flaky on the new harnesses
  (`store_receipt_write_throughput`, `guard_pool_checkout_p99`). Mitigation:
  the trajectory-1 M05.P3.T4 gate already uses 100-sample median with 95
  percent CI on the diff; the new harnesses follow the same shape, and the
  P0.T3 reference-runner contract pins the OS, core count, and warm-cache
  policy.

## Success criteria

- `cargo test --workspace` green, including new loom suites under `--cfg loom`.
- M01 vector corpus passes byte-identity through `CanonicalBytes` for 100
  percent of vectors (M06.P1.T2).
- `chio_signing_queue_block_total`, `chio_otel_ingress_drop_total`, and
  `chio_otel_sink_drop_total` counters scrape green from `/metrics` and
  appear on the trajectory-1 M06.P4.T5 Grafana dashboard with a saturation
  alert wired (M06.P2.T3, M06.P2.T4).
- `store_receipt_write_throughput` Criterion harness lands and the
  trajectory-1 M05.P3.T4 regression gate runs it (M06.P3.T6).
- `guard_pool_checkout_p99` Criterion harness lands and the same gate runs
  it (M06.P4.T6); cache hit-rate is recorded in the audit doc.
- `dhat` allocation-count harness reports a numeric reduction on the
  dispatch-allow bench attributable to `Arc<CanonicalBytes>` collapsing
  3-4 reserialises into one (M06.P5.T1, recorded in audit doc).
- `twiggy` browser-kernel bundle artifact uploaded by every PR (M06.P5.T2);
  budget enforcement deferred to M07.
- 30-minute sustained p99 nightly job green for seven consecutive
  nightly runs before M06 closes (M06.P5.T3). The orchestrator
  parses run-count, not calendar time.
- Audit doc final pass complete with before/after counts (M06.P5.T4).
