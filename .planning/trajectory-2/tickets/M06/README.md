# M06: Performance Hardening Pack

**Wave:** W1  |  **Trust-boundary:** no  |  **Tickets:** 31  |  **Effort:** 36.75 days

## In one paragraph

M06 lands four performance primitives early so every later milestone benefits: the `Arc<CanonicalBytes>` zero-copy newtype that collapses 3-4 reserialises into one, bounded backpressure on the OTEL exporter (drop-oldest) and signing mpsc (backpressured-block), SQLite group-commit + `INSERT ... RETURNING`, and a `wasmtime::InstancePre` guard pool. M03 hybrid signing and M09 lineage anchoring both consume `CanonicalBytes`.

## Phases at a glance

| Phase | Tickets | One-liner |
|---|---|---|
| P0 | 3 | Pin dhat + dashmap; document bench reference-runner contract; open audit doc |
| P1 | 6 | `CanonicalBytes` newtype + property test + signing/kernel/store/exporter migration |
| P2 | 6 | Bounded backpressure on OTEL ingress + sink + signing channel; drop counters; loom |
| P3 | 6 | SQLite group-commit actor; `INSERT ... RETURNING`; pool sizing; throughput bench |
| P4 | 6 | `wasmtime::InstancePre` cache, per-tenant warmed-instance ring, loom, p99 bench |
| P5 | 4 | dhat allocation harness, twiggy bundle artifact, 30-min p99 nightly, audit close |

## Load-bearing artifacts

- `crates/chio-core-types/src/canonical.rs` `CanonicalBytes` newtype (M06.P1.T1)
- `chio_signing_queue_drop_total`, `chio_otel_ingress_drop_total`, `chio_otel_sink_drop_total` Prometheus counters (M06.P2.T3)
- Per-store group-commit actor in `crates/chio-store-sqlite/` (M06.P3.T1)
- `crates/chio-store-sqlite/benches/store_receipt_write_throughput.rs` (M06.P3.T6)
- `crates/chio-wasm-guards/src/runtime.rs` `InstancePre` cache (M06.P4.T1)
- `crates/chio-wasm-guards/benches/guard_pool_checkout_p99.rs` (M06.P4.T6)
- 30-minute sustained p99 nightly lane (M06.P5.T3)

## Cross-trajectory deps

- trajectory-1 M01 canonical-JSON vectors - consumed by `CanonicalBytes` byte-identity property test (M06.P1.T2)
- trajectory-1 M05.P1.T3 signing task and M05.P3.T4 regression gate - audited and extended (soft_dep)
- trajectory-1 M06.P3.T1 ArcSwap reload - cache invalidation hook fires from it (M06.P4.T2)
- trajectory-1 M06.P4 dashboard - new saturation alert wired into existing Grafana JSON (M06.P2.T4)
- trajectory-2 M03 hybrid signing path - consumer (declared soft_dep on M03.P1; M06.P1 lands first per D16)
- trajectory-2 M09 lineage anchor encoding - consumer

## Locked decisions

- D15 Drop-oldest only at OTEL boundary; signing channel stays backpressured-block (correctness vs observability)
- D16 `CanonicalBytes` ships in M06.P1 before M03.P1 starts; M03 declares it as soft_dep

## Active freezes

none.

## When this milestone is done

- `cargo test --workspace` green including new loom suites under `--cfg loom`.
- M01 vector corpus passes byte-identity through `CanonicalBytes` for 100% of vectors.
- Three drop counters scrape green from `/metrics` and appear on the trajectory-1 dashboard with saturation alert.
- `store_receipt_write_throughput` and `guard_pool_checkout_p99` Criterion harnesses feed the trajectory-1 M05.P3.T4 regression gate.
- `dhat` allocation-count harness reports a numeric reduction on dispatch-allow bench attributable to `Arc<CanonicalBytes>`.
- `twiggy` browser-kernel bundle artifact uploaded by every PR; budget enforcement deferred to M07.
- 30-minute sustained p99 nightly job green for one week before M06 closes.
