# M09: Economic Layer + Lineage

**Wave:** W4  |  **Trust-boundary:** no  |  **Tickets:** 38  |  **Effort:** 47.00 days

## In one paragraph

M09 wakes the dormant `chio-credit`, `chio-settle`, `chio-reputation`, `chio-mercury`, `chio-underwriting`, and `chio-appraisal` crates as a guard marketplace where priced installs settle at receipt finalization, and ships `chio-lineage` as a SQLite-backed recursive-CTE provenance graph indexing the OTEL receipt stream and the M04 corpus. Each kernel-evaluator hook is observer-only; failure-to-settle never blocks dispatch.

## Phases at a glance

| Phase | Tickets | One-liner |
|---|---|---|
| P0 | 4 | Pin petgraph + csv; scaffold `chio-lineage`; add `marketplace` and `lineage` cargo features |
| P1 | 6 | `chio-credit` activation: `CreditEvaluatorHook`, IOU mint, SQLite persistence, property tests |
| P2 | 6 | `chio-settle` activation: `SettlementHook`, observer wiring, retry policy, dead-letter table |
| P3 | 6 | `chio-reputation` activation: `ReputationFeed` trait, arena + verdict-matrix feeds, tiers |
| P4 | 7 | Marketplace surface: manifest schema (`price`/`reputation_floor`), `arc guard market {list,info,install}` |
| P5 | 9 | `chio-lineage` genesis: DAG schema, OTEL/M04 ingest, recursive-CTE queries, diff, anchor pinning |

## Load-bearing artifacts

- `crates/chio-lineage/` (M09.P0.T2 scaffolds; P5 fills)
- `iou_envelope` SQLite table (M09.P1.T3)
- `settle_dead_letters` table + `arc settle status` (M09.P2.T3, M09.P2.T5)
- `ReputationTier` enum + threshold table (M09.P3.T4)
- `chio-guard-registry` manifest schema extension (`price`, `reputation_floor`) (M09.P4.T1)
- `arc guard market {list,info,install}` subcommands (M09.P4.T4-T6)
- `crates/chio-lineage/schemas/lineage-graph.v1.json` (M09.P5.T1)
- Recursive-CTE query layer atop `chio-store-sqlite` (M09.P5.T4)
- `arc lineage {query,diff,roots}` (M09.P5.T7)

## Cross-trajectory deps

- trajectory-1 M01 canonical-JSON receipt vectors - IOU envelope + lineage frames lock encoding
- trajectory-1 M05 async kernel evaluator post-dispatch observer slot - hook attachment point
- trajectory-1 M10 OTEL receipt exporter NDJSON stream - lineage ingest source (M09.P5.T2)
- trajectory-2 M03 hybrid backend - lineage anchor frontier signing (soft_dep on M09.P5.T6)
- trajectory-2 M04 delegation - revenue attribution across kernels
- trajectory-2 M06 `CanonicalBytes` - anchor encoding (soft_dep)
- trajectory-2 M08 arena outputs - `ArenaSurvivalFeed` source (soft_dep)

## Locked decisions

- D21 Activate dormant economic crates as-is; do not invent new primitives (no `chio-economy` unification, no `chio-bounty`)
- D22 `chio-lineage` is a SQLite recursive-CTE indexer, not a new graph DB

## Active freezes

none.

## When this milestone is done

- `cargo test -p chio-credit` green; IOU mint property test passes (one IOU per finalized receipt at manifest price, or zero).
- `cargo test -p chio-settle` green; settlement integration test shows ten receipts produce ten settlements.
- `cargo test -p chio-reputation` green; both ingress feeds produce monotonic deltas under property test.
- `cargo test -p chio-guard-registry --features marketplace` green; manifest schema accepts/rejects price + reputation floor as documented.
- `cargo test -p chio-lineage` green; forward and reverse recursive-CTE queries return correct results on the M04 corpus fixture.
- `arc guard market {list,install,info}` exercised by end-to-end demo test (M09.P4.T7).
- `arc lineage {query,diff,roots}` present; static viewer at `docs/demo/lineage/index.html` opens and renders sample dump.
