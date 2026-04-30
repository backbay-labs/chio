# M09 Economic Layer and Lineage Audit

Snapshot date: 2026-04-30

Ticket: M09.P0.T4

Source of truth:

- `.planning/trajectory-2/09-economic-layer-and-lineage.md`
- `.planning/trajectory-2/tickets/M09/P0.yml`
- `.planning/trajectory-2/tickets/manifest.yml`
- `.planning/trajectory-2/EXECUTION-BOARD.md`
- `.planning/trajectory-2/freezes.yml`

## Scope

M09 wakes the dormant economic crates (`chio-credit`, `chio-settle`,
`chio-reputation`, `chio-mercury`, `chio-mercury-core`, `chio-underwriting`,
`chio-appraisal`) and turns the trajectory-1 M06 OCI guard registry into a
priced marketplace settling at receipt finalization. M09 also lands
`chio-lineage`, a provenance DAG ingesting the trajectory-1 M10 OTEL receipt
exporter stream and the trajectory-1 M04 deterministic corpus.

M09 is not a trust-boundary milestone in `freezes.yml`. M09.P0.T4 owns only
this audit file. Later M09 tickets must respect active freezes in M03, M04,
M05, and M10 when their outputs touch those surfaces.

## Starting counts (P0 baseline, 2026-04-30)

These starting counts are the "before" numbers used by the closing audit
pass at M09.P5.T9.
The pre-flight numbers in the M09 narrative are dated 2026-04-29; the
counts below are remeasured on the P0 open day and supersede the narrative
when they diverge.

### Dormant economic-crate LOC

Reproduce with:

```bash
wc -l crates/chio-credit/src/lib.rs
find crates/chio-settle/src -name '*.rs' | xargs wc -l | tail -1
find crates/chio-reputation/src -name '*.rs' | xargs wc -l | tail -1
find crates/chio-mercury/src -name '*.rs' | xargs wc -l | tail -1
find crates/chio-mercury-core/src -name '*.rs' | xargs wc -l | tail -1
find crates/chio-underwriting/src -name '*.rs' | xargs wc -l | tail -1
wc -l crates/chio-appraisal/src/lib.rs
find crates/chio-anchor/src -name '*.rs' | xargs wc -l | tail -1
find crates/chio-link/src -name '*.rs' | xargs wc -l | tail -1
```

Measured today:

| Crate | Files (rs) | Total LOC |
|-------|------------|-----------|
| `chio-credit` | 1 (`src/lib.rs`) | 1524 |
| `chio-settle` | 8 | 6316 |
| `chio-reputation` | 5 | 1265 |
| `chio-mercury` | 13 | 14399 |
| `chio-mercury-core` | 1 | 9357 |
| `chio-underwriting` | 4 | 2075 |
| `chio-appraisal` | 1 (`src/lib.rs`) | 3822 |
| `chio-anchor` | 12 | 4704 |
| `chio-link` | 12 | 3472 |

The `chio-mercury` total has grown since the 2026-04-29 narrative
snapshot (947); P0 accepts the live tree as the baseline so the closing
audit can compute deltas against today's reality.

### Caller counts (today)

Reproduce with the `grep` invocations cited in the narrative.

- `chio-credit` callers from outside its own crate
  (`grep -rE 'use\s+chio_credit' crates/ | grep -v 'crates/chio-credit/'`):
  4 occurrences across `chio-settle` and adjacent surfaces. The kernel
  does not consume `chio-credit` today.
- `chio-settle` callers from outside its own crate
  (`grep -rE 'use\s+chio_settle' crates/ | grep -v 'crates/chio-settle/'`):
  1 caller (`chio-mercury-core`). Not wired into kernel finalization.
- `chio-reputation` consumer files outside its own crate: 12 unique files
  spread across `chio-cli` and `chio-credentials`. There is no kernel-side
  scoring loop.
- `chio-mercury` consumers outside the mercury crates: 0.
- `chio-mercury-core` consumers outside the mercury crates: 3 occurrences
  (the `chio-mercury` binary surface).
- `chio-anchor` consumers outside its own crate: 4 occurrences. M09 P5.T6
  consumes the anchored-root corpus path transitively.
- `chio-otel-receipt-exporter` consumers outside its own crate
  (`grep -rE 'chio_otel_receipt_exporter' crates/ | grep -v 'crates/chio-otel-receipt-exporter/'`):
  0. No downstream lineage subscriber today; M09 P5.T2 lands the first one.

### Marketplace and lineage placeholders

- `chio-guard-registry` manifest `price` field
  (`grep -c 'price' crates/chio-guard-registry/src/oci.rs`): 0.
  M09 P4.T1 lands it under the `marketplace` cargo feature gated in
  M09.P0.T3.
- `chio-store-sqlite` recursive-CTE queries
  (`grep -h 'WITH RECURSIVE' crates/chio-store-sqlite/src/*.rs | wc -l`):
  2 (existing capability lineage helpers). M09 P5.T4 adds the lineage
  recursive-CTE query layer under the `lineage` cargo feature gated in
  M09.P0.T3.
- `chio-store-sqlite` source files
  (`ls crates/chio-store-sqlite/src/*.rs | wc -l`): 16. The additive
  `iou_envelope` migration in P1.T3 and the `lineage_cte.rs` module in
  P5.T4 are the only new files; no schema columns are dropped.
- `chio-lineage` LOC
  (`find crates/chio-lineage/src -name '*.rs' | xargs wc -l | tail -1`):
  zero before this PR. After M09.P0.T2 lands, the crate ships only the
  `LINEAGE_GRAPH_SCHEMA` constant and a placeholder `LineageError` type;
  the DAG schema, ingest paths, and query layer follow in M09 P5.

## P1 close (2026-04-30)

P1 wakes `chio-credit` against finalized signed receipts. The credit
hook surface is owned by `chio-credit` (`hook.rs`, `local_account.rs`,
`store_binding.rs`); the SQLite implementation of the IOU envelope
store ships in `chio-store-sqlite::iou_store`. Both the
`SqliteIouEnvelopeStore::open_with_pool` migration and the
`SqliteReceiptStore::open` bootstrap apply the additive
`iou_envelope` migration; reopening an existing store is a no-op.

### Kernel callers

After P1, the count of kernel callers of `chio-credit` outside its
own crate
(`grep -rE 'use\s+chio_credit' crates/ | grep -v 'crates/chio-credit/' | wc -l`):
6 occurrences. The new callers are `chio-store-sqlite::iou_store` and
its test fixtures; the kernel still does not consume `chio-credit`
directly. The kernel observer-slot wiring is deferred to P2 along
with the settlement hook so both economic hooks register through the
same evaluator surface.

### IOU envelope schema row

Reproduce with:

```bash
sqlite3 /tmp/example.sqlite '.schema iou_envelope'
```

Column layout (additive, `CREATE TABLE IF NOT EXISTS`):

| Column | Type | Notes |
|--------|------|-------|
| `receipt_id` | TEXT PRIMARY KEY | Stable uniqueness key. Re-processing the same finalized receipt is idempotent. |
| `iou_id` | TEXT NOT NULL | Deterministic from `receipt_id` (sha256 prefix). |
| `receipt_timestamp` | INTEGER NOT NULL | Carried over for cheap sort by issuance time. |
| `tenant_id` | TEXT | NULL in single-tenant deployments. |
| `amount_units` | INTEGER NOT NULL | Currency minor units; always > 0 for stored rows. |
| `currency` | TEXT NOT NULL | ISO 4217 (e.g. "USD"). |
| `issuer_key` | TEXT NOT NULL | JSON encoding of the kernel signing public key. |
| `canonical_json` | TEXT NOT NULL | Canonical JSON of the signed envelope, used for idempotency byte-equality checks. |

Indexes: `idx_iou_envelope_receipt_timestamp`,
`idx_iou_envelope_tenant`. No existing schema columns were dropped.

### Property-test coverage

- `crates/chio-credit/tests/iou_invariants.rs`: 256 proptest cases
  cover the (decision, financial metadata, cost, currency, tenant)
  product. Exactly-one-or-zero IOU per receipt; tampered receipts
  fail closed.
- `crates/chio-credit/tests/legacy_receipt_migration.rs`: every
  pre-M09 receipt shape (no financial metadata; non-financial
  metadata) mints zero IOUs and the receipt's canonical JSON bytes
  are byte-identical before and after evaluation.

## Wave entry status

Status: P0 wave-opener landing under the W4 capstone schedule. The audit
records the workspace-level cargo gates landed by M09.P0.T1 through T3 so
later tickets reference a single source of truth:

- `petgraph = "0.6"` and `csv = "1"` pinned in `[workspace.dependencies]`
  (M09.P0.T1).
- `crates/chio-lineage/` registered under the `Observability & ops`
  members section (M09.P0.T2).
- `marketplace` feature on `chio-guard-registry` (default-off) and
  `lineage` feature on `chio-store-sqlite` (default-off) (M09.P0.T3).

## Closing-pass plan (M09.P5.T9)

The closing audit pass must record, against the same `wc -l` and `grep -c`
commands above:

- Lineage crate LOC delta (P0 baseline near zero -> P5 close).
- Recursive-CTE query count (today 2 -> at least 4 after P5.T4 lands the
  forward and reverse queries).
- Anchored roots count produced by `arc lineage roots` (today 0).
- Marketplace manifest count surfaced by `arc guard market list` (today 0;
  the marketplace fixture in P4.T7 lifts this above zero).
- IOU envelope row count against the M04 corpus (today 0; P1.T4 plus the
  end-to-end demo in P4.T7 lift this).
- Settlement throughput counters from P2.T6 (today 0 settlements through
  the new hook path).
- Reputation tier distribution on the M04 corpus from P3.T6.

The closing pass also captures the transitive caller count for
`chio-mercury`, `chio-mercury-core`, and `chio-anchor` so the
no-new-crates discipline (decisions.yml D26) stays observable.
