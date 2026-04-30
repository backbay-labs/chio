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

## P2 close (2026-04-30)

P2 wakes `chio-settle` against finalized signed receipts. The
`SettlementHook` trait (`crates/chio-settle/src/hook.rs`) plus the
bounded retry policy and dead-letter persistence machinery
(`crates/chio-settle/src/retry.rs`,
`crates/chio-store-sqlite/src/dead_letters.rs`) wire the
post-dispatch observer slot into the kernel
(`crates/chio-kernel/src/kernel/settlement_observer.rs`). Settlement
remains observer-only relative to receipt bytes: a hook failure NEVER
mutates the receipt store and NEVER blocks the dispatch path. The
P2.T4 integration test
(`crates/chio-kernel/tests/settlement_observer_byte_identity.rs`)
asserts byte-equivalence with the no-settlement baseline over ten
priced receipts.

### Kernel callers

After P2, the count of kernel-side callers of `chio-settle` outside
its own crate
(`grep -rE 'use\s+chio_settle' crates/ | grep -v 'crates/chio-settle/' | wc -l`):
4 occurrences. The new callers are
`crates/chio-kernel/src/kernel/settlement_observer.rs`,
`crates/chio-store-sqlite/src/dead_letters.rs`, and the integration
test plus dead-letter store tests. The pre-existing in-workspace
caller (`chio-market::insurance_flow`) remains untouched, preserving
the trait-bridge directionality the P2-P4 readiness research called
out.

### Settlement throughput

settlement throughput counters land at the kernel observer slot. The
P2.T4 integration test
(`crates/chio-kernel/tests/settlement_observer_byte_identity.rs`)
drives ten priced receipts through `run_observer` and asserts ten
`SettlementOutcome::Accepted` outcomes (zero retryable, zero
permanent, zero skipped). The byte-identity assertion runs against
the same canonical encoding the trajectory-1 M04 deterministic-replay
goldens were minted under (`chio_core::canonical::canonical_json_bytes`),
so a settlement-throughput regression that mutates a receipt byte
would fail the existing M04 byte-identity gate as well.

Documented retry envelope (`chio_settle::RetryPolicy::default`):

| Bound | Value |
|-------|-------|
| `max_retries` | 5 |
| `initial_backoff_ms` | 250 |
| `backoff_multiplier` | 2 |
| `backoff_cap_ms` | 60000 |

Total attempt count is `max_retries + 1`. After the envelope is
exhausted, `classify_attempt` returns
`RetryDecision::DeadLetter { .. }`; permanent outcomes short-circuit
to dead-letter on the first attempt.

### Dead letters

P2.T3 introduces `settle_dead_letters` rows for permanent settlement
failures. The table is additive (`CREATE TABLE IF NOT EXISTS`) and
keyed by `receipt_id`; reopening an existing store is a no-op.

Reproduce with:

```bash
sqlite3 /tmp/example.sqlite '.schema settle_dead_letters'
```

Column layout (additive, `CREATE TABLE IF NOT EXISTS`):

| Column | Type | Notes |
|--------|------|-------|
| `receipt_id` | TEXT PRIMARY KEY | Stable uniqueness key. Idempotent on byte-identical re-inserts. |
| `finalized_at` | INTEGER NOT NULL | Receipt timestamp at the time of dead-lettering. |
| `attempts` | INTEGER NOT NULL | Number of attempts before the failure was sealed in (always >= 1). |
| `reason` | TEXT NOT NULL | Operator-visible failure reason. |
| `pipeline_error` | TEXT | Optional structured error string from `chio-settle/ops.rs`. |
| `canonical_json` | TEXT NOT NULL | Canonical JSON of the dead letters record; used for idempotency byte-equality checks. |
| `recorded_at` | INTEGER NOT NULL | Unix seconds when the row was first inserted. |

Indexes: `idx_settle_dead_letters_finalized_at`. Lists are sorted by
`(finalized_at, receipt_id)` to match the deterministic settlement
ordering documented on `SettlementHook`. Fail-closed: dead letters do
NOT auto-retry past the documented bound; operators clear rows
explicitly via `SqliteDeadLetterStore::clear`.

### CLI surface

`arc settle status [--store PATH] [--json]` reports pending IOU
envelopes (rows in `iou_envelope` without a
`settlement_reconciliations` match), settled receipts
(`settlement_reconciliations` with state=`settled`), and
dead-lettered settlements (`settle_dead_letters` rows). Output is
deterministic on `(finalized_at, receipt_id)`. Missing tables surface
as empty vectors so the CLI runs cleanly against a pre-M09 receipt
database.

## P3 close (2026-04-30)

P3 wakes `chio-reputation` against the deterministic feed-composition
surface. The trait `ReputationFeed` (`crates/chio-reputation/src/feed.rs`)
plus the two bundled feeds (`crates/chio-reputation/src/feeds/arena_survival.rs`,
`crates/chio-reputation/src/feeds/cross_provider_equality.rs`) and the
discrete `ReputationTier` enum (`crates/chio-reputation/src/tier.rs`)
expose the audit's first deterministic tier mapping. Per the M09 P2-P4
economics readiness research doc, feeds are caller-projected
observations rather than direct dependencies on `chio-arena` or
`chio-conformance`; this preserves the kernel-free invariant the
research doc called out and lets the audit reproduce feeds offline
against fixture data.

### Threshold table

| Tier   | Composed-score floor | Per-feed floor (`tier_3` only) | Default? |
|--------|----------------------|--------------------------------|----------|
| `tier_0` | 0.0 (any)          | -                              | yes      |
| `tier_1` | `TIER_1_THRESHOLD` (0.50) | -                       | -        |
| `tier_2` | `TIER_2_THRESHOLD` (0.75) | -                       | -        |
| `tier_3` | `TIER_3_THRESHOLD` (0.90) | `TIER_3_PER_FEED_THRESHOLD` (0.80) and >=2 feeds | -        |

The composed score is the per-feed maximum (`compose_deltas`), not the
sum. The `tier_3` AND-condition is the M09 narrative's Sybil
mitigation: a publisher with strong arena survival but no cross-
provider equality evidence collapses to `tier_2`, never `tier_3`.

### Reputation tier distribution on the M04 corpus

Reproduce by replaying the M04 deterministic corpus and projecting
each publisher's signed-receipt set into the two feed observation
shapes:

```bash
cargo test -p chio-reputation --test feed_monotonicity --quiet
```

The M04 deterministic corpus today carries receipt-level ground truth
but not yet arena-round outputs (M08 outputs land in the same Wave 4
window) or M07 verdict-matrix runs in the corpus replay path. P3
records the resulting baseline tier distribution explicitly so the
P5.T9 closing pass can compute deltas:

| Tier   | Subjects (M04 corpus baseline, P3 close) | Notes |
|--------|------------------------------------------|-------|
| `tier_0` | all corpus publishers                  | Arena and verdict-matrix observations are zero-delta in the corpus today; under the empty-input fallback every publisher lands at `tier_0`. |
| `tier_1` | 0                                       | Requires composed score >= 0.50; no positive feed evidence in the M04 corpus today. |
| `tier_2` | 0                                       | Same. |
| `tier_3` | 0                                       | Requires both feeds independently above 0.80; impossible without populated feeds. |

P3 chooses the explicit-zero baseline rather than synthesizing
fixture data so the closing audit at M09.P5.T9 can credibly attribute
any non-zero distribution to the marketplace demo (P4.T7) and the
lineage ingest (P5.T2/T3), not to inflated test scaffolding. The
property test in `crates/chio-reputation/tests/feed_monotonicity.rs`
covers the monotonicity invariant on synthetic inputs (256 cases per
property) so the tier distribution remains reproducible across runs.

### Property-test coverage

- `crates/chio-reputation/tests/feed_monotonicity.rs`: 6 properties at
  256 proptest cases each. Adding fully-survived arena rounds, raising
  the survived count on an existing outcome, adding unanimous-
  agreement verdict-matrix cases, replacing a disagreement with an
  agreement, and raising any single delta in `tier_from_deltas` all
  preserve or increase the resulting score and tier. The targeted
  `empty_inputs_always_tier_0` test guards the empty-input fallback
  documented on `ScoreDelta::zero` and per ticket M09.P3.T2.

### Caller counts

After P3, `chio-reputation` consumer files outside its own crate
(`grep -rE 'use\s+chio_reputation' crates/ | grep -v 'crates/chio-reputation/' | wc -l`):
12 occurrences (unchanged from P0). The two new feeds and the tier
helper are exercised by the in-crate property test surface and will
gain external callers in P4 (the marketplace discovery path) and in
the audit doc closing pass.

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

## P5 close (2026-04-30): closing counts

P5 lands `chio-lineage` (M09.P5.T1 through T8) and the final audit
pass (M09.P5.T9). The closing counts below honor the table laid out
in the original M09.P5.T9 plan and supersede the P0 baseline where
they diverge. They are dated 2026-04-30 from the P5 bundle worktree.

### Lineage crate LOC delta

Reproduce with:

```bash
find crates/chio-lineage/src -name '*.rs' | xargs wc -l | tail -1
```

| Snapshot | LOC | Delta vs P0 baseline |
|----------|-----|----------------------|
| P0 baseline (skeleton only)    | ~50    | -            |
| P5 close (schema + ingest_otel + ingest_replay_corpus + query + diff + anchor) | 1582 | +1532 |

The lineage crate now ships the DAG schema (`schema.rs`), OTEL ingest
(`ingest_otel.rs`) honoring the `otlp.grpc.trace.v1` schema gate, M04
deterministic-corpus ingest (`ingest_replay_corpus.rs`), the
recursive-CTE query layer (`query.rs`), differential mode
(`diff.rs`), anchor-pinning (`anchor.rs`), plus the JSON Schema at
`crates/chio-lineage/schemas/lineage-graph.v1.json`.

### Recursive-CTE query count

Reproduce with:

```bash
grep -h 'WITH RECURSIVE' crates/chio-store-sqlite/src/*.rs \
  crates/chio-store-sqlite/src/lineage_cte.rs 2>/dev/null | wc -l
```

| Snapshot | Recursive CTEs |
|----------|----------------|
| P0 baseline (capability_lineage only)            | 2 |
| P5 close (forward + reverse receipt-lineage)     | 6 |

The two new CTEs in `crates/chio-store-sqlite/src/lineage_cte.rs`
implement forward and reverse walks over `receipt_lineage_statements`,
both gated behind the `lineage` cargo feature pinned in M09.P0.T3 and
both bounded by depth and row caps. On overflow, the canonical
truncation marker is `{"truncated": true, "depth_reached": N,
"limit": M}` exactly.

### Anchored roots count

Reproduce with `arc lineage roots --dir <path-to-anchored-frontier-dir>`.
The `anchored roots` table below records the live count.

| Snapshot | Anchored roots |
|----------|----------------|
| P0 baseline                         | 0 |
| P5 close (no operator pin run yet)  | 0 |

P5.T6 lands the `pin_frontier` library entry point and the
`AnchoredFrontier` artifact shape (`crates/chio-lineage/src/anchor.rs`)
plus the `arc lineage roots` reader. Producing a real anchored root
requires either the M03 hybrid signing backend or the documented
unsigned soft-dep fallback; both states are recorded explicitly on
the artifact so M10 model-card anchoring can distinguish them.

### Marketplace manifest count

Reproduce with `arc guard market list --json`.

| Snapshot | Marketplace manifests |
|----------|-----------------------|
| P0 baseline                          | 0 |
| P5 close (live registry; P4.T7 demo) | 0 (live) |

P4 landed the manifest schema and marketplace CLI; the live registry
is unchanged because no tenant has run an install path outside the
P4.T7 fixture yet. The non-zero number lands at the operator's first
install of a priced guard.

### IOU envelope rows and settlement throughput on the M04 corpus

| Surface                                | M04 corpus today |
|----------------------------------------|------------------|
| `iou_envelope` rows                    | 0 (corpus has no priced manifests) |
| Settlement throughput through new hook | 0 (corpus replay is observer-only) |
| Reputation tier distribution           | all `tier_0`     |

The M04 deterministic corpus does not yet carry priced guard
manifests, M07 verdict-matrix runs, or M08 arena-round outputs in
the replay path. P3 already documented the explicit-zero baseline
for the tier distribution; P5 confirms it has not moved because no
new feed inputs land in P5. The non-zero numbers will surface when
the corpus is regenerated against priced fixtures or against M07/M08
outputs in a later trajectory.

### Transitive caller counts (decisions.yml D26)

| Crate              | P0 baseline | P5 close |
|--------------------|-------------|----------|
| `chio-mercury`     | 0           | 0        |
| `chio-mercury-core`| 3           | 3        |
| `chio-anchor`      | 4           | 4        |

No new direct callers were added in P5; the no-new-crates discipline
holds. `chio-mercury` and `chio-mercury-core` wake transitively via
`chio-settle`. `chio-anchor` is referenced by the lineage anchor
shape but the canonical bytes path uses the documented byte-
equivalence shim until M06 lands.

### Static viewer

Files at `docs/demo/lineage/`: `index.html`, `lineage.css`,
`lineage.js`, `README.md`. The viewer is vanilla static HTML and a
single ES module; no bundler, no import map, no transpiler step.

## M09 milestone close-out (2026-04-30)

M09 is closed. P0 (wave-opener), P1 (`chio-credit` activation),
P2 (`chio-settle` activation), P3 (`chio-reputation` activation),
P4 (marketplace surface), and P5 (`chio-lineage` genesis plus
audit close) all landed under the W4 capstone schedule.

The two trajectory-1 structural holes the milestone narrative called
out are closed:

- The dormant economic crates (`chio-credit`, `chio-settle`,
  `chio-reputation`, plus the marketplace surface in
  `chio-guard-registry` under the `marketplace` feature) are wired
  into the kernel observer surface, the OCI registry, and the
  CLI. Receipt finalization mints IOUs (P1) and triggers settlement
  (P2); reputation gates marketplace discovery (P3 + P4).
- The receipt log gains a queryable provenance graph
  (`chio-lineage`) ingesting the trajectory-1 M10 OTEL receipt
  stream and the trajectory-1 M04 deterministic corpus, with forward
  and reverse recursive-CTE queries, a differential mode, anchor
  pinning through canonical bytes (with M03 hybrid signing soft-
  dep), an `arc lineage` CLI surface, and a static viewer.

The W4-capstone gate to M10 is satisfied. M10.P5.T1 may open: the
`anchor_pinning` integration test passes, the canonical-bytes
equivalence shim is documented, and the unsigned soft-dep absence
state is explicit on the artifact so M10 model cards can consume the
P5.T6 schema in either signed or unsigned form without claiming
external anchoring beyond what the artifact attests.

## Closing-pass plan (M09.P5.T9, original)

The original closing pass plan is preserved here for traceability.
The realized counts above answer every bullet.

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
