# Milestone 09: Economic Layer + Lineage

## Lens

Economic substrate plus provenance and audit. One milestone, two interlocking
halves. Half A wakes the dormant economic crates (`chio-credit`,
`chio-settle`, `chio-reputation`, `chio-mercury`, `chio-mercury-core`,
`chio-underwriting`, `chio-appraisal`) and turns the trajectory-1 M06 OCI
guard registry into a priced marketplace whose installs settle at receipt
finalization. Half B introduces `chio-lineage`, a provenance graph that
ingests the trajectory-1 M10 OTEL receipt exporter stream plus the M04
deterministic corpus and materializes a queryable DAG of prompt -> capability
check -> guard verdict -> tool call -> downstream receipts. The two halves
share the same anchor surface: marketplace settlements emit signed receipts,
and lineage roots can be PQ-anchored via trajectory-2 M03.

## Why this is on the trajectory

trajectory-1 left two specific structural holes that block downstream value:

- The economic crates (`crates/chio-credit/`, `crates/chio-settle/`,
  `crates/chio-reputation/`, `crates/chio-mercury/`, `crates/chio-mercury-core/`,
  `crates/chio-underwriting/`, `crates/chio-appraisal/`) ship complete
  type machinery (around 30k LOC measured 2026-04-29) but are not wired
  into the kernel, the guard registry, or the CLI. They are dormant by
  design: trajectory-1 shipped the substrate without choosing a single
  surface to commerce-ize. M09 chooses guard installs as that surface.
- The receipt log is append-only and queryable only by primary key
  (`crates/chio-store-sqlite/src/receipt_store.rs`). The M10 OTEL
  exporter (trajectory-1 commit `3e0f04b52`) produces a stream of
  spans linkable to receipts, but no crate consumes that stream as
  graph input. An operator who asks "show every tool call whose
  capability transitively depended on credential X revoked at T"
  has no answer surface today.

Both gaps survive into trajectory-2 because they were correctly out of
scope for trajectory-1; M09 is the W4 capstone that unifies them. The
economic half depends on M04's revocation oracle (publishers' credentials
revoke on the same sparse-Merkle root that revokes capabilities) and on
M07's provider matrix (the cross-provider verdict equality result is the
comparability oracle for guard reputation). The lineage half depends on
M06's `CanonicalBytes` newtype (lineage anchors hash canonical bytes,
not loose JSON) and on M03's PQ-hybrid surface (anchor roots can be
PQ-signed for long-horizon audit).

## Prior-art reckoning

trajectory-1 shipped the substrate; M09 wakes it without forking.

What is preserved untouched:

- `crates/chio-credit/src/lib.rs` (1524 lines): the existing account
  model, IOU envelope shapes, `CreditAccount`, `BondedExecution`, and
  the underwriter/appraisal hooks. M09 adds a kernel-evaluator path
  that mints IOU envelopes against finalized receipts; the type
  surface is consumed, not redrawn.
- `crates/chio-settle/` (6316 lines across 8 files): the EVM, Solana,
  CCIP, and ops surfaces are preserved. M09 binds settlement to receipt
  finalization through a new `SettlementHook` trait; existing modes
  (`automation.rs`, `ccip.rs`, `evm.rs`, `solana.rs`) keep working.
- `crates/chio-reputation/src/{model,score,compare,issuance}.rs` (1265
  lines): the deterministic local scoring crate is consumed as-is. M09
  adds two ingress feeds (M08 arena survival rate; trajectory-1 M07
  cross-provider equality) and an output binding that gates marketplace
  discovery.
- `crates/chio-underwriting/` (2075 lines) and `crates/chio-appraisal/`
  (3822 lines): the underwriting decision/appeal artifacts and pricing
  oracle types are reused. M09 adds a guard-pricing helper that
  consumes `chio-appraisal` and a credit-limit helper that consumes
  `chio-underwriting`; neither crate's public types change.
- `crates/chio-guard-registry/src/{publish,pull,verify,oci,offline,
  cache}.rs`: the OCI registry plus cosign bundle gating from
  trajectory-1 M06. M09 adds a price field to manifests and a
  reputation-gated `discover` path; the verify and pull paths are
  unchanged.
- `crates/chio-otel-receipt-exporter/src/{ingress,sink,denylist}.rs`:
  the trajectory-1 M10 OTEL surface is the lineage feed. M09 adds a
  consumer crate (`chio-lineage`) that subscribes to the same NDJSON
  frames; the exporter is unchanged.
- `crates/chio-store-sqlite/src/{receipt_store,receipt_query,
  capability_lineage}.rs`: existing receipt query and capability
  lineage indexers. M09's `chio-lineage` builds a DAG view on top of
  the same SQLite store; the underlying schema gains additive columns
  only.

What is changed (deliberately):

- `chio-credit::CreditAccount` gains a `kernel_evaluator_hook`
  registration entry point. Receipts emitted by the kernel after
  signing trigger an IOU mint at finalization. The signed receipt
  is the trigger; no IOUs ship without a signed receipt. Fail-closed:
  if signing fails, no IOU is minted.
- `chio-settle::SettlementHook` trait lands as a kernel evaluator
  observer (trajectory-1 M05's async-kernel evaluator surface). The hook receives
  `(receipt_root, finalization_time)` and routes through the existing
  `chio-settle/ops.rs` pipeline.
- `chio-reputation` grows two `Feed` impls: `ArenaSurvivalFeed`
  consuming trajectory-2 M08's arena rounds, and `CrossProviderEqualityFeed`
  consuming trajectory-1 M07's verdict-equality result. Both feeds
  produce deterministic score deltas.
- `chio-guard-registry` manifest gains `price: GuardPrice` and
  `reputation_floor: ReputationTier` (additive optional fields).
  Manifests without these fields keep working at zero price and the
  lowest tier, preserving trajectory-1 M06 cosign-bundle behaviour.
- `crates/chio-cli/src/main.rs` gains `arc guard market {list,install,info}`
  and `arc lineage {query,diff,roots}` subcommands. Existing
  subcommands (`guard`, `reputation`) are unaffected.
- `crates/chio-lineage/` is new (zero lines today). All schema, query
  surface, and indexer logic ships here.

## Hard counts (measured 2026-04-29)

Reproduce with the commands in parentheses; update the date and numbers
if you re-run.

- Dormant economic crates (count of `.rs` lines):
  `chio-credit/src/lib.rs` 1524;
  `chio-settle/src/` 6316 (8 files);
  `chio-reputation/src/` 1265 (5 files);
  `chio-mercury/src/` 947 (2 files);
  `chio-mercury-core/src/` 9357;
  `chio-underwriting/src/` 2075;
  `chio-appraisal/src/lib.rs` 3822;
  `chio-anchor/src/` 4704;
  `chio-link/src/` 3472.
  (`wc -l crates/chio-{credit,settle,reputation,mercury,mercury-core,
  underwriting,appraisal,anchor,link}/src/*.rs`)
- `chio-credit` callers from outside its own crate
  (`grep -rE 'use\s+chio_credit' crates/ | grep -v 'crates/chio-credit/'`):
  1 caller (`chio-settle` only). The kernel does not consume it today.
- `chio-settle` callers from outside its own crate: 1 caller
  (`chio-mercury-core`). Not wired into kernel finalization.
- `chio-reputation` consumers other than `chio-cli/src/reputation.rs`:
  zero. The CLI surfaces a CLI but no kernel-side scoring loop runs.
- `chio-guard-registry` manifest `price` field
  (`grep -c 'price' crates/chio-guard-registry/src/oci.rs`): zero.
- `chio-otel-receipt-exporter` consumers
  (`grep -rE 'chio_otel_receipt_exporter' crates/`): one (the binary
  shim in `crates/chio-otel-receipt-exporter/src/main.rs`). No
  downstream lineage subscriber.
- `chio-store-sqlite` recursive-CTE queries
  (`grep -c 'WITH RECURSIVE' crates/chio-store-sqlite/src/*.rs`):
  zero today. The lineage half adds them.
- `chio-store-sqlite` source files at start of M09 (P0 baseline):
  16 files under `crates/chio-store-sqlite/src/`. The additive
  `iou_envelope` migration in P1.T3 and the `lineage_cte.rs` module
  in P5.T4 are the only new files; no schema columns are dropped.
  (`ls crates/chio-store-sqlite/src/*.rs | wc -l`)
- New crate `crates/chio-lineage/`: zero lines. M09 creates it.
- `arc` CLI subcommand surface (`grep -E '^\s+[A-Z][a-z]+\(.*Args\)'
  crates/chio-cli/src/main.rs`): existing surface present; M09 adds two
  subcommand groups (`Market`, `Lineage`).

## Workspace dependency state

Pinned in `[workspace.dependencies]` of root `Cargo.toml` today and
reused by M09:

- `serde`, `serde_json` (canonical encodings of guard manifest pricing
  and lineage frames).
- `thiserror` (error types throughout the economic crates).
- `tokio`, `tokio-stream` (lineage indexer ingest from OTEL stream).
- `rusqlite` (lineage store reuses `chio-store-sqlite`).
- `clap` (already used by `chio-cli`; new subcommands plug in).
- `tracing` (lineage ingest spans).

Pinned by M09 wave-opener (P0). Re-check crates.io for current latest
patch versions on the day P0 opens before pasting these. Targets at the
time of authoring (2026-04-29):

- `petgraph = "0.6"`. Pin rationale: the lineage DAG holds receipts as
  nodes and capability/guard edges; `petgraph` provides the in-memory
  graph type used during diff computation. The persistent store is
  SQLite; `petgraph` is for the in-memory window inside a query.
- `csv = "1"`. Pin rationale: priced-guard demo workflow exports
  per-tenant settlement summaries as CSV from `arc guard market`.
- No new direct PQ or KEM crates. Lineage anchor signing reuses M03's
  hybrid backend (soft-dep).
- No new web3 deps. The dormant `web3` features on `chio-settle`,
  `chio-anchor`, and `chio-link` stay default-on for callers that
  already used them; M09 does not add new chains.

Cargo.lock changes are confined to the P0 wave-opener. Subsequent
tickets add no new direct dependencies.

## Scope

In:

- Wake `chio-credit` as a receipt-finalization-driven IOU mint surface.
  Each receipt with a non-zero invocation price emits one IOU envelope
  signed by the existing kernel signing key (M03 hybrid-aware via
  soft-dep).
- Wake `chio-settle` via `SettlementHook` registered into the kernel
  evaluator observer slot. Settlements run only after the receipt is
  signed and stored; failure to settle does not roll back a signed
  receipt (fail-closed but non-blocking on the dispatch path).
- Wake `chio-reputation` with two ingress feeds (`ArenaSurvivalFeed`,
  `CrossProviderEqualityFeed`) and an output `ReputationTier` enum
  consumed by the marketplace discovery path. Reputation gates
  discovery; cosign verify (trajectory-1 M06) gates publication.
- Marketplace surface: pricing through `chio-appraisal` helpers,
  underwriting through `chio-underwriting` helpers, reputation-weighted
  credit limits per cluster operator. `arc guard market list/install/info`
  exposed on `chio-cli`.
- Cluster-operator subscription model: a tenant binds a "guard bundle"
  (set of guard package refs); each invocation of any guard in the
  bundle settles at receipt finalization through `chio-settle` ops.
- New crate `crates/chio-lineage/`: indexer subscribing to the
  trajectory-1 M10 OTEL receipt exporter stream and the M04
  deterministic corpus; DAG schema atop `chio-store-sqlite` with
  recursive-CTE query layer; Cypher-ish surface for forward and
  reverse queries; differential mode comparing lineage roots across
  guard versions.
- `arc lineage query/diff/roots` CLI subcommand on `chio-cli`.
- Tiny web viewer at `docs/demo/lineage/` (static HTML + the lineage
  JSON dump format). No build pipeline; the viewer reads a single
  JSON file produced by `arc lineage query`.
- Optional anchor pinning of lineage roots through trajectory-1 M10
  anchored-root corpus and trajectory-2 M03 PQ-signed anchors.

Out (and why):

- On-chain anchoring or bug-bounty bridges. Wildcard V07-adjacent;
  out of trajectory-2 scope per the round-2 decisions in `README.md`.
- New economic primitives. M09 activates what `chio-credit`,
  `chio-settle`, `chio-reputation`, `chio-underwriting`, and
  `chio-appraisal` already model. The IOU envelope, account, bond,
  and tier types are reused; no new currencies or bond shapes are
  introduced.
- `chio-mesh` consensus. Explicitly out of trajectory-2 (round-2
  decision 4). Settlement runs through the existing single-kernel
  path; there is no cross-kernel consensus surface in M09.
- New chains or settlement venues. The dormant `web3` features in
  `chio-settle`, `chio-anchor`, and `chio-link` stay as-is; M09 does
  not add EVM L2s, Solana programs, or new CCIP routes.
- A general-purpose graph database. `chio-lineage` rides on
  `chio-store-sqlite`; the in-memory `petgraph` window is per-query,
  not persistent. A swap to a real graph DB would be a separate
  milestone.
- Live web dashboards or hosted SaaS. `docs/demo/lineage/` is a static
  viewer, not a service. Hosted lineage is out of trajectory-2.
- Non-receipt provenance sources. The lineage indexer consumes only
  the M10 OTEL stream and the M04 corpus; arbitrary log sources
  are out of scope.

## Phases

### P0: Wave-opener Cargo.lock bump and audit-doc seeding

- M09.P0.T1: Pin `petgraph` and `csv` in workspace `Cargo.toml`;
  refresh `Cargo.lock`.
- M09.P0.T2: Genesis the `crates/chio-lineage/` crate skeleton with
  `Cargo.toml`, an empty `src/lib.rs`, and workspace registration.
- M09.P0.T3: Add `marketplace` cargo feature to `chio-guard-registry`
  (default-off; gates the new `price` and `reputation_floor` manifest
  fields) and `lineage` cargo feature to `chio-store-sqlite`
  (default-off; gates the recursive-CTE query helpers).
- M09.P0.T4: Open the audit doc at
  `.planning/audits/M09-economic-layer-and-lineage.md` with the
  starting counts (dormant-crate LOC, zero kernel callers, zero
  recursive-CTE queries, zero lineage crate lines).

### P1: `chio-credit` activation

- M09.P1.T1: Define `CreditEvaluatorHook` trait inside `chio-credit`
  (signed-receipt-in, IOU-envelope-out). Hook is `&dyn Trait`,
  registered with the kernel evaluator surface from trajectory-1 M05
  (async kernel post-dispatch observer slot).
- M09.P1.T2: Implement the in-memory `LocalCreditAccount` IOU mint
  path: each finalized receipt produces exactly one IOU envelope or
  zero (zero-price guards). Signing reuses the kernel's existing
  signing backend (M03 hybrid-aware via soft-dep).
- M09.P1.T3: Persist IOUs through `chio-store-sqlite` via a new
  `iou_envelope` table (additive schema migration; idempotent).
- M09.P1.T4: Property test in `crates/chio-credit/tests/`: every
  finalized receipt either produces exactly one IOU at the manifest
  price or no IOU when manifest price is zero. No partial state.
- M09.P1.T5: Migration test: existing receipts (no manifest price)
  re-process under M09 with zero IOUs minted; bytes unchanged.
- M09.P1.T6: Audit-doc update with kernel-caller count and IOU
  schema row.

### P2: `chio-settle` activation

- M09.P2.T1: Define `SettlementHook` trait in `chio-settle`; route
  finalized receipts through `chio-settle/ops.rs` once the IOU has
  been minted. Settlements are ordered by receipt finalization
  timestamp; ties broken by receipt id (deterministic).
- M09.P2.T2: Wire the hook into the kernel evaluator's observer slot
  (trajectory-1 M05 async-kernel evaluator surface). Settlement runs after signing,
  on the post-dispatch task; failure-to-settle never blocks dispatch.
- M09.P2.T3: Bind retry policy: settle failures retry exponentially up
  to a documented bound; permanent failures land in a
  `settle_dead_letters` table for operator review. Fail-closed: dead
  letters do not auto-retry past the documented bound.
- M09.P2.T4: Integration test: drive ten receipts through the kernel,
  assert ten settlements processed, assert byte-equivalence of the
  receipts vs the no-settlement baseline (settlement is observer-only
  on the receipt path).
- M09.P2.T5: `arc settle status` CLI surface showing pending, settled,
  dead-lettered for the local store.
- M09.P2.T6: Audit-doc update with settlement throughput counters.

### P3: `chio-reputation` activation

- M09.P3.T1: Define `ReputationFeed` trait. Feeds are deterministic
  functions from observed signal to score delta; feeds do not call
  back into the kernel.
- M09.P3.T2: Implement `ArenaSurvivalFeed` consuming trajectory-2
  M08's arena round outputs (soft-dep on M08; if absent, the feed
  reports zero deltas and the milestone proceeds).
- M09.P3.T3: Implement `CrossProviderEqualityFeed` consuming
  trajectory-1 M07's `chio-conformance/verdict_matrix/` results.
- M09.P3.T4: Define `ReputationTier` enum (`tier_0` through `tier_3`)
  and the threshold table that maps numeric scores to tiers. Tiers
  gate marketplace discovery; cosign verify still gates publication.
- M09.P3.T5: Property test in `crates/chio-reputation/tests/`: feed
  composition is monotonic in observed signal (more arena survival
  never decreases score; more equality never decreases score).
- M09.P3.T6: Audit-doc update with reputation tier distribution on
  the M04 corpus.

### P4: Marketplace surface

- M09.P4.T1: Extend `chio-guard-registry` manifest schema with
  optional `price: GuardPrice` and `reputation_floor: ReputationTier`
  fields (gated by the `marketplace` feature). Manifests without
  these fields keep working at zero price and tier_0 floor.
- M09.P4.T2: Implement `chio-appraisal`-backed pricing helper: given
  a guard manifest plus tenant context, compute the per-invocation
  price. Reuses existing `chio-appraisal` types; no new pricing
  primitives.
- M09.P4.T3: Implement `chio-underwriting`-backed credit-limit helper:
  reputation-weighted limits per cluster-operator account. Reuses
  existing `chio-underwriting::Decision` shape.
- M09.P4.T4: `arc guard market list` subcommand on `chio-cli`. Lists
  guards filtered by tenant reputation tier; output is a stable,
  sorted, machine-readable JSON plus a TTY-friendly table.
- M09.P4.T5: `arc guard market info <ref>` subcommand showing price,
  reputation floor, cosign bundle status, and recent settlement
  summary for the tenant.
- M09.P4.T6: `arc guard market install <ref>` subcommand: pulls and
  verifies the guard via the existing M06 path, registers the
  per-invocation price, and adds the guard to the tenant's bundle.
  Idempotent; re-installing the same ref produces no diff.
- M09.P4.T7: End-to-end demo test in
  `crates/chio-cli/tests/market_demo.rs`: install a priced fixture
  guard, run a tool call, assert one IOU minted and one settlement
  processed.

### P5: `chio-lineage` crate genesis

- M09.P5.T1: Define the lineage DAG schema in `crates/chio-lineage/src/`:
  nodes for prompt, capability check, guard verdict, tool call,
  receipt; edges typed by the relation kind. The schema is the
  source of truth and has a JSON Schema artifact at
  `crates/chio-lineage/schemas/lineage-graph.v1.json`.
- M09.P5.T2: Implement the OTEL ingest path: subscribe to the
  trajectory-1 M10 OTEL receipt exporter NDJSON stream
  (`crates/chio-otel-receipt-exporter/src/sink.rs` is the source);
  fold each frame into the DAG. Idempotent on re-ingest.
- M09.P5.T3: Implement the M04 deterministic corpus ingest path:
  read replay-corpus fixtures and reconstruct the same DAG shape
  for offline ground truth.
- M09.P5.T4: Implement the recursive-CTE query layer atop
  `chio-store-sqlite`. Two canonical queries land first: forward
  ("show every receipt downstream of model M with capability C in
  window W") and reverse ("show every tool call whose capability
  transitively depended on credential X revoked at T").
- M09.P5.T5: Differential mode: given two guard versions
  (`pii-mask v1` vs `pii-mask v2`), produce the symmetric diff of
  lineage edges across the same M04 corpus run. Output is a stable
  JSON diff plus a Cypher-ish text summary.
- M09.P5.T6: Anchor pinning: optional command that hashes the
  current lineage frontier through M06's `CanonicalBytes` and
  PQ-signs via M03's hybrid backend. The signed frontier writes to
  the trajectory-1 M10 anchored-root corpus path. Soft-deps on
  M03 and M06; if either is absent, the command logs and exits
  cleanly without producing a signed root.
- M09.P5.T7: `arc lineage query/diff/roots` subcommand on `chio-cli`.
  `query` runs a named query with parameters; `diff` runs the
  differential mode; `roots` lists anchored roots.
- M09.P5.T8: Tiny web viewer at `docs/demo/lineage/index.html` plus
  a CSS file and a JS file. Reads a single `lineage.json` produced
  by `arc lineage query --emit demo`. No build step; vanilla static
  files. Documented in `docs/demo/lineage/README.md`.
- M09.P5.T9: Audit-doc final pass: closing counts (lineage crate
  LOC, recursive-CTE query count, anchored roots count, marketplace
  manifest count).

## Cross-milestone interactions

- trajectory-1 M01 (`crates/chio-core/tests/`) canonical-JSON receipt
  vectors lock receipt encoding. The IOU envelope and lineage frames
  use canonical JSON; no existing receipt vectors change.
- trajectory-1 M04 (`.planning/audits/M04-deterministic-replay.md`)
  deterministic corpus is the lineage ground truth in P5.T3. The
  receipt schema is unchanged; the lineage indexer reads it.
- trajectory-1 M06 (`crates/chio-guard-registry/`) OCI registry plus
  cosign bundle verification is the marketplace substrate. M09 adds
  optional manifest fields; the verify and pull paths are unchanged.
- trajectory-1 M07 (`crates/chio-conformance/verdict_matrix/`)
  cross-provider verdict equality is the comparability oracle for
  `CrossProviderEqualityFeed` in P3.T3.
- trajectory-1 M10 (`crates/chio-otel-receipt-exporter/src/sink.rs`)
  OTEL receipt stream is the lineage feed in P5.T2.
- trajectory-2 M03 (`crates/chio-attest-verify/`) hybrid signing
  surface is the soft-dep for IOU envelope signing (P1.T2) and
  anchor signing (P5.T6). If M03 is absent, the IOU envelope falls
  back to the existing classical signing path.
- trajectory-2 M04 (`crates/chio-revocation-oracle/`) sparse-Merkle
  revocation oracle revokes guard-publisher credentials. The
  marketplace discovery path consults the oracle; revocation
  cascades through lineage in the differential mode (P5.T5 surfaces
  the cascade).
- trajectory-1 M05 async kernel (post-dispatch evaluator/observer
  surface) is the registration point for `CreditEvaluatorHook`
  (P1.T1) and `SettlementHook` (P2.T2). The slot is already live on
  `main`; M09 only plugs into it.
- trajectory-2 M06 (`CanonicalBytes` newtype) is the byte source
  hashed by anchor pinning (P5.T6). Soft-dep; if M06 lands later,
  P5.T6 uses a byte-equivalence shim.
- trajectory-2 M08 (`crates/chio-arena/`) arena round outputs feed
  `ArenaSurvivalFeed` in P3.T2. Per the wave plan, M08 closes in
  Wave 3 before M09 opens in Wave 4, so the feed always finds M08
  outputs at runtime. The M09.P3.T2 ticket retains a defensive
  empty-input fallback for unit-test isolation; this is not a
  schedule-tolerance soft-dep.
- D21 enumerates `chio-mercury`, `chio-mercury-core`, and
  `chio-anchor` alongside the directly-activated economic crates.
  Per decisions.yml D26, those three wake transitively rather than
  through dedicated phases: `chio-mercury` and `chio-mercury-core`
  exercise their surfaces via `chio-settle` activation in P2 (the
  one existing in-workspace caller is `chio-settle`); `chio-anchor`
  is consumed by lineage anchor-pinning at P5.T6 via the trajectory-1
  M10 anchored-root corpus path. The audit doc records transitive-
  caller counts for the three so the no-new-crates discipline stays
  observable.

## Risks and mitigations

- **Receipt-finalization back-pressure from settlement.** Hook
  failures in `SettlementHook` could stall the dispatch path.
  Mitigation: settlement runs on the post-dispatch task; the
  dispatch path emits and signs the receipt before any settlement
  call. P2.T2 enforces this ordering. Dispatch latency benches in
  trajectory-2 M06 catch regressions.
- **IOU minting without settlement.** A finalized receipt with a
  minted IOU but no settlement leaves an accounting drift.
  Mitigation: dead-letter table in P2.T3 plus the property test in
  P1.T4 ensure every IOU has a downstream lifecycle entry. Audit
  doc tracks open dead letters.
- **Reputation feed Sybil attacks.** A flood of arena rounds or
  cross-provider equality wins could inflate a publisher's tier.
  Mitigation: feeds compose monotonically (P3.T5) but tiers are
  bounded; `tier_3` requires both feeds to clear independent
  thresholds. The threshold table is policy-loaded and
  fail-closed.
- **Anchor-pinning soft-dep absence.** M03 or M06 may land after
  M09 closes. Mitigation: P5.T6 logs and exits cleanly when soft
  deps are absent; the audit doc records the unsigned frontier so
  late-binding anchor signing can backfill.
- **Lineage indexer drift vs OTEL stream.** Schema changes in the
  M10 exporter could break ingestion. Mitigation: ingest path has
  a `schema_version` gate; unknown versions reject fail-closed.
  P5.T2 includes a regression fixture pinned against the
  trajectory-1 M10 NDJSON shape.
- **Recursive-CTE query cost.** SQLite recursive CTEs can blow up
  on dense graphs. Mitigation: query layer caps recursion depth
  with a documented bound; queries that exceed the bound return a
  truncation marker rather than failing. Bench coverage in P5.T4.
- **Marketplace pricing oracle drift.** `chio-appraisal` is reused
  but its pricing helper is new; misconfiguration could underprice
  or overprice guards. Mitigation: pricing helper outputs are
  deterministic functions of manifest + tenant; the property test
  in P3.T5 (monotonic feeds) plus a separate pricing-bench in P4
  catch drift.

## Success criteria

- `cargo test -p chio-credit` green; IOU mint property test passes.
- `cargo test -p chio-settle` green; settlement integration test
  shows ten receipts produce ten settlements.
- `cargo test -p chio-reputation` green; both ingress feeds produce
  monotonic deltas under the property test.
- `cargo test -p chio-guard-registry --features marketplace` green;
  manifest schema accepts and rejects price + reputation floor as
  documented.
- `cargo test -p chio-lineage` green; both forward and reverse
  recursive-CTE queries return correct results on the M04 corpus
  fixture.
- `arc guard market {list,install,info}` subcommands present and
  exercised by the end-to-end demo test in P4.T7.
- `arc lineage {query,diff,roots}` subcommands present.
- Static viewer at `docs/demo/lineage/index.html` opens in a browser
  and renders a sample lineage JSON dump.
- Audit doc at `.planning/audits/M09-economic-layer-and-lineage.md`
  closes with the count deltas listed in the hard-counts table
  (LOC, kernel-caller count, IOU rows, anchored roots, marketplace
  manifests).
