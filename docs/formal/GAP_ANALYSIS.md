# Formal Verification: Gap Analysis

- Status: Reassessed 2026-07-15 after roadmap execution
- Companion docs: [CURRENT_STATE.md](CURRENT_STATE.md),
  [HYGIENE_PASS.md](HYGIENE_PASS.md), [ROADMAP.md](ROADMAP.md), plan specs
  under [plan/](plan/)

The original six load-bearing gaps are retained below as execution history.
The implementation closes their code and local-evidence portions. Three
boundaries remain deliberately open:

- G3 retains hosted concurrency and distributed-systems qualification. Local
  Loom and deterministic-simulation gates pass, but hosted streaks are not
  inferred.
- G4 retains semantic scope exclusions documented by each refinement bridge.
  Mirror hashes and generated equivalence prevent drift; they do not prove
  parsers, cryptographic implementations, storage engines, transports, or
  behavior outside each explicitly modeled domain.
- G5 retains mutation survivors and timeout evidence as visible limitations.
  A timeout counts as not killed, and no survivor is reclassified as success.

The collection-level economy proof is separately blocked on the absent netting
surface. Scalar conservation groundwork does not license P11. A full
staleness inventory follows; the mechanical fixes are specified item-by-item
in [HYGIENE_PASS.md](HYGIENE_PASS.md).

## G1: Pull requests lacked proof feedback (resolved 2026-07-09)

Closure:

- `.github/workflows/formal-pr-smoke.yml` now classifies affected paths and
  runs Lean compilation, sorry scanning, proof-registry cross-references, all
  25 public kernel-core PR Kani harnesses, the 16 non-core PR Kani harnesses,
  and explicitly metadata-only Rust verification checks.
- `.github/workflows/mutants.yml` now triggers on changes to six
  trust-boundary crates and skips untouched matrix packages before tool setup.
- Nightly retains the union of PR and nightly-only Kani coverage, plus strict
  Creusot and release proof evidence. The PR metadata job cannot substitute for
  those strict checks.

The new checks are initially advisory. Their exact job names, reset boundaries,
freshness limits, and postures are registered in `releases.toml` and evaluated
against job-level GitHub Actions history by `scripts/lane-gate.sh`. The
five path-scoped pull-request entries are frozen until a run-always aggregator
exists and real proof execution emits a per-attempt marker. PR history is bound
to the configured base branch. Mirror drift
detection remains tracked by
[plan/FV-A4-mirror-drift-hashes.md](plan/FV-A4-mirror-drift-hashes.md).

## G2: The proven code is often not the running code (resolved 2026-07-10)

Closure:

- The eight admission helpers are curated public exports from
  `chio-kernel-core`. Shared projection functions on the production budget,
  DPoP, nonce replay, guard, revocation, and receipt-signing paths require the
  corresponding helper decisions before continuation or signing.
- Retained equivalence properties cover every projection family. Public Kani
  harnesses bind the exact shared budget and lazy revocation projection
  functions used by both production backends or callers, and both Kani
  catalogs plus `formal/MAPPING.md` register them. These harnesses do not model
  storage IO, snapshot freshness, mutation journals, or ledger transitions.
- The proof manifest names every absorbed helper and its runtime shell
  entrypoints. Hold settlement and release remain outside this closure because
  they implement a separate ledger law.
- The Rust relying-party Merkle verifier now calls a checked scalar walk step.
  Lean proves the fold against the existing receipt model, the authenticated
  Aeneas production registry extracts the step mirror and requires its
  generated-to-model theorem, Kani binds both scalar copies and the real
  bounded proof walk, and Rust-TypeScript tamper differentials pin non-Rust
  replay behavior.

Original evidence:

- At proposal time, `crates/kernel/chio-kernel-core/src/formal_core.rs` carried
  `#![allow(dead_code)]`. Its verified helpers `budget_precheck`,
  `budget_commit`, `dpop_freshness_valid`, `dpop_admits`, `nonce_admits`,
  `guard_pipeline_allows`, `revocation_snapshot_denies`, and
  `receipt_fields_coupled` are called by Kani harnesses, Creusot contracts,
  and the Lean model, but not by production code. The runtime logic they
  mirrored lived separately in chio-kernel (budget store, DPoP admission,
  guard verdict fold, revocation view, receipt assembly).
- At proposal time only two helper families were absorbed: the time-window
  classifier (called from real token verification in `capability_verify.rs`)
  and the five subset helpers (called from `NormalizedToolGrant::is_subset_of`
  in `normalized.rs`).

Consequence resolved: the bounded predicates now execute in the runtime
decision paths. Storage, clocks, cryptography, orchestration, and ledger
settlement remain explicitly scoped rather than being implied by the absorbed
pure decisions.

Addressed by:
[plan/FV-A1-absorb-verified-helpers.md](plan/FV-A1-absorb-verified-helpers.md)
(primary), with
[plan/FV-A2-aeneas-generated-equivalence.md](plan/FV-A2-aeneas-generated-equivalence.md)
and [plan/FV-A3-creusot-dedup.md](plan/FV-A3-creusot-dedup.md) hardening the
other two hops.

## G3: The drop/cancel unwind surface is under-modeled, and it is where the bugs were (materially mitigated 2026-07-10)

Evidence:

- The most recent kernel fix family (this branch, 2026-07): retained
  reservations on incomplete-stream outputs (`84e98b9d0`), completed
  pre-dispatch drop unwind with invocation and child budget plus a fault
  receipt (`a6d26dbc4`), retained reservations on post-invocation block
  denials (`58abf33d2`), flushing buffered nested child receipts on
  post-dispatch drop (`38cc91471`), retained runtime-admission reservations
  on aborted unwind paths (`c201afbd0`), a `dispatch_started` split of the
  drop unwind (`c2e8be7e3`). None of these commits touched `formal/`.
- `formal/apalache/KernelTransitionCancelSafe.tla` abstracts only the clean
  pre-dispatch branch. Its header admits the invariant holds by construction
  (`Commit` is guarded on `cancel_pending = FALSE`), does not model the Rust
  reversal transition, and excludes post-dispatch, fault, and concurrent
  commit-vs-cancel paths.
- All ten Loom models, including the drop-guard race, now have a closed
  `.loom/harnesses.toml` registry and a scheduled `loom-nightly` lane with
  timing and log artifacts. They remain bounded test-local synchronization
  models and do not substitute Loom primitives into production kernel code.
- The deterministic simulation lane now partially polls and drops real
  `ChioKernel` futures on both sides of dispatch-start, injects receipt,
  budget, and admission faults, and applies ReceiptBeforeAllow, exact drop
  disposition, and reservation-conservation oracles after every episode. The
  fixed PR corpus has 64 seeds; the locally executed wide sweep passed 10,000
  episodes.
- Crash episodes now close and reopen real SQLite receipt and budget stores at
  both sides of receipt persistence. This covers single-process,
  single-store recovery. Distributed message loss and cross-store atomicity
  remain outside the claim boundary.

Consequence: the single most bug-productive region of the TCB has the weakest
formal coverage. The models passed while production was wrong, which is the
worst failure mode a formal estate can have (false confidence).

Current mitigation: `PostAdmissionDropGuard.tla` models the lifecycle and its
fixed defect classes have required counterexample variants. The shared
reservation law adds a counted Apalache partition, a pure Kani/Creusot/Lean
transition, a debug replay of concrete single-node journal events, a stateful
real-store proptest, registered Loom models, and the real-kernel deterministic
simulation lane. G3 remains open only for production-primitive refinement and
distributed recovery, not for the implemented single-process DST scope.

Addressed by: [plan/FV-B1-drop-guard-model.md](plan/FV-B1-drop-guard-model.md),
[plan/FV-B2-regression-negative-tests.md](plan/FV-B2-regression-negative-tests.md),
[plan/FV-B3-budget-conservation-law.md](plan/FV-B3-budget-conservation-law.md),
[plan/FV-B4-loom-registry-and-dst.md](plan/FV-B4-loom-registry-and-dst.md).

## G4: Duplication drift is already observable in the sync layer

Evidence (details and exact fixes in [HYGIENE_PASS.md](HYGIENE_PASS.md)):

- `formal/rust-verification/creusot-core/src/lib.rs` has 7 contract
  functions; `creusot-contracts.toml` lists 6
  (`revocation_snapshot_denies_contract` missing).
- `formal/MAPPING.md` cites `formal_core::revocation_snapshot_denies` as a
  covered symbol; `formal/proof-manifest.toml` `covered_rust_symbols` does
  not contain it.
- `formal/MAPPING.md` references a workflow
  `.github/workflows/apalache-nightly.yml` that does not exist, and lacks
  rows for the two WYSIWYS signing harnesses present in the Kani pr lane.
- The `RevocationPropagation.tla` header contradicts its own cfg companion on
  nightly liveness bounds (PROCS=4/CAPS=8 vs PROCS=6/CAPS=16); the liveness
  issue template repeats one of the two.
- Two fully-proven Lean theorems (`witness_soundness`,
  `sibling_sum_soundness`) are still marked `assumed` in
  `theorem-inventory.json` with the stale reason "Lean toolchain unavailable
  in CI", while a third theorem proved under the same conditions is marked
  `proved`.
- The original `proof-manifest.toml` synchronized mirrors by symbol name only.
  This is now mechanically closed for seven Lean models and seven TLA+
  models: 57 mirror entries hash 171 parser-resolved Rust symbol references,
  with per-symbol diagnostics in required PR CI. The repaired TLA+ records are
  labeled abstraction anchors so their hashes require review without claiming
  that the Rust code establishes a modeled property.
- Confirmed while grounding the plan specs: the Lean core-model "Mirrors:"
  headers drifted in the Phase 6 crate moves (Capability.lean and Scope.lean
  point at a file that no longer exists; Revocation.lean points at a
  function that moved; Receipt.lean misnames its module). The MAPPING
  liveness row also cited `ASSUME-PROPAGATE-FAIRNESS`, an id absent from
  `assumptions.toml`. H14 and H15 are now closed by corrected pointers and an
  explicit model-only fairness boundary.

Consequence: each individual item is small, but together they show the sync
layer relies on human discipline where it could be mechanical. Auditors
sampling these files would find contradictions.

Addressed by: [HYGIENE_PASS.md](HYGIENE_PASS.md) (immediate fixes),
[plan/FV-A4-mirror-drift-hashes.md](plan/FV-A4-mirror-drift-hashes.md)
(implemented Rust-to-model prevention),
[plan/FV-A3-creusot-dedup.md](plan/FV-A3-creusot-dedup.md) (Creusot
prevention),
[plan/FV-C5-proof-coverage-map.md](plan/FV-C5-proof-coverage-map.md)
(cross-registry join that makes inconsistency visible).

## G5: The proof lanes are never adversarially measured

Evidence:

- `.cargo/mutants.toml` and the per-crate configs exclude `formal_aeneas.rs`,
  `formal_core.rs`, and both Kani harness files with the rationale "covered
  by the proof lane". No lane ever mutates those files and checks whether the
  proof lane notices.
- The negative-test discipline is registered as the advisory scheduled
  `apalache-negative` lane. Its B2 workflow integration and post-reset hosted
  evidence remain pending.
- The trust-boundary mutation baseline (2026-04-29) measured a 30.7% kill
  rate against an 80% activation target; the ratchet in `releases.toml` shows
  0 observed consecutive green nights; `mutants-nightly` is
  continue-on-error.
- `CHIO_RUST_VERIFICATION_METADATA_ONLY=1` produces a proof report whose global
  mode is `metadata_only`. The C5 coverage drift preflight must pass while every
  proof command is `not_run`. Nightly publishes that mode in the summary and
  artifact name. Release qualification requires `strict`, so metadata-only
  evidence cannot satisfy the formal claim rule.
- Strict report generation requires a clean worktree and records the evidence
  boundary: the protected generator attests gate execution, while the checker
  validates structure, source binding, hashes, and commit identity without
  replaying proof commands.

Consequence: a vacuous harness, a tautological invariant, or a weakened
contract would pass every lane indefinitely. The estate cannot currently
answer "would the proofs catch a real bug in the files they own?" with
measurement.

Addressed by:
[plan/FV-E1-spec-mutation-testing.md](plan/FV-E1-spec-mutation-testing.md)
(primary),
[plan/FV-B2-regression-negative-tests.md](plan/FV-B2-regression-negative-tests.md)
(bug-grounded falsifiability),
[plan/FV-E5-lane-ratchets.md](plan/FV-E5-lane-ratchets.md) (strictness
recording and posture ratchets).

## G6: Fuzz plumbing leaks

Status: Closed (2026-07-09).

Evidence:

- Every corpus directory matches a `fuzz/Cargo.toml` binary and contains at
  least three deterministic seeds.
- `fuzz/corpus_metadata.toml` indexes every seed by target, path, source, and
  SHA-256; the required structural lane runs the fail-closed metadata check.
- The locked fuzz workspace smoke suite cross-checks binaries, the scheduled
  matrix, owner mappings, and the seed floor. It runs on fuzz-scoped pull
  requests and nightly.
- `fuzz/owners.toml` covers all 27 targets, so seed promotion resolves every
  owning crate.
- Pull-request fuzz and mutation budget checks explicitly fail at the cap;
  scheduled measurement lanes retain their explicit advisory setting.

Consequence resolved: corpus and inventory drift now fail before merge, and
scheduled replay detects upstream panics between fuzz campaigns.

Addressed by:
[plan/FV-E4-fuzz-plumbing-repair.md](plan/FV-E4-fuzz-plumbing-repair.md).

## Staleness inventory (mechanical)

Complete list with exact edits in [HYGIENE_PASS.md](HYGIENE_PASS.md):

1. Proven-but-"assumed" theorem statuses (2) and one inconsistent `proved`.
2. `creusot-contracts.toml` missing one contract.
3. `MAPPING.md`: phantom workflow reference; two missing WYSIWYS Kani rows;
   symbol citation absent from the proof manifest.
4. `check-mapping.sh` stale comment about `RevocationEventuallySeen`.
5. `RevocationPropagation.tla` header vs cfg bound contradiction, echoed in
   the liveness issue template.
6. `kani-public-harnesses.toml` dangling "added for ," ticket reference.
7. `nightly.yml` phantom `kani-public-pr` comment; `mutants.yml` header
   claiming a required PR lane.
8. `lean-toolchain` pinned to a release candidate (`v4.28.0-rc1`).
9. Fuzz budget "hard halt" comments vs `warn` default.
10. Empty placeholder dirs (`formal/tla/counterexamples/`,
    `formal/diff-tests/proptest-regressions/canonical_json_diff/`) vs the
    live regression file location.
11. Stale Lean "Mirrors:" headers after the Phase 6 crate moves (H14, closed).
12. MAPPING citing the unregistered id `ASSUME-PROPAGATE-FAIRNESS` (H15,
    closed by recording model-only fairness rather than inventing a runtime
    assumption).

## What is deliberately out of scope here

- The `CONTRACTOR-SIGNOFF.md` external-review debt (tracked in that file).
- The known-unreliable Apalache temporal lane (its header forbids promotion
  until the property is fixed; see
  [plan/FV-D1-distributed-revocation-model.md](plan/FV-D1-distributed-revocation-model.md)
  for the model rework that likely subsumes it).
- OSS-Fuzz acceptance (files complete, upstream decision pending).
