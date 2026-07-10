# Formal Verification: Gap Analysis

- Status: Assessed 2026-07-09 (survey at commit `dbb4639e1`)
- Companion docs: [CURRENT_STATE.md](CURRENT_STATE.md),
  [HYGIENE_PASS.md](HYGIENE_PASS.md), [ROADMAP.md](ROADMAP.md), plan specs
  under [plan/](plan/)

Six load-bearing gaps (G1-G6), each with evidence, consequence, and the plan
docs that address it. A full staleness inventory follows; the mechanical
fixes are specified item-by-item in [HYGIENE_PASS.md](HYGIENE_PASS.md).

## G1: Nothing proof-shaped runs on pull requests

Evidence:

- `.github/workflows/nightly.yml` (near L69) refers to a PR job
  "kani-public-pr in ci.yml" that does not exist in any workflow file.
- `formal/rust-verification/kani-public-harnesses.toml` defines a `lanes.pr`
  containing all 20 kernel-core public harnesses, with a note that the full
  sweep takes about 2.2 minutes, within a 6-minute PR budget. That lane
  executes only inside the nightly job.
- `.github/workflows/mutants.yml` has `on: schedule` and `workflow_dispatch`
  only; its `mutants-pr` job is gated on `github.event_name ==
  'pull_request'` and can never fire. The file header still calls it a
  required lane.
- No workflow path-triggers on `formal/lean4/**`. A PR editing Lean proofs
  merges without a `lake build`; `scripts/check-formal-proofs.sh` runs only
  on push to main (release qualification) and nightly.
- The only PR-time formal gates are Apalache safety (path-scoped) and the
  diff-tests crate (workspace tests).

Consequence: a PR can break any proof, harness, or contract and the breakage
surfaces the next morning (or at release qualification), after the author has
moved on. Feedback latency also discourages contributors from touching the
formal tree at all.

Addressed by: [plan/FV-E3-pr-formal-smoke-tier.md](plan/FV-E3-pr-formal-smoke-tier.md)
(wiring), [plan/FV-E5-lane-ratchets.md](plan/FV-E5-lane-ratchets.md)
(promotion to required),
[plan/FV-A4-mirror-drift-hashes.md](plan/FV-A4-mirror-drift-hashes.md)
(PR-cheap drift detection without toolchains).

## G2: The proven code is often not the running code

Evidence:

- `crates/kernel/chio-kernel-core/src/formal_core.rs` carries
  `#![allow(dead_code)]`. Its verified helpers `budget_precheck`,
  `budget_commit`, `dpop_freshness_valid`, `dpop_admits`, `nonce_admits`,
  `guard_pipeline_allows`, `revocation_snapshot_denies`, and
  `receipt_fields_coupled` are called by Kani harnesses, Creusot contracts,
  and the Lean model, but not by production code. The runtime logic they
  mirror lives separately in chio-kernel (budget store, DPoP admission, guard
  verdict fold, revocation view, receipt assembly).
- Only two helper families are absorbed today: the time-window classifier
  (called from real token verification in `capability_verify.rs`) and the
  five subset helpers (called from `NormalizedToolGrant::is_subset_of` in
  `normalized.rs`).

Consequence: for the unabsorbed families, theorems and proofs attach to a
parallel model, so a divergence between model and runtime is invisible to the
proof lanes. This is precisely the class of claim the CLAIM_REGISTRY
downgrades (approved-with-scope rather than implementation-linked).

Addressed by:
[plan/FV-A1-absorb-verified-helpers.md](plan/FV-A1-absorb-verified-helpers.md)
(primary), with
[plan/FV-A2-aeneas-generated-equivalence.md](plan/FV-A2-aeneas-generated-equivalence.md)
and [plan/FV-A3-creusot-dedup.md](plan/FV-A3-creusot-dedup.md) hardening the
other two hops.

## G3: The drop/cancel unwind surface is under-modeled, and it is where the bugs were

Evidence:

- The most recent kernel fix family (this branch, 2026-07): retained
  reservations on incomplete-stream outputs (`84e98b9d0`), completed
  pre-dispatch drop unwind with invocation and child budget plus a fault
  receipt (`a6d26dbc4`), retained reservations on post-invocation block
  denials (`58abf33d2`), flushing buffered nested child receipts on
  post-dispatch drop (`38cc91471`), retained runtime-admission reservations
  on aborted unwind paths (`c201afbd0`), a `dispatch_started` split of the
  drop unwind (`c2e8be7e3`). None of these commits touched `formal/`.
- `formal/apalache/KernelTransitionCancelSafe.tla` covers exactly this
  surface, but its header admits the invariant holds by construction (Commit
  is guarded on `cancel_pending = FALSE`) and defers concurrent
  commit-vs-cancel races.
- A loom race model for the drop guard exists in chio-kernel but has no
  registry or CI lane.

Consequence: the single most bug-productive region of the TCB has the weakest
formal coverage. The models passed while production was wrong, which is the
worst failure mode a formal estate can have (false confidence).

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
- Sync in `proof-manifest.toml` is by symbol name only; nothing hashes the
  mirrored content, so a semantic change on the Rust side of a mirror is
  invisible until a human notices.
- Confirmed while grounding the plan specs: the Lean core-model "Mirrors:"
  headers drifted in the Phase 6 crate moves (Capability.lean and Scope.lean
  point at a file that no longer exists; Revocation.lean points at a
  function that moved; Receipt.lean misnames its module), and the MAPPING
  liveness row cites `ASSUME-PROPAGATE-FAIRNESS`, an id absent from
  `assumptions.toml`. See H14 and H15.

Consequence: each individual item is small, but together they show the sync
layer relies on human discipline where it could be mechanical. Auditors
sampling these files would find contradictions.

Addressed by: [HYGIENE_PASS.md](HYGIENE_PASS.md) (immediate fixes),
[plan/FV-A4-mirror-drift-hashes.md](plan/FV-A4-mirror-drift-hashes.md) and
[plan/FV-A3-creusot-dedup.md](plan/FV-A3-creusot-dedup.md) (mechanical
prevention),
[plan/FV-C5-proof-coverage-map.md](plan/FV-C5-proof-coverage-map.md)
(cross-registry join that makes inconsistency visible).

## G5: The proof lanes are never adversarially measured

Evidence:

- `.cargo/mutants.toml` and the per-crate configs exclude `formal_aeneas.rs`,
  `formal_core.rs`, and both Kani harness files with the rationale "covered
  by the proof lane". No lane ever mutates those files and checks whether the
  proof lane notices.
- The negative-test discipline exists (two broken Apalache specs) but is
  manual, local-only, and covers 2 of 6 models.
- The trust-boundary mutation baseline (2026-04-29) measured a 30.7% kill
  rate against an 80% activation target; the ratchet in `releases.toml` shows
  0 observed consecutive green nights; `mutants-nightly` is
  continue-on-error.
- `CHIO_RUST_VERIFICATION_METADATA_ONLY=1` downgrades the strict
  Creusot/Kani gates to schema-only checks in three places, and the proof
  report does not record which mode produced it.

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

Evidence:

- Orphaned corpus directories that no `[[bin]]` name matches:
  `fuzz/corpus/fuzz_capability_receipt` (13 rich binding vectors),
  `fuzz_canonical_json` (2), `fuzz_manifest_roundtrip` (6), while the
  bin-named directories hold 1-3 seeds each. The richer seed sets are unused
  by default corpus resolution.
- Four targets have no seed corpus directory at all: `eval_receipt_bundle`,
  `federation_trust_establishment`, `underwriting_policy_input`,
  `revocation_oracle_merkle`.
- `fuzz/tests/smoke.rs` (corpus smoke plus matrix-vs-binaries inventory sync
  tests) is run by no CI job; `fuzz/` is a standalone workspace excluded from
  `cargo test --workspace`.
- `scripts/check-corpus-metadata.sh` is wired to no workflow.
- `fuzz/owners.toml` is missing 5 targets, which breaks
  `scripts/promote_fuzz_seed.sh` owner resolution.
- The budget-cap contract (PR lanes hard halt, scheduled lanes advisory) is
  written into `docs/fuzzing/continuous.md`, both PR budget-step comments,
  and a dedicated contract test
  (`scripts/tests/fuzz-budget-hard-halt.test.sh`), but neither PR budget
  step sets `GH_FUZZ_BUDGET_CAP_MODE` (the script defaults to warn) and the
  contract test is wired into no CI job, so effective behavior is warn
  everywhere; only the four scheduled lanes set warn explicitly and
  deliberately.

Consequence: fuzzing effectiveness silently degrades (empty corpora, unused
seeds) and inventory-sync regressions land unnoticed. All items are cheap to
fix.

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
11. Stale Lean "Mirrors:" headers after the Phase 6 crate moves (H14).
12. MAPPING citing the unregistered id `ASSUME-PROPAGATE-FAIRNESS` (H15).

## What is deliberately out of scope here

- The `CONTRACTOR-SIGNOFF.md` external-review debt (tracked in that file).
- The known-unreliable Apalache temporal lane (its header forbids promotion
  until the property is fixed; see
  [plan/FV-D1-distributed-revocation-model.md](plan/FV-D1-distributed-revocation-model.md)
  for the model rework that likely subsumes it).
- OSS-Fuzz acceptance (files complete, upstream decision pending).
