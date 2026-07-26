# Formal Verification: Hygiene Pass

- Status: Implemented and reverified (2026-07-15)
- Companion docs: [GAP_ANALYSIS.md](GAP_ANALYSIS.md) (why these matter),
  [ROADMAP.md](ROADMAP.md) (sequencing: this is Wave 0)

All fifteen items below are complete. Their targeted checks, the generated
coverage check, and the full workspace build, test, clippy, and formatting
quartet passed before the implementation commit. The pull-request formal tier
now makes the lane comments and required-check posture truthful.

Fifteen mechanical fixes: thirteen found by the 2026-07-09 survey (H1-H13)
and two more found while grounding the plan specs (H14-H15). Each item lists
the file, the defect, the fix, and how to verify. None changes verification
semantics; together they remove every known contradiction an auditor could
sample. Suggested delivery: one PR, conventional commit
`docs(formal): hygiene pass over manifests, mappings, and lane comments`
(split the workflow-comment items into a second commit if reviewers prefer
CI files isolated).

## H1. Proven theorems still marked `assumed`

- File: `formal/theorem-inventory.json` (entries
  `theorem.attenuation.witness_soundness`, near L735, and
  `theorem.budget.sibling_sum_soundness`, near L759).
- Defect: both theorems are fully proven in
  `formal/lean4/Chio/Chio/Proofs/AttenuationWitness.lean` and
  `Proofs/SiblingSumBudget.lean` (no `sorry`, root-imported), but carry
  status `assumed` with the reason "the Lean toolchain is currently
  unavailable in CI". The nightly `formal-qualification` job now installs
  Lean and runs the proof report, so the reason is stale. Inconsistently,
  `theorem.handshake.negotiation_safety` is marked `proved` under identical
  conditions.
- Fix: confirm the nightly proof report actually exercises
  `check-formal-proofs.sh` (inspect a recent
  `target/formal/proof-report.json` artifact or the nightly log), then flip
  both statuses to `proved` and update the matching status-note comments in
  the two Lean files (AttenuationWitness.lean header near L13-17,
  SiblingSumBudget.lean near L18-24). If the nightly turns out not to run
  lake, fix that first (it is then also a
  [plan/FV-E3](plan/FV-E3-pr-formal-smoke-tier.md) item) and keep the status
  but correct the reason text.
- Verify: `scripts/check-formal-proofs.sh` passes; grep the inventory for
  `"assumed"` and confirm only genuinely-assumed entries remain.

## H2. Creusot registry missing one contract

- File: `formal/rust-verification/creusot-contracts.toml`.
- Defect: `creusot-core/src/lib.rs` defines 7 contract functions;
  the toml's covered wrapper list has 6. Missing:
  `revocation_snapshot_denies_contract` (lib.rs near L44).
- Fix: add the entry with its chio-kernel-core witness symbol
  (`formal_core::revocation_snapshot_denies`), mirroring the format of the
  other six.
- Verify: count `*_contract` fns in lib.rs equals count of registry entries.
  [plan/FV-A3](plan/FV-A3-creusot-dedup.md) adds the automated completeness
  check so this cannot regress.

## H3. Proof manifest missing a symbol that MAPPING cites

- Files: `formal/proof-manifest.toml` (`covered_rust_symbols`),
  `formal/MAPPING.md`.
- Defect: MAPPING rows for `RevocationCutCompleteness` (near L80) and
  `verify_revocation_predicate_idempotent` (near L104) cite
  `formal_core::revocation_snapshot_denies` as a covered symbol; the
  manifest's `covered_rust_symbols` lists only five formal_core symbols and
  not that one.
- Fix: add `chio_kernel_core::formal_core::revocation_snapshot_denies` to
  `covered_rust_symbols` (it is real, proven, and extracted; the manifest is
  simply behind).
- Verify: every `covered_rust_symbols`-style citation in MAPPING.md resolves
  to a manifest entry (one-off grep; the durable fix is the
  [plan/FV-C5](plan/FV-C5-proof-coverage-map.md) cross-registry join).

## H4. MAPPING references a workflow that does not exist

- File: `formal/MAPPING.md` (near L75, and the "nightly Apalache lane"
  wording near L37).
- Defect: references `.github/workflows/apalache-nightly.yml`. The real
  workflows are `apalache-safety.yml` (safety, path-scoped PR plus nightly)
  and `apalache-temporal.yml` (liveness, nightly only).
- Fix: repoint both mentions to the two real workflow files, with one line on
  the split.
- Verify: every workflow path named in MAPPING.md exists on disk (this is
  the same class `cargo xtask check crate-paths` guards for crate paths;
  consider adding workflow paths to its scan targets).

## H5. Two Kani harnesses missing from the MAPPING table

- Files: `formal/MAPPING.md`,
  `formal/rust-verification/kani-public-harnesses.toml`, and
  `scripts/check-mapping.sh`.
- Defect: the pr lane lists 20 harnesses; the MAPPING Kani table has 18
  rows. Missing: `public_sign_receipt_refuses_content_hash_mismatch` and
  `public_sign_receipt_accepts_matching_content_hash` (the WYSIWYS signing
  pair). Since `check-mapping.sh` claims to enforce a row per
  `#[kani::proof]` fn and CI is green, the script's enforcement has a hole
  for exactly these two.
- Fix: first add the two rows (property: WYSIWYS content-hash binding;
  Rust call sites: the `sign_receipt` recompute-and-refuse path in
  `chio-kernel-core/src/receipts.rs`). Then reproduce why `check-mapping.sh`
  did not flag them (likely a grep pattern or whitelist gap) and close the
  hole so the gate actually fails on a missing row.
- Verify: intentionally delete one row locally; `check-mapping.sh` must fail.

## H6. Stale comment in check-mapping.sh

- File: `scripts/check-mapping.sh`.
- Defect: comment says `RevocationEventuallySeen` "is not yet landed"; it is
  defined (`formal/tla/RevocationPropagation.tla` near L374) and has a
  MAPPING row.
- Fix: delete or rewrite the comment.
- Verify: comment grep.

## H7. Liveness bounds contradiction

- Files: `formal/tla/RevocationPropagation.tla` (header, near L21-22 and
  L33-34), `formal/issue-templates/liveness-counterexample.md` (near L68-69),
  `formal/tla/MCRevocationPropagationTemporal.cfg`.
- Defect: the header says the nightly liveness lane runs at PROCS=4/CAPS=8 in
  one place and PROCS=6/CAPS=16 in another; the actual temporal cfg pins
  PROCS=4/CAPS=8; the issue template repeats the 6/16 claim.
- Fix: decide the intended nightly bounds (the cfg is authoritative today:
  4/8), align both header mentions and the template, and note the larger
  bounds as a possible future TLC lane if that was the intent.
- Verify: grep for `PROCS` across formal/ and the templates; one story.

## H8. Dangling ticket reference in the Kani lane registry

- File: `formal/rust-verification/kani-public-harnesses.toml` (near L54).
- Defect: "added for , which sign over..." (empty ticket slot from a
  template).
- Fix: fill in the actual motivation (the WYSIWYS signing work, BAC-539 per
  commit `2ebab1ef1`) or drop the clause.
- Verify: grep for `for ,`.

## H9. Phantom PR-lane comments in CI files

- Files: `.github/workflows/nightly.yml` (near L69),
  `.github/workflows/mutants.yml` (header),
  `formal/rust-verification/kani-public-harnesses.toml` and
  `.kani/harnesses.toml` lane comments.
- Defect: nightly.yml claims "the PR job (kani-public-pr in ci.yml) only runs
  lanes.pr" (no such job exists anywhere); mutants.yml header calls the dead
  `mutants-pr` job a required lane; the harness registries describe
  `lane = "pr"` as "always runs on every PR".
- Fix: two options. (a) Interim honesty: rewrite the comments to state that
  all Kani and mutants lanes are nightly-only today. (b) Preferred: land
  [plan/FV-E3](plan/FV-E3-pr-formal-smoke-tier.md), which makes the comments
  true instead of editing them. If E3 lands within the same milestone, skip
  the comment edit and let E3 fix both code and prose.
- Verify: grep workflows for `kani-public-pr`; either the job exists or no
  text references it.

## H10. Lean toolchain pinned to a release candidate

- File: `formal/lean4/Chio/lean-toolchain` (`leanprover/lean4:v4.28.0-rc1`).
- Defect: release evidence builds on an RC compiler pin.
- Fix: move to the corresponding stable release once available (check the
  lean4 release feed; v4.28.0 stable or the nearest later stable), rebuild,
  and update the elan pin in `nightly.yml` if it names the toolchain
  explicitly. Zero-dependency project, so migration risk is low; budget one
  proof-fix session in case of simp-set drift.
- Verify: `lake build` green under the stable pin; `#print axioms` output
  unchanged for the headline theorems.

## H11. Fuzz budget hard-halt contract not enforced in behavior

- Files: `.github/workflows/cflite_pr.yml`, `.github/workflows/mutants.yml`
  (PR budget steps), `scripts/check-fuzz-budget.sh`,
  `scripts/tests/fuzz-budget-hard-halt.test.sh`,
  `.github/workflows/ci.yml`.
- Defect: the repository contract says PR-time budget gates hard halt while
  scheduled lanes are advisory (`docs/fuzzing/continuous.md`, both PR
  budget-step comments, and the dedicated contract test
  `scripts/tests/fuzz-budget-hard-halt.test.sh`, which rejects an explicit
  warn on those steps). But neither PR budget step sets
  `GH_FUZZ_BUDGET_CAP_MODE` at all, the script defaults `cap_mode` to warn
  (`check-fuzz-budget.sh:54`), and the contract test is wired into no CI
  job. Effective behavior is warn everywhere; only the four scheduled lanes
  set warn explicitly and deliberately.
- Fix: set `GH_FUZZ_BUDGET_CAP_MODE: fail` explicitly on the two PR budget
  steps, harden the contract test to require the explicit fail (rejecting
  only an explicit warn is vacuous against a warn default), and wire the
  test into the required check job. Scheduled lanes stay warn. Full design
  in [plan/FV-E4](plan/FV-E4-fuzz-plumbing-repair.md) item 6.
- Verify: `bash scripts/tests/fuzz-budget-hard-halt.test.sh` passes, runs in
  ci.yml, and fails locally when either PR step's fail setting is removed.

## H12. Placeholder directories that mislead

- Files: `formal/tla/counterexamples/` (only `.gitkeep`),
  `formal/diff-tests/proptest-regressions/canonical_json_diff/` (only
  `.gitkeep`); the live regression seeds actually live at
  `formal/diff-tests/tests/canonical_json_diff.proptest-regressions`.
- Defect: the empty proptest-regressions directory suggests the harness
  writes there; proptest's file-per-test-module convention put the real
  catches next to the test file instead. New contributors will look in the
  wrong place.
- Fix: either configure proptest regression paths to the directory, or (less
  churn) delete the empty directory and add a README line in
  `formal/diff-tests/ARCHITECTURE.md` pointing at the real location. Keep
  `formal/tla/counterexamples/` (it is the documented commit target for
  future liveness traces) but add a one-line README instead of a bare
  .gitkeep.
- Verify: tree matches the documented locations.

## H13. Aeneas pilot-vs-production status tension

- Files: `formal/aeneas/pilot.toml` (status `active_pilot`),
  `formal/proof-manifest.toml` (`pilot_toolchain = []` while
  `primary_toolchain` includes aeneas).
- Defect: the pilot lane still presents as active although the production
  extraction supersedes it; the manifest's toolchain fields disagree about
  which lane is which.
- Fix: either retire the pilot (status `superseded_by_production`, keep the
  file as history, drop its gate from required commands) or state its
  remaining purpose (a minimal reproduction target for Aeneas toolchain
  bumps is a legitimate one; if so, say that). Align the manifest toolchain
  fields with the decision.
- Verify: `formal/proof-manifest.toml` gate_commands and the two aeneas toml
  statuses tell one story.

## H14. Stale "Mirrors:" headers in the Lean core models

- Files: `formal/lean4/Chio/Chio/Core/Capability.lean` (near L4),
  `Core/Scope.lean` (near L3), `Core/Revocation.lean` (near L3),
  `Core/Receipt.lean`, `Core/Protocol.lean`.
- Defect: found while grounding
  [plan/FV-A4](plan/FV-A4-mirror-drift-hashes.md): Capability.lean and
  Scope.lean cite `chio-kernel-core/src/capability.rs`, which no longer
  exists after the core-type splits (commits `bedaa8453`, `34af9f159`);
  Revocation.lean cites `ChioKernel::check_revocation` in
  `chio-kernel/src/lib.rs`, but the function now lives in
  `kernel/validation.rs`; Receipt.lean cites `receipt.rs` while the module is
  `receipts.rs`; Protocol.lean carries no Mirrors annotation at all.
- Fix: repoint each header to the current post-Phase-6 source, and add the
  missing Protocol.lean annotation (its mirror is
  `chio-kernel-core/src/formal_core.rs` plus the kernel budget and DPoP
  paths). [plan/FV-A4](plan/FV-A4-mirror-drift-hashes.md) then prevents
  recurrence mechanically.
- Verify: every `Mirrors:` path under `formal/lean4/` resolves on disk
  (one-off script now; a standing check once the FV-A4 xtask lands).

## H15. MAPPING cites an assumption id that is not registered

- Files: `formal/MAPPING.md` (the `RevocationEventuallySeen` row),
  `formal/assumptions.toml`.
- Defect: found while grounding
  [plan/FV-D1](plan/FV-D1-distributed-revocation-model.md): the liveness row
  cites `ASSUME-PROPAGATE-FAIRNESS`, but no such id exists in
  `formal/assumptions.toml` (the fairness argument lives only as prose in the
  `RevocationPropagation.tla` comments).
- Fix: either register the assumption properly (class, prose, mapped
  property ids) or repoint the row at the in-spec fairness note. FV-D1's
  narrowing PR replaces this area wholesale, so if D1 is scheduled prefer
  the minimal repoint now.
- Verify: every `ASSUME-*` id cited in MAPPING.md exists in
  assumptions.toml (add to the H3 grep set).

## Decisions

- The two root-imported theorem statuses are `proved`. Lean `v4.28.0` builds
  the full project, the formal proof gate passes, and both the former RC and
  stable compiler report only `propext` for those theorems.
- Revocation safety and nightly liveness retain the configured `PROCS=4`,
  `CAPS=8`, `DEPTH_MAX=4` bounds. Larger bounds remain a future TLC option.
- Kani and mutation comments describe the current nightly-only wiring until
  the pull-request smoke tier is implemented.
- Pull-request fuzz and mutation budget checks fail at the cap; scheduled
  measurement lanes remain advisory.
- The Aeneas pilot remains a minimal toolchain-upgrade fixture. Production
  evidence continues to come from `formal/aeneas/production.toml`.
- Revocation propagation fairness is cited directly from the TLA+ spec rather
  than registered as a transport assumption that the distributed model will
  later replace.

## Execution notes

- Everything here is editable without the Lean/Aeneas/Creusot toolchains
  except H1's confirmation step and H10's rebuild.
- H5 includes a small script fix, not just prose: treat it as the one item
  needing a reviewer with CI context.
- After the pass, run: `scripts/check-mapping.sh`,
  `scripts/check-formal-proofs.sh` (if toolchain available),
  `cargo xtask check crate-paths`, and `cargo test -p chio-formal-diff-tests`
  as the smoke set.
