# FV-A2: Prove equivalence against the generated Aeneas output

- Status: Proposed (2026-07-09)
- Theme: A - Make the proven code the running code
- Effort: M
- Depends on: none
- Feeds: [FV-C2](./FV-C2-verified-inclusion-verifier.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G4, G1), [FV-A1](./FV-A1-absorb-verified-helpers.md), [FV-A4](./FV-A4-mirror-drift-hashes.md), [FV-E5](./FV-E5-lane-ratchets.md)

## Summary

The Aeneas production lane extracts `crates/kernel/chio-kernel-core/src/formal_aeneas.rs` through Charon and Aeneas into generated Lean under `target/formal/aeneas-production/lean/`, but the tracked equivalence proofs never look at that output: `formal/lean4/Chio/Chio/Proofs/AeneasEquivalence.lean` hand-restates the extracted semantics in a namespace called `AeneasMirror` and proves 14 theorems against the handwritten Chio model. The hand-restatement is a manual transliteration seam of exactly the kind gap G4 warns about, sitting in the middle of the lane whose whole purpose is to remove manual transliteration. This document closes the gap: vendor the Aeneas Lean support library pinned to the existing release tag, commit the generated `Funs.lean`/`Types.lean` as reviewed snapshots, gate regeneration drift in CI, and prove each generated definition equal to its `AeneasMirror` counterpart so the chain Rust -> generated Lean -> handwritten model is machine-checked end to end.

## Motivation and evidence

- `scripts/check-aeneas-equivalence.sh` currently asserts only that `def <symbol>` appears in the generated `Funs.lean` for all 15 extracted symbols plus `BudgetCommitResult` in `Types.lean` (lines 25-50), records SHA-256 hashes of source and generated files into `target/formal/aeneas-production/equivalence-artifacts.json` (lines 52-77), and then builds `Chio.Proofs.AeneasEquivalence` (lines 80-83). Nothing checks that the generated definitions mean what the mirror says they mean.
- `formal/lean4/Chio/Chio/Proofs/AeneasEquivalence.lean` states its own limitation in its header (lines 1-9): "Aeneas emits Lean that depends on its support library and generated `Std.U*` wrappers under target/formal. This tracked module mirrors the extracted pure helper semantics in ordinary Lean values". The `AeneasMirror` namespace (lines 20-84) is a third handwritten copy of the decision logic (after `formal_aeneas.rs` itself and the Creusot contract bodies; see [FV-A3](./FV-A3-creusot-dedup.md)).
- A transliteration bug in `AeneasMirror` would be invisible: the 14 theorems (lines 86-179) would still close because both sides of each theorem are handwritten. The `def <symbol>` grep in the gate cannot catch a generated function whose body diverges from the mirror.
- The toolchain is already pinned and reproducible: `.github/workflows/nightly.yml:25` sets `CHIO_AENEAS_RELEASE_TAG=build-2026.04.22.215158-38d10a22642d75d051e14006cc6e45055381f10e` and downloads release binaries at line 252 (sha256-pinned [v]). The Lean project uses `leanprover/lean4:v4.28.0-rc1` with zero external packages (`formal/lean4/Chio/lake-manifest.json` has `"packages": []`). Everything needed to make the generated code a first-class proof subject exists; it is just not wired.
- Gap G1 context: because generation happens only under the nightly toolchain, PR reviewers today cannot even see what the generated Lean looks like, let alone diff a change to it. Committed snapshots fix the reviewability half of that gap for this lane even before FV-E3 builds the PR smoke tier.

## Current state

- Extraction: `scripts/check-aeneas-production.sh` runs `charon rustc --preset=aeneas` over `formal_aeneas.rs` (lines 36-37), then `aeneas -backend lean -split-files -namespace Chio.AeneasProduction` into `target/formal/aeneas-production/lean/` (lines 46-47), greps for the 15 symbols (lines 56-77), and chains into the equivalence script.
- `formal/aeneas/production.toml` names the lane: source, both scripts, `equivalence_module = "formal/lean4/Chio/Chio/Proofs/AeneasEquivalence.lean"`, `artifact_report`, and the 15 `extracted_symbols` [v].
- The Lean project (`formal/lean4/Chio/lakefile.lean`: single `lean_lib Chio`, `srcDir := "."`) does not import the generated code and has no path to it: the generated files live under `target/`, are never committed, and depend on the Aeneas support library that the project does not vend.
- The 14 equivalence theorems connect `AeneasMirror` to the handwritten model (`Chio.Core.budgetPrecheck`, `dpopNonceAdmits`, `revocationSnapshotDenies`, `receiptFieldsCoupled`, `CapabilityToken.isValidAt`, and friends), mostly by `rfl` or `cases ... <;> rfl`.

## Design

### Vendor the Aeneas Lean support library

Vendor the support library (the `Aeneas` lake package shipped with the pinned release) under `formal/lean4/vendor/aeneas/`, added to the Chio lakefile as a path dependency. Pinning discipline: a `formal/lean4/vendor/aeneas/VENDOR.toml` records the source release tag (must equal `CHIO_AENEAS_RELEASE_TAG`) and a content hash; `scripts/check-aeneas-equivalence.sh` verifies the recorded tag matches the workflow env so the vendored library and the extraction binary cannot silently diverge.

Why vendored-path over a git lake dependency: the Lean project currently has zero external packages, builds offline, and is itself release evidence; a git dependency reintroduces network fetch into proof CI and unpins the library from the binary release actually used for extraction. The vendored tree is refreshed only by a deliberate re-vendor script run when `CHIO_AENEAS_RELEASE_TAG` bumps.

Main compatibility constraint: the support library must compile under the repo's `lean-toolchain` (`v4.28.0-rc1`). Aeneas releases pin their own Lean version; if the pinned release's library does not build on `v4.28.0-rc1`, the resolution order is (1) pick the Aeneas release matching our toolchain, (2) bump `lean-toolchain` in lockstep with the whole proof tree. Phase 1 exists to discover this early and cheaply.

### Commit generated snapshots

Commit `Funs.lean` and `Types.lean` snapshots under `formal/lean4/Chio/Chio/Generated/` so they build as `Chio.Generated.Funs` / `Chio.Generated.Types` inside the existing `lean_lib`. The snapshot step normalizes only what is required for that placement (module header/import lines emitted for the `Chio.AeneasProduction` namespace layout) via a small deterministic rewrite in the check script; the function and type bodies are committed byte-for-byte as generated. If header rewriting proves brittle across Aeneas versions, the fallback is to commit under the emitted module path (`formal/lean4/Chio/Chio/AeneasProduction/`) instead; decide in phase 2 and record the choice in `production.toml`.

Committed snapshot vs build-time-only generation, decided: committed.

- Reviewability: a Rust edit to `formal_aeneas.rs` produces a visible generated-Lean diff in the same PR, reviewable by people who do not run Charon.
- PR-time checking: Lean-side jobs (and FV-E3's smoke tier) can build and prove against the snapshot with only `lake`, no Charon/Aeneas toolchain, closing part of G1 for this lane.
- Drift is still caught: nightly regenerates with the pinned toolchain and fails on any difference from the snapshot, so the snapshot cannot go stale silently.
- Cost: a two-file committed artifact that changes only when the 140-line source [v] changes; accepted.

### Drift gate

Extend `scripts/check-aeneas-equivalence.sh`: after regeneration, apply the same normalization used at snapshot time and `diff` against the committed files; any difference fails with instructions to re-run the snapshot step and commit the result. The existing `equivalence-artifacts.json` gains the snapshot hashes next to the source and generated hashes so the artifact report ties all three together. Intended failure output:

```
aeneas-equivalence: SNAPSHOT DRIFT
  regenerated target/formal/aeneas-production/lean/Funs.lean differs from
  committed formal/lean4/Chio/Chio/Generated/Funs.lean
  Re-run: ./scripts/check-aeneas-production.sh && ./scripts/snapshot-aeneas-generated.sh
  then commit the Generated/ diff. If you did not change formal_aeneas.rs,
  the extraction toolchain moved: check CHIO_AENEAS_RELEASE_TAG.
```

(The snapshot step lands as `scripts/snapshot-aeneas-generated.sh` so the normalization logic exists exactly once and both the gate and the bless path call it.)

### Generated-equivalence proofs

New module `formal/lean4/Chio/Chio/Proofs/AeneasGeneratedEquivalence.lean`, importing `Chio.Generated.Funs`, `Chio.Generated.Types`, the vendored support library, and the existing proofs module. For each of the 15 symbols: a theorem that the generated definition agrees with its `AeneasMirror` counterpart, then (by composition with the existing 14 theorems) with the handwritten model.

The main friction, called out plainly: Aeneas emits Result-typed, machine-integer code. Generated functions return `Result Bool` (or `Result BudgetCommitResult`) and operate on `U32`/`U64` scalars with wrapped arithmetic, so the theorems are not literally `rfl` against `Nat`-and-`Bool` mirror functions. Expected statement shape:

- Pure boolean combinators (`dpop_admits`, `nonce_admits`, `guard_step_allows`, `revocation_snapshot_denies`, `receipt_fields_coupled`, the two covers-by-flags functions, `required_true_is_preserved`): `generated f args = Result.ok (AeneasMirror.f args)`; expected to close by `simp [f]` or `rfl` once unfolded, since no scalar arithmetic is involved.
- Comparison-based predicates (`classify_time_window_code`, `time_window_valid`, `optional_u32_cap_is_subset`, `monetary_cap_is_subset_by_parts`, `budget_precheck`, `dpop_freshness_valid`): need a small helper-lemma layer translating `U64`/`U32` comparisons and saturating adds to `Nat` comparisons on `.val`, stated once and reused (proposed `Chio/Proofs/AeneasScalarLemmas.lean` if the support library's simp set is not sufficient on its own; prefer the support library's `progress`/simp machinery first).
- `budget_commit`: the only function with subtraction guarded by a precheck. The proof must show the `U64` subtractions cannot underflow given `budget_precheck = true`, then relate the generated `BudgetCommitResult` struct to `AeneasMirror.budgetCommit`'s `Option BudgetState`. This is the single most expensive proof of the set; budget it as such.

Statements quantify over scalar values (`forall (a b c d : U64), ...`) with `.val` projections on the mirror side, so the theorems also document the operating range explicitly instead of leaving `Nat`-vs-`u64` implicit. Expected shape, sketched for the two representative difficulty classes:

```lean
-- Boolean combinator class: no scalar layer, expected simp/rfl.
theorem generated_dpop_admits_eq_mirror
    (required present valid fresh : Bool) :
    Chio.AeneasProduction.dpop_admits required present valid fresh =
      Result.ok (AeneasMirror.dpopAdmits required present valid fresh) := by
  simp [Chio.AeneasProduction.dpop_admits, AeneasMirror.dpopAdmits]

-- Scalar class: comparisons cross the U64 layer via .val lemmas.
theorem generated_budget_precheck_eq_mirror
    (ri ru ic uc : U64) :
    Chio.AeneasProduction.budget_precheck ri ru ic uc =
      Result.ok (AeneasMirror.budgetPrecheck
        { remainingInvocations := ri.val, remainingUnits := ru.val }
        { invocationCost := ic.val, unitCost := uc.val }) := by
  ...
```

Exact generated names and the `Result`/scalar spellings follow whatever the pinned Aeneas release emits; the sketch fixes the statement discipline (generated on the left, `Result.ok` of the mirror projection on the right), not the surface syntax.

### Demote AeneasMirror

After per-symbol proofs land, `AeneasMirror` stops being the lane's semantic anchor and becomes an internal stepping-stone layer: the composed theorems (generated = mirror = model) are exported under new names, `production.toml`'s `equivalence_module` points at the new module, and the module docstring in `AeneasEquivalence.lean` is rewritten to say the mirror is now derived, not load-bearing. The mirror is kept (it makes the composed proofs short) but any future edit to it must break a generated-equivalence theorem to matter, which is the point.

## Implementation plan

1. Phase 1: vendor and compile.
   - Add `formal/lean4/vendor/aeneas/` (support library from the pinned release), `formal/lean4/vendor/aeneas/VENDOR.toml`, and `scripts/vendor-aeneas-lean.sh` (re-vendor script).
   - Modify `formal/lean4/Chio/lakefile.lean` (path dependency) and `formal/lean4/Chio/lake-manifest.json` as lake requires.
   - Exit criterion: `lake build` green on `v4.28.0-rc1` with the vendored library; toolchain mismatch resolved per the design if it appears.
2. Phase 2: snapshot and drift gate.
   - Add `scripts/snapshot-aeneas-generated.sh` (single home for the normalization; called by gate and by authors).
   - Add `formal/lean4/Chio/Chio/Generated/Funs.lean` and `Types.lean` (first snapshot, produced by that script).
   - Modify `scripts/check-aeneas-equivalence.sh` (snapshot diff, artifact hashes, failure message above) and `scripts/check-aeneas-production.sh` only if the dest layout needs an extra hook.
   - Modify `formal/aeneas/production.toml` (new `generated_snapshot` paths field).
   - Exit criterion: nightly red on unrefreshed snapshot, green after refresh; the module-placement question (Generated/ vs emitted path) resolved and recorded.
3. Phase 3: per-symbol proofs.
   - Add `formal/lean4/Chio/Chio/Proofs/AeneasGeneratedEquivalence.lean` (and `AeneasScalarLemmas.lean` if the support library's simp set is not enough).
   - Order: the eight pure boolean combinators first, then the comparison predicates, then `budget_commit` last.
   - Modify `formal/lean4/Chio/Chio.lean` (root import) so the module is root-imported and counts as evidence under the manifest's rules.
   - Exit criterion: 15/15 theorems sorry-free; scalar-lemma layer (if any) documented as the single U*/Result seam.
4. Phase 4: demote the mirror.
   - Modify `formal/lean4/Chio/Chio/Proofs/AeneasEquivalence.lean` (docstring rewrite, exported composed generated-vs-model theorems), `formal/aeneas/production.toml` (`equivalence_module`), and the registries below.
   - Exit criterion: no property-matrix aeneas row whose only evidence is a mirror-only theorem.

## CI and gating changes

- `scripts/check-aeneas-equivalence.sh` (already in `proof-manifest.toml` `gate_commands`) gains the snapshot drift check and the vendor-tag consistency check; it remains the nightly gate.
- The Lean build job that runs `./scripts/check-formal-proofs.sh` now also compiles `Chio.Generated.*`, the vendored library, and the new proof module; expect a one-time build-minutes increase from the vendored library (mitigated by lake caching).
- New failure mode made explicit in the script output: "generated snapshot drift" (Rust changed, snapshot not refreshed) vs "generated equivalence failure" (snapshot refreshed, proofs no longer close). The second is the alarm that means semantics moved.
- PR-time: no new required job in this doc; FV-E3 should pull `lake build Chio.Proofs.AeneasGeneratedEquivalence` into its smoke tier since it needs no Rust toolchain. FV-A4's hash gate covers the cheap PR-time tripwire for the mirror seams this doc does not remove.

## Acceptance criteria

- [ ] Vendored Aeneas support library builds under the repo `lean-toolchain`, with `VENDOR.toml` tag equal to `CHIO_AENEAS_RELEASE_TAG` and checked by script.
- [ ] `Funs.lean`/`Types.lean` snapshots are committed, and a deliberate one-character edit to `formal_aeneas.rs` fails `check-aeneas-equivalence.sh` until the snapshot is refreshed.
- [ ] All 15 extracted symbols have a generated-vs-mirror theorem in `AeneasGeneratedEquivalence.lean`, sorry-free and root-imported.
- [ ] Composed generated-vs-handwritten-model theorems exist for the symbols the property matrix cites (P1, P2, P3, P4, P8 aeneas rows in `formal/proof-manifest.toml`).
- [ ] `AeneasMirror` is documented as derived; no property-matrix row cites a mirror-only theorem as its sole aeneas evidence.
- [ ] `equivalence-artifacts.json` ties source hash, snapshot hash, and regenerated hash together in one report.

## Risks and mitigations

- Toolchain incompatibility (support library vs `v4.28.0-rc1`). Mitigation: phase 1 is deliberately tiny and lands nothing proof-facing; if lockstep bumping is required it is a contained, reviewable event with the whole proof tree rebuilt.
- Aeneas output format churn: a future `CHIO_AENEAS_RELEASE_TAG` bump can rewrite the generated code shape and break every per-symbol proof at once. Mitigation: snapshots make the churn visible as a diff before any proof work starts; the scalar-lemma layer concentrates the U*/Result plumbing so most breakage lands in one file; tag bumps are already deliberate (sha256-pinned binaries).
- Normalization bugs in the snapshot step could mask a real generated-code change. Mitigation: normalization is limited to module header/import lines by construction, is itself unit-tested with a fixture pair, and the raw generated hashes still land in the artifact report for audit.
- Proof cost underestimate on `budget_commit`. Mitigation: it is sequenced last; if it stalls, the other 14 still land and the gap left is one named theorem, tracked in the theorem inventory as pending rather than silently absent.
- Vendored-library bloat and license obligations. Mitigation: vendor only the Lean support library (not the toolchain), record upstream license alongside `VENDOR.toml`, and keep the re-vendor script the only write path.

## Open questions

- Does the pinned Aeneas release's support library build on `v4.28.0-rc1` as-is? (Phase 1 answers this; both fallback paths are pre-agreed above.)
- Exact emitted module/import layout under `-split-files -namespace Chio.AeneasProduction`: is the `Chio/Generated/` placement achievable with header rewriting alone, or do we adopt the emitted path? (Phase 2 decision point.)
- Should the generated snapshot also feed FV-A4's hash manifest as a `[[mirror]]` entry (Rust source -> committed snapshot), making the drift check uniform with the other seams instead of bespoke in the equivalence script? Lean towards yes once FV-A4's xtask exists; keep the bespoke check until then.
- When FV-A1 extends `formal_aeneas.rs` (new absorbed helpers), do we require the generated-equivalence theorem in the same PR or allow a one-nightly lag? Proposed: same PR once phase 3 tooling exists, enforced by the symbol list in `production.toml`.

## Manifest and registry updates

- `formal/proof-manifest.toml`: add `formal/lean4/Chio/Chio/Proofs/AeneasGeneratedEquivalence.lean` (and the scalar-lemma module if created) to `root_modules`; update the `aeneas|production|formal/aeneas/production.toml` row context in `rust_refinement_lanes` notes; property-matrix aeneas entries (P1, P2, P3, P4, P8) re-point or extend their `proof.aeneas_*` theorem ids to the composed generated-equivalence theorems.
- `formal/aeneas/production.toml`: new `generated_snapshot` field listing the committed snapshot paths; `equivalence_module` updated in phase 4; vendor tag field mirroring `CHIO_AENEAS_RELEASE_TAG`.
- `formal/theorem-inventory.json`: new entries (schema `chio.theorem-inventory.v1`) for each generated-equivalence theorem, `claimClass` consistent with the existing aeneas rows, `mapsTo` copied from the property-matrix wiring; the demoted mirror theorems get a note pointing at their composed successors.
- `formal/MAPPING.md`: no new rows required (the script enforces TLA invariants and Kani harnesses, not Lean theorems), but the informational Lean cross-reference block should mention the generated-equivalence module.
- `docs/reference/CLAIM_REGISTRY.md`: the `FORM-IMPLEMENTATION-LINKED` evidence list already names `aeneas_production` and `aeneas_equivalence`; once this lands, the equivalence evidence genuinely includes the generated code, which is worth a one-line strengthening through the claim gate.
