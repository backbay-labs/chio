# FV-A2: Prove equivalence against the generated Aeneas output

- Status: Implemented (2026-07-11; local evidence complete)
- Theme: A - Make the proven code the running code
- Effort: M
- Depends on: none
- Feeds: [FV-C2](./FV-C2-verified-inclusion-verifier.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G4, G1), [FV-A1](./FV-A1-absorb-verified-helpers.md), [FV-A4](./FV-A4-mirror-drift-hashes.md), [FV-E5](./FV-E5-lane-ratchets.md)

## Summary

The production lane now extracts two Rust sources with authenticated Charon
and Aeneas binaries, commits byte-identical emitted-path Lean snapshots, and
proves every generated production function equivalent to its registered
semantic target. The 15 decision helpers are tied to `AeneasMirror`; the
ledger pair, inclusion step, and two economy conversion functions are tied
directly to their semantic models. All 20 functions across four targets have
`generated_equivalence` status, with no lower-assurance escape hatch.

## Implementation outcome

- `formal/aeneas/production.toml` is schema v1 and carries exact x86_64 and aarch64 archive, binary, and repaired-runtime hashes. `scripts/install-aeneas-toolchain.py` installs into a fixed architecture path, verifies the official archive and binaries, applies the deterministic aarch64 interpreter repair, and writes a registry-bound receipt.
- `formal/lean4/vendor/aeneas/` contains the explicit transitive import closure for both `Aeneas` and `AeneasMeta`. Its vendor manifest pins the release, source archive, content digest, and Mathlib revision; the root Lake manifest records the real dependency closure.
- `formal/lean4/Chio/FormalAeneas/Funs.lean` and `Types.lean` are identity-normalized snapshots at the emitted module path. The production gate regenerates them with the authenticated toolchain and fails on any byte drift.
- The generated-equivalence proofs cover all 20 production functions. The
  ledger transition is related directly to the handwritten ledger model, the
  inclusion step to the Merkle-walk model, and both conversion directions to
  the checked economy-conversion model.
- `formal/aeneas/negative-tests.toml` registers six fail-closed mutations: status downgrade, theorem removal, archive substitution, driver substitution, snapshot drift, and a semantic generated-code change. The targeted campaign requires all six to be killed and records hashed logs.
- Local completion evidence: authenticated production extraction and equivalence passed, all registered production artifacts appeared in proof coverage, focused proof-coverage tests passed, the full Lean proof check passed, `lake build Aeneas AeneasMeta` passed, and focused Rust tests plus package clippy passed.

## Pre-implementation evidence

- Before this work, `scripts/check-aeneas-equivalence.sh` asserted only that `def <symbol>` appeared for 15 extracted decision helpers, hashed raw files, and built the handwritten mirror proof. It did not prove the generated definitions meant what the mirror claimed.
- `AeneasEquivalence.lean` explicitly described itself as a handwritten restatement. A transliteration bug in `AeneasMirror` was invisible because both sides of its equivalence theorems were handwritten.
- The initial workflow pinned one release tag and archive hash but trusted PATH resolution for the driver, had no architecture-specific runtime repair evidence, and had an empty Lake package manifest. Those were pinning and closure gaps rather than a complete authenticated toolchain.
- Generated Lean lived only under `target/`, so reviewers could not inspect or diff it. Committed identity snapshots and a PR-buildable proof module close that reviewability gap.

## Implemented state

- `scripts/check-aeneas-production.sh` validates the schema-v2 registry before running tools, authenticates all three installed executables and their receipt, invokes the exact Charon driver, extracts all registered functions, and always chains into the equivalence gate.
- `scripts/check-aeneas-equivalence.sh` validates snapshot identity, vendor closure, exact Lake pins, theorem inventory, source and generated hashes, architecture-specific tool evidence, and the `#print axioms` output before writing a schema-v3 artifact report.
- The Lean project imports `FormalAeneas.Types` and `FormalAeneas.Funs` through a separate library rooted at the emitted snapshot path. Its local Aeneas dependency and complete Mathlib closure are recorded in `lakefile.lean` and `lake-manifest.json`.
- `production.toml` has four target groups containing 20 functions from two
  sources. Each function has one registered equivalence theorem, and every
  group requires `generated_equivalence`.

## Design

### Vendor the Aeneas Lean support library

The support closure for both `Aeneas` and `AeneasMeta` is vendored under `formal/lean4/vendor/aeneas/` and added to the Chio lakefile as a path dependency. `VENDOR.toml` records the authenticated source archive, release tag, content digest, module roots, and exact Mathlib revision. `scripts/vendor-aeneas-lean.sh` derives the explicit transitive import closure, and `scripts/check-aeneas-equivalence.sh` recomputes and checks it.

Why vendored-path over a git Aeneas dependency: the support code remains reviewable and pinned to the exact binary release used for extraction. Mathlib and its transitive packages remain normal Lake dependencies at exact revisions recorded in the real root manifest. The vendored tree is refreshed only by the authenticated re-vendor script.

The vendored closure and generated snapshots compile under the repository `lean-toolchain`. Both `lake build Aeneas AeneasMeta` and the full Chio proof build are required evidence.

### Commit generated snapshots

The committed snapshots live at the emitted module path, `formal/lean4/Chio/FormalAeneas/Funs.lean` and `Types.lean`, and build as `FormalAeneas.Funs` and `FormalAeneas.Types`. Snapshot normalization is identity: the committed files must be byte-for-byte equal to regenerated output. This avoids a handwritten header rewrite between generated semantics and proof input.

Committed snapshot vs build-time-only generation, decided: committed.

- Reviewability: a Rust edit to `formal_aeneas.rs` produces a visible generated-Lean diff in the same PR, reviewable by people who do not run Charon.
- PR-time checking: Lean-side jobs (and FV-E3's smoke tier) can build and prove against the snapshot with only `lake`, no Charon/Aeneas toolchain, closing part of G1 for this lane.
- Drift is still caught: nightly regenerates with the pinned toolchain and fails on any difference from the snapshot, so the snapshot cannot go stale silently.
- Cost: a two-file committed artifact that changes only when the registered production source changes; accepted.

### Drift gate

`scripts/check-aeneas-equivalence.sh` applies the snapshot normalization after regeneration and diffs the result against the committed files. Any difference fails with instructions to re-run the snapshot step and commit the result. `equivalence-artifacts.json` records the snapshot hashes next to the source and generated hashes so the artifact report ties all three together. Failure output is:

```
aeneas-equivalence: GENERATED SNAPSHOT DRIFT
  regenerated target/formal/aeneas-production/lean/Funs.lean differs from
  committed formal/lean4/Chio/FormalAeneas/Funs.lean
  Re-run: ./scripts/check-aeneas-production.sh
  then: ./scripts/snapshot-aeneas-generated.sh --write
```

The snapshot script has explicit `--check` and `--write` modes and fixture-only path overrides used by its drift selftest.

### Generated-equivalence proofs

The generated-equivalence modules import the emitted snapshots, vendored
support library, reservation-ledger, Merkle-walk, and economy-conversion
models. They cover 20 functions from two sources and connect every generated
definition to the model cited by the property matrix.

The main friction is that Aeneas emits Result-typed, machine-integer code. Generated functions return `Result Bool` (or `Result BudgetCommitResult`) and operate on `U32`/`U64` scalars with wrapped arithmetic, so the theorems are not literally `rfl` against `Nat`-and-`Bool` mirror functions. The implemented proof structure is:

- Pure boolean combinators (`dpop_admits`, `nonce_admits`, `guard_step_allows`, `revocation_snapshot_denies`, `receipt_fields_coupled`, the two covers-by-flags functions, `required_true_is_preserved`) unfold to `Result.ok` equalities against `AeneasMirror`.
- Comparison-based predicates (`classify_time_window_code`, `time_window_valid`, `optional_u32_cap_is_subset`, `monetary_cap_is_subset_by_parts`, `budget_precheck`, `dpop_freshness_valid`) reuse private scalar lemmas in the generated-equivalence module for `U64`/`U32` comparisons, checked addition, saturating addition, and value projections.
- `budget_commit` discharges the guarded subtraction obligations before relating the generated `BudgetCommitResult` to `AeneasMirror.budgetCommit`'s `Option BudgetState`.

Statements quantify over scalar values (`forall (a b c d : U64), ...`) with `.val` projections on the mirror side, so the theorems document the operating range explicitly instead of leaving `Nat`-vs-`u64` implicit. Representative statement shapes are:

```lean
-- Boolean combinator class: no scalar layer.
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

`AeneasMirror` is an internal stepping-stone for the 15 decision functions rather than the lane's semantic anchor. The two ledger functions bypass it and target `ReservationLedger` directly. `production.toml` points at the generated-equivalence module, and no production function can be registered without an equivalence theorem.

## Implementation record

1. Vendored the authenticated Aeneas and AeneasMeta closure, pinned the real Lake dependency graph, and passed `lake build Aeneas AeneasMeta`.
2. Chose emitted-path, identity-normalized snapshots and added deterministic check/write tooling plus a drift selftest.
3. Added root-imported generated-code proofs for all 20 production functions,
   including both economy conversion directions.
4. Made the production gate registry-driven and fail-closed, demoted the decision mirror, and linked the generated ledger directly to its model.
5. Added authenticated x86_64 and aarch64 installation, including exact deterministic aarch64 interpreter repair and a receipt binding the installed binaries to the registry.
6. Added six registered negative mutations and required structured killed results with hashed logs.

## CI and gating changes

- `scripts/check-aeneas-equivalence.sh` is registered in `proof-manifest.toml`, checks snapshot drift and vendor-tag consistency, and remains the nightly gate.
- The Lean build job that runs `./scripts/check-formal-proofs.sh` compiles `FormalAeneas.*`, the vendored libraries, and the generated-equivalence proof module.
- New failure mode made explicit in the script output: "generated snapshot drift" (Rust changed, snapshot not refreshed) vs "generated equivalence failure" (snapshot refreshed, proofs no longer close). The second is the alarm that means semantics moved.
- PR-time: the root-imported module builds through the existing formal smoke tier with only Lake. FV-A4's hash gate remains the cheap PR-time tripwire for mirror seams this work does not remove.

## Acceptance criteria

- [x] Vendored Aeneas and AeneasMeta support builds under the repository toolchain, with release, archive, content, and Mathlib pins checked by script.
- [x] Identity-normalized `Funs.lean` and `Types.lean` snapshots are committed, and the drift mutation proves a changed generated file is rejected.
- [x] All 18 production functions have a registered, sorry-free generated-equivalence theorem and the proof module is root-imported.
- [x] Composed generated-vs-model theorems exist for the property-matrix decision evidence, and `ledger_apply` is registered as P1 evidence against the ledger model.
- [x] `AeneasMirror` is documented as derived; the ledger functions do not depend on it.
- [x] `equivalence-artifacts.json` ties the registry, source, tools, raw output, snapshots, proof module, vendor closure, Lake files, and architecture report together.
- [x] Six independent negative mutations are killed and emitted in a structured report with log hashes.

## Risks and mitigations

- Toolchain incompatibility (support library vs `v4.28.0-rc1`). Resolution: the authenticated vendored closure builds under the pinned repository toolchain, and any future lockstep bump must rebuild the whole proof tree.
- Aeneas output format churn: a future `CHIO_AENEAS_RELEASE_TAG` bump can rewrite the generated code shape and break every per-symbol proof at once. Mitigation: snapshots make the churn visible as a diff before any proof work starts; the scalar-lemma layer concentrates the U*/Result plumbing so most breakage lands in one file; tag bumps are already deliberate (sha256-pinned binaries).
- Snapshot normalization could mask a real generated-code change. Resolution: normalization is identity, so any emitted byte change is visible and fails the gate.
- Checked-arithmetic proof cost could leave partial coverage. Resolution: the
  registry rejects any non-equivalence target or missing function-to-theorem
  row; all 20 functions compile and pass the axiom audit.
- Vendored-library bloat and license obligations. Mitigation: vendor only the Lean support library (not the toolchain), record upstream license alongside `VENDOR.toml`, and keep the re-vendor script the only write path.

## Decisions

- The pinned support closure builds under the repository Lean toolchain.
- Snapshots use the emitted `FormalAeneas` path with identity normalization.
- Snapshot drift remains a dedicated production-lane check and is also hashed into the artifact report.
- New production functions require a same-change registry row and generated-equivalence theorem; the gate does not permit a lagging extraction-only state.

## Manifest and registry updates

- `formal/proof-manifest.toml` registers the generated proof, production and negative-test gates, target artifacts, and P1 ledger evidence.
- `formal/aeneas/production.toml` records the snapshots, vendor release, two
  architecture toolchains, 20 functions in four targets from two sources, and
  exact theorem rows.
- `formal/theorem-inventory.json` records the generated decision, composed model, and direct ledger theorems.
- `formal/MAPPING.md` names the generated module and states that it covers every production function.
- `docs/reference/CLAIM_REGISTRY.md` binds the implementation-linked claim to authenticated extraction, generated proofs, snapshots, vendor closure, and negative evidence.
