# FV-E2: Counterexample-to-regression pipeline for Apalache traces

Status: Proposed (2026-07-09)
Theme: E - Verify the verification, and make lanes bite
Effort: S-M
Depends on: none
Feeds: [FV-B2](FV-B2-regression-negative-tests.md) (negative-test wrapper consumes the same trace tooling), [FV-C1](FV-C1-receipt-trace-validation.md) (replay glue targets), [FV-E5](FV-E5-lane-ratchets.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G1, G3 context), [FV-B1](FV-B1-drop-guard-model.md), `formal/issue-templates/property-counterexample.md`, `formal/issue-templates/liveness-counterexample.md`, `scripts/check-regression-tests.sh`

## Summary

When Apalache finds a counterexample today, the issue templates require committing the raw trace and classifying it (spec bug, implementation bug, harness bug), and that is where the pipeline ends: nothing turns the trace into executable Rust evidence that the fixed implementation can never regress along that path. This document proposes a converter that takes an Apalache ITF JSON trace and emits a committed regression-test skeleton: the trace embedded as data, a step table with per-state assertions on the abstract variables, and clearly marked TODO glue where a human maps abstract states to kernel harness calls. Full automatic mapping from TLA state to kernel API calls is not feasible and is not claimed; the deliverable is the skeleton plus embedded trace plus assertion scaffolding, which turns "we fixed the bug the model found" into a compiling, deletion-guarded artifact. The fuzz estate already has exactly this discipline (`scripts/promote_fuzz_seed.sh` promotes crashes into `regression_*.rs` tests and `scripts/check-regression-tests.sh` guards their deletion); this extends it to the formal estate.

## Motivation and evidence

- The counterexample workflow stops at paperwork. `formal/issue-templates/property-counterexample.md` requires the raw trace committed (for Apalache: under `formal/tla/counterexamples/`, lines 33-35) and a triage checklist (lines 78-96) ending in classification and a fix PR. `formal/issue-templates/liveness-counterexample.md` adds four severity tiers driving release-gate posture (lines 109-136). Neither produces a runnable regression.
- The fuzz side solved this years ago in-tree: `scripts/promote_fuzz_seed.sh` writes `crates/<owner>/tests/regression_<target>_<sha16>.rs` (line 304) from a crash file, and `scripts/check-regression-tests.sh` fails any PR that deletes a `regression_*.rs` without a per-file paired issue link (run in the required `check-regression-tests` CI job, `.github/workflows/ci.yml:274-289`). Formal counterexamples deserve the same lifecycle.
- The counterexample directory exists and is empty: `formal/tla/counterexamples/` is preserved by `.gitkeep`. When [FV-B1](FV-B1-drop-guard-model.md)'s drop-guard model and [FV-B2](FV-B2-regression-negative-tests.md)'s negative tests land, traces will start existing; the converter should exist before the first real one arrives.
- Apalache emits machine-readable ITF JSON traces alongside its TLA-format output [v]; ITF is a stable, documented JSON schema (states as JSON objects with typed variable values), which makes typed conversion practical.

## Current state

- No `regression_*.rs` files exist anywhere in the repo yet (verified by `find` this session); the naming convention and placement contract are defined by `scripts/promote_fuzz_seed.sh` and by the deletion-guard glob in `scripts/check-regression-tests.sh:138-140`:
  `(^tests/regression_[^/]+\.rs$|^crates/([^/]+/)+tests/regression_[^/]+\.rs$)`.
- The formal differential-test crate `chio-formal-diff-tests` lives at `formal/diff-tests/` ("Differential testing: random inputs compared against reference spec and production implementation", its `Cargo.toml`), already depends on `serde_json` and `chio-kernel-core`, has an existing `tests/` directory (`canonical_json_diff.rs`, `receipt_encoding_diff.rs`, `scope_diff.rs`, `anchored_root.rs`, ...), and runs on every PR inside the required "Build, lint, test" job via `cargo test --workspace --exclude chio-wasm-guards` (`.github/workflows/ci.yml:173-177`).
- `cargo xtask` is an established pattern in this repo: the required check job runs `cargo xtask check crate-paths` (`ci.yml:101`) and `cargo xtask verify launch-acceptance` (`ci.yml:170`); the crate lives at `xtask/`.

## Design

### Converter: xtask subcommand (recommended) vs python script

Weighed:

- `scripts/itf-to-regression.py`: cheap to write, but it would hand-assemble Rust source from JSON with no type checking of either side, and its output drifts silently from the trace-parsing code the generated test itself contains.
- `cargo xtask formal itf-to-regression` (recommended): typed ITF handling via serde structs shared between the converter and the generated test's runtime parser (the same struct definitions are emitted into the skeleton), unit-testable in-workspace against a committed sample trace, no new toolchain, and consistent with the existing `xtask check`/`xtask verify` subcommand shape.

Invocation:

```bash
cargo xtask formal itf-to-regression \
  --trace formal/tla/counterexamples/<name>.itf.json \
  --spec ReceiptBeforeAllow \
  [--out formal/diff-tests/tests/]
```

### What gets generated

Output file: `formal/diff-tests/tests/regression_formal_<spec_snake>_<shortsha>.rs`, where `<shortsha>` is the first 12 hex chars of the sha256 of the ITF file (content-addressed, mirroring both promote_fuzz_seed's sha16-of-seed and the property template's `formal/tla/counterexamples/<sha256>.tla` convention). The raw ITF trace itself is committed under `formal/tla/counterexamples/` exactly as the issue templates already require; the test embeds it by relative `include_str!` (`../../tla/counterexamples/<name>.itf.json`), so trace and test cannot drift apart and the trace file gains a compile-time existence check.

Generated skeleton structure:

1. Header comment: spec name, invariant violated, source issue link placeholder, generating command, and the git sha of the run that found it.
2. `const TRACE_JSON: &str = include_str!(...)` plus minimal serde structs for the ITF shape (`ItfTrace { states: Vec<serde_json::Map<...>> }` level; variables stay `serde_json::Value` so the skeleton never fails to compile on exotic Apalache types).
3. A generated step table: one `Step { index, action_hint, expected: &[(&str, Value)] }` entry per trace state, with the abstract variable assignments baked in as data. `action_hint` is best-effort (ITF traces do not always name actions; when absent the converter emits the state diff as the hint).
4. Test one, `regression_formal_<spec>_<shortsha>_trace_shape` (active immediately): parses `TRACE_JSON`, asserts state count, variable-name set, and that the baked step table matches the embedded trace. This pins the artifact against silent edits and proves the ITF is parseable at every future commit.
5. Test two, `regression_formal_<spec>_<shortsha>_replay`, annotated `#[ignore = "TODO(formal): map abstract states to kernel calls, then remove this attribute"]`: iterates the step table and calls a stub `fn apply_abstract_step(state: &KernelUnderTest, step: &Step)` containing `todo!()` with a written mapping recipe in comments (which kernel-core entry points correspond to which model actions; for drop-guard traces, the FV-B1 ground-truth table is the recipe). Honest scope: this glue is human work per spec family; the converter cannot synthesize it.
6. Once a human completes the glue, they delete the `#[ignore]` and the test becomes a live spec-to-implementation replay in the required PR lane.

Rationale for the two-test split: the skeleton must be safe to commit the same day the counterexample is found (test one is green, test two is ignored and visible in `cargo test -- --ignored` inventories), while never faking a replay that does not exist.

Sketch of the emitted skeleton (abbreviated; the golden test in phase 1 pins the exact shape):

```rust
//! Generated by `cargo xtask formal itf-to-regression` from
//! formal/tla/counterexamples/ReceiptBeforeAllow-<...>.itf.json
//! Spec: ReceiptBeforeAllow. Invariant violated: SafetyInv. Issue: #TODO.

const TRACE_JSON: &str =
    include_str!("../../tla/counterexamples/ReceiptBeforeAllow-<...>.itf.json");

struct Step {
    index: usize,
    action_hint: &'static str,
    expected: &'static [(&'static str, &'static str)], // var name -> ITF value as JSON text
}

const STEPS: &[Step] = &[
    Step { index: 0, action_hint: "Init", expected: &[("allowed", "[]"), ("receipts", "[]")] },
    Step { index: 1, action_hint: "diff: allowed +cap1", expected: &[("allowed", "[\"cap1\"]"), ("receipts", "[]")] },
    // one entry per trace state, baked in by the converter
];

#[test]
fn regression_formal_receipt_before_allow_ab12cd34ef56_trace_shape() {
    let trace: serde_json::Value = serde_json::from_str(TRACE_JSON).unwrap();
    // asserts: state count == STEPS.len(), variable-name set, per-state agreement
}

#[test]
#[ignore = "TODO(formal): map abstract states to kernel calls, then remove this attribute"]
fn regression_formal_receipt_before_allow_ab12cd34ef56_replay() {
    // Recipe: model action "Allow" corresponds to chio_kernel_core::evaluate(...);
    // "EmitReceipt" to sign_receipt(...). See the mapping table in this file's header.
    for step in STEPS { apply_abstract_step(step); }
}
```

### Placement and the deletion guard

Recommended placement is `formal/diff-tests/tests/` because the crate's purpose, dependencies, and PR-time execution match exactly (see Current state). One consequence must be handled honestly: the deletion-guard regex in `scripts/check-regression-tests.sh:138-140` covers `tests/` and `crates/**/tests/` but NOT `formal/diff-tests/tests/`. The plan therefore extends the glob with one alternative:

```
(^tests/regression_[^/]+\.rs$|^crates/([^/]+/)+tests/regression_[^/]+\.rs$|^formal/diff-tests/tests/regression_[^/]+\.rs$)
```

The `regression_formal_*` naming already matches the existing `regression_[^/]+` stem, so no other guard change is needed. Alternative placement in the owning kernel crate (`crates/kernel/chio-kernel/tests/`, following the promote_fuzz_seed owner convention) was considered and rejected for phase 1: counterexample replays are spec-vs-implementation artifacts spanning model and kernel, the diff-tests crate is the established home for that comparison, and a single location keeps the converter's `--out` default meaningful. The `--out` flag exists for future traces whose glue clearly belongs to one crate.

### Liveness traces

Liveness counterexamples (lasso traces from `apalache-temporal.yml`) convert with the same tooling; the step table gains a `loop_start` index from the ITF lasso marker, and test two's recipe comment notes that a liveness replay asserts non-progress along the loop rather than a violated state predicate. No separate converter mode is needed beyond carrying the marker through.

## Implementation plan

1. Phase 1 - converter core (files to add: `xtask/src/formal/mod.rs`, `xtask/src/formal/itf.rs` (serde structs + parser), `xtask/src/formal/itf_to_regression.rs` (emitter); files to modify: `xtask/src/main.rs` to register the `formal itf-to-regression` subcommand).
   - Commit a hand-made sample ITF trace as a fixture: `xtask/tests/fixtures/sample.itf.json` plus `xtask/tests/itf_to_regression.rs` golden test asserting the emitted skeleton compiles-by-inclusion (emit into `OUT_DIR` and `include!` it in a test harness, or assert against a committed golden file; golden file preferred for reviewability).
2. Phase 2 - guard and placement wiring (files to modify: `scripts/check-regression-tests.sh` line 139 glob extension as specified above; `formal/diff-tests/ARCHITECTURE.md` gains a section describing the regression_formal convention).
   - Add a self-test case to whatever exercises the guard locally (`scripts/check-regression-tests.sh --dry-run` stays a no-op; the glob change is covered by a new case in the script's usage docs and verified manually with `git diff --diff-filter=D` on a scratch branch).
3. Phase 3 - first real conversion (files to add: produced on demand, `formal/tla/counterexamples/<name>.itf.json` + `formal/diff-tests/tests/regression_formal_<spec>_<shortsha>.rs`).
   - Cheapest guaranteed source of a real trace without waiting for a production bug: run one of the `_negative_tests` broken specs (`formal/apalache/_negative_tests/README.md` documents the two commands) and convert its counterexample. This exercises the whole pipeline end to end and doubles as the FV-B2 integration point.
4. Phase 4 - glue completion for one spec family: fill `apply_abstract_step` for the ReceiptBeforeAllow family (or the FV-B1 drop-guard model if it has landed, using its Rust ground-truth table), remove the `#[ignore]`, and let the replay run in the required PR lane.
5. Phase 5 - template and runbook updates (proposed edits listed under Manifest and registry updates; not performed by this document).

## CI and gating changes

- No new CI lane. Generated tests ride the existing required workspace test lane (`ci.yml:173-177`) because `chio-formal-diff-tests` is a workspace member; test one is active immediately, test two activates when the glue lands.
- The converter itself gets a unit-test in the xtask crate, which already builds in the required job (xtask is exercised at `ci.yml:101` and `ci.yml:170`).
- `scripts/check-regression-tests.sh` glob extension makes the new location deletion-guarded in the existing `check-regression-tests` job; no workflow edit needed.
- Interaction with [FV-E5](FV-E5-lane-ratchets.md): none required; these are ordinary tests, already inside a required check.

## Acceptance criteria

- [ ] `cargo xtask formal itf-to-regression --trace <fixture> --spec Sample` emits a skeleton that compiles and whose `_trace_shape` test passes.
- [ ] The emitter is deterministic: same trace in, byte-identical skeleton out (golden test).
- [ ] Generated `_replay` test carries `#[ignore]` with the TODO message and a written mapping recipe comment; `cargo test -p chio-formal-diff-tests -- --ignored --list` shows it.
- [ ] Raw ITF file committed under `formal/tla/counterexamples/` and referenced via `include_str!`; deleting the trace file breaks compilation of the test (verified once by hand).
- [ ] `scripts/check-regression-tests.sh` glob covers `formal/diff-tests/tests/regression_*.rs`; a scratch-branch deletion without an issue link fails the guard.
- [ ] One end-to-end conversion from a `_negative_tests` counterexample exists in-tree.
- [ ] One completed replay (ignore attribute removed) exists for at least one spec family, running green in the required PR lane.

## Risks and mitigations

- The glue never gets written and skeletons accumulate as ignored tests. Mitigation: the issue-template checklist edit (below) makes glue completion an explicit triage step with an owner; ignored `regression_formal_*` tests are enumerable (`--ignored --list`) and [FV-C5](FV-C5-proof-coverage-map.md) can surface the count.
- ITF variable encodings (big integers, functions/records) do not map cleanly onto simple serde types. Mitigation: variables stay `serde_json::Value` in the skeleton; typed extraction happens only in human-written glue where the semantics are known.
- Abstract-to-concrete mapping is wrong and the replay pins the wrong behavior. Mitigation: the classification step in the issue template (spec bug vs implementation bug vs harness bug) happens before conversion; the replay encodes the post-classification understanding, and the trace-shape test keeps the raw evidence immutable regardless.
- Two sources of truth for the trace (committed ITF vs baked step table). Mitigation: test one asserts they agree; a divergence is a test failure, not silent drift.
- `include_str!` path breaks if the diff-tests crate moves. Mitigation: acceptable; the compile error is loud and the fix is mechanical.

## Open questions

- Should the converter also emit a proptest generator biased toward the counterexample's action sequence (shrinking-friendly neighborhood exploration), not just the exact replay? Deferred; the diff-tests crate already has proptest infrastructure if wanted later.
- Naming for multi-violation runs (Apalache can emit several traces): suffix `-1`, `-2` on the trace files and separate skeletons, or one skeleton with multiple tables? Proposal: separate files, one trace one skeleton; revisit if volume demands.
- Do Kani CBMC counterexamples (the other lens in the property template) deserve the same converter? Out of scope here; Kani harnesses are already Rust and their counterexamples are best pinned as ordinary unit tests. Noted for the template edit so triagers are not confused.

## Manifest and registry updates

- Proposed edit (not performed here) to `formal/issue-templates/property-counterexample.md`: insert a triage step between Step 1 and Step 2, "Step 1b - for Apalache traces, run `cargo xtask formal itf-to-regression --trace formal/tla/counterexamples/<file>.itf.json --spec <Spec>` and commit the generated `formal/diff-tests/tests/regression_formal_*.rs` skeleton in the same PR as the trace"; and in the Resolution section add "Replay glue completed and `#[ignore]` removed: yes / deferred (issue #nnn)".
- Proposed edit to `formal/issue-templates/liveness-counterexample.md` triage checklist: same converter step, noting the lasso `loop_start` handling.
- `formal/diff-tests/ARCHITECTURE.md`: document the `regression_formal_<spec>_<shortsha>` convention and the two-test split.
- `docs/formal/ROADMAP.md`: link this pipeline as the standing consumer of every future counterexample.
- No changes to `formal/proof-manifest.toml`: `cargo test -p chio-formal-diff-tests` is already a gate command there (line 45), so completed replays automatically join the proof-report gate sweep.
