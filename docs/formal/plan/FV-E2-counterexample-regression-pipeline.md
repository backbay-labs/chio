# FV-E2: Counterexample-to-regression pipeline for Apalache traces

Status: Implemented (2026-07-09)
Theme: E - Verify the verification, and make lanes bite
Effort: S-M
Depends on: none
Feeds: [FV-B2](FV-B2-regression-negative-tests.md) (negative-test wrapper consumes the same trace tooling), [FV-C1](FV-C1-receipt-trace-validation.md) (replay glue targets), [FV-E5](FV-E5-lane-ratchets.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G1, G3 context), [FV-B1](FV-B1-drop-guard-model.md), `formal/issue-templates/property-counterexample.md`, `formal/issue-templates/liveness-counterexample.md`, `scripts/check-regression-tests.sh`

## Summary

When Apalache finds a counterexample, the pipeline now converts its ITF JSON
trace into content-addressed executable Rust evidence. The generated test
embeds the raw trace, pins every abstract state, and runs a completed production
replay mapping. The converter refuses unsupported replay families instead of
emitting ignored or incomplete code. The first in-tree conversion captures the
broken ReceiptBeforeAllow trace and verifies that the production kernel records
a signed allow receipt before returning the allow response.

## Implementation outcome

`cargo xtask formal itf-to-regression` validates the ITF schema, declared
variables and parameters, type metadata, state indices, loop bounds, input
size, and family-specific tagged values before writing. For
`ReceiptBeforeAllow`, every state must have exact integer, set, map, and receipt
encodings with matching authority domains, and the complete trace must contain
a missing-receipt witness exactly as the named invariant defines it. The
converter does not reimplement the model's `Init` and `Next` relations;
Apalache remains the authority for transition reachability, and trace
provenance is review evidence rather than converter attestation. Output is
deterministic, formatted with the pinned
Rust toolchain, and named from the first 12 hexadecimal characters of the trace
SHA-256 digest. Existing files are accepted only when their bytes already
match; divergent output is never overwritten.

The diff-test crate owns shared trace assertions and registered production
replays. The converter records the violating authority and capability, and
`replay_receipt_before_allow` revalidates them with the same strict decoder
before exercising the full `ChioKernel` allow path. The replay checks the
returned signed receipt is already present in the kernel receipt log. The
regression deletion guard now covers the formal diff-test location, requires a
separate same-line issue pairing for each deletion, and validates base and head
references as existing commit objects. Its scratch-repository self-test and the
live PR guard run inside the required `Build, lint, test` job.

Apalache 0.50.1 produced the committed three-state trace from
`ReceiptBeforeAllowBroken.tla`, with `SafetyInv` failing in state 2. Its exact
SHA-256 is `c01406cfbbeb13798640c1957aebe459071df06db1679be4c872082ef5f0bec3`.

## Motivation and evidence

- Before implementation, the counterexample workflow stopped at paperwork. The property and liveness issue templates required raw traces and classification but did not produce runnable regressions.
- The fuzz side solved this years ago in-tree: `scripts/promote_fuzz_seed.sh` writes `crates/<owner>/tests/regression_<target>_<sha16>.rs` (line 304) from a crash file, and `scripts/check-regression-tests.sh` fails any PR that deletes a `regression_*.rs` without a per-file paired issue link (run inside the required `Build, lint, test` CI job). Formal counterexamples deserve the same lifecycle.
- At planning time the counterexample directory was empty and preserved only by `.gitkeep`. The committed ReceiptBeforeAllow negative trace now exercises the converter before later drop-guard traces arrive.
- Apalache emits machine-readable JSON traces in its documented [ITF trace format](https://apalache-mc.org/docs/adr/015adr-trace.html), which makes typed conversion practical.

## Previous state

- No `regression_*.rs` files existed before implementation; the naming convention and placement contract were defined by `scripts/promote_fuzz_seed.sh` and by the deletion-guard glob in `scripts/check-regression-tests.sh:138-140`:
  `(^tests/regression_[^/]+\.rs$|^crates/([^/]+/)+tests/regression_[^/]+\.rs$)`.
- The formal differential-test crate `chio-formal-diff-tests` lives at `formal/diff-tests/` ("Differential testing: random inputs compared against reference spec and production implementation", its `Cargo.toml`), already depends on `serde_json` and `chio-kernel-core`, has an existing `tests/` directory (`canonical_json_diff.rs`, `receipt_encoding_diff.rs`, `scope_diff.rs`, `anchored_root.rs`, ...), and runs on every PR in the required "Workspace tests" step of "Build, lint, test".
- `cargo xtask` is an established pattern in this repo: the required check job runs the "crate-path go-dark guard" and "Proof Room launch acceptance package" xtask steps; the crate lives at `xtask/`.

## Design

### Converter: xtask subcommand (recommended) vs python script

Weighed:

- `scripts/itf-to-regression.py`: cheap to write, but it would hand-assemble Rust source from JSON with no type checking of either side, and its output drifts silently from the trace-parsing code the generated test itself contains.
- `cargo xtask formal itf-to-regression` (recommended): typed ITF handling via serde in the converter, shared runtime assertions in the diff-test crate, unit-testable generation against a committed sample trace, no new toolchain, and consistency with the existing `xtask check`/`xtask verify` command shape.

Invocation:

```bash
cargo xtask formal itf-to-regression \
  --trace formal/tla/counterexamples/<name>.itf.json \
  --spec ReceiptBeforeAllow \
  [--out formal/diff-tests/tests/]
```

### What gets generated

Output file: `formal/diff-tests/tests/regression_formal_<family>_<shortsha>.rs`,
where `<shortsha>` is the first 12 hex characters of the SHA-256 of the exact
ITF bytes. The raw trace remains under `formal/tla/counterexamples/` and is a
compile-time dependency through a relative `include_str!`.

The generated file contains the source digest, declared variable list, lasso
loop index, and one `ExpectedStep` per state. Each step carries a deterministic
action hint and the exact JSON encoding of every declared variable. Both tests
are active in native builds: `_trace_shape` checks the digest and complete step
table, while `_replay` calls the registered production mapping. Trace-shape
support remains portable to wasm; full-kernel dependencies and replay compile
only on non-wasm targets. The converter returns an error without writing when a
mapping is unavailable.

Abbreviated emitted shape:

```rust
const TRACE_JSON: &str =
    include_str!("../../tla/counterexamples/ReceiptBeforeAllowBroken-c01406cfbbeb.itf.json");

#[test]
fn regression_formal_receipt_before_allow_c01406cfbbeb_trace_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_trace_shape(
        file!(), TRACE_JSON, TRACE_SHA256, VARIABLES, STEPS, LOOP_START,
    )?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn regression_formal_receipt_before_allow_c01406cfbbeb_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    replay_receipt_before_allow(
        TRACE_JSON, WITNESS_AUTHORITY, WITNESS_CAPABILITY,
    )?;
    Ok(())
}
```

### Placement and the deletion guard

The selected placement is `formal/diff-tests/tests/` because the crate's purpose, dependencies, and PR-time execution match exactly (see Previous state). One consequence required an explicit guard change: the prior deletion-guard regex covered `tests/` and `crates/**/tests/` but not `formal/diff-tests/tests/`. The implementation extends the glob with one alternative:

```
(^tests/regression_[^/]+\.rs$|^crates/([^/]+/)+tests/regression_[^/]+\.rs$|^formal/diff-tests/tests/regression_[^/]+\.rs$)
```

The `regression_formal_*` naming already matches the existing `regression_[^/]+` stem. Pairing was also tightened so each deletion consumes one line that contains both its path or basename and an issue reference; a single link cannot authorize multiple deletions. Alternative placement in the owning kernel crate (`crates/kernel/chio-kernel/tests/`, following the promote_fuzz_seed owner convention) was considered and rejected for phase 1: counterexample replays are spec-vs-implementation artifacts spanning model and kernel, the diff-tests crate is the established home for that comparison, and a single location keeps the converter's `--out` default meaningful. The `--out` flag exists for future traces whose glue clearly belongs to one crate.

### Liveness traces

Liveness counterexamples carry the ITF `loop` index into `LOOP_START`, and the
trace-shape test pins it. A liveness family must register an active production
replay before conversion; there is no mode that emits an incomplete lasso
test.

## Implementation plan

1. Phase 1 - converter core (files to add: `xtask/src/formal/mod.rs`, `xtask/src/formal/itf.rs` (serde structs + parser), `xtask/src/formal/itf_to_regression.rs` (emitter); files to modify: `xtask/src/main.rs` to register the `formal itf-to-regression` subcommand).
   - Commit a hand-made sample ITF trace as a fixture: `xtask/tests/fixtures/sample.itf.json` plus `xtask/tests/itf_to_regression.rs` golden and determinism tests. Compile and run the emitted golden module against the diff-test crate.
2. Phase 2 - guard and placement wiring (files to modify: `scripts/check-regression-tests.sh` line 139 glob extension as specified above; `formal/diff-tests/ARCHITECTURE.md` gains a section describing the regression_formal convention).
   - Add a scratch-repository self-test that proves an unpaired deletion fails and a per-file paired deletion passes.
3. Phase 3 - first real conversion (files to add: produced on demand, `formal/tla/counterexamples/<name>.itf.json` + `formal/diff-tests/tests/regression_formal_<spec>_<shortsha>.rs`).
   - Cheapest guaranteed source of a real trace without waiting for a production bug: run one of the `_negative_tests` broken specs (`formal/apalache/_negative_tests/README.md` documents the two commands) and convert its counterexample. This exercises the whole pipeline end to end and doubles as the FV-B2 integration point.
4. Phase 4 - mapping completion for one family: register `replay_receipt_before_allow`, exercise the full kernel allow path, and require the signed receipt to be present before the allow response is returned.
5. Phase 5 - update the issue templates, architecture guide, mapping registry, roadmap, and this implementation record.

## CI and gating changes

- No new CI lane. Generated tests ride the existing required "Workspace tests" step because `chio-formal-diff-tests` is a workspace member; both tests are active on the native runner, while trace-shape support remains wasm-portable.
- The converter itself gets a unit-test in the xtask crate, which already builds in the required job and is exercised by its existing command steps.
- `scripts/check-regression-tests.sh` makes the new location deletion-guarded. Its scratch-repository self-test runs before the live PR guard in the required `Build, lint, test` job.
- Interaction with [FV-E5](FV-E5-lane-ratchets.md): none required; these are ordinary tests, already inside a required check.

## Acceptance criteria

- [x] `cargo xtask formal itf-to-regression --trace <fixture> --spec ReceiptBeforeAllow` emits a test that compiles and whose `_trace_shape` test passes.
- [x] The emitter is deterministic: same trace in, byte-identical test out (golden test).
- [x] Generated `_replay` tests are active and conversion fails when no completed mapping is registered.
- [x] Raw ITF file committed under `formal/tla/counterexamples/` and referenced via `include_str!`; deleting the trace file breaks compilation of the test (verified once by hand).
- [x] `scripts/check-regression-tests.sh` glob covers `formal/diff-tests/tests/regression_*.rs`; a scratch-branch deletion without an issue link fails the guard.
- [x] One end-to-end conversion from a `_negative_tests` counterexample exists in-tree.
- [x] One completed replay exists for the ReceiptBeforeAllow family and runs green in the required PR lane.

## Risks and mitigations

- Replay mappings could lag new model families. Mitigation: conversion fails without writing until the family has an active mapping, so incomplete tests cannot accumulate.
- ITF variable encodings (big integers, functions/records) do not map cleanly onto simple serde types. Mitigation: generated step values remain JSON text; typed extraction occurs only in each registered production mapping where the semantics are known.
- Abstract-to-concrete mapping is wrong and the replay pins the wrong behavior. Mitigation: the classification step in the issue template (spec bug vs implementation bug vs harness bug) happens before conversion; the replay encodes the post-classification understanding, and the trace-shape test keeps the raw evidence immutable regardless.
- An edited ITF file can encode an unreachable transition sequence. Mitigation: the converter validates the typed state shape and invariant witness but deliberately does not duplicate `Init` or `Next`; reviewers retain the Apalache invocation and output as provenance, and the first committed trace was reproduced with Apalache 0.50.1.
- Two sources of truth for the trace (committed ITF vs baked step table). Mitigation: test one asserts they agree; a divergence is a test failure, not silent drift.
- `include_str!` path breaks if the diff-tests crate moves. Mitigation: acceptable; the compile error is loud and the fix is mechanical.

## Decisions

- Emit exact replays only. Neighborhood proptest generation is not part of
  conversion because it has a different oracle and shrinking contract.
- Keep one trace per generated test. Multiple violations produce separate ITF
  files and independently content-addressed Rust tests.
- Keep Kani counterexamples outside this converter. Their harnesses are already
  Rust, so minimized witnesses belong in ordinary unit or property tests.
- Require completed replay mappings before generation. This replaces the
  dormant-test design with a fail-closed registry and keeps every
  committed generated test active.
- Carry the ITF `loop` index generically, but require liveness-specific replay
  semantics in the registered mapping.

## Manifest and registry updates

- `formal/issue-templates/property-counterexample.md`: require the raw ITF and active generated replay in the same change.
- `formal/issue-templates/liveness-counterexample.md`: require raw ITF output, loop-aware conversion, and an active replay mapping.
- `formal/diff-tests/ARCHITECTURE.md`: document the content-addressed naming convention, active two-test split, and mapping registry.
- `formal/MAPPING.md`: add the ReceiptBeforeAllow replay implementation as executable evidence; the coverage generator inventories the generated diff test explicitly.
- `docs/formal/ROADMAP.md`: describe the pipeline as the standing consumer of future counterexamples.
- No changes to `formal/proof-manifest.toml`: `cargo test -p chio-formal-diff-tests` is already a gate command there (line 46), so completed replays automatically join the proof-report gate sweep.
