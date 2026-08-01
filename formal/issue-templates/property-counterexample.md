---
name: Property counterexample
about: File a counterexample report for a TLA+, Kani, Loom, DST, or proptest failure.
title: "[counterexample] <named invariant or harness> failing on <git sha>"
labels: ["formal-verification", "counterexample"]
assignees: []
---

<!--
This template is referenced by formal/MAPPING.md and by the property-failure
  triage runbook. Use it whenever Apalache, Kani, Loom, DST, or a proptest produces a
counterexample on PR or nightly. The cross-ref gate in scripts/check-mapping.sh
runs on every PR; the named property below MUST correspond to a row in
formal/MAPPING.md.
-->

## Summary

- **Lens** (pick one): `proptest` | `kani` | `apalache` | `loom` | `dst`
- **Named property** (full canonical name as it appears in
  `formal/MAPPING.md`): `<name>`
- **Source file** (TLA+ module / Kani harness / proptest): `<path>`
- **Git SHA at failure**: `<sha>`
- **CI run URL** (if reproduced in CI): `<url>` or `local`
- **First-seen date (UTC)**: `<YYYY-MM-DD>`

## Counterexample

Pick the section that matches the lens and delete the others.

### Apalache safety counterexample

Run Apalache with `--output-traces` and commit the resulting ITF JSON under
`formal/tla/counterexamples/` in the same PR. Convert it with:

```bash
cargo xtask formal itf-to-regression \
  --trace formal/tla/counterexamples/<trace>.itf.json \
  --spec <replay-family>
```

The converter emits only replay families with completed production mappings.
If the family is not registered, add its mapping before resolving the issue.

```text
<paste the apalache-mc check stdout, including the witnessed invariant
 violation, action sequence, and committed ITF path>
```

- **Witnessed invariant**:
  `<ReceiptBeforeAllow | RevocationCutCompleteness | NoAllowAfterRevoke | MonotoneLog | AttenuationPreserving | RevocationEventuallySeen>`
- **Apalache version**: `<version reported by apalache-mc version>`
- **Config**: `<path>` (constants and length: `<values>`)
- **Action sequence length**: `<n>` steps
- **First state where invariant breaks**: state `<index>`

### Kani CBMC counterexample

If Kani produced a concrete trace under `target/kani/<harness>/`, copy the
relevant excerpt below. The full trace can be attached as a file.

```text
<paste the kani output, including the failing harness name, the failing
 assertion, and the concrete counterexample assignment>
```

- **Failing harness**: `<verify_scope_intersection_associative | verify_revocation_predicate_idempotent | ... full name from kani_public_harnesses.rs>`
- **Failing assertion**: `<line and assert! text>`
- **Kani version / unwind bound**: `<version> / unwind=<n>`
- **Concrete inputs** (one per `kani::any` axis): `<paste>`

### Loom schedule failure

Start with the registered runner so the manifest bound and crate-local cfg are
identical to CI:

```bash
bash scripts/run-loom-manifest.sh --lane nightly
```

The runner prints an exact command for the failing model. Set a model-specific
checkpoint file on the first run, then rerun with a checkpoint interval of one
to isolate the next failing schedule. Add `LOOM_LOG=trace LOOM_LOCATION=1` only
after the checkpoint reproduces.

```bash
RUSTFLAGS="--cfg chio_kernel_loom" \
  LOOM_MAX_PREEMPTIONS=<bound> \
  LOOM_CHECKPOINT_FILE=target/loom/checkpoints/<model>.json \
  cargo test -p chio-kernel --release --test loom_concurrency \
  <model> -- --exact --nocapture

LOOM_CHECKPOINT_INTERVAL=1 \
  RUSTFLAGS="--cfg chio_kernel_loom" \
  LOOM_MAX_PREEMPTIONS=<bound> \
  LOOM_CHECKPOINT_FILE=target/loom/checkpoints/<model>.json \
  cargo test -p chio-kernel --release --test loom_concurrency \
  <model> -- --exact --nocapture
```

- **Failing model**: `<full test name from .loom/harnesses.toml>`
- **Preemption bound**: `<LOOM_MAX_PREEMPTIONS>`
- **Checkpoint path**: `<path>`
- **Model scope**: `bounded_abstract_model`
- **Production behavior reproduced separately**: `yes` / `no`

Loom rows in this repository are test-local abstract synchronization models.
A schedule failure is evidence against the modeled ordering obligation, but a
green model is not proof over the kernel's production synchronization
primitives.

### Deterministic simulation failure

Replay the exact seed through the closed runner. It prints the derived poll,
drop, and fault plan before executing the real kernel episode.

```bash
bash scripts/run-dst.sh --lane replay --seed <u64>
```

- **Failing seed**: `<u64>`
- **Derived plan**: `<plan printed by dst_replay_seed>`
- **Failed oracle**: `ReceiptBeforeAllow` | `drop disposition` | `reservation conservation` | `ChildReceiptsFlushed`
- **Regression corpus path**: `crates/kernel/chio-kernel/tests/dst/dst-regressions.toml`
- **Scope**: `single_process_single_store`

### Proptest minimized failure

The shrunk seed must already be committed under
`crates/<crate>/proptest-regressions/<file>.txt` per the runbook. Paste
the seed line plus the minimized input.

```text
<paste the seed line from proptest-regressions and the minimized input
 as printed by `cargo test`>
```

- **Failing test**: `<crate>::<module>::<test_name>`
- **Regression file path**: `crates/<crate>/proptest-regressions/<file>.txt`
- **PROPTEST_CASES at failure**: `<n>` (PR=256, nightly=4096 by default)

## Triage

Mark each box as you complete the corresponding step from the property-failure
triage runbook.

- [ ] Step 1 - regression seed persisted (proptest only) and committed in
      this PR or in the linked PR.
- [ ] Step 1b - Apalache ITF trace and generated `regression_formal_*.rs`
      test committed together; both generated tests run without exclusions.
- [ ] Step 2 - this issue filed with all required fields above.
- [ ] Step 3 - merge gate set on the offending PR (do not merge until the
      defect is fixed or a documented invariant amendment is signed off
      by `formal-verification` plus a second reviewer).
- [ ] Step 4 - cross-checked against the Lean theorem(s) cited for this
      property in `formal/MAPPING.md`. If a discrepancy was found, a
      `discrepancy` block was added to `formal/proof-manifest.toml`.
- [ ] Step 5 - if the invariant text changed, `formal/MAPPING.md` was
      updated in the same PR and `bash scripts/check-mapping.sh` exits 0.
- [ ] Step 5a - if an Apalache invariant changed, every paired entry in
      `formal/apalache/_negative_tests/REGISTRY.toml` was re-validated with
      `scripts/check-apalache-negative.sh` in the same PR.
- [ ] Step 6 - if the property is on a release branch, the regression
      seed (or Kani trace, or Apalache trace) was backported to every
      backport target.

## Classification

Pick one and justify in one or two sentences.

- [ ] **Spec bug** - the TLA+ / Lean / Kani specification is wrong; the
      Rust implementation matches the protocol intent.
- [ ] **Implementation bug** - the Rust implementation is wrong; the
      specification correctly captures the protocol intent.
- [ ] **Harness bug** - the proptest / Kani harness is wrong; both spec
      and implementation are correct.

Justification:

```
<one or two sentences>
```

## Resolution

Link the PR(s) that close this issue and confirm the gate passes:

- Fix PR: `<#nnn>`
- Mapping PR (if invariant text changed): `<#nnn>`
- Final `scripts/check-mapping.sh` run: `OK` / `FAIL`
- Final Apalache / Kani / proptest run: `OK` / `FAIL`
- Generated replay path and result: `<path>` / `OK` / `FAIL`
