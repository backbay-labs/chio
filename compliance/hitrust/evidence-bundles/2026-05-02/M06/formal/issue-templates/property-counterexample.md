---
name: Property counterexample
about: File a counterexample report for a TLA+ invariant, Kani harness, or proptest.
title: "[counterexample] <named invariant or harness> failing on <git sha>"
labels: ["formal-verification", "counterexample"]
assignees: []
---

<!--
This template is referenced by the property-failure triage runbook in
.planning/trajectory/03-capability-algebra-properties.md (Phase 3) and by
formal/MAPPING.md. Use it whenever Apalache, Kani, or a proptest produces
a counterexample on PR or nightly. The cross-ref gate in
scripts/check-mapping.sh runs on every PR; the named property below MUST
correspond to a row in formal/MAPPING.md.
-->

## Summary

- **Lens** (pick one): `proptest` | `kani` | `apalache`
- **Named property** (full canonical name as it appears in
  `formal/MAPPING.md`): `<name>`
- **Source file** (TLA+ module / Kani harness / proptest): `<path>`
- **Git SHA at failure**: `<sha>`
- **CI run URL** (if reproduced in CI): `<url>` or `local`
- **First-seen date (UTC)**: `<YYYY-MM-DD>`

## Counterexample

Pick the section that matches the lens and delete the others.

### Apalache safety counterexample

If Apalache produced a `--counter-example=trace.tla` file, attach it under
`formal/tla/counterexamples/<sha256>.tla` in the same PR and link the path
here. Otherwise paste the trace inline.

```text
<paste the trace.tla contents or the apalache-mc check stdout, including
 the witnessed invariant violation and the action sequence>
```

- **Witnessed invariant**: `<NoAllowAfterRevoke | MonotoneLog | AttenuationPreserving | RevocationEventuallySeen>`
- **Apalache version**: `<version reported by apalache-mc version>`
- **Config**: `formal/tla/MCRevocationPropagation.cfg` (PROCS=`<n>`, CAPS=`<n>`, length=`<n>`)
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

Mark each box as you complete the corresponding step from the runbook in
`.planning/trajectory/03-capability-algebra-properties.md`.

- [ ] Step 1 - regression seed persisted (proptest only) and committed in
      this PR or in the linked PR.
- [ ] Step 2 - this issue filed with all required fields above.
- [ ] Step 3 - merge gate set on the offending PR (do not merge until the
      defect is fixed or a documented invariant amendment is signed off
      by `formal-verification` plus a second reviewer).
- [ ] Step 4 - cross-checked against the Lean theorem(s) cited for this
      property in `formal/MAPPING.md`. If a discrepancy was found, a
      `discrepancy` block was added to `formal/proof-manifest.toml`.
- [ ] Step 5 - if the invariant text changed, `formal/MAPPING.md` was
      updated in the same PR and `bash scripts/check-mapping.sh` exits 0.
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
