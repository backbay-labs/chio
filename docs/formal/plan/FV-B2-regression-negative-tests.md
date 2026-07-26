# FV-B2: Fixed production bugs as CI-enforced negative model tests

Status: Implemented (2026-07-10; local evidence complete, hosted verification pending)
Theme: B - Aim the formal tools at the actual bug generator
Effort: S
Depends on: [FV-B1](FV-B1-drop-guard-model.md) for the drop-guard variants (phase 2); phase 1 stands alone on the two existing negative tests
Feeds: [FV-E1](FV-E1-spec-mutation-testing.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G5, G3), `formal/apalache/_negative_tests/README.md`, [FV-E2](FV-E2-counterexample-regression-pipeline.md)

## Summary

A model that has never produced a counterexample is unmeasured, not trustworthy (gap G5). The repo already has the right discipline in embryo: `formal/apalache/_negative_tests/` holds two deliberately broken spec variants that must produce counterexamples, but they are local-only, run by hand, and cover none of the five drop-guard bugs fixed in production this month. This document (a) encodes each fixed drop-guard bug as a Broken variant of the FV-B1 spec that MUST yield a counterexample, (b) adds a machine-readable registry mapping each Broken spec to the production commit it re-derives, and (c) promotes the whole negative suite into CI via a wrapper script that inverts the signal correctly: the job is green exactly when every Broken spec is caught.

## Decisions (2026-07-10)

- The negative suite is a separate CI job so failures identify the
  falsifiability lane directly.
- The dedicated `chio.apalache-negative.v1` registry remains authoritative.
  Each production-derived entry includes the full fix SHA and a current Rust
  regression-test anchor.
- Both recommended variants landed. The suite has two pre-existing checks and
  eight drop-guard mutations, for ten entries total.
- A caught violation requires exit 12, the Apalache 0.50.1 Error outcome, and
  a parseable ITF trace with at least one state. `NoError`, timeout, parse
  failure, JVM failure, and every other exit are separate fail-closed outcomes.
- The wrapper self-test restores the ReceiptBeforeAllow precondition by
  simulating `NoError` for that entry and proves the inverted gate rejects it.
- Local evidence is complete. Hosted evidence remains an explicit landing
  condition and is not inferred from workflow wiring.

## Motivation and evidence

- Before this implementation, `formal/apalache/_negative_tests/README.md` described negative specs as local diagnostics and cited signal inversion as the reason for excluding them from CI. The concern is real but solvable with one layer of indirection: the wrapper maps a caught counterexample to exit 0 and fails closed on every other outcome.
- The two existing variants are `ReceiptBeforeAllowBroken.tla` (drops the `HasAllowReceipt(a, c)` precondition from `PublishAllow`; verified by reading the spec, broken action at lines 65-70) and `RevocationCutCompletenessBroken.tla` (flips only the root) [v]. Both are exercised at `--length=4` per the README.
- Five production drop-guard bugs now have exact spec-level fingerprints (commit family verified via `git show --stat` this session): `38cc91471`, `a6d26dbc4` (Findings A/B/C), `58abf33d2`, `84e98b9d0`, `c201afbd0`. Encoding each as a Broken variant of `PostAdmissionDropGuard.tla` turns "the model would have caught it" from a claim into a checked artifact, and is the falsifiability gate FV-B1 requires before its model counts as evidence.
- `formal/issue-templates/property-counterexample.md` already requires counterexamples to be committed raw and classified spec-bug / implementation-bug / harness-bug [v]; the registry proposed here reuses that classification vocabulary.

## Baseline

- The directory originally held two broken model/config pairs plus a copied
  common module and a local-only README.
- The original convention required one guard or state-update mutation per
  property and a short counterexample, but no machine-readable registry tied
  the model to an invariant, production fix, or runtime regression test.
- CI originally ran only the unbroken specs, leaving falsifiability as a
  manual check. The separate negative job and versioned registry close that
  gap.

## Design

### One Broken variant per fixed drop-guard bug

Each variant mutates exactly one transition of `formal/apalache/PostAdmissionDropGuard.tla` (per the existing single-mutation convention) and names the invariant it must falsify:

| Broken spec (in `_negative_tests/`) | Mutation | Falsifies | Re-derives commit |
| --- | --- | --- | --- |
| `DropGuardDiscardChildBufferBroken.tla` | `DropPostDispatch` skips the child-buffer flush (appends only the parent cancel record; `child_buf` zeroed without logging) | `ChildReceiptsFlushed` | `38cc91471` |
| `DropGuardSkipChildBudgetReleaseBroken.tla` | `DropPreDispatch` leaves `ledger[i]["child"]` at `reserved` | `ReservationConservation` | `a6d26dbc4` Finding B |
| `DropGuardChildOversubscriptionBroken.tla` | `Admit` permits a second child reservation after the shared `ChildMax` capacity is exhausted | `ReservationConservation` | bounded model non-vacuity witness |
| `DropGuardNoFaultReceiptBroken.tla` | `DropPreDispatch` with a failed unwind step appends no `fault` record | `TerminalReceiptExactlyOne` | `a6d26dbc4` Finding C |
| `DropGuardReleaseOnIncompleteStreamBroken.tla` | `IncompleteStream` sets `ledger[i]["lease"]` to `released` instead of `retained` | `RetainedIffAborted` | `84e98b9d0` |
| `DropGuardNoRetainOnPostInvocationDenyBroken.tla` | `DenyPostInvocation` leaves the lease `reserved` (no retained marking) | `RetainedIffAborted` | `58abf33d2` |
| `DropGuardSkipInvocationReversalBroken.tla` | `DropPreDispatch` leaves `ledger[i]["slot"]` at `reserved` | `ReservationConservation` | `a6d26dbc4` Finding A |
| `DropGuardReleaseOnPostDispatchAbortBroken.tla` | `DropPostDispatch` releases the lease despite ambiguous side effects | `RetainedIffAborted` | `c201afbd0` |

Each Broken spec gets its own `MC*.cfg` with constants identical to
`MCPostAdmissionDropGuard.cfg` and selects the exact invariant named by its
registry `falsifies` field. Counterexample search uses `--length=4`; every
mutation above is reachable through Admit, optional StartDispatch and
StreamChunk, then Drop or another terminal action.

### Registry: `formal/apalache/_negative_tests/REGISTRY.toml`

Machine-readable so the wrapper script iterates it (same single-source-of-truth pattern as `.kani/harnesses.toml`, schema line verified this session):

```toml
schema = "chio.apalache-negative.v1"

[[negative]]
spec = "formal/apalache/_negative_tests/ReceiptBeforeAllowBroken.tla"
cfg = "formal/apalache/_negative_tests/MCReceiptBeforeAllowBroken.cfg"
falsifies = "ReceiptBeforeAllow"
production_commit = "n/a (non-tautology check, predates this registry)"
runtime_test = "n/a (structural receipt-order check)"
classification = "spec-mutation"
length = 4
timeout_secs = 300
notes = "PublishAllow drops the HasAllowReceipt precondition."
```

Fields: `spec`, `cfg`, `falsifies` (the exact invariant name, which MUST have a `formal/MAPPING.md` row), `production_commit` (full sha of the fix the variant re-derives, or `n/a` for pure non-tautology checks), `runtime_test` (the Rust regression anchor, or `n/a` for the structural checks), `classification`, `length`, `timeout_secs`, and `notes`. Seven production-derived drop-guard rows carry full commit SHAs and runtime anchors; the eighth is the child-capacity non-vacuity witness with its conformance-test anchor.

### Wrapper: `scripts/check-apalache-negative.sh`

The inversion layer that makes CI-green mean "all broken specs are caught":

- Iterate `REGISTRY.toml` entries (python3 `tomllib` one-liner or a small parser, matching the repo's existing python usage in `scripts/check-apalache-formal-slice.py`).
- For each entry run `apalache-mc check --length=<length> --config=<cfg> <spec>` under `timeout <timeout_secs>`.
- Success for an entry requires all three Apalache 0.50.1 signals: exit 12, `The outcome is: Error`, and a non-empty `violation*.itf.json` trace. Requiring all three is load-bearing: a parse error or crashed JVM also exits nonzero, and a marker without a durable trace is insufficient evidence. `NoError`, timeout, and every other tool outcome fail as distinct classes.
- Exit nonzero if ANY entry reports `NoError` (that invariant has silently regressed to a tautology, exactly the condition README lines 39-40 warns about) or fails the marker check.
- Per-entry `--out-dir` and `--run-dir` paths land under the configured artifact root and are uploaded for triage, not committed (committed raw counterexamples remain the issue-template flow when a positive spec fails).

The implemented outcome classification is explicit: exit 0 with `NoError`
is a tautology regression; exit 12 is accepted only with the Error marker and
ITF trace; timeout exit 124 is reported separately; every other exit is a tool
failure.

The gate pins `The outcome is: Error` from Apalache 0.50.1 and rejects any
other tool version before running the registry. Exit codes are never accepted
without the matching outcome and trace evidence.

### Budget

Negative runs are shallow: every mutation is reachable in at most four steps.
Per-spec `timeout_secs = 300` across ten entries gives a 50-minute worst case,
inside the separate job's 60-minute timeout. Local calibration completes well
below that ceiling.

## Implementation plan

1. Phase 1 - wrapper against the existing suite (no FV-B1 dependency). Add `scripts/check-apalache-negative.sh` and `formal/apalache/_negative_tests/REGISTRY.toml` with the two existing entries. Add a `apalache-negative` job (or a step after the safety matrix) to `.github/workflows/apalache-safety.yml`. Rewrite the "Why these are not in CI" section of `formal/apalache/_negative_tests/README.md` to describe the wrapper posture ("CI-green means every Broken spec still yields its counterexample") and keep the local commands.
2. Phase 2 - drop-guard variants (after FV-B1 phase 2). Add all eight `DropGuard*Broken.tla` + cfg files and their registry rows with full production commit SHAs where applicable and Rust test anchors. Reproduce each counterexample locally once and record the run in the FV-B1 verification record; from then on CI owns it.
3. Phase 3 - closure hook. Mark FV-B1's Phase 3 acceptance box checked only when this suite is green in a hosted run; cross-link the run URL from the FV-B1 verification record.

Files added: `scripts/check-apalache-negative.sh`, `formal/apalache/_negative_tests/REGISTRY.toml`, eight `DropGuard*Broken.tla` modules, and eight matching configs. Files modified: `.github/workflows/apalache-safety.yml`, `formal/apalache/_negative_tests/README.md`, and `formal/MAPPING.md`.

## CI and gating changes

- `.github/workflows/apalache-safety.yml`: new `apalache-negative` job, same triggers (path-scoped PR + nightly cron), same Java/Apalache install steps, running `scripts/check-apalache-negative.sh`. Run it as a separate job rather than a step so a negative-suite failure is legible in the checks UI as "a broken spec was NOT caught" rather than blending into the safety matrix output. Path scope additions: `formal/apalache/_negative_tests/**` and `scripts/check-apalache-negative.sh` must be in the workflow's `paths` list so registry or wrapper edits re-run the job.
- Gating: the job is REQUIRED on PRs that touch `formal/apalache/**`. This is deliberately stronger than the positive matrix alone: a PR that weakens an invariant into a tautology currently passes CI (the unbroken spec still reports `NoError`); with this job it fails, because the paired Broken spec stops producing its counterexample.
- No ratchet mechanics here; per-lane budgets and trend tracking belong to [FV-E5](FV-E5-lane-ratchets.md), and generalizing from hand-written mutations to systematic spec mutation is [FV-E1](FV-E1-spec-mutation-testing.md).

## Acceptance criteria

- [x] `scripts/check-apalache-negative.sh` exists, iterates `REGISTRY.toml`, and distinguishes violations, `NoError`, timeouts, and other tool failures.
- [x] `REGISTRY.toml` covers both pre-existing Broken specs and all eight drop-guard variants, each with a mapped invariant and exact production commit SHA where applicable.
- [x] All eight drop-guard Broken variants produce counterexamples at `--length=4` under pinned apalache-mc 0.50.1 locally.
- [ ] All ten registered entries pass in the hosted job on the landing PR.
- [x] The `apalache-negative` job is wired into the same path-scoped and nightly triggers as the safety matrix.
- [ ] The `apalache-negative` job is green on the landing PR.
- [x] `_negative_tests/README.md` documents the wrapper inversion and registry.
- [x] Restoring the `HasAllowReceipt` precondition makes the wrapper observe `NoError` and fail in `scripts/tests/check-apalache-negative.test.sh`.

## Risks and mitigations

- The wrapper misclassifies a tool crash as a caught violation. Mitigation: the explicit violation-marker requirement plus fail-closed handling of the third outcome class; acceptance criterion 1 makes this a reviewable behavior, not an implementation detail.
- Broken specs drift as the positive spec evolves (a rename in `PostAdmissionDropGuard.tla` leaves a stale Broken copy checking nothing). Mitigation: negative specs fail loudly on parse errors under the fail-closed third class, and [FV-E1](FV-E1-spec-mutation-testing.md) replaces hand-maintained copies with generated mutations long-term. Short-term, keep Broken variants as minimal diffs against the positive spec so review catches drift.
- CI time creep as the registry grows. Mitigation: per-spec `timeout_secs` in the registry, nightly-only lane flag as an escape hatch (add a `lane` field mirroring `.kani/harnesses.toml` if needed; default all current entries to the PR lane since they are seconds-cheap).
- A counterexample exists but at a depth beyond the registry `length`. Mitigation: each variant's registry row is only accepted with a reproduced counterexample at that length (acceptance criterion 3); the length is part of the recorded evidence, not a guess.

## Resolved questions

- Job-level or step-level integration in `apalache-safety.yml`. Decision: use a separate job so a missing counterexample is legible in the checks UI.
- Should `production_commit` rows also link the kernel test that pins the same bug at the Rust level? Decision: yes; every production-derived row includes a `runtime_test` anchor.
- Whether `REGISTRY.toml` should be folded into a future unified negative-testing registry. Decision: keep the dedicated versioned schema authoritative; a later migration can consume `chio.apalache-negative.v1` mechanically.

## Manifest and registry updates

- New registry: `formal/apalache/_negative_tests/REGISTRY.toml` (schema `chio.apalache-negative.v1`) as specified above; this is the authoritative list the wrapper and CI consume.
- `formal/MAPPING.md`: no new property rows (Broken specs are not properties); add a short subsection under the Apalache table. `scripts/check-apalache-negative.sh` now rejects every registry `falsifies` value without a mapped table row.
- `formal/proof-manifest.toml`: append `./scripts/check-apalache-negative.sh` to `gate_commands` so the formal evidence bundle includes the falsifiability gate.
- `formal/theorem-inventory.json`, `formal/assumptions.toml`, `.kani/harnesses.toml`: no changes.
- `formal/issue-templates/property-counterexample.md`: add one line to the Apalache section noting that if a POSITIVE spec's counterexample leads to an invariant amendment, the paired negative-test registry rows must be re-validated in the same PR.
