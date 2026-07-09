# FV-B2: Fixed production bugs as CI-enforced negative model tests

Status: Proposed (2026-07-09)
Theme: B - Aim the formal tools at the actual bug generator
Effort: S
Depends on: [FV-B1](FV-B1-drop-guard-model.md) for the drop-guard variants (phase 2); phase 1 stands alone on the two existing negative tests
Feeds: [FV-E1](FV-E1-spec-mutation-testing.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G5, G3), `formal/apalache/_negative_tests/README.md`, [FV-E2](FV-E2-counterexample-regression-pipeline.md)

## Summary

A model that has never produced a counterexample is unmeasured, not trustworthy (gap G5). The repo already has the right discipline in embryo: `formal/apalache/_negative_tests/` holds two deliberately broken spec variants that must produce counterexamples, but they are local-only, run by hand, and cover none of the five drop-guard bugs fixed in production this month. This document (a) encodes each fixed drop-guard bug as a Broken variant of the FV-B1 spec that MUST yield a counterexample, (b) adds a machine-readable registry mapping each Broken spec to the production commit it re-derives, and (c) promotes the whole negative suite into CI via a wrapper script that inverts the signal correctly: the job is green exactly when every Broken spec is caught.

## Motivation and evidence

- `formal/apalache/_negative_tests/README.md` states the current posture plainly: "Negative-spec runs are local diagnostic only; CI does not enforce them" (lines 8-9), and gives the reason for exclusion: "Running negative tests in CI would gate a green build on a counterexample, which inverts the green/red signal" (lines 43-48). The reason is real but solvable with one layer of indirection; nothing about a counterexample requirement prevents wrapping it so that caught-counterexample maps to exit 0.
- The two existing variants are `ReceiptBeforeAllowBroken.tla` (drops the `HasAllowReceipt(a, c)` precondition from `PublishAllow`; verified by reading the spec, broken action at lines 65-70) and `RevocationCutCompletenessBroken.tla` (flips only the root) [v]. Both are exercised at `--length=4` per the README.
- Five production drop-guard bugs now have exact spec-level fingerprints (commit family verified via `git show --stat` this session): `38cc91471`, `a6d26dbc4` (Findings A/B/C), `58abf33d2`, `84e98b9d0`, `c201afbd0`. Encoding each as a Broken variant of `PostAdmissionDropGuard.tla` turns "the model would have caught it" from a claim into a checked artifact, and is the falsifiability gate FV-B1 requires before its model counts as evidence.
- `formal/issue-templates/property-counterexample.md` already requires counterexamples to be committed raw and classified spec-bug / implementation-bug / harness-bug [v]; the registry proposed here reuses that classification vocabulary.

## Current state

- `formal/apalache/_negative_tests/`: `Common.tla` (copy), `ReceiptBeforeAllowBroken.tla` + `MCReceiptBeforeAllowBroken.cfg`, `RevocationCutCompletenessBroken.tla` + `MCRevocationCutCompletenessBroken.cfg`, `README.md`. Verified by listing the directory this session.
- The convention (README lines 17-21): for property `P` in `formal/apalache/Foo.tla`, `FooBroken.tla` mutates exactly one guard or one state update so `P` becomes falsifiable, and Apalache must report `SafetyInv` violated within a few states.
- No registry ties a Broken spec to the invariant it falsifies or to any production commit; the "captured output is the authoritative record at the time the negative test was last run" (README lines 12-14), i.e. the evidence is a human memory.
- CI: `.github/workflows/apalache-safety.yml` runs only the unbroken specs (matrix at lines 66-73).

## Design

### One Broken variant per fixed drop-guard bug

Each variant mutates exactly one transition of `formal/apalache/PostAdmissionDropGuard.tla` (per the existing single-mutation convention) and names the invariant it must falsify:

| Broken spec (in `_negative_tests/`) | Mutation | Falsifies | Re-derives commit |
| --- | --- | --- | --- |
| `DropGuardDiscardChildBufferBroken.tla` | `DropPostDispatch` skips the child-buffer flush (appends only the parent cancel record; `child_buf` zeroed without logging) | `ChildReceiptsFlushed` | `38cc91471` |
| `DropGuardSkipChildBudgetReleaseBroken.tla` | `DropPreDispatch` leaves `ledger[i]["child"]` at `reserved` | `ReservationConservation` | `a6d26dbc4` Finding B |
| `DropGuardNoFaultReceiptBroken.tla` | `DropPreDispatch` with a failed unwind step appends no `fault` record | `TerminalReceiptExactlyOne` | `a6d26dbc4` Finding C |
| `DropGuardReleaseOnIncompleteStreamBroken.tla` | `IncompleteStream` sets `ledger[i]["lease"]` to `released` instead of `retained` | `RetainedIffAborted` | `84e98b9d0` |
| `DropGuardNoRetainOnPostInvocationDenyBroken.tla` | `DenyPostInvocation` leaves the lease `reserved` (no retained marking) | `RetainedIffAborted` | `58abf33d2` |

Optional sixth (recommended, same pattern): `DropGuardSkipInvocationReversalBroken.tla`, `DropPreDispatch` leaves `ledger[i]["slot"]` at `reserved`, falsifying `ReservationConservation` and re-deriving `a6d26dbc4` Finding A. And a seventh for `c201afbd0` if its aborted-unwind retention is not already subsumed by the incomplete-stream variant; decide when writing the specs.

Each Broken spec gets its own `MC*.cfg` (constants identical to `MCPostAdmissionDropGuard.cfg`, `INVARIANT SafetyInv`) so the counterexample search runs under the same bounds as the positive check, at a shorter `--length` (4 is the existing negative-test convention and every mutation above is reachable within 4 steps: Admit, StartDispatch, one mid-flight action, Drop/terminal).

### Registry: `formal/apalache/_negative_tests/REGISTRY.toml`

Machine-readable so the wrapper script iterates it (same single-source-of-truth pattern as `.kani/harnesses.toml`, schema line verified this session):

```toml
schema = "chio.apalache-negative.v1"

[[negative]]
spec = "formal/apalache/_negative_tests/ReceiptBeforeAllowBroken.tla"
cfg = "formal/apalache/_negative_tests/MCReceiptBeforeAllowBroken.cfg"
falsifies = "ReceiptBeforeAllow"
production_commit = "n/a (non-tautology check, predates this registry)"
classification = "spec-mutation"
length = 4
timeout_secs = 300
notes = "PublishAllow drops the HasAllowReceipt precondition."
```

Fields: `spec`, `cfg`, `falsifies` (the exact invariant name, which MUST have a `formal/MAPPING.md` row), `production_commit` (full sha of the fix the variant re-derives, or `n/a` for pure non-tautology checks), `classification` (reusing the issue template's vocabulary: these are all deliberate spec mutations standing in for implementation bugs), `length`, `timeout_secs`, `notes`. The five drop-guard rows carry their commit shas from the table above.

### Wrapper: `scripts/check-apalache-negative.sh`

The inversion layer that makes CI-green mean "all broken specs are caught":

- Iterate `REGISTRY.toml` entries (python3 `tomllib` one-liner or a small parser, matching the repo's existing python usage in `scripts/check-apalache-formal-slice.py`).
- For each entry run `apalache-mc check --length=<length> --config=<cfg> <spec>` under `timeout <timeout_secs>`.
- Success for an entry requires BOTH: (a) the run did not report `NoError`, and (b) the output contains Apalache's explicit violation marker (the checker's "found an error / invariant violated" report) or produced a counterexample trace file. Requiring the marker, not just a nonzero exit code, is load-bearing: a TLA+ parse error or a crashed JVM also exits nonzero, and without the marker check a syntactically broken Broken spec would masquerade as a caught bug forever. Fail closed on anything that is neither a clean violation nor `NoError` (timeout, parse error, tool crash) with a distinct message per failure class.
- Exit nonzero if ANY entry reports `NoError` (that invariant has silently regressed to a tautology, exactly the condition README lines 39-40 warns about) or fails the marker check.
- `--output` counterexample artifacts land in a scratch dir and are uploaded as workflow artifacts for triage, not committed (committed raw counterexamples remain the job of the issue-template flow when a POSITIVE spec fails [v]).

Skeleton (final version lands with the PR; the three-outcome contract is the part to review now):

```bash
#!/usr/bin/env bash
set -euo pipefail
fail=0
while IFS='|' read -r spec cfg length timeout; do
  out="$(mktemp)"
  if timeout "${timeout}" apalache-mc check --length="${length}" \
       --config="${cfg}" "${spec}" >"${out}" 2>&1; then
    echo "NEGATIVE-TEST FAILURE: ${spec} reported NoError (tautology regression)" >&2
    fail=1
  elif grep -q "found an error\|The outcome is: Error" "${out}"; then
    echo "ok: ${spec} produced its counterexample"
  else
    echo "NEGATIVE-TEST FAILURE: ${spec} failed without a violation report" >&2
    echo "  (parse error, timeout, or tool crash; see log below)" >&2
    cat "${out}" >&2
    fail=1
  fi
done < <(python3 - <<'PY'
import tomllib
reg = tomllib.load(open("formal/apalache/_negative_tests/REGISTRY.toml", "rb"))
for n in reg["negative"]:
    print(f'{n["spec"]}|{n["cfg"]}|{n["length"]}|{n["timeout_secs"]}')
PY
)
exit "${fail}"
```

The exact violation-marker strings must be confirmed against pinned apalache-mc 0.50.1 output during phase 1 and pinned in the script with a comment naming the version; do not rely on exit codes alone in either direction.

### Budget

Negative runs are cheap because the counterexamples are shallow (README: "within a few states", and every mutation above is reachable in <= 4 steps): expect seconds to low minutes per spec on the hosted runner, bounded by SMT startup. Per-spec `timeout_secs = 300` with 7 specs gives a worst case of 35 minutes, comfortably inside the workflow's 180-minute job timeout; typical runs should be under 10 minutes total.

## Implementation plan

1. Phase 1 - wrapper against the existing suite (no FV-B1 dependency). Add `scripts/check-apalache-negative.sh` and `formal/apalache/_negative_tests/REGISTRY.toml` with the two existing entries. Add a `apalache-negative` job (or a step after the safety matrix) to `.github/workflows/apalache-safety.yml`. Rewrite the "Why these are not in CI" section of `formal/apalache/_negative_tests/README.md` to describe the wrapper posture ("CI-green means every Broken spec still yields its counterexample") and keep the local commands.
2. Phase 2 - drop-guard variants (after FV-B1 phase 2). Add the five (plus optional sixth/seventh) `DropGuard*Broken.tla` + cfg files and their REGISTRY rows with `production_commit` shas. Reproduce each counterexample locally once and record the run in the FV-B1 verification record; from then on CI owns it.
3. Phase 3 - closure hook. Mark FV-B1's Phase 3 acceptance box checked only when this suite is green in a hosted run; cross-link the run URL from the FV-B1 verification record.

Files added: `scripts/check-apalache-negative.sh`, `formal/apalache/_negative_tests/REGISTRY.toml`, `formal/apalache/_negative_tests/DropGuard*Broken.tla` (5-7), `formal/apalache/_negative_tests/MCDropGuard*Broken.cfg` (matching). Files modified: `.github/workflows/apalache-safety.yml`, `formal/apalache/_negative_tests/README.md`, `formal/MAPPING.md` (see registry section below).

## CI and gating changes

- `.github/workflows/apalache-safety.yml`: new `apalache-negative` job, same triggers (path-scoped PR + nightly cron), same Java/Apalache install steps, running `scripts/check-apalache-negative.sh`. Run it as a separate job rather than a step so a negative-suite failure is legible in the checks UI as "a broken spec was NOT caught" rather than blending into the safety matrix output. Path scope additions: `formal/apalache/_negative_tests/**` and `scripts/check-apalache-negative.sh` must be in the workflow's `paths` list so registry or wrapper edits re-run the job.
- Gating: the job is REQUIRED on PRs that touch `formal/apalache/**`. This is deliberately stronger than the positive matrix alone: a PR that weakens an invariant into a tautology currently passes CI (the unbroken spec still reports `NoError`); with this job it fails, because the paired Broken spec stops producing its counterexample.
- No ratchet mechanics here; per-lane budgets and trend tracking belong to [FV-E5](FV-E5-lane-ratchets.md), and generalizing from hand-written mutations to systematic spec mutation is [FV-E1](FV-E1-spec-mutation-testing.md).

## Acceptance criteria

- [ ] `scripts/check-apalache-negative.sh` exists, iterates `REGISTRY.toml`, and distinguishes three outcomes per spec (violation caught = pass; `NoError` = fail; anything else = fail with a distinct tool-error message).
- [ ] `REGISTRY.toml` covers both pre-existing Broken specs and all drop-guard variants, each with `falsifies` naming a MAPPING.md-rowed invariant and (for the drop-guard rows) the exact production commit sha.
- [ ] All five drop-guard Broken variants produce counterexamples at `--length=4` under pinned apalache-mc 0.50.1, locally and in a hosted run.
- [ ] The `apalache-negative` job is green on the landing PR and wired into the same path-scoped + nightly triggers as the safety matrix.
- [ ] `_negative_tests/README.md` no longer claims CI exclusion; it documents the wrapper inversion and points at the registry.
- [ ] Deleting the `HasAllowReceipt` guard check from the wrapper (mutation smoke test of the wrapper itself) makes the job fail; documented once in the PR description.

## Risks and mitigations

- The wrapper misclassifies a tool crash as a caught violation. Mitigation: the explicit violation-marker requirement plus fail-closed handling of the third outcome class; acceptance criterion 1 makes this a reviewable behavior, not an implementation detail.
- Broken specs drift as the positive spec evolves (a rename in `PostAdmissionDropGuard.tla` leaves a stale Broken copy checking nothing). Mitigation: negative specs fail loudly on parse errors under the fail-closed third class, and [FV-E1](FV-E1-spec-mutation-testing.md) replaces hand-maintained copies with generated mutations long-term. Short-term, keep Broken variants as minimal diffs against the positive spec so review catches drift.
- CI time creep as the registry grows. Mitigation: per-spec `timeout_secs` in the registry, nightly-only lane flag as an escape hatch (add a `lane` field mirroring `.kani/harnesses.toml` if needed; default all current entries to the PR lane since they are seconds-cheap).
- A counterexample exists but at a depth beyond the registry `length`. Mitigation: each variant's registry row is only accepted with a reproduced counterexample at that length (acceptance criterion 3); the length is part of the recorded evidence, not a guess.

## Open questions

- Job-level or step-level integration in `apalache-safety.yml`: a separate job costs a duplicate Apalache install (~minutes); a step muddies failure attribution. Proposal above says job; flip to step if runner minutes matter more than legibility.
- Should `production_commit` rows also link the kernel test that pins the same bug at the Rust level (e.g. the `chio_runtime.rs` tests each fix commit added), giving a three-way bug fingerprint (commit, Rust test, Broken spec)? Cheap to add; leaning yes.
- Whether `REGISTRY.toml` should be folded into a future unified negative-testing registry with Kani/proptest mutation entries under [FV-E1](FV-E1-spec-mutation-testing.md); keep the schema string versioned (`chio.apalache-negative.v1`) so migration is mechanical.

## Manifest and registry updates

- New registry: `formal/apalache/_negative_tests/REGISTRY.toml` (schema `chio.apalache-negative.v1`) as specified above; this is the authoritative list the wrapper and CI consume.
- `formal/MAPPING.md`: no new property rows (Broken specs are not properties), but add a short subsection under the Apalache table stating that every Apalache invariant row is required to name at least one negative-test registry entry once FV-B2 lands, and that `scripts/check-apalache-negative.sh` is the enforcement point. A later hardening can make `check-mapping.sh` verify the invariant-name join between MAPPING.md and REGISTRY.toml.
- `formal/proof-manifest.toml`: append `./scripts/check-apalache-negative.sh` to `gate_commands` so the formal evidence bundle includes the falsifiability gate.
- `formal/theorem-inventory.json`, `formal/assumptions.toml`, `.kani/harnesses.toml`: no changes.
- `formal/issue-templates/property-counterexample.md`: add one line to the Apalache section noting that if a POSITIVE spec's counterexample leads to an invariant amendment, the paired negative-test registry rows must be re-validated in the same PR.
