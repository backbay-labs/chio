# Trajectory 5.1 Stabilization Plan

Status: superseded by Trajectory 5.2.

Trajectory 5.2 starts from post-#630 main
`7f56cf5383fc1caa7a4f06b4cd59e45177f00496` and recasts the remaining strict
bounded-gate partials outside the active release claim.

Trajectory 5.1 is the stabilization and truth-reconciliation pass after the
Trajectory 5 integration merge. It does not introduce a product release. It
turns the merged Trajectory 5 source state into a clean, reviewable baseline,
then closes the assurance gaps that remain partial or false-positive today.

## Baseline

- Integrated main: `7f56cf5383fc1caa7a4f06b4cd59e45177f00496`.
- Planning preflight: passing.
- Bounded assurance gate: superseded by Trajectory 5.2 recast.
- Targeted Rust baseline: initially failing in `chio-conformance` because
  several test `ToolServerConnection` impls retained `?Send` after the trait
  landed with `Send` futures.

## Goals

1. Restore a clean integrated build baseline.
2. Close Lane B runtime safety gaps before widening evidence claims.
3. Reconcile Lane A evidence truth with strict scripts and observed data.
4. Keep Lane C as a canary until it is regenerated from merged `main`.
5. Retire stale PRs or restack only the deltas still missing from `main`.

## Non-Goals

- Cutting `v0.1.0-bounded-chiodome`.
- Claiming full BBS+, zero-knowledge, strict CHIO bilateral invocation, or
  release readiness before the strict gates pass.
- Treating hosted CI failures as blockers for the merge pass. 5.1 will record
  local and hosted evidence separately.

## Execution Order

1. **Baseline repair**: fix merged conformance break and close stale PR state.
2. **Lane B hardening**: cancellation safety, explicit receipt context,
   federated durability, and DSSE cosigner routing.
3. **Lane A evidence**: full mutation rebaseline, strict threat-mutants
   evidence, Kani and formal truth alignment.
4. **Lane C canary**: regenerate deterministic canary artifacts from merged
   `main` only after Lane B is stable.
5. **Package restart gate**: leave packaging blocked until strict A/B/C gates
   pass.

## Gate Commands

```bash
bash .planning/trajectory-5/tools/planning-preflight.sh
bash scripts/tests/check-bounded-ship-bar.test.sh
cargo check -p chio-kernel -p chio-anchor -p chio-federation -p chio-conformance --tests
bash scripts/check-tool-server-async.sh
bash scripts/check-anchor-batch-async-witness.sh
bash scripts/check-threat-coverage-mutants.sh
bash scripts/check-bounded-ship-bar.sh
```

## Execution Closeout - 2026-05-09

Status: implemented baseline stabilization with honest release blockers.

- Remote PR closeout: #609, #610, #611, #614, #615, #616, #617, #618,
  #620, #628, and #629 are closed. The integration train landed through
  #627 on `main`.
- Lane B: cancellation cleanup, request-keyed receipt context, federated
  durable receipt-store fail-closed behavior, cosigner-routed DSSE PAE
  signing, and strict B4 conformance fixtures are implemented.
- Lane A: threat coverage is demoted to 20 pending rows with `deferred_to`
  owners. The strict threat-mutants gate passes with zero false covered
  rows. Local Kani and Lean proof gates pass. Mutation baselines remain
  honest partials.
- Lane C: deterministic canary fixtures, replay transcripts, golden receipt
  explain output, and release metadata were regenerated from merged `main`.
- Package status: Trajectory 5.2 parks `v0_1_0_bounded_chiodome` outside
  active release scope; no release is cut by this pass.

The original 5.1 strict assurance snapshot was red with eight partial rows.
Trajectory 5.2 converts those release blockers into machine-readable
non-release recasts and owns the strict gate result from this point forward.
