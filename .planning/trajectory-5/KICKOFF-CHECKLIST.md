# Trajectory 5 Planning Checklist

This checklist records planning readiness only. It is not a release gate and
does not authorize `v0.1.0-bounded-chiodome`.

## Current Corrections

- [x] PR #620 is the sole planning-truth owner for `.planning/trajectory-5/**`.
- [x] Trajectory 5 is framed as assurance and integration work, not a product
  release or tag vehicle.
- [x] The execution order is Lane B integration first, Lane A assurance addendum
  second, and Lane C canary demo after Lane B.
- [x] #618 release packaging remains last and must be regenerated from merged
  `main`.
- [x] The old aggregate ship-bar wording is superseded by the claim-by-claim
  assurance matrix in the legacy-named `SHIP-BAR-TRACKER.md`.
- [x] Release status is normalized to the optional
  `releases.toml` `[v0_1_0_bounded_chiodome].release_status` namespace, but PR
  #620 does not author that root package truth.
- [x] Executable gates do not depend on `tickets.md`.

## Planning Artifacts

- [x] `README.md`
- [x] `R4-MERGE-TOPOLOGY.md`
- [x] `SHIP-BAR-TRACKER.md`
- [x] `EXECUTION-BOARD.md`
- [x] `SCOPE-LOCK.md`
- [x] `TIMELINE.md`
- [x] `OWNERS.toml`
- [x] `READINESS.md`
- [x] `CLOSEOUT.md`
- [x] `lane-a-floor/PLAN.md` and `lane-a-floor/README.md`
- [x] `lane-b-wiring/PLAN.md` and `lane-b-wiring/README.md`
- [x] `lane-c-demo/PLAN.md` and `lane-c-demo/README.md`

Lane ticket files remain planning records and are intentionally not part of any
executable release or assurance gate.

## Executable Checks

- [x] `.planning/trajectory-5/tools/planning-preflight.sh` exists. It validates
  planning consistency and the root release/config boundary. It does not check
  `tickets.md`.
- [x] `scripts/check-bounded-ship-bar.sh` exists. The filename is kept for
  compatibility; the script now checks assurance claims and is not a release
  readiness gate.
- [x] `scripts/tests/check-bounded-ship-bar.test.sh` covers strict and diagnostic
  behavior.
- [x] `.github/workflows/ci.yml` invokes
  `bash ./scripts/tests/check-bounded-ship-bar.test.sh`.

## Assurance Claims

- [x] Claim B: Lane B hot-path enforcement is the first integration slice.
- [x] Claim A: Lane A evidence is an assurance addendum and can remain partial.
- [x] Claim C: Lane C is a post-Lane-B canary, not a release driver.

## Release-Key Contract

The only bounded package status key is:

```toml
[v0_1_0_bounded_chiodome]
release_status = "blocked_pending_lane_b_integration"
```

`[trajectory_5]` must not be added to root `releases.toml` by this planning PR.
Planning inventory stays under `.planning/trajectory-5/**`.

## Verification

Run:

```bash
bash .planning/trajectory-5/tools/planning-preflight.sh
bash scripts/tests/check-bounded-ship-bar.test.sh
bash scripts/check-bounded-ship-bar.sh --diagnostic
```

The diagnostic assurance run may report partial rows until source/evidence
branches merge and regenerate artifacts from `main`. The strict assurance gate
must fail while any claim remains partial.

## R6 Closure

Closed for PR #620: R6-P0-001, R6-P0-003, R6-P0-004, R6-P1-005,
R6-P2-001, R6-P2-002, R6-P2-003, R6-P2-007, R6-P2-009.
