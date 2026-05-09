# Trajectory 5.1 Design

## Purpose

Trajectory 5.1 stabilizes the merged Trajectory 5 code and evidence. It treats
Trajectory 5 as an integrated planning and assurance baseline, not as release
readiness.

## Design

The work is split into five lanes:

- Baseline repair restores a clean build and closes stale PR state.
- Lane B hardens the runtime and federation hot path.
- Lane A reconciles assurance evidence with strict scripts.
- Lane C regenerates the canary from merged `main`.
- Packaging stays blocked until strict A/B/C gates pass.

Lane B executes before Lane A evidence claims are upgraded. Lane C executes
after Lane B because the canary depends on runtime semantics and DSSE federation
truth. Packaging is last.

## Success Criteria

- The targeted conformance and runtime check passes.
- `scripts/check-bounded-ship-bar.sh` moves from failing to passing only when
  every partial row is either closed or honestly demoted.
- No release, zk, BBS+, strict DSSE, or package claim is made without matching
  evidence.

