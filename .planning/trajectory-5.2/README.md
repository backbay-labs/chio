# Trajectory 5.2 Active Lane

Status: implemented gate recast.

Trajectory 5.2 is the active release-truth lane after PR #630. It does not add
product APIs or runtime behavior. Its job is to make the bounded assurance gate
green by either closing evidence rows or recasting them outside the active
release claim with machine-readable metadata.

## Baseline

- Post-#630 main: `7f56cf5383fc1caa7a4f06b4cd59e45177f00496`.
- PR #630 proof evidence is merged into `main`.
- Kani, Lean, Apalache, threat-mutants, and Lane B fixtures remain evidence
  inputs.

## Active Decisions

- Six mutation baselines stay advisory and are marked with
  `chio.assurance-recast.v1`.
- C5 selective disclosure stays deferred with `release_claim_allowed = "no"`
  and `strict_gate_effect = "accept_recast"`.
- `v0.1.0-bounded-chiodome` is parked as `parked_non_release`; deterministic
  fixtures remain evidence artifacts, not a package release.
- Trajectory 6 may plan in shadow only. It cannot merge runtime code or claim
  shipped protocol behavior until this lane exits.

## Exit

Trajectory 5.2 exits when `bash scripts/check-bounded-ship-bar.sh` passes in
default mode and the bounded assurance manifest hashes the current evidence
state.
