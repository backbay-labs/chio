# Trajectory 5.2 Active Lane Design

## Purpose

Trajectory 5.2 turns Trajectory 5.1's honest diagnostic snapshot into a strict
gate result. It does that by adding machine-readable claim narrowing rather
than by pretending advisory mutation evidence or deferred selective disclosure
work is complete.

## Design

The bounded assurance gate accepts `chio.assurance-recast.v1` on mutation rows
only when the row explicitly says the evidence is deferred, outside the active
release claim, accepted by the strict gate, approved by the 5.2 lane, dated,
and tied to a follow-up path. Invalid recast metadata is a failure.

C5 selective disclosure is accepted in strict mode only when its marker keeps
`release_claim_allowed = "no"` and `strict_gate_effect = "accept_recast"`.
If a future marker claims `evidence_complete`, the gate still requires real
implementation and proof fixtures.

The bounded Chiodome package is parked as `parked_non_release`. Deterministic
fixtures remain evidence, but no package release is claimed by this lane.

## Success Criteria

- The strict bounded assurance gate passes without diagnostic mode.
- Existing proof and threat-mutants gates remain green.
- Release-facing docs record advisory mutation evidence and non-release package
  status.
- Trajectory 6 planning remains specs-only.
