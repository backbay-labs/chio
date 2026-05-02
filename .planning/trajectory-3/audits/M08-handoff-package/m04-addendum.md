# M08 Handoff Addendum: M04 Mutation Gate

**Trajectory:** trajectory-3
**Source milestone:** M04 mutation gate
**Consumer:** M08 independent crypto and protocol review
**Date:** 2026-05-02

## Summary

M04 moved the mutation lane and verdict matrix from advisory evidence
to release-gate evidence before M08 active review. The mutation
kill-rate target remains 80 percent, but D08 explicitly allows the
trajectory to ship the gate at the achieved honest threshold if the
week-12 target cannot reach 80 percent. The enforced floor is 65
percent through `releases.toml [mutants].activation_threshold_percent_per_crate`.

## Evidence for reviewer intake

- Primary audit doc: `.planning/trajectory-3/audits/M04-mutation-gate.md`.
- Mutation gate evidence directory:
  `.planning/trajectory-3/audits/M04-mutation-gate-evidence/`.
- Activation threshold: 65 percent per crate.
- Target catch ratio: 80 percent.
- Priority surfaces: `chio-attest-verify`, `chio-kernel-core`,
  `chio-siem`, `chio-policy`, `chio-guards`, and `chio-anchor`.
- Verdict-matrix required drivers: Rust oracle, Python SDK, and Go HTTP
  SDK with zero local divergence in the recorded P2 and P4 runs.

## Reviewer guidance

M08 reviewers should treat sub-80 mutation results as documented risk,
not hidden release drift. The expected review question is whether the
fail-closed behavior, capability algebra, receipt construction,
revocation checks, TEE quote verification, and PQ / hybrid signature
paths have enough targeted tests to make the 65 percent floor honest.
If a reviewer finds a surviving mutant that implies allow-by-default,
silent verifier bypass, or receipt forgery, it should be logged as a
finding even if the aggregate mutation kill-rate remains above the D08
floor.

## Cross-reference

The M04 audit doc quotes the D08 rationale and records:

- mutation kill-rate target: 80 percent
- enforced floor: 65 percent
- threshold flip: blocking semantics
- hosted replay status: tracked in `.planning/trajectory-3/work/CI-DEBT.md`

This addendum is append-only and does not reopen M04.
