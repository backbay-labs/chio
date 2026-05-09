# Trajectory 5 Planning

**Status**: RW5 release-architecture correction applied. PR #620 is the
planning-truth owner for `.planning/trajectory-5/**`; it is not a product
release, release package, or tag vehicle.

Trajectory 5 may close only as an accepted planning/integration map or assurance
matrix. It cannot close as release readiness, tag readiness, or proof that
future work has been completed. The corrected security-reviewable execution
order is:

1. **Lane B integration first**: make the spec hot path real in source.
2. **Lane A assurance addendum second**: regenerate mutation, threat, Kani,
   TLA+, and Lean evidence from the merged Lane B source state.
3. **Lane C canary demo after Lane B**: prove composition only after the Lane B
   enforcement stack exists on merged source.
4. **#618 packaging last**: regenerate any bounded chiodome package from
   merged `main`, not from the current open PR set.

The prior "one ship-bar visible from outside" language is superseded. The active
contract is the claim-by-claim assurance matrix in `SHIP-BAR-TRACKER.md`; that
filename is retained only because existing scripts and review links require it.

## What PR #620 Owns

PR #620 owns planning control data:

- `.planning/trajectory-5/**`
- release architecture and merge-topology records
- assurance matrix wording
- planning-local preflight script registration
- the executable assurance checker and its regression test

PR #620 does not own:

- Lane B source enforcement
- Lane A mutation/threat/formal evidence branches
- Lane C demo sources
- #618 release packaging
- a tag push for `v0.1.0-bounded-chiodome`

## Assurance Claims

| Claim | Lane | Purpose | Current posture |
|---|---|---|---|
| B | Lane B hot-path enforcement | Single-entry verifier, receipt v2 fail-closed, anchor-batch async-only, DSSE bilateral signing. | Must integrate first from a clean source branch. |
| A | Lane A assurance addendum | Mutation, threat, Kani, TLA+, and Lean evidence. | Regenerated from merged Lane B code; partial rows stay partial. |
| C | Lane C canary demo | Bounded chiodome end-to-end composition fixture. | Canary only; downstream of Lane B. |

The assurance checker is `scripts/check-bounded-ship-bar.sh`. The filename is
kept for compatibility, but the script validates assurance evidence, not release
readiness. Any legacy C5 output from that checker is compatibility metadata only;
C5 selective disclosure is future work outside the current closure matrix.

## Release-Audit Non-Inheritance

`docs/release/RELEASE_AUDIT.md` records an older repo-local go/no-go decision
for a bounded release candidate. Trajectory 5 does not inherit that posture.
For this trajectory, local-go is false: Lane B must integrate first, Lane A
evidence must be regenerated from merged code, Lane C is only a canary after
Lane B, and #618 packaging stays pending-upstream-merges until a later package
owner regenerates from `main`.

The branch-scoped non-inheritance rule is recorded in
`RELEASE-AUDIT-NON-INHERITANCE.md`.

## Release-Key Namespace

Do not add Trajectory 5 planning inventory, release-state, or tag-state keys to
root `releases.toml` in this PR.

The bounded chiodome package status, if and when the release-package owner
records it, is:

```toml
[v0_1_0_bounded_chiodome]
release_status = "blocked_pending_lane_b_integration"
```

PR #620 does not author that root status. It records the boundary: #618 or the
release owner may add package truth only after Lane B integration and merged-main
canary regeneration.

## Gate Semantics

`.planning/trajectory-5/tools/planning-preflight.sh` checks planning consistency
and the root release/config boundary. It does not depend on `tickets.md` and is
not wired as a root release gate.

`scripts/check-bounded-ship-bar.sh` checks evidence artifacts only:

- `audits/evidence/mutants/banner.json`
- `audits/evidence/mutants/<crate>/*.json`
- `audits/evidence/threats/*.json`
- Lane B negative conformance fixtures under `crates/chio-conformance/tests/`
- `scripts/check-anchor-batch-async-witness.sh`
- Lane C canary fixtures under `examples/chiodome-bilateral/`
- optional `[v0_1_0_bounded_chiodome].release_status` and
  `integrated_merge_sha` if the package owner has recorded them

Planning docs can track tickets. Executable gates cannot pass or fail because a
ticket file exists.

## Document Layout

| File | Purpose |
|---|---|
| `R4-MERGE-TOPOLOGY.md` | Current merge topology and replacement strategy. |
| `SHIP-BAR-TRACKER.md` | Legacy filename for the claim-by-claim assurance matrix. |
| `EXECUTION-BOARD.md` | Planning board; not an executable release gate. |
| `SCOPE-LOCK.md` | In-scope and deferred work catalog. |
| `TIMELINE.md` | Corrected sequencing: Lane B first, Lane A addendum, Lane C canary. |
| `KICKOFF-CHECKLIST.md` | Planning checklist; not a release claim. |
| `OWNERS.toml` | Owner-class and coordination metadata. |
| `READINESS.md` | Historical readiness summary plus corrected release-truth note. |
| `CLOSEOUT.md` | Historical closeout map and integration debt. |
| `RELEASE-AUDIT-NON-INHERITANCE.md` | Branch-scoped rule preventing old local-go release posture from applying to Trajectory 5. |
| `lane-a-floor/tickets.md` | Lane A planning tickets. |
| `lane-b-wiring/tickets.md` | Lane B planning tickets. |
| `lane-c-demo/tickets.md` | Lane C planning tickets. |
| `reviews/` | Historical review records and closure logs. |

## Out Of Scope

- Treating Trajectory 5 as a public product launch.
- Cutting `v0.1.0-bounded-chiodome` from the current open PR set.
- Letting Lane C demo packaging precede Lane B source enforcement.
- Using ticket inventories as executable release gates.
- Claiming full BBS+, full hosted-nightly mutation closure, full 17-step
  bilateral verifier coverage, or kernel-signed KB MCP receipts while those
  rows remain partial.

## RW5 Closure

This pass closes RW5-BI-P0-001, RW5-BI-P0-002, RW5-BI-P1-003,
RW5-BI-P1-004, RW5-BI-P2-002, and RW5-BI-P2-003 for PR #620 prose. The earlier
R6 issue closures remain recorded in the historical files.
