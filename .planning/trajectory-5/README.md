# Trajectory 5 Planning

**Status**: R6 release-architecture correction applied. PR #620 is the
planning-truth owner for `.planning/trajectory-5/**`; it is not a product
release, release package, or tag vehicle.

Trajectory 5 is an assurance and integration program. The corrected execution
order is:

1. **Lane B integration first**: make the spec hot path real in source.
2. **Lane A assurance addendum second**: attach mutation, threat, Kani, TLA+,
   and Lean evidence to the integrated source state.
3. **Lane C canary demo after Lane B**: prove composition only after the Lane B
   enforcement stack exists on merged source.
4. **#618 packaging last**: regenerate any bounded chiodome package from
   merged `main`, not from the current open PR set.

The prior "one ship-bar visible from outside" language is superseded. The live
contract is the claim-by-claim assurance matrix in `SHIP-BAR-TRACKER.md`.

## What PR #620 Owns

PR #620 owns planning control data:

- `.planning/trajectory-5/**`
- release architecture and merge-topology records
- assurance matrix wording
- planning preflight script registration
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
| A | Lane A assurance addendum | Mutation, threat, Kani, TLA+, and Lean evidence. | Attaches after source ownership is clean; partial rows stay partial. |
| C | Lane C canary demo | Bounded chiodome end-to-end composition fixture. | Canary only; downstream of Lane B. |

The assurance gate is `scripts/check-bounded-ship-bar.sh`. The filename is kept
for compatibility, but the script validates the matrix above, not a release
claim.

## Release-Key Namespace

Do not add release-state or tag-state keys under `[trajectory_5]`.

`[trajectory_5]` is planning metadata only. The bounded chiodome package status
is:

```toml
[v0_1_0_bounded_chiodome]
release_status = "blocked_pending_lane_b_integration"
```

This status does not authorize a product release. It records whether the
bounded canary evidence is complete enough for a human release owner to decide
whether #618 can be regenerated from merged `main`.

## Gate Semantics

`scripts/bounded-release-preflight.sh` checks planning consistency and the release-key
namespace contract. It does not depend on `tickets.md`.

`scripts/check-bounded-ship-bar.sh` checks evidence artifacts only:

- `audits/evidence/mutants/banner.json`
- `audits/evidence/mutants/<crate>/*.json`
- `audits/evidence/threats/*.json`
- Lane B negative conformance fixtures under `crates/chio-conformance/tests/`
- `scripts/check-anchor-batch-async-witness.sh`
- Lane C canary fixtures under `examples/chiodome-bilateral/`
- `[v0_1_0_bounded_chiodome].release_status` and `integrated_merge_sha`

Planning docs can track tickets. Executable gates cannot pass or fail because a
ticket file exists.

## Document Layout

| File | Purpose |
|---|---|
| `R4-MERGE-TOPOLOGY.md` | Current merge topology and replacement strategy. |
| `SHIP-BAR-TRACKER.md` | Claim-by-claim assurance matrix. |
| `EXECUTION-BOARD.md` | Planning board; not an executable release gate. |
| `SCOPE-LOCK.md` | In-scope and deferred work catalog. |
| `TIMELINE.md` | Corrected sequencing: Lane B first, Lane A addendum, Lane C canary. |
| `KICKOFF-CHECKLIST.md` | Planning checklist; not a release claim. |
| `OWNERS.toml` | Owner-class and coordination metadata. |
| `READINESS.md` | Historical readiness summary plus corrected release-truth note. |
| `CLOSEOUT.md` | Historical closeout map and integration debt. |
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

## R6 Closure

This pass closes R6-P0-001, R6-P0-003, R6-P0-004, R6-P1-005,
R6-P2-001, R6-P2-002, R6-P2-003, R6-P2-007, and R6-P2-009 for PR #620.
