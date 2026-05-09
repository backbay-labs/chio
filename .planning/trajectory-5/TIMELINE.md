# Trajectory 5 Corrected Timeline

Trajectory 5 no longer runs as a product-release train. The timeline is an
integration and assurance sequence.

## Required Order

```text
W1-W3   Lane B integration foundation
        B0 -> B1/B2/B3 -> B4

W3-W5   Lane A assurance addendum
        mutation, threat, Kani, TLA+, Lean evidence attaches to integrated source

W5-W7   Lane C canary demo
        rebase after Lane B, regenerate fixtures from merged main

W7+     #618 packaging review
        only after Lane B, Lane A assurance, and Lane C canary evidence are regenerated
```

Lane C is not allowed to drive the schedule ahead of Lane B. #618 is never
first, never a substitute for integration, and never regenerated from open PR
branches.

## Claim Milestones

| Milestone | Owner lane | Exit condition |
|---|---|---|
| B-integrated | Lane B | Four hot-path primitives integrated with negative conformance evidence. |
| A-assurance-attached | Lane A | Mutation/threat/formal evidence is re-evaluated against the integrated source state. |
| C-canary-ran | Lane C | Bounded chiodome canary runs after Lane B and produces pinned fixtures. |
| package-regenerated | #618 | Release notes and package metadata regenerated from merged `main`. |

## Slip Rules

- If Lane B slips, Lane A evidence can still be prepared, but it cannot become
  final assurance for the integrated source state.
- If Lane A slips, Lane B can merge, but the assurance matrix remains partial.
- If Lane C slips, no bounded chiodome canary claim is available.
- If #618 is not regenerated last, the package status remains blocked.

## Release Status

The bounded package status is recorded only in:

```toml
[v0_1_0_bounded_chiodome]
release_status = "blocked_pending_lane_b_integration"
```

The timeline does not authorize a tag. It tells the integrator which evidence
must exist before a human release owner can evaluate packaging.
