# Chio specification registries

This directory holds the three canonical registries the trajectory-4 Evidence Gate references. Every T1.x slice that introduces a signed artifact, a verifiable claim, or a theorem must update the relevant registry before its Evidence Gate ticket closes.

## Files

| File | Owner | What it lists |
|---|---|---|
| `claim-registry.v1.json` | Protocol eng | Every verifiable claim a Chio kernel can make on behalf of a tenant (including the schema ID, claim shape, and the artifact that carries it). |
| `proof-manifest.v1.json` | Protocol eng | The mapping from each claim in the claim registry to the evidence that backs it (Lean theorem ID, Kani harness, Apalache module, conformance test, or signed assertion). |
| `theorem-inventory.v1.json` | Formal-methods eng | The catalog of formal theorems (Lean / TLA+ / Kani / hand-proof) including their statement, dependencies, and current status. |

## How they relate

```
threat / claim ----> claim-registry ----> proof-manifest ----> theorem-inventory
                     (what we say)        (what backs it)       (what is proved)
```

A trj4 slice closes when:
- The new artifact (or behavior) is registered in `claim-registry.v1.json`.
- A `proof-manifest.v1.json` row ties the claim to one or more entries in `theorem-inventory.v1.json` and / or named conformance tests.
- The referenced theorem entries are status `proven` (or explicitly status `assumed` with a deferral target).

## Status conventions

`claim-registry.v1.json[*].status`:
- `proposed` - claim defined but not yet implemented.
- `enforced` - kernel emits the claim and verifiers can check it.
- `deprecated` - kept for v1 compatibility; new code uses successor.

`theorem-inventory.v1.json[*].status`:
- `proposed` - theorem statement drafted; proof in progress.
- `proven` - proof script accepted by the listed checker (lean / apalache / kani).
- `assumed` - axiom or unproved assumption with `deferral_target` pointing at a tracking ticket.

## Bootstrap status (trj4)

These three files are **bootstrapped** by `TRJ4-000` (see `.planning/trajectory-4/EXECUTION-BOARD.md`) before any Tier 1 slice begins. They start with the existing claims and theorems that trajectories 1-3 implicitly relied on; trj4 slices add new rows.
