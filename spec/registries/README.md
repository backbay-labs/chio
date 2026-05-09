# Chio specification registries

This directory holds the three canonical registries used by verifier and
evidence tooling. Any change that introduces a signed artifact, a verifiable
claim, or a theorem must update the relevant registry before the claim is
advertised as supported.

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

A registry change is complete when:
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

## Bootstrap Status

These three files are bootstrapped as the v1 protocol registry set. They start
with the existing claims and theorems already relied on by verifier code, and
new protocol surfaces add rows as they become checkable.
