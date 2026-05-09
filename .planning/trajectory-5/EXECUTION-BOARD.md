# Trajectory 5 Execution Board

This board is planning metadata. It is not an executable release gate.

## Corrected Work Order

| Order | Lane | Work | Exit condition |
|---:|---|---|---|
| 1 | B | Source integration for B0/B1/B2/B3/B4. | Source branches merge cleanly and four negative conformance fixtures exist. |
| 2 | A | Assurance addendum. | Mutation, threat, Kani, TLA+, and Lean rows are rerun or explicitly partial against the integrated source state. |
| 3 | C | Canary demo. | `examples/chiodome-bilateral/` canary runs after Lane B and writes pinned fixtures. |
| 4 | #618 | Package regeneration. | Release notes, fixtures, and `[v0_1_0_bounded_chiodome]` metadata are regenerated from merged `main`. |

## Lane B Source Integration

| Item | Summary | Depends on |
|---|---|---|
| B0 | `ToolServerConnection` async foundation and dispatch sync-hop collapse. | none |
| B1 | Single-entry capability verifier. | B0 |
| B2 | Receipt v2 fail-closed under negotiated v2. | B0, B1 preferred |
| B3 | Anchor-batch async-only when public witness is required. | B0 |
| B4 | DSSE-conformant bilateral signing. | B0, B1 preferred |

## Lane A Assurance Addendum

| Item | Summary | Depends on |
|---|---|---|
| A1 | Mutation evidence and banner artifact under `audits/evidence/mutants/**`. | Lane B source state for final evidence |
| A2 | Threat evidence under `audits/evidence/threats/**`. | Lane B source state for final evidence |
| A3 | Kani harness evidence. | Lane B source state for final evidence |
| A4 | TLA+ bounded rewrites. | Lane B source state for final evidence |
| A5 | Lean4 `negotiation_safety` re-proof. | Lane B source state for final evidence |

## Lane C Canary

| Item | Summary | Depends on |
|---|---|---|
| C1-C5 | Canary composition pieces: bilateral invocation, lease/bond, anchor, selective-disclosure placeholder, KB MCP wrap. | Lane B integrated |
| C6 | Pinned canary fixtures and explain golden output. | C1-C5, merged `main` regeneration |

## Executable Gate Boundary

`tickets.md` files are not gate inputs. The executable assurance checker reads
only evidence artifacts, source fixtures, scripts, and release-status keys.

The current checker is:

```bash
bash scripts/check-bounded-ship-bar.sh
```

Use `--diagnostic` for an advisory snapshot while claims are partial.

## R6 Closure

Closed for PR #620: R6-P0-001, R6-P0-003, R6-P0-004, R6-P1-005,
R6-P2-001, R6-P2-002, R6-P2-003, R6-P2-007, R6-P2-009.
