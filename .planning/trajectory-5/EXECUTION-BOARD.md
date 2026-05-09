# Trajectory 5 Execution Board

This board is planning metadata. It is not an executable release gate, release
readiness record, or tag authorization.

## Corrected Work Order

| Order | Lane | Work | Exit condition |
|---:|---|---|---|
| 1 | B | Source integration for B0/B1/B2/B3/B4. | Source branches merge cleanly and production-call-path conformance fixtures exist; B4 needs full DSSE PAE conformance, not only the interim signature-slice regression. |
| 2 | A | Assurance addendum. | Mutation, threat, Kani, TLA+, and Lean rows are regenerated or explicitly partial against the merged Lane B source state. |
| 3 | C | Canary demo. | `examples/chiodome-bilateral/` canary runs after Lane B and writes pinned fixtures. |
| 4 | #618 | Package regeneration. | Release notes, fixtures, and any `[v0_1_0_bounded_chiodome]` root metadata are regenerated from merged `main` by the package owner. |

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
| C1-C4 | Canary composition pieces: bilateral invocation, lease/bond, anchor, KB MCP wrap, and receipt explain. | Lane B integrated |
| C5 | Selective-disclosure research boundary. | Future work outside current closure; not a canary or release row. |
| C6 | Pinned canary fixtures and explain golden output. | C1-C4, merged `main` regeneration |

## Executable Gate Boundary

`tickets.md` files are not gate inputs. The executable assurance checker reads
only evidence artifacts, source fixtures, scripts, and release-status keys.

The current compatibility-named checker is:

```bash
bash scripts/check-bounded-ship-bar.sh
```

Use `--diagnostic` for an advisory snapshot while claims are partial.

C5 may still appear in legacy checker output until Worker A changes gate
behavior. That output is compatibility metadata only and does not make C5 a
current closure row.

## R6 Closure

Closed for PR #620: R6-P0-001, R6-P0-003, R6-P0-004, R6-P1-005,
R6-P2-001, R6-P2-002, R6-P2-003, R6-P2-007, R6-P2-009.
