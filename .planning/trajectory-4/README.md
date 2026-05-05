> **SUPERSEDED**: this document's closeout claim is retracted by [TRAJECTORY-4-CLOSEOUT-ERRATUM.md](./TRAJECTORY-4-CLOSEOUT-ERRATUM.md). The trj4 release is reopened pending the wave-based closeout in /Users/connor/.claude/plans/typed-coalescing-hejlsberg.md.

# Trajectory-4 Planning

Working drafts for trajectory-4. **Not normative** until scope-lock and the audit docs in `audits/` are signed off.

## Doc layout

| File | Purpose |
|---|---|
| `SYNTHESIS-V2-INTEGRATED-PLAN.md` | **Active plan**. Four-tier scope (T0/T1/T2/T3), reviewer-recommended scope-lock, 30-condition close bar. Six review passes. Execution evidence is summarized in `TRAJECTORY-4-FINAL.md`. |
| `EXECUTION-BOARD.md` | Master ticket list (~95 tickets) organized by lane and tier; close-bar mapping; per-ticket dependencies and effort. |
| `audits/T*.md` | Per-milestone audit-doc skeletons. The unit of close per milestone; accumulates evidence and signs off when referenced tickets are merged. |
| `BRAINSTORM-V1-FEATURE-CATALOG.md` | Comprehensive catalog of every proposal from the 9-lens brainstorm. ~126 distinct items with effort and impact. |
| `REJECTED-IDEAS.md` | Every idea raised and rejected, with rationale. |
| `SYNTHESIS-V1-INTERNAL-ONLY.md` | Original substrate-hardening floor distilled from the 5-perspective scope debate. Superseded by v2 but retained as the perspective-debate record. |

## Audit docs

| Audit | Tickets covered | Status |
|---|---|---|
| `audits/T0.A-substrate-closeout.md` | TRJ4-001..006 | reopened (per CLOSEOUT-ERRATUM.md; Wave 0) |
| `audits/T0.B-substrate-hardening.md` | TRJ4-010..024 | reopened (per CLOSEOUT-ERRATUM.md; Wave 2/3) |
| `audits/T0.C-mobile-attestation.md` | TRJ4-030..033 | reopened (per CLOSEOUT-ERRATUM.md; Wave 6) |
| `audits/T0.D-threat-coverage.md` | TRJ4-040..049 | reopened (per CLOSEOUT-ERRATUM.md; Wave 0/4) |
| `audits/T1.0-capability-negotiation.md` | TRJ4-100..104 + T1.0.E | reopened (per CLOSEOUT-ERRATUM.md; Wave 1/2) |
| `audits/T1.1-macaroon-attenuation.md` | TRJ4-110..118 + T1.1.E | reopened (per CLOSEOUT-ERRATUM.md; Wave 1) |
| `audits/T1.2-receipt-dag.md` | TRJ4-120..131 + T1.2.E | reopened (per CLOSEOUT-ERRATUM.md; Wave 2) |
| `audits/T1.3-anchor-batch.md` | TRJ4-140..147 + T1.3.E | reopened (per CLOSEOUT-ERRATUM.md; Wave 2) |
| `audits/T1.4-archaeology.md` | TRJ4-150..160 | reopened (per CLOSEOUT-ERRATUM.md; Wave 0/4) |
| `audits/T1.5-sre-foundations.md` | TRJ4-170..178 | reopened (per CLOSEOUT-ERRATUM.md; Wave 14) |
| `audits/T1.6-chio-explain.md` | TRJ4-180..183 | reopened (per CLOSEOUT-ERRATUM.md; recheck under wave plan) |
| `audits/T2.1-hybrid-pq-cross-surface.md` | TRJ4-200..207 + T2.1.E | reopened (per CLOSEOUT-ERRATUM.md; Wave 5) |

Stretch audits added when scoped: `T2.2-hot-path.md`, `T2.3-trust-graph.md`, plus per-T3 picks.

## Reading order

For a fast scan: `SYNTHESIS-V2-INTEGRATED-PLAN.md` then `EXECUTION-BOARD.md`.

For deep context: read v1, then the catalog, then v2, then the per-milestone audit corresponding to the slice you're working on.

For implementers picking up a ticket: open the relevant `audits/T*.md` first; it lists the close bar for the ticket's parent slice plus the Evidence Gate items.

## Status

Reopened - see `TRAJECTORY-4-CLOSEOUT-ERRATUM.md` and the wave plan at `/Users/connor/.claude/plans/typed-coalescing-hejlsberg.md`. The earlier "six review passes complete; T0..T2.1 landed through the integrated trj4 PR set" claim is retracted; `TRAJECTORY-4-FINAL.md` is preserved for provenance under a SUPERSEDED banner.

## Recommended scope-lock (round-3 narrowed, round-6 stable)

- **Tier 0** (full floor): 8-10 wk
- **T1.0** (capability negotiation + token versioning): ~1.5 wk
- **T1.1** (macaroon attenuation + new witness API): ~3 wk
- **T1.2** (receipt DAG + receipt-id migration to `body_hash`): ~3 wk
- **T1.3** (anchor-batch Merkle trees, additive, full Evidence Gate): ~2 wk
- **T1.4** (archaeology finish-line + cargo-vet debt): ~2 wk
- **T1.5** (foundational SRE; **mandatory**): ~3 wk
- **T1.6** (`chio explain` CLI): ~1 wk
- **T2.1** (hybrid PQ end-to-end + cross-surface conformance)

Stretch: T2.2 hot-path verdict cache + Tower load-shed; T2.3 trust-graph maturity; 1-2 T3 picks max.

Total: **14-18 weeks two-lane parallel** / **20-24 weeks single-track**. Optional split into trj4a (closeout, 8-10 wk) + trj4b (primitives, 6-8 wk).

## Follow-up

1. Keep `TRAJECTORY-4-FINAL.md` current with post-review fixes and any slipped stretch items.
2. Use `EXECUTION-BOARD.md` only as the dependency-ordered historical ticket board; close state lives in the audit docs.
3. Treat T2.2, T2.3, and T3 picks as trajectory-5 candidates unless explicitly rescoped.
