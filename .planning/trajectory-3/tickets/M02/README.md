# M02: AI-Lab Evaluation Infrastructure Beachhead

**Wave:** W1  |  **Trust-boundary:** yes  |  **Tickets:** 28  |  **Effort weeks:** 6/9/13

## In one paragraph

M02 is the second customer-anchor milestone of trajectory-3: an AI-lab
evaluation team consumes Chio receipts as the verdict-evidence
substrate for their tool-use eval pipeline. The release-gate anchor
is PROTOCOL: a partner-signed conformance memo committed within 7
days of P5 close (D15 freshness rule). Implementation focuses on
partner-grade infrastructure - a new eval-report receipt format
spec at `spec/eval/receipt-format.v1.json` (schema
`chio.eval-report.bundle.v1`), a reference verifier at
`crates/chio-eval-receipt/`, a partner-pipeline-language integration
sample at `examples/eval-receipt-ingest/<partner-slug>/`, and a
1-page partner-signed conformance memo at
`.planning/trajectory-3/audits/M02-memo.md`. The cross-language
verdict-matrix driver promotion (Python and Go) is owned by M04 per
the `m02-m04-verdict-matrix-coupling` freeze; M02 reads the
verdict-matrix manifest read-only and embeds the corpus sha256
(`47e8d539...`) in bundle metadata.

## Phases at a glance

| Phase | One-liner | Tickets |
|-------|-----------|---------|
| P0 | Audit baseline + partner shortlist scoping + week-1 contract | 5 |
| P1 | Partner pick committed + week-1 deadline tickets | 4 |
| P2 | Evidence-export contract | 4 |
| P3 | Eval-report receipt format implementation (`chio.eval-report.bundle.v1`) | 5 |
| P4 | Partner integration spike + sample eval-report ingest | 4 |
| P5 | Partner-signed conformance memo received | 4 |

Total: 26 tickets (P0=5, P1=4, P2=4, P3=5, P4=4, P5=4). Wave-opener
is M02.P0.T5; wave-closer is M02.P5.T4.

## Locked decisions

- D10 design partner picked in week 1 from named shortlist
  (Anthropic evaluations team, METR, Apollo Research). Halt-trigger
  12 fires if all three decline by end of week 2.
- D15 customer evidence freshness 7-day window. Each customer
  evidence log row's date stamp must be no more than 7 days behind
  the merging ticket; CI enforces.

## Partner Contract

- Partner contracted: METR
- partner-slug: `metr`
- Contract date: 2026-05-02
- Acceptance surface: single eval-report bundle ingest, reference
  verifier review, partner technical reviewer through P2/P3, and P5
  conformance memo.
- Bench fallbacks: Apollo Research first fallback, Anthropic
  evaluations team second fallback if Halt 12 conditions require a
  substitution.

## Locked freezes

- `m02-m04-verdict-matrix-coupling`
  (`.planning/trajectory-3/freezes.yml`) overlaps on
  `crates/chio-conformance/verdict_matrix/`. Start trigger:
  M02.P2.T1 merge. End trigger: M02.P3.T5 merge. While the freeze
  is open, only M02 may write to that path. The freeze rationale in
  `freezes.yml` references Python/Go driver promotion; per the user
  prompt overriding the research draft, the driver promotion is
  owned by M04. The freeze is retained because the verdict-matrix
  manifest is a shared read surface (M02) and write surface (M04).

## When this milestone is done

- Partner-signed conformance memo received and committed under
  `.planning/trajectory-3/audits/M02-memo.md` with detached cosign
  signature `M02-memo.sig` (or PGP detached fallback).
- `spec/eval/receipt-format.v1.json` published; schema linter green
  on CI.
- `crates/chio-eval-receipt/` reference verifier merged; CLI
  `chio eval-receipt verify` round-trips green on the golden
  vector at `tests/bindings/vectors/eval/v1.json`.
- `examples/eval-receipt-ingest/<partner-slug>/` integration sample
  runs end-to-end; CI run URL recorded in the audit doc.
- Public partnership note (blog post or README entry) published;
  URL recorded in the audit doc.
- M04.P3 may open after the `m02-m04-verdict-matrix-coupling`
  freeze end-trigger fires.
