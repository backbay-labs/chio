# Trj5 Closeout

This directory holds the per-wave closeout artifacts for trajectory 5 execution.
Closeout means accepted planning/integration map or assurance matrix only. It
does not mean release readiness, tag authorization, or completion of future
research rows such as C5 selective disclosure.

**Convention**: each wave produces a `wave-NN-summary.md` recording what landed, what slipped, and which findings transitioned in the close-bar tracker. The summaries are filled during execution; they are not pre-authored.

## Expected files (filled during execution)

- `wave-01-summary.md` -- Wave 1 (W1) summary (kickoff -> end of week 2). Records B0 progress, A1.0/A1.1/A1.2 baseline mutation runs, A2.0 threat triage start, A4.0 Apalache feasibility spike start.
- `wave-02-summary.md` -- W2 summary. Records A1/A4 work continuing, B0 close (ToolServerConnection async migration), B1/B2/B3 unblock, A3 Kani feasibility spike close.
- `wave-03-summary.md` -- W3 summary. Records B1/B2/B3 mid-flight, Lane C scaffolding (C1.1/C1.2/C1.4) starting, B4 wire-format design (B4.1) landing.
- `wave-04-summary.md` -- W4 summary. Records B1.6/B2.5/B3.5 negative conformance fixtures, B4.2/B4.3 module landing.
- `wave-05-summary.md` -- W5 summary. Records Lane C C2 starting against B4 envelopes, C3 KB-MCP wiring start.
- `wave-06-summary.md` -- W6 summary. Records B4 close (B4.5/B4.6/B4.E), Lane B `.E` Evidence Gate tickets close.
- `wave-07-summary.md` -- W7 summary. Records Lane C C2.E close, C4 canary work, A2 / A3 / A5 closing, and C5 remaining future work outside closure unless a later protocol-owned branch supplies real proof evidence.
- `wave-08-summary.md` -- W8 summary (integration / assurance-matrix verification week). Records assurance claims verified or partial; no release close ceremony is implied.

The wave numbering above is the canonical execution-week numbering per `TIMELINE.md`. If a wave slips, the corresponding `wave-NN-summary.md` records the slip and the recovery plan.

## Assurance tracker

The legacy tracker language is replaced by the assurance matrix. Until kickoff,
the live closeout truth is the per-lane planning docs files (Lane A / B / C),
`../SHIP-BAR-TRACKER.md` as a legacy-named assurance matrix, and the review
closure logs. Future work rows do not block current planning/matrix closure.

## Pointers

- Synthesis (the contract): `../debate/00-SYNTHESIS.md`
- Wave 4 closeout matrix: `../reviews/W4-closeout-matrix.md`
- Readiness summary: `../READINESS.md`
- Kickoff checklist: `../KICKOFF-CHECKLIST.md`
