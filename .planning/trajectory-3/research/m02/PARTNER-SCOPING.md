# M02 Partner Scoping

**Date:** 2026-05-02
**Decision input:** D10 named shortlist and `research/m02/RESEARCH.md`
**Goal:** contract one AI-lab partner by the end of week 1 and keep two
fallbacks warm through week 2.

## Candidate Summary

| Candidate | Fit | Cycle-time risk | Public-credit weight | Integration shape |
|-----------|-----|-----------------|----------------------|-------------------|
| Anthropic evaluations team | Highest public model-card visibility and Inspect-adjacent eval flow | High | Highest | Python helper plus Chio sidecar |
| METR | Fastest path to a narrow signed conformance memo and sandbox-side receipt export | Low | Medium | Hosted sidecar plus receipt-log export |
| Apollo Research | Strong reproducibility fit for deception and scheming eval reports | Medium | Medium | Python library import plus verifier |

## Recommendation

Recommendation: contract METR first for M02.P0 because the milestone
needs a week-1 signed scope and a week-6 to week-9 conformance memo,
not maximum public-brand weight. METR has the lowest estimated
cycle-time risk and the cleanest fit for a small eval-report bundle
ingest sample. Keep Apollo Research as the first fallback and Anthropic
evaluations as the high-public-credit fallback if their contract path
can fit the D10 schedule.

## Outreach Order

1. METR: ask for a single-bundle ingest review and one-page
   conformance memo.
2. Apollo Research: ask for a Python verifier import review and memo
   if METR cannot sign by the week-1 deadline.
3. Anthropic evaluations team: ask for Inspect-compatible feedback and
   public eval-card language, with an explicit contract-cycle caveat.

## Acceptance Criteria For Contract

- Partner agrees to review `chio.eval-report.bundle.v1` and the
  reference verifier.
- Partner commits to a P5 conformance memo or records a scoped caveat
  before the D15 freshness window.
- Partner supplies a named technical reviewer for P2/P3 feedback.
- Partner accepts METR, Apollo, or Anthropic identity disclosure in the
  M02 audit doc. If identity disclosure is not allowed, M02 cannot close.

