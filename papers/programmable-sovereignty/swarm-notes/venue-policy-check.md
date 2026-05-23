# NDSS 2026 / USENIX Security 2026 simultaneous-submission policy check

Per iter-7 fresh-hostile residue agent's flag: verify the two-paper plan (long paper + bilateral-receipt-admission short paper) does not trigger desk-reject under either venue's CFP.

## NDSS 2026

[Call for Papers](https://www.ndss-symposium.org/ndss2026/submissions/call-for-papers/)

> "Technical papers must not substantially overlap with papers that have been published or that are simultaneously submitted to a journal or a conference/workshop with proceedings."

**Implication**: the two-paper plan is at risk if both papers are submitted to NDSS. If the short paper goes to a workshop ahead of the long paper to NDSS, the long paper must clearly identify the short paper as prior work and quantify the non-overlap. NDSS additionally bars "major overlap between a rejected paper from the summer cycle and a submission to the fall cycle."

## USENIX Security 2026

[Call for Papers](https://www.usenix.org/conference/usenixsecurity26/call-for-papers)

> "Papers may cite simultaneously submitted papers, with these citations anonymized in the submission; non-anonymous versions must be emailed to program co-chairs. Failure to point out and explain overlap with published or simultaneously submitted papers will be grounds for rejection."

**Implication**: USENIX Security tolerates simultaneous submission with explicit anonymized citation and program-co-chair notification. This is the more permissive of the two venues for the two-paper plan.

Per-author cap: 7 papers per cycle.

## Decision

**The bilateral-receipt-admission short paper should target USENIX Security, NOT NDSS.** Three reasons:

1. USENIX Security's CFP explicitly accommodates simultaneous-submission with anonymized citation; NDSS forbids "substantial overlap."
2. The iter-3 strategic agent recommended HotSec / WOOT for the short paper first, ahead of the long paper. WOOT (Workshop on Offensive Technologies) is a USENIX workshop and inherits the more permissive policy.
3. Co-targeting NDSS for the long paper and USENIX Security (or WOOT) for the short paper keeps each venue happy as long as both citations are explicit.

## Recommended sequencing

1. **Walch pre-disclosure embargo on the long paper** (per [walch-invitation-draft.md](walch-invitation-draft.md)). 14 days.
2. **Long paper to arXiv** with all swarm-disclosed limitations integrated.
3. **Short paper to WOOT 2026 or HotSec 2026** (USENIX workshop track) once the short paper's §4 freestanding accept-set theorem is drafted (iter-3 comparator's salami-slice escape).
4. **Long paper to NDSS 2027** (Aug 2026 deadline) with the short paper cited as prior work and quantitatively delimited.
5. **Empirical-evaluation paper (#5 in iter-8 next-paper pipeline) to USENIX Security 2027 full** (Aug 2026 deadline) — alongside or after long paper v2 lands.

Do NOT submit both short paper and long paper to NDSS in the same cycle. Do NOT submit the short paper to NDSS at all.

## Status of the two-paper plan

The bilateral-receipt-admission short paper at `papers/bilateral-receipt-admission/` currently has:
- `paper.tex` skeleton
- `sections/01-introduction.tex` drafted
- `sections/02-receipt-admission-primitive.tex` drafted
- `sections/03` through `sections/09` stubbed

Iter-3 comparator's verdict (B: Conditional split) requires drafting §4 with a freestanding accept-set theorem before submission. Iter-3 strategic wants it shipped FIRST (6 weeks ahead of long paper). Both demand short-paper work; the v2 substantive lift on the long paper can happen in parallel.

Short-paper §4 drafting is recorded as outstanding work in the v2 MINOR tier.
