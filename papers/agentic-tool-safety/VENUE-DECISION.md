# Venue Decision: Tool Calls as Reversible-Action Admission

## Workshop pick

**Primary target: a NeurIPS 2026 AI-safety workshop.** The specific workshop will be one of the safety / Safe-GenAI / Safe-ML / Agentic-Safety workshops accepted in the NeurIPS 2026 workshop track. The exact workshop list is finalised after the workshop proposal deadline (June 6, 2026 AoE), with workshop acceptance notification on July 11, 2026.

## Deadline (verified from web)

- **NeurIPS 2026 workshop proposal deadline:** June 6, 2026 AoE (organisers, not authors).
- **NeurIPS 2026 workshop acceptance notification (to organisers):** July 11, 2026 AoE.
- **NeurIPS 2026 suggested workshop paper submission:** August 29, 2026 AoE (authors).
- **NeurIPS 2026 workshop notification:** September 29, 2026 AoE.
- **Workshop dates:** December 11-12, 2026, San Diego.

Today is May 18, 2026. The workshop list is not yet published; the suggested author deadline is about 14 weeks out. That is a realistic window for the polish-to-submit path.

Source: `https://neurips.cc/Conferences/2026/Dates`.

## Page-budget fit

- **Workshop convention:** Typical NeurIPS workshops accept 4-8 page short papers (varies by workshop; the recurring Safe Generative AI workshop at NeurIPS 2024 was 4-8 pages excluding references).
- **Current polished draft (article 11pt template):** 11 pages including references. The NeurIPS workshop template (`neurips_2024.sty`, expected to track to `neurips_2026.sty`) is 10pt with tighter geometry; the same body text compresses to roughly 6-7 pages. That sits comfortably inside a typical 4-8 page workshop limit.
- **Word count after polish:** 4896 (down from 6033, a 19% reduction). Distribution across nine sections is approximately balanced (320-700 words per section).

## Why this venue over alternatives

| Venue | Status | Decision |
|---|---|---|
| NeurIPS 2026 workshop track | Open; suggested author deadline Aug 29, 2026 | **Primary target** |
| ICML 2026 "Agents in the Wild" workshop | Author deadline May 8, 2026 AoE (extended once); already passed | Not actionable |
| ICML 2027 AI safety workshop | No CFP published | Not actionable in this cycle |
| CAIS 2026 (Copenhagen) | Abstract-only, July 1 deadline | Possible secondary submission but abstract-only and different track |
| AAAI 2026 / IEEE AI-SS 2026 | Lower fit on threat-model framing | Backup options |

NeurIPS workshops are also the natural audience: the alignment, scalable-oversight, and red-teaming research communities are concentrated there, and the paper's argument is in dialogue with that literature.

## Open items for the human

1. **Workshop name selection.** Wait for the NeurIPS 2026 workshop list (announced ~July 11, 2026) and choose which AI-safety workshop is the best fit. Likely targets: the Safe Generative AI workshop (if it recurs), an AgentAI / Agentic-Safety workshop, or a Trustworthy ML workshop. Choosing the specific workshop in advance is a guess; choosing the venue family (NeurIPS workshops) is not.

2. **Template swap.** The current paper uses a generic `article` 11pt template as a placeholder. Once the workshop is named, swap the preamble to the workshop's required template (almost certainly `neurips_2026.sty` with `\usepackage[final]{neurips_2026}` for camera-ready or the un-final variant for double-blind submission).

3. **Co-author decision.** The README's note about Ethan Perez as primary contact stands, but the paper as polished is publishable at workshop tier without a co-author. The co-author decision affects top-conference (NeurIPS main, ICML main) eligibility, not workshop acceptance. Decide whether to approach Perez (or Bowman, secondary) before or after workshop submission; the W5.b outreach memo handles the approach itself.

4. **Worked example expansion.** Section 5 currently contains two short worked examples (reversible-class branch delete, destructive-class cascading delete). If the chosen workshop has page budget to spare, consider expanding one example into a half-page traced admission walk-through (envelope construction, four admission operations, receipt emission). This is the highest-value addition if space permits and is the natural hook for a reviewer who wants concreteness.

5. **Substrate-citation strength.** The paper cites `programmableSovereignty2026` as `Submitted`. Strength of the substrate citation depends on whether the parent paper has landed by the time this workshop paper is submitted. If the parent is still in submission, this paper carries more of the structural weight; consider expanding the formal-grammar section by half a page with a minimal self-contained statement of the bounded-executive-action constructor.

6. **No experiments by design.** Reviewers may push for empirical evaluation. The polished draft holds the position-paper-with-formal-grounding line in §1 and §8. If a reviewer's experimental ask is severe, the response is the companion substrate's EDR corpus evaluation, not new experiments in this paper.

## Confirmation of constraints

- No em-dash characters in the paper body (verified by grep).
- No banned engineering-meta phrases in the paper body (verified by grep across the full banned-phrase list).
- 4-pass build (`pdflatex` then `bibtex` then `pdflatex` then `pdflatex`) is clean: zero errors, zero LaTeX warnings, zero BibTeX warnings (after one `@inproceedings` to `@misc` fix for the debate citation), zero undefined references, zero overfull/underfull boxes.
