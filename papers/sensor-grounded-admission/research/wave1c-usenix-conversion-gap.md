# Wave 1C: USENIX template conversion gap analysis

The execution-complete memo, dated 2026-05-18, listed "Conference-template conversion (2-3 days)" as remaining human action. That memo predates the USENIX shell and SUBMISSION-CHECKLIST.md verification pass committed later the same day. The audit below shows the conversion is already done: `paper-usenix.tex` is a near-complete USENIX Security shell that builds clean to 12 pages with the body inside the venue body limit.

## 1. State of paper-usenix.tex

The shell is a near-complete USENIX Security build, not a stub. Its preamble:

- `\documentclass[letterpaper,twocolumn,10pt]{article}` (USENIX two-column 10pt).
- `\usepackage{usenix2019_v3}` (loads the venue style file bundled in the directory).
- Section inputs are byte-identical to `paper.tex`: `\input{sections/01-introduction}` through `\input{sections/10-conclusion}` in the same order. `diff` on the `\input` lines is empty.
- Author block: `\author{ {\rm Anonymous Author(s)}\\ Anonymous Institution }`, with a comment block explicitly declaring "Double-blind submission: anonymous author block per USENIX Security 2027 double-blind policy." The style file does not define a `[anonymous]` option; USENIX double-blind is handled by anonymizing the author string itself, which this shell does.

The abstract is duplicated byte-for-byte from `paper.tex` rather than `\input`'d (a minor maintenance redundancy, not a gap).

## 2. Does paper-usenix.tex build cleanly?

Yes. Four-pass `pdflatex / bibtex / pdflatex / pdflatex` finishes with exit 0 on every pass. `grep -c '^!' /tmp/sga_u3.log` returns 0 (no fatal errors). Zero undefined citations, zero undefined cross-references, zero overfull hboxes, zero BibTeX warnings in `paper-usenix.blg` (34 entries cited, all resolved). The log carries 26 underfull-hbox messages, the expected two-column line-break aesthetics, not errors. The only `Warning` lines in the log are `breakurl` (notes pdflatex mode, harmless) and a microtype non-French-spacing notice (cosmetic).

## 3. Page-count delta

- `paper.pdf` (article-class 11pt 1in): 18 pages.
- `paper-usenix.pdf` (USENIX two-column 10pt): 12 pages total, 10 body, references begin page 11. This is recorded in SUBMISSION-CHECKLIST.md as the verified `check-pages` result and the audit reproduces it (`pdfinfo` reports 12 pages, 204852 bytes).

USENIX Security 2027 limits the body to 13 pages (references and appendices excluded). The 10-page body has 3 pages of headroom, which is the right margin for the still-undrafted Open Science and Ethics Considerations appendices noted in the checklist. The execution-complete memo's "conference template projection: ~12-13" was conservative; the actual conversion landed at 10 body / 12 total.

## 4. Macro compatibility

Both shells define the same author macros at file scope:

- `\codepath` and `\thm` are each defined as `\path{#1}` in `paper.tex` (lines 12-13) and in `paper-usenix.tex` (lines 25-26).
- `paper-usenix.tex` additionally `\providecommand{\Description}{}` as a no-op stand-in for acmart's `\Description` (defensive against future section edits).
- Both set `\Urlmuskip=0mu plus 1mu`. Only `paper.tex` sets `\emergencystretch=6em`; `paper-usenix.tex` does not need it because USENIX two-column line-breaking is governed by the style file. The audit found no macros used in `sections/*.tex` that are defined in one shell and not the other; the 18-to-12-page reflow lands without macro misses.

## 5. Bibliography handling

Both shells use `\bibliographystyle{plain}` and `\bibliography{bib}` (single shared `bib.bib`, 34 entries cited from a larger pool). Quoted from `paper.tex:39` and `paper-usenix.tex:62`: `\bibliographystyle{plain}`. USENIX Security accepts `plain` (the historical USENIX style); `acm` is not USENIX's house style. The shell is correctly set. BibTeX runs clean against `plain.bst`, 0 `Warning--` lines.

## 6. Anonymization state

Author block in `paper-usenix.tex`: `{\rm Anonymous Author(s)} \\ Anonymous Institution`. No `\thanks{}` content. No `\institution{}` or `\affiliation{}` calls (acmart-only macros, intentionally absent). No acknowledgements section in any `sections/*.tex`. No funding statement. The em-dash scan in SUBMISSION-CHECKLIST.md was performed across `paper-usenix.tex`, `paper.tex`, `sections/*.tex`, and `supplementary/*` and returned clean.

Self-citing references in `bib.bib`: one entry, `chioProgrammableSovereignty2027`, authored `{Chio Project}` (project name rather than personal name; double-blind-permissible by USENIX policy when self-citation is in third person, which it is in `sections/08-related-work.tex:23` and `sections/01-introduction.tex:6`). No GitHub URLs reveal personal handles; bib URLs point to institutional repos (secure-systems-lab/dsse, apple/security-pcc, aws/aws-nitro-enclaves-nsm-api, linux-audit).

Items that the checklist flagged for human review: the substrate identifier "Chio" appears in body prose at Section 1 and Section 8 and in the bib entry. The checklist notes this as "the natural author-identifying artifact under double-blind" and recommends the human confirm interpretation, but it is not a clear violation. No internal paths, branch names, GitHub handles, or wave/swarm/orchestrator terminology in the body.

## 7. Conversion-completion estimate vs reality

The execution-complete memo, written 2026-05-18 before the W4.a verification pass, estimated 2-3 days. The audit finds the conversion already landed: the shell exists, builds clean, sits inside the page limit, and the SUBMISSION-CHECKLIST records `[submit-check] VERDICT: PASS` against `paper-usenix`. The estimate was an overestimate against the as-found state; mechanical template-conversion work is done.

What actually remains is content-drafting work, not template-conversion work:
1. Open Science appendix (~1 page; material exists in `supplementary/README.md`, needs writing into a section file).
2. Ethics Considerations appendix (~1 page; mandatory per USENIX policy even for formal-substrate work; no draft exists in repo).
3. Human confirmation that citing `{Chio Project}` as parent paper and naming "Chio substrate" in body is the right reading of USENIX double-blind policy.
4. USENIX account registration and submission upload.

These are 1-3 days of writing, not template conversion. The "2-3 days for conversion" line in `execution-complete.md` is stale.

## 8. Submission-checklist alignment

SUBMISSION-CHECKLIST.md sections 1, 2, 4, 5, 6, 7 are all checked as VERIFIED. Section 3 (Anonymization) has one item marked NOTED for human review (the Chio identifier appearing in body and bib). Section 8 has the Open Science appendix marked NOT DONE. Section 9 (Ethics Considerations) has all three items marked NOT DONE. Of the four open items at the bottom of the checklist, items 1 and 2 are the ~1-page appendix drafts; item 3 is a policy-interpretation confirmation; item 4 is the actual submission upload. None of the open items is template-conversion work.

## Conversion-completion verdict

**Submission-ready** for the template-conversion deliverable narrowly defined. Build is clean (0 errors, 0 undefined refs, 0 BibTeX warnings). Page count is 12 total / 10 body, comfortably under the 13-page USENIX Security body limit. Macro definitions match between shells. Bibliography style is `plain`, USENIX-compatible. Author block is anonymized; no `\thanks`, no `\institution`, no acknowledgements section, no funding statement; the one parent-paper self-citation uses a project-name author rather than a personal name.

The paper is not yet submission-ready as a whole document because two ~1-page mandatory appendices (Open Science, Ethics Considerations) have not been drafted; but those are content tasks downstream of the template-conversion gate, not part of it. The execution-complete memo's "Conference-template conversion (2-3 days)" line is now stale: that work shipped in the W4.a verification pass dated 2026-05-18.
