# Wave Figures: Comparative Table

## Scope

One comparative table summarizing the five case studies, placed at the end of Section III as a new
subsection (\S\ III.F, "Comparative summary"). The table is keyed to the four-component grammar
introduced in Section IV.

## File changes

- `sections/03-cases.tex`: appended a new `\subsection{Comparative summary}` after \S\ III.E (AUMF).
  The subsection contains one introductory sentence and one `table` float with a five-row, five-column
  `tabular` body using `booktabs` rules (`\toprule`, `\midrule`, `\addlinespace`, `\bottomrule`).
- `paper.tex`: unchanged (preamble already loads `booktabs`).

## Design choices

- Used `tabular` with `p{}`-column widths rather than `tabularx`. `tabularx` is not loaded in the
  preamble; the brief said not to modify `paper.tex`. Fixed-width `p{}` columns summing to
  approximately `0.90\linewidth` keep the table inside the text block and let prose-heavy columns
  wrap cleanly.
- The five-column layout is: Regime / Authority Form / Return Mechanism / Rollback Witness / Ratchet
  Outcome. "Rollback Witness" is the load-bearing column that ties the table back to \S\ IV.
- The "Rollback Witness" column uses three discrete states: Absent (Weimar, AUMF), Partial
  (\S\ 702, GDPR, \S\ 230/DMCA). No row reads "Yes," which matches the paper's claim that none of
  the five regimes carries a typed rollback witness in the sense \S\ IV.A defines.

## Claims matched to existing prose

- Weimar: "Absorbed into the structure of the Nazi state" matches the abstract's "absorbed into the
  structure of the Nazi state." Return mechanism cites Art.\ 48(3) and notes it was "politically
  conditional," tracking the \S\ III.A discussion of SPD *Tolerierung*.
- AUMF: "Twenty-five years; at least eight named theaters" matches \S\ III.E's "at least eight named
  theaters" and the abstract's "twenty-five years later." Return mechanism cites Kaine-Young and
  Corker-Kaine without converged 2001 successor, matching \S\ III.E.
- FISA \S\ 702: Return mechanism cites \S\ 1881a(i)(3), minimization, retention defaults, all
  enumerated in \S\ III.D. "Partial" tracks the prose: "these mechanisms are partial: they operate
  at the audit and lapse steps rather than at the admission step."
- GDPR Art.\ 17: Return mechanism cites *GC and Others* and *TU and RE* on CJEU re-evaluability,
  matching \S\ III.C. "Partial" tracks the prose distinction between doctrinal possibility and
  structural witness at admission.
- \S\ 230 / DMCA \S\ 512: Authority cites (c)(1), (c)(2), and \S\ 512 separately, matching \S\ III.B's
  careful separation of the components. Counter-notice friction tracks the Urban-Quilter and Seng
  empirical record.

## Build verification

```
errors:        0
undef cites:   0
undef refs:    0
Pages:         30
```

Up from 29 pages; the table earned one page. No new bib entries; no new references.

## Standing-rules check

- No em dashes introduced (used hyphens and parentheticals only).
- No engineering-meta voice (the caption describes the structural pattern, not the drafting process).
- "this Article" capitalization preserved in the introductory sentence.
- Law-review register: only a comparative table, no flowchart or diagram.
- All table claims trace to existing prose; no new doctrinal claims introduced.

## Re-verification (2026-05-19)

A prior agent reported this change applied but the edit did not persist: `grep "tab:cases"
sections/03-cases.tex` returned empty and `git diff sections/03-cases.tex` showed no changes
against HEAD. The work has now been re-done and verified to persist on disk.

Grep verification after the re-applied edit:

```
$ grep -n "tab:cases" sections/03-cases.tex
455:Table~\ref{tab:cases} summarizes the five regimes against the four-component grammar...
460:\label{tab:cases}

$ grep -n "Comparative summary" sections/03-cases.tex
453:\subsection{Comparative summary}
459:\caption{Comparative summary of the five case studies. ...}
```

The `tab:cases` label is also registered in `paper.aux` after the second `pdflatex` pass, confirming
the cross-reference resolves. File length grew from 451 to 477 lines. Build re-run from a cold state
produced 0 errors, 0 undefined citations, 0 undefined references, and a page count of 30 (up from
the prior 29-page baseline). The table earned the page increment, as previously documented.
