# Wave 4C: §4 reorder + §7 cross-ref + bib activation

Wave 4C applies the three structural fixes identified by Wave 3 (§4 lead, §4 line 60 DMCA-Section 230 compound, §7 redundancy with §2.1) and activates the bibliography by uncommenting `\bibliography{bib}` in `paper.tex`.

## 1. §4 reorder: legal gloss before displayed math

The §4 opening was rewritten so that two prose paragraphs of legal-doctrinal framing precede the displayed expression `a = (\text{act}, \TTL, w, q)`. The first paragraph names the four components in lay-legal terms (substantive action, duration, witness of recoverable prior state, quorum predicate) and identifies their correspondence to existing doctrinal categories (substantive action, sunset, reversibility, authorization procedure). The second paragraph establishes the structural-not-substantive framing and locates the quorum predicate against the Ackerman-Sunstein structural-correction proposals already developed in §2.2. A new third paragraph, "With that legal framing in place, the formal expression of the grammar can be stated compactly," now introduces the displayed math. The component-by-component walkthrough that follows is unchanged in substance.

Word delta: §4 grew from 1,375 to 1,619 words (+244, slightly over the 100-200 target). The growth is concentrated in the two new framing paragraphs and is judged acceptable given the redirection of §4's signal from systems-paper to legal-academy.

New opening prose paragraph, quoted: "The grammar this Article proposes formalizes a four-component requirement for any delegated emergency authority. At the moment an authority is exercised, the exercising actor must specify four things: the substantive action to be performed, a duration after which the authority lapses, a witness that the prior state remains constructively recoverable, and a predicate naming the actors whose concurrence is required to admit the action into the polity's history. The four components correspond to the doctrinal categories of substantive action, sunset, reversibility, and authorization procedure as those categories appear in existing constitutional and administrative law. The grammar's contribution is not the invention of any of the four categories, each of which has a long doctrinal pedigree. The contribution is the requirement that all four be present, simultaneously and at the moment of admission, as conditions of an exercise of authority that the legal order will recognize."

## 2. §4 line 60 DMCA-Section 230 compound noun

Replaced the compound "DMCA-Section 230 takedown regime" with "DMCA Section 512 notice-and-takedown regime, operating alongside Section 230's liability shield for platform self-regulation." Also sharpened the next sentence's reference from a bare "counter-notice procedure" to the specific "Section 512(g) counter-notice procedure." The walkthrough's structural mapping (`act` = removal, implicit `TTL`, witness absent, quorum is the platform) is preserved; only the doctrinal label is corrected to honor §3.2's post-Wave-2C separation.

Word delta on the affected paragraph: +14 (small net growth, no impact on §4 budget).

## 3. §7 Schmittian subsection: cross-reference plus implication-for-scope

The §7 Schmittian subsection's opening was rewritten so that it now cross-references §2.1's Schmittian-defensible passage instead of restating it: "Part~\ref{sec:pattern} acknowledged that for Schmitt the constitutive character of the sovereign decision is normatively defensible under conditions of genuine emergency, not merely descriptive of how legal orders are seen to fail, and that the structural argument this Article advances is incompatible with that normative view rather than orthogonal to it. This Part considers the implication for the Article's scope." The remainder of the subsection now treats the substantive implication: that the Article's argument does not bind a reader holding the strong Schmittian view, that the addressed readership is the constitutional-law academy in its mainstream post-Weimar formation, and that this scope-concession is offered as candor rather than evasion.

Word delta: the §7 Schmittian subsection went from approximately 360 words to 309 words (~ -50 words, within the 50-150 target). The total §7 word count moved from 1,426 to 1,417 because additional clauses were folded into the implication-for-scope analysis where the old text had repeated the wrapper-content distinction already developed in §4.

## 4. bib.bib activation

`paper.tex` lines 97-98 previously read:

```
% Bibliography file deferred until placeholders in legal-references.md are resolved.
% \bibliography{bib}
```

Both lines were replaced with:

```
\bibliography{bib}
```

The deferral comment was removed since the deferral is over.

## Build verification

Pipeline: `pdflatex -> bibtex -> pdflatex -> pdflatex`, all from the paper directory.

- pdflatex pass 1 (pre-bbl): 0 LaTeX errors.
- bibtex: exit 0; **0 "didn't find a database entry" warnings**; all 66 citation keys resolved against `bib.bib`'s 72 entries.
- pdflatex pass 4 (final): 0 undefined-citation warnings; **13 LaTeX errors emitted by the `\plain` bibstyle's rendering of three bib entries whose `note` fields contain unescaped `TODO_` references (underscores entering math mode)**.
- PDF output: 28 pages (up from 27 pre-activation; the bibliography renders but with malformed entries for the three notes containing `TODO_`-style cross-references).

The bibtex stage is clean. The pdflatex error is an out-of-scope finding in `bib.bib` at:

- entry `TODO_jacobson_schlink_weimar` (~line 183), `note = {Same volume as TODO_jacobson_weimar_pdf; ...}`
- entry `TODO_dmca_512g_counter_notice` (~line 225), `note = {Same provision as TODO_dmca_512g; ...}`
- entry `TODO_fisc_702_opinions` (~line 445), `note = {Aggregate citation; specific opinions enumerated separately under TODO_fisc_bates_2011_upstream, TODO_fisc_collyer_2017_about, TODO_fisc_boasberg_2018, TODO_fisc_contreras_2022}`

Each underscored TODO_ token in a printed note field triggers `Missing }` / `Extra }` cascades when LaTeX renders the bibliography in text mode. Wave 3C's synthetic `bibtex dea_test.aux` invocation did not exercise pdflatex rendering, which is why this was not caught at construction time.

Recommended next-wave action (Wave 4D or rolled into Wave 5 cleanup): rewrite the three `note` fields to drop the bib-internal cross-references or to wrap the TODO keys in `\texttt{...}` (which protects underscores). This is a 3-line surgical change in `bib.bib` outside Wave 4C's permitted file scope. With that change applied, the build should produce a clean 28-page PDF with no LaTeX errors. All citation resolution is already correct; only the bibliography's display of three notes is malformed.

## Summary metrics

- Files touched: 3 (`sections/04-grammar.tex`, `sections/07-limits.tex`, `paper.tex` lines 96-98 only).
- Em-dash count introduced: 0 (verified by `grep -P "\xe2\x80\x94"`).
- LaTeX errors in final pass: 13 (all in bibliography rendering, traced to three `note` fields in `bib.bib`; outside Wave 4C scope).
- BibTeX missing-database warnings: 0.
- Undefined-citation warnings in final pass: 0.
- PDF page count: 28.
