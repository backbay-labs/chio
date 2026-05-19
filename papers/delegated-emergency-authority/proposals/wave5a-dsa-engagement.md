# Wave 5A: DSA Article 16 engagement

Wave 3A identified the absence of any Digital Services Act engagement in §3.4 as a
first-impression flag a 2026 internet-law reviewer (Keller) would raise, and Wave 1C
identified the DSA Article 16 notice-and-action regime as supplying a partial
counterexample whose structured complaint-handling channel looks more like the
typed rollback the paper proposes than the paper acknowledged. Wave 5A closes that
gap with a single paragraph in §3.4 and one bib entry.

## (i) Paragraph added

The new paragraph (216 words by `wc -w` after stripping LaTeX commands, within the
150-220 target) reads:

> A more structurally proximate EU instrument is the Digital Services Act
> [cite TODO_dsa_2022], Regulation (EU) 2022/2065, whose principal obligations
> applied to hosting providers from 17 February 2024 and to designated Very Large
> Online Platforms and Search Engines from 25 August 2023. Article 16 installs a
> notice-and-action regime requiring providers to receive, to process in a timely
> and non-arbitrary manner, and to decide notices of allegedly illegal content;
> Article 17 attaches a statement-of-reasons obligation to any restriction imposed
> on recipients; Article 20 requires an internal complaint-handling system that
> must remain available for at least six months after the contested decision and
> that must operate electronically and free of charge; and Article 21 supplies
> certified out-of-court dispute settlement through bodies recognized by national
> Digital Services Coordinators. The conjunction of these provisions, and the
> six-month Article 20 complaint window in particular, comes structurally closer
> to what this Article calls a typed rollback witness than any regime examined
> above: a removal cannot, in the DSA's regime, be admitted without an
> accompanying procedural path by which it may be reversed. The DSA's existence
> strengthens the structural case advanced here. The European Union has
> demonstrated that the construction is buildable and operative in a regulated
> market, and the regime's confinement to intermediary content moderation
> illustrates the generalization gap this Article argues should be closed.

## (ii) Placement

The paragraph lands in §3.4 (GDPR Article 17) immediately after the
EDPB / Article 29 WP paragraph that closes the regulatory-guidance discussion and
immediately before the academic-literature footnote paragraph that opens with
"The data-protection academic literature has framed the right structurally
rather than transactionally." The placement is correct because (a) the DSA is
an EU regulatory instrument and sits in conversation with the EDPB and Article 29
WP guidance the prior paragraph treats; (b) the paragraph functions as the
regulatory bridge between the GDPR-specific regime and the broader structural
contention the §3.4 closing paragraph then carries; and (c) it is additive,
not displacing, so the existing §3.4 architecture survives intact. §3.2 was
considered as an alternative placement but rejected: the DSA's structural
proximity is to GDPR Article 17 (admission-time witness for content-affecting
orders) rather than to Section 230's incentive shadow or DMCA 512(g)'s
counter-notice mechanism.

## (iii) New bib entries

One entry added, `TODO_dsa_2022`, in the GDPR / EU data protection section
immediately after `TODO_mantelero_gdpr_enforcement`:

```
@misc{TODO_dsa_2022,
  author       = {{European Parliament and Council of the European Union}},
  title        = {{Regulation (EU) 2022/2065 of the European Parliament and of the Council of 19 October 2022 on a Single Market For Digital Services and amending Directive 2000/31/EC (Digital Services Act)}},
  howpublished = {Official Journal of the European Union, L 277/1 (27 October 2022)},
  year         = {2022},
  note         = {Article 16 (notice and action mechanisms); Article 17 (statement of reasons); Article 20 (internal complaint-handling system); Article 21 (out-of-court dispute settlement); Article 22 (trusted flaggers). Principal obligations applied from 17 February 2024 for hosting providers; from 25 August 2023 for designated Very Large Online Platforms and Very Large Online Search Engines},
}
```

A single consolidated key was used (the paragraph cites the DSA once with
`\cite{TODO_dsa_2022}`, and the note field enumerates the operative articles).
No separate per-article keys were needed.

## (iv) Build verification

Full `pdflatex / bibtex / pdflatex / pdflatex` cycle from the paper directory
returns:

- LaTeX errors: 0
- bib misses ("didn't find a database entry"): 0
- Undefined citations: 0
- Page count: 29 (was 28; one paragraph addition consistent with the
  expected delta)

The DSA paragraph compiles cleanly, the single new `\cite{TODO_dsa_2022}`
resolves against the new bib entry, and the paper retains its compile-clean
state heading into Wave 5B (Hart engagement) and Wave 5C (final adversarial
re-certification).
