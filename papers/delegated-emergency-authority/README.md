# Delegated Emergency Authority as Bounded Executive Action

LaTeX project for `Delegated Emergency Authority as Bounded Executive Action: A Formal Grammar for Time-Limited Constitutional Amendments`. Build with `pdflatex paper.tex && bibtex paper && pdflatex paper.tex && pdflatex paper.tex` from this directory. Text is intended for CC-BY-4.0 review circulation.

## Audience

Primary: legal-academy readers in constitutional law, comparative-government theory, and administrative-law-of-emergencies. Secondary: cross-disciplinary law-and-technology readers comfortable with type theory or formal-methods literature at the level of a careful citation rather than line-by-line proof reading.

## Venue

Primary target: Yale Law Journal, Stanford Law Review Online, or Harvard Journal of Law and Technology. The law-journal cadence (longer abstract, footnote-heavy prose, fewer numbered sections, hedged claims) is the target voice.

Secondary target: a Lawfare longread, ICAIL, or AI and Law's emergency-powers track. The cross-disciplinary venues will accept a tighter version; the law-journal version is the longer ambition.

## What this paper contributes

A claim about constitutional law that uses a formal-methods substrate as its anchor rather than as its subject. The argument is:

1. Delegated emergency authority across five disparate legal regimes shares a structural pattern: an authority intended as time-bounded ratchets to permanent authority because nothing in the original statute mathematically prevented the ratchet.
2. The structural defect has a name and a corrective grammar. Bounded executive action with a typed rollback witness and a time-to-live (TTL) constructible-at-admission would have prevented each ratchet by construction rather than by political will.
3. The Lean substrate developed in the parent paper (cited, not re-derived) supplies the construction. The contribution here is the application to constitutional doctrine, not the proof machinery.
4. One implementation exhibits the grammar in practice. The implementation is one paragraph in Section 6, not the focus of the paper.

## What this paper is not

It is not a defense of any particular emergency authority. It is not an argument that Section 230, the AUMF, FISA Section 702, GDPR Article 17, or Article 48 of Weimar should be retained, expanded, or repealed on substantive grounds. It is a structural argument about the form authority takes, not the content of any individual authority.

It is also not a positivist claim that emergency-powers doctrine reduces to a type system. The paper explicitly engages the Schmitt-Agamben tradition and acknowledges that the political content of the exception cannot be reduced to a constructor. The grammar formalizes the wrapper, not the content.

## Relationship to the parent paper

The parent paper (`programmable-sovereignty/`) constructs the formal substrate and is scoped to Hart's condition (a): a machine-checkable criterion for which receipts count as part of the polity's history. That paper notes in its discussion section that conditions (b) and (c) -- settled practice and internal acceptance -- are sociological and out of scope.

This paper engages conditions (b) and (c) directly. Emergency authority is a sociological pattern as much as a doctrinal one. The ratcheting failure mode is documented in two thousand years of constitutional history. The structural correction is the same one the parent paper gives for amendment refinement, applied at the executive boundary rather than the legislative boundary.

This paper cites the parent for the substrate and does not re-prove its theorems.

## Status

This section flags every place the paper risks being read as cross-disciplinary overreach so a co-author or reviewer can correct early.

### Genuine contribution vs. CS overreach

The paper genuinely contributes:

- A unifying name for a pattern legal scholars have written about case by case for decades but have not given a structural account of. The Schmitt-Agamben tradition supplies the diagnostic; the substrate supplies a corrective grammar.
- A test that the corrective grammar would have prevented specific historical ratchets. The test is most defensible for Article 48 of Weimar, where the historical trajectory from emergency decree to dictatorship is well-documented and the formal grammar is a clean fit. The test is contested for Section 230 (where the takedown regime is not strictly an emergency power) and most political for the AUMF (where the politics of military authorization dominate the formal question).
- An application of typed rollback witnesses to a domain where they are not currently the operative metaphor. Legal scholars discuss sunset clauses, but sunset clauses are not the same as TTL-plus-typed-rollback. A sunset can expire without anyone being obligated to roll back the state the authority created; the typed-rollback discipline requires the rollback path to exist at construction.

The paper risks being read as CS overreach in:

- Section 4's grammar: a legal-academy reviewer will ask whether the grammar adds anything beyond what a careful drafter could write into a statute. The honest answer is that the grammar makes a class of authority unconstructible (in the well-typed sense) rather than only forbidden, which is a structural distinction not a substantive one. A skeptical reviewer may still read the contribution as semantic relabeling.
- Section 3's case studies: each case study is in tension with the framing. Weimar Article 48 is the cleanest. Section 230 is debatable as an emergency power at all. AUMF is genuinely an emergency power but the politics are intractable. GDPR Article 17 erasure is a takedown regime more than an emergency power. FISA 702 is the most opaque on the public record. A reviewer who specializes in any one of these will know more than the paper does, and that asymmetry is dangerous.
- Section 6's implementation: the implementation is one instance and is not the load-bearing claim. The temptation to expand the implementation into a centerpiece must be resisted. Legal reviewers do not want a systems paper.

### Legal claims that need vetting

The following claims should be vetted by a constitutional-law scholar before submission:

1. The characterization of Weimar Article 48 as the canonical ratcheting failure. The historiography is contested (Kershaw vs. Mommsen vs. Caldwell on whether the ratchet was structural or political). The paper should hedge.
2. The characterization of Section 230 as bearing structural similarity to an emergency-takedown regime. Section 230 scholars (Citron, Goldman, Keller) have argued the contrary and the contrary is defensible.
3. The claim that the AUMF's 25-year continuation is a structural-grammar failure rather than a political failure. This is the most aggressive claim in the paper and must be hedged.
4. The handling of FISA 702 emergency authorizations. The public record is incomplete; the paper relies on declassified opinions and the PCLOB reports. A national-security-law scholar should review.
5. The handling of GDPR Article 17 erasure orders. EU data-protection scholars (Mantelero, Kuner) have written on the erasure-without-rollback failure mode and should be cited and engaged.
6. The Schmitt-Agamben framing in Section 2. The paper takes Agamben's side on the question of whether the exception became permanent. A Schmittian or a Schmittian-sympathetic reviewer (which is rare in mainstream American legal academia but common in continental theory) will push back. The paper should acknowledge this.

### Timeline to publishable polish

Realistic estimate: 12 to 18 months from current draft to law-review submission. The drafting work is the smallest fraction. The vetting work, citation hardening, and legal-scholar co-author engagement are the bulk of the timeline.

- Months 1-3: legal-scholar co-author identified and engaged, draft circulated, first round of historical claims vetted.
- Months 4-6: case studies rewritten with primary-source citation hardening. Schmitt-Agamben framing engaged in detail with continental-theory readers.
- Months 7-9: substrate section reworked to address skepticism about whether the grammar adds substance over careful statutory drafting. The implementation paragraph trimmed or expanded based on co-author feedback.
- Months 10-12: legal-review submission cycle (Yale, Stanford Online, Harvard JOLT). Expedited-review window opens in March.
- Months 13-18: revision in response to law-journal student-editor comments, which are typically extensive and often substantive.

### Recommended co-author

The primary contact identified by the parent paper's outreach is Angela Walch (St. Mary's University School of Law), whose work on developer power, miner extractable value, and the formal-vs-informal authority question is directly adjacent to the bounded-executive-action framing. If Walch declines, candidates in priority order:

1. Aziz Huq (University of Chicago Law School). Constitutional theory of emergency powers, structural-constitutionalism approach. Recent work on algorithmic accountability is the closest doctrinal anchor for the paper's framing.
2. Cass Sunstein (Harvard Law). Administrative law of emergencies, sunset clauses, structural correction. Has written about the AUMF and post-9/11 emergency authorities. Senior, busy, unlikely to co-author but a target for an outreach reading.
3. Kim Lane Scheppele (Princeton SPIA). Comparative constitutional emergency law, Hungary's constitutional decay, Weimar-as-analog scholarship. Strongest fit for the Article 48 case study.
4. Daphne Keller (Stanford Cyber Policy Center). Section 230, intermediary liability, EU data-protection regimes. The right reviewer for Sections 3.2 (Section 230) and 3.3 (GDPR Article 17).
5. Jameel Jaffer (Knight First Amendment Institute). FISA, surveillance authorities, AUMF and post-9/11 emergency-powers litigation. The right reviewer for Sections 3.4 and 3.5.

A reasonable submission strategy is to draft solo, circulate to two of the above for early feedback, and only seek formal co-authorship if the feedback identifies a section that needs primary-source legal-history work beyond what a non-lawyer can produce. Solo authorship is achievable for the structural argument; co-authorship is necessary for primary-source historical claims.

## File map

- `paper.tex` -- LaTeX shell with macro stubs and section includes.
- `sections/01-introduction.tex` through `sections/08-conclusion.tex` -- main text.
- `legal-references.md` -- the legal citations the paper will need, with placeholders where the author is not yet certain.
- `bib.bib` -- not yet present. To be populated once references are vetted.
