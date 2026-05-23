# Wave 5B: Hart's Concept of Law engagement

## (i) Location chosen and rationale

The Hart paragraph was placed in `sections/02-pattern.tex`, at the end of the
structural-reading subsection, immediately after the paragraph that connects
the typed rollback witness to the substrate's admission-step discipline (and
before the paragraph beginning "The remainder of the Article develops the
implications...").

Rationale. Part 2 is where the paper builds its conceptual scaffolding: it
introduces the Schmitt-Agamben framing, develops the structural reading of
the ratcheting pattern, and draws the forbidden-versus-unconstructible
distinction. Hart's primary/secondary rules distinction is the natural
conceptual ancestor of that move and therefore belongs in the scaffolding
rather than in the limits section. Part 7 (limits) handles what the
structural claim does not capture (the Schmittian normative objection, the
legal-realist objection, the doctrinal-fit objection, the cross-disciplinary
asymmetry); Hart is conceptual support for the move the paper makes, not a
limit on it.

The placement after the substrate-discipline paragraph is deliberate: the
preceding paragraphs have already introduced the typed rollback witness and
distinguished it from sunset clauses. The Hart paragraph then identifies the
jurisprudential lineage of that distinction before the section transitions
to the case studies in Part 3.

## (ii) Paragraph added

The new paragraph reads, in full:

> The conceptual move that distinguishes the typed rollback witness from a
> substantive prohibition on the underlying action has a defensible lineage
> in Hart's analysis of legal systems \cite{TODO_hart_concept_of_law}.
> Hart's central jurisprudential distinction is between primary rules,
> which impose duties on conduct, and secondary rules, which are rules
> about rules: rules of recognition that fix the criteria of legal
> validity, rules of change that govern how further rules may be enacted
> or amended, and rules of adjudication that govern how the rules are to
> be applied. The typed rollback witness, as this Article uses the term,
> is most naturally read not as a primary rule forbidding the substance of
> any particular emergency action, but as a secondary rule of change: a
> constraint on the form a delegated authority may take at the moment of
> its construction, rather than a constraint on what the authority, once
> validly constructed, may substantively do. The forbidden-versus-unconstructible
> distinction that this Part has drawn tracks the primary-versus-secondary
> rule distinction Hart developed. A substantively prohibited action is
> one that an actor must not perform; an unconstructible authority is one
> that cannot validly be brought into being in the first place. The
> argument operates, in Hart's vocabulary, from the internal point of
> view: it presupposes that legal actors accept the structural constraint
> as a binding criterion governing the construction of further rules, not
> merely as an external prediction about what conduct will attract
> sanction. The Article does not claim that Hart's framework entails the
> structural-grammar argument it advances; Hart did not address delegated
> emergency authority, and the application of his categories to typed
> witnesses is one this Article makes rather than one it inherits. The
> narrower claim is that the conceptual move from forbidden to
> unconstructible is not novel in jurisprudence and stands within a
> tradition that the legal academy already recognizes as serious.

The paragraph hits all five requirements from the brief: names Hart with
citation, identifies the primary/secondary rules distinction as the lineage
for forbidden/unconstructible, frames the typed rollback witness as a
secondary rule of change, engages the internal point of view, and hedges
explicitly against the over-claim that Hart entails the argument.

## (iii) New bib entry

Appended to `bib.bib` under a new subsection heading "Analytical
jurisprudence: primary/secondary rules, internal point of view":

```bibtex
@book{TODO_hart_concept_of_law,
  author    = {Hart, H. L. A.},
  title     = {The Concept of Law},
  publisher = {Oxford University Press},
  year      = {2012},
  edition   = {3},
  address   = {Oxford},
  note      = {First published 1961; second edition with author's postscript 1994; third edition with introduction by Leslie Green 2012. Citations herein are to the third edition},
}
```

Appended after `TODO_chio_parent_paper` (the last existing entry), which
keeps the Wave 5A bib edit room to land cleanly at the end of file without
overwriting this addition or vice versa.

## (iv) Build verification

Build command from the brief, run from the paper directory after both edits.

First-pass build (Wave 5A's bib entry had not yet landed):

- LaTeX errors: 0
- bib misses: 1 (Wave 5A's `TODO_dsa_2022`)
- undefined citations: 1 (Wave 5A's `TODO_dsa_2022`)
- pages: 29

Second-pass build (after Wave 5A's bib entry landed via the concurrent edit):

- LaTeX errors: 0
- bib misses: 0
- undefined citations: 0
- pages: 29 (+1 from the Wave 4 baseline, consistent with the single-paragraph
  addition)

The Hart citation resolves cleanly to the new bib entry on both passes; the
single transient miss was Wave 5A's, which cleared once Wave 5A's bib entry
landed at line 408. The Hart entry at line 679 was not disturbed by the
concurrent edit because each wave appended to the file rather than rewriting
shared regions.
