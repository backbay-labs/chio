# Wave 3A: Adversarial re-read after Wave 2

A hostile articles-editor cold-read on the post-Wave-2 draft, asking whether the
seven framing hedges and five case-study rewrites landed, what they cost in
prose density, and what a co-author candidate (Walch, Huq, Scheppele, Keller,
Jaffer) would flag on a five-minute first impression.

## 1. Did the Wave 2 fixes actually land?

**Fix A (§1 Article 48 historiography hedge) lands.** The original "continuous
trajectory" gloss is gone; the new "occurred through a sequence of contested
political decisions, each conducted within a constitutional grammar that did
not require lapse-by-construction" (§1 line 27-28) does the work and matches
the §3.1 disaggregation. Clean.

**Fix B (§2.1 Schmitt as normatively defensible) is the strongest of the
seven.** The new sentences at §2 lines 43-49 ("For Schmitt, the constitutive
character of the decision is normatively defensible under conditions of genuine
emergency, not merely descriptive of how legal orders are seen to fail. The
structural argument this Article advances is therefore incompatible with that
normative view, not orthogonal to it") name the precise point Wave 1A demanded
and concede it cleanly. The Kelsenian-formalist-disease line is in.

**Fix C (§1 AUMF political-equilibrium hedge) lands but is verbose.** §1 lines
44-52 do the work, but the paragraph that follows the original AUMF sentence
spends six lines on the Kaine-Young / Lee-Murphy / 2023 Iraq AUMF litany before
delivering the structural-not-displacing-political concession. The point is
made; the air is heavy.

**Fix D (§1 Section 702 disambiguation) lands.** Lines 54-66 cleanly say "The
program is not itself an emergency authority, but §1881a(c)(2) contains a
sub-provision," which is the Wave 1B-prescribed language nearly verbatim.

**Fix F (§1 GDPR re-evaluability hedge) lands but is mechanical.** Lines 73-76
say "not, on the regulation's default operation, restored, although the
underlying balance is re-evaluable and the controller may re-index where the
supporting facts change." The text is correct, but the "re-evaluable"
qualification reads as inserted rather than integrated. A copyeditor will
rephrase.

## 2. What did Wave 2 introduce that wasn't there before?

The §3 case studies grew from 2,668 to 4,600 words (+72%); much of this growth
is justified (Preußen contra Reich, FISC opinions by docket, the EDPB
guidelines). Some of it is not.

**§3.3 AUMF is the worst offender for padding.** Lines 403-421 repeat the
political-vs-structural concession three times: once at line 403 ("admits both
a political and a structural reading"), once at lines 414-417 ("does not
displace the political account; it identifies an additional feature"), and
once at lines 418-421 ("the structural asymmetry is the feature ... it operates
alongside, not in displacement of, the political-equilibrium account"). Pick
one statement and delete the other two. The triple-hedge reads as the author
worried the reader might miss the concession; in a law review this looks
defensive.

**§3.4 GDPR includes one paragraph that belongs in a footnote.** Lines
249-257, on the EDPB Guidelines 5/2019 superseding the Article 29 WP 225, are
necessary cites but the entire paragraph is bibliographic prose. A law-review
articles editor moves this to a single footnote.

**§3.1 Weimar's *Preußen contra Reich* paragraph (lines 84-105) is over-long.**
The Staatsgerichtshof discussion is substantive and earned, but the closing
sentence at lines 99-105 ("The accommodation is that the structural absence
of a typed rollback witness made the ratchet structurally available, in the
sense that nothing in the text or surrounding architecture made the ratchet
unconstructible") is itself a fifty-eight-word run-on that re-states the
weak-claim hedge for the third time in the subsection. Cut.

## 3. The abstract is over band.

Wave 2A claims the abstract is 448 words. A `wc -w` on the abstract block
returns 444 words after stripping LaTeX commands. The YLJ band Wave 1D
identified is 250-400 words. The abstract is over by ~44-48 words and
**this is the single thing an articles editor reads first.**

The added normative-payoff sentence Wave 1D recommended ("The Article's claim
therefore is not abolition or expansion of any particular emergency authority
but reformulation: any future grant should be enacted with the four-component
grammar this Article specifies") is well-placed structurally (it closes
paragraph 3) but it is also one of the sentences that pushes the abstract over
the cap.

Recommendation: trim the FISA sentence in paragraph 1 from "The Foreign
Intelligence Surveillance Act's emergency authorities have been documented,
in declassified Foreign Intelligence Surveillance Court opinions and Privacy
and Civil Liberties Oversight Board reports, to operate at a boundary of
judicial review that the original statute did not contemplate" (40 words) to a
20-word version. The disambiguation belongs in §1, not the abstract.

Also: the abstract says "typed rollback witness" before the body explains it.
The phrase appears in paragraph 2 at line 71, with the explanation following
in lines 73-77. This is acceptable law-review practice (a term of art
introduced and immediately explained), but the explanation is dense; a careful
articles editor will note that "constructible," "exhibits a proof," and
"unconstructible as a matter of construction" all land in the same three
sentences. Lighten one of them.

## 4. Is §6 compressed enough?

Yes, narrowly. The body is now 99 words (Wave 2A's number checks out); the
footnote is dense but contained. **However, the footnote still contains two
phrases that smell systems-paper.** "Quorum tiers scale with severity" and
"concurrent device-level and operator-level signatures within a bounded
window" are the surviving EDR fingerprints. Either rewrite to "the quorum
required to admit an action scales with the action's reversibility cost" (an
ostensibly law-flavored gloss), or accept that the footnote is technical and
shorten it further.

The body sentence "The constructibility of the witness is an empirical feature
of the operational regime, not an a priori feature of the action's category"
is the one sentence that does redemptive work: it explicitly says the
implementation is a buildability proof, not an applicability claim. Keep it.

## 5. Cross-section consistency drift exists.

**§1 AUMF hedge and §3.3 AUMF hedge are mutually consistent.** Both say the
structural reading does not displace the political account. Good.

**§1 Section 230/DMCA separation and §3.2 separation are mostly consistent but
diverge on the (c)(2) treatment.** §1 says "Section 230's incentive shadow
produces takedown-like behavior in platform self-regulation, though the
statute itself does not authorize takedown" (line 89-90), which leaves (c)(2)
ambiguous. §3.2 lines 137-145 then say (c)(2) "is, on its face, a hedged
authorization of takedown by the private intermediary." The §1 framing and
the §3.2 framing are not contradictory but they are in different keys: §1
sounds like (c)(2) is incidental, §3.2 sounds like (c)(2) is structurally
load-bearing. Reconcile: add a half-sentence to §1 acknowledging that (c)(2)
is itself a hedged takedown authorization.

**§1 line 70-71** still uses "the article" to refer to GDPR Article 17 ("The
Court of Justice of the European Union's enforcement of the article has
produced erasure orders"). Wave 1D flagged exactly this ambiguity (the paper
calls itself "the Article" 28+ times). §3.1 also still has lowercase "the
article" referring to Article 48 at lines 26, 31, 52, 69, 107, and 112. Fix.

## 6. What a real law-review reader would flag on first impression.

**The §4 grammar section, untouched by Wave 2, is the real systems-paper
centerpiece.** §4 line 7-8 still presents "a four-tuple $a = (\text{act},
\TTL, w, q)$" in displayed math form, and the subsection that follows reads
the four components in sequence. After the abstract and §6 have been detoxed,
this is the section that an articles editor sees on the second skim and
concludes "ah, this is a CS paper after all." The math notation can stay
(it's actually less alien than the prose of "typed rollback witness"), but
the lead paragraph at lines 6-21 should be rewritten in legal-doctrinal prose
("four components: the substantive action, a time-to-live...") before the
notation is introduced. Currently the math comes first and the gloss comes
after, which reads as a CS paper convention.

**§5 holds the cite-don't-rederive discipline but over-explains §5.1.** Wave
1D §3 already flagged this; nothing in Wave 2 addressed §5. The "$K(r) =
\text{accept}$" notation at line 27 is the one item that still earns a strike.

**§8 conclusion is now slightly out of alignment.** The conclusion at line 7
says "the structural explanation for the ratcheting pattern documented in the
historical record of each regime." After Wave 2B's hedges, the §1 and §2
framing is now narrower than this ("an additional feature ... that lowers the
cost of continuation"). The conclusion still reads as if the structural
account is the explanation, not an additional feature. Soften.

## 7. Wave 1 items Wave 2 did not address.

- **§3.2 (c)(2) good-Samaritan engagement** (Wave 1C finding 6): partially
  addressed. §3.2 lines 137-145 now name (c)(2) explicitly and call it "a
  hedged authorization of takedown." But the case law construing (c)(2)
  (*Zango v. Kaspersky*, *e-ventures Worldwide v. Google*) that Wave 1C
  flagged is **not** cited. A Section 230 reviewer will notice.
- **DSA Article 16 notice-and-action regime** (Wave 1C finding 6): not
  addressed. The Wave 2 §3.4 GDPR rewrite engages the EDPB and the CJEU line
  but does not mention the DSA, which Wave 1C identified as supplying the
  partial counterexample. A Brussels-trained data-protection reviewer would
  flag the omission immediately, especially in May 2026 when the DSA has been
  operative for over two years.
- **The Hart's *Concept of Law* gap** (Wave 1D §6): legal-references.md
  flagged this as a known gap; the Wave 2 passes did not engage Hart. For a
  paper that explicitly engages "Hart's condition (a)" in the README's
  Relationship-to-Parent-Paper section, citing *The Concept of Law* (1961) is
  unavoidable in a law-review submission. Currently neither §1 nor §2
  mentions Hart.
- **Footnote density** (Wave 1D §2): the draft still has roughly 3-5 footnotes
  total. A T14 article at this length carries 100+. Wave 2 added inline
  citations but did not convert them to footnotes. This is flagged as a known
  conversion task, but a Walch or Huq reading this draft will see the inline
  numeric `\cite{}` calls and recognize they are reading a pre-footnote-pass
  document.
- **Article-vs-article capitalization** (Wave 1D §1): see §5 above; still
  unfixed.
- **Lincoln habeas / Article 16 / Article 356 in §8** (Wave 1D §6): the
  conclusion lists these as "instances of the pattern" but the paper does not
  engage any of them. A reviewer who reads the conclusion will ask why these
  were flagged but unexamined.

## Submission readiness verdict

**NO, not ready for Walch / Huq / Scheppele / Keller / Jaffer circulation as it
stands.** The first-impression flag a co-author candidate would raise is the
abstract: it is 44+ words over the YLJ band and an articles editor would mark
this on read 1. The second flag is §4: untouched by Wave 2, it still leads
with displayed math before the legal-doctrinal gloss, which reads as a CS
paper's signature on the page where a law-review reader expects the
contribution's core to land. The third flag is the missing DSA engagement in
§3.4 and the missing Hart engagement throughout: in May 2026, an internet-law
reviewer (Keller) reads a 2026-dated draft on intermediary liability that does
not cite the DSA and concludes the author has been working from a 2022 reading
list. These three things are bounded fixes (abstract trim 30 minutes, §4 lead
paragraph rewrite 1 hour, DSA + Hart insertion 2 hours) and the paper is
**probably ready after a Wave 3 with that 4-hour scope.** As it currently
stands, on a first impression read by an articles editor or by Keller
specifically, it would draw a "needs another revision" flag, not a quick
reject, but not a clean pass either.
