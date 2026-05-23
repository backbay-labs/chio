# Wave 4B: Abstract + §1 + §6 voice cleanup

Three targeted fixes from Wave 3A's adversarial pass, executed against
`paper.tex` (abstract block only), `sections/01-introduction.tex`, and
`sections/06-implementation.tex`. No other files touched.

## 1. Abstract trim: 445 to 389 words (under YLJ 400 cap)

Wave 3A flagged the abstract at 444 words against the 250-400 YLJ band. The
revised abstract measures 389 words by `wc -w` on the block (delta of -56).

Cuts: (a) the FISA sentence compressed from 40 to ~22 words, dropping the
"declassified Foreign Intelligence Surveillance Court opinions and Privacy and
Civil Liberties Oversight Board reports" expansion to "declassified FISC
opinions and PCLOB reports," and folding the boundary-of-review clause into
one sentence; (b) the Article~48 lead tightened ("an emergency-decree
authority intended for narrowly delimited use; it was used 250 times" became
"intended for narrowly delimited emergency use, was invoked roughly 250
times"); (c) paragraph 2's three-sentence "exhibits a proof / constructible /
unconstructible as a matter of construction" stack lightened to a single
relative-clause construction; (d) the closing payoff sentence compressed
from two clauses to one ("Its claim is not abolition or expansion of
existing authority but reformulation: any future grant should be enacted
with the four-component grammar this Article specifies"). The three-paragraph
structure, "this Article" capitalization, and the normative payoff Wave 1D
required all hold.

## 2. §6 footnote voice cleanup

Two systems-paper phrases removed without changing the substantive claim.
"Quorum tiers scale with severity" became "The authorization requirement
varies with the consequence of the action." "Concurrent device-level and
operator-level signatures within a bounded window for higher-severity ones"
became "concurrent assent from both the device's local authority and a
human operator within a specified time window." Footnote body is now 97
words (was 83); the small length increase is the cost of unpacking the
compressed jargon into legal-academy register. The body sentence at line 14
("constructibility... empirical feature... not an a priori feature") is
preserved per Wave 3A's instruction to keep it as the redemptive sentence.

## 3. §1 lowercase "the article" capitalization

Line 70: "enforcement of the article" became "enforcement of Article~17"
(GDPR). Line 23: "The article required notification to the Reichstag"
became "Article~48 required notification to the Reichstag." Both
disambiguate from "this Article" (the paper itself, capitalized eight times
in §1 and unchanged). No replacement was applied to "this Article"
instances.

## Revised abstract (full text)

> Delegated emergency authority has, across two thousand years of
> constitutional practice, exhibited a consistent failure mode: an
> authority granted as a time-bounded exception ratchets, through use and
> reuse, into a permanent feature of the legal order. The pattern recurs
> in regimes that have little in common doctrinally. Article~48 of the
> Weimar Constitution, intended for narrowly delimited emergency use, was
> invoked roughly 250 times in twelve years before being absorbed into the
> structure of the Nazi state. The Authorization for Use of Military
> Force enacted in September 2001 has, twenty-five years later, been
> cited as legal basis for armed action in at least eight countries.
> Statutory takedown regimes under Section~230 of the Communications
> Decency Act and Article~17 of the General Data Protection Regulation
> produce orders that are, in form, time-bounded executive acts; in
> practice the orders are irreversible by construction because no
> rollback path is statutorily required. The Foreign Intelligence
> Surveillance Act's emergency authorities, as documented in declassified
> FISC opinions and PCLOB reports, operate at a boundary of judicial
> review the original statute did not contemplate.
>
> This Article argues that the ratcheting pattern has a structural rather
> than merely political explanation. Each of these regimes shares a
> missing element at the level of statutory grammar: the authority is
> granted without a typed rollback obligation that must be constructed at
> the moment of authorization. A typed rollback witness, a formal-methods
> construct drawn from recent work on machine-checkable governance
> receipts, requires that an authority cannot be exercised unless, at the
> moment of exercise, the actor demonstrates a constructible path back to
> the prior state. The grammar renders the corresponding class of
> unbounded emergency authority *unconstructible* rather than merely
> forbidden. The distinction matters because forbidden authority can be
> exercised against the prohibition; unconstructible authority cannot be
> exercised because the construction itself fails.
>
> The Article applies the grammar to five case studies, situates it
> within the Schmitt-Agamben tradition on the state of exception, and
> exhibits one implementation drawn from a Lean-attestable governance
> substrate. The implementation is offered as proof that the grammar is
> buildable, not as the centerpiece of the argument. The Article is
> structural; it does not defend any particular emergency authority on
> the merits. Its claim is not abolition or expansion of existing
> authority but reformulation: any future grant should be enacted with
> the four-component grammar this Article specifies.

## Build verification

`pdflatex -interaction=nonstopmode paper.tex`: exit 0, zero `^!` errors,
23 pages (no page-count delta). No em-dashes introduced in any edited
file (byte scan for U+2014 returns zero hits across all three).
