# Wave 3B: Cross-section consistency + voice integrity audit

Scope: post-Wave-2 read of `paper.tex` plus `sections/01` through `sections/08`. Wave 2A
touched `paper.tex` (abstract) + §6; 2B touched §1 + §2; 2C touched §3. §4, §5, §7, §8
were untouched.

## 1. Voice consistency across the three Wave 2 agents

**Terminology.** The load-bearing term "typed rollback witness" holds across all three
agents' work. Variants observed are intentional and consistent: "typed rollback witness"
(noun phrase, the object itself), "typed-rollback discipline" (the practice of requiring
it), "typed-rollback grammar" (the framework). 2A's abstract uses the hyphenated forms
sparingly, 2B's §1 uses the unhyphenated noun phrase, 2C's §3 mixes both forms
identically to §4 and §7. No agent slipped into "constructible rollback" or "typed
witness" as the headline term. The single bare "typed witness" appears in §8 line 6
("exhibit a typed witness for the path back") which was untouched by Wave 2 and predates
the convention; it should be normalized in a separate cleanup pass.

**Hedging language.** "This Article" capitalization holds across 2A, 2B, 2C: 18 of 19
instances use the capitalized form (the lone lowercase exception in `paper.tex` line 89
is at the head of a clause and is grammatically fine). The phrases "the better view" and
"on a defensible reading" appear nowhere in any agent's prose; 2B's wave2b proposal
introduced "narrower and more defensible claim" (§1 line 113) which is the closest
analog. This is consistent: the paper has its own hedge vocabulary ("the narrower claim,"
"on the framing this Article develops," "structurally available rather than inevitable")
and all three agents stayed inside it.

**Engineering-meta voice.** No instances of "the construction defended here," "the
codebase," "checked-in fixtures," "release-engineering," "bless recipe," "v1/v2," or
branch names appear in the post-Wave-2 prose. 2A's compressed §6 footnote uses
"signed receipt that is auditable in canonical form" which is the closest the paper
comes; this is acceptable because §6 is the implementation paragraph where the
operational vocabulary is licensed. Outside §6, no agent slipped. The one borderline
case: 2A's abstract substitution "machine-checkable governance receipts" (paper.tex
line 72) is a CS-flavored noun phrase, but it is bounded to one sentence and explicitly
attributed to "recent work," which is the correct disposition.

**Em dashes.** Confirmed absent. A byte-level scan for U+2014 (UTF-8 `e2 80 94`) across
`paper.tex` and `sections/*.tex` returns zero hits. All three agents held the rule.

## 2. Cross-section redundancy after expansion

**The Kershaw/Mommsen/Caldwell historiography hedge appears three times.**
- §1 line 27-29: "The transition from emergency power to instrument of dictatorship
  occurred through a sequence of contested political decisions, each conducted within
  a constitutional grammar that did not require lapse-by-construction."
- §2.2 lines 57-66: full hedge paragraph naming Kershaw, Mommsen, Caldwell and citing
  all three.
- §3.1 lines 65-75: a second full hedge paragraph naming the same three scholars with
  the same citations plus Jacobson/Schlink and Dyzenhaus.

Three statements of one hedge. **Fix: keep §2.2 (the analytic frame) and §3.1 (where the
historiography matters most for the Weimar case); compress §1 to a single sentence and
add `\cite{TODO_kershaw_hitler}` only, deferring to §2.2 and §3.1 for the named dispute.**
The current §1 phrasing is actually fine as-is; the redundancy is between §2.2 and §3.1.
Recommend cutting §3.1's named-scholar list to a parenthetical: "(Kershaw, Mommsen,
Caldwell differ on this question, as Part~II.B notes)" and keeping the substantive
Jacobson/Schlink and Dyzenhaus citations.

**The Section 230 academy hedge appears twice.**
- §1 lines 92-95: "That characterization is one this Article advances against the
  consensus of the Section 230 academy (Goldman, Citron, Keller)..."
- §3.2 lines 121-129: the full Goldman/Citron-Wittes/Keller engagement paragraph.

Two statements, but the §1 instance is a forward gesture and the §3.2 instance is the
substantive engagement. This is the correct disposition; no fix needed.

**The AUMF political-equilibrium hedge appears twice.**
- §1 lines 44-52: bipartisan repeal proposals, Kaine-Young, Lee-Murphy, 2023 Iraq AUMF
  repeal.
- §3.5/AUMF lines 403-421: the same list, expanded with Corker-Kaine 2018 and S.1228.

These are not redundant. §1 is the framing gesture; §3 is the substantive case study.
The same names appearing in both is appropriate.

## 3. Length proportions

Body word counts (excluding abstract and front matter):

| Section | Words | Share |
|---|---|---|
| §1 Introduction | 1,379 | 11.7% |
| §2 Pattern | 1,476 | 12.5% |
| §3 Cases | 4,600 | **39.1%** |
| §4 Grammar | 1,375 | 11.7% |
| §5 Substrate | 860 | 7.3% |
| §6 Implementation | 185 | 1.6% |
| §7 Limits | 1,426 | 12.1% |
| §8 Conclusion | 467 | 4.0% |
| **Total** | **11,768** | |

**Verdict: the post-Wave-2 distribution is law-review-clean.** §3 at 39.1% is at the
upper edge of the 30-40% YLJ band for case-study sections but does not exceed it. §6 at
1.6% is appropriately compressed for a cross-disciplinary piece. §1+§2 at 24.2% is
correct for an article that needs to establish a Schmitt-Agamben framing before the
cases. §7+§8 at 16.1% is appropriate for the limits-plus-conclusion close.

The one paragraph that should be considered for relocation to a footnote is §3.4 lines
261-269 (Lynskey/Bygrave/Mantelero/Kuner). This is a literature-review paragraph that
reads as catalog rather than argument; folding it into a single footnote attached to
the structural-irreversibility claim would tighten the section without losing the
citations.

## 4. Citation density distribution

`grep -c "\\cite"` per file:

| Section | Cites |
|---|---|
| §1 | 15 |
| §2 | 8 |
| §3 | **57** |
| §4 | 0 |
| §5 | 3 |
| §6 | 0 |
| §7 | 0 |
| §8 | 0 |

§3 carries the citation load, which matches Wave 1D's recommendation. §4 (grammar) and
§7 (limits) carrying zero cites is acceptable: they are conceptual sections. §8 with
zero cites is conventional. §5 with three cites all to the parent paper is correct. The
distribution is balanced for a case-study-heavy law-review piece. Wave 2C achieved the
density §3 needed.

## 5. Hedge-without-content failures

Two passages of the form "the Article does not claim X" followed by prose that proceeds
as if X is settled:

**§3.5 FISA, lines 358-371.** "The Article's claim here is the most cautious of the five
case studies... A national-security-law scholar with classified-clearance access to the
full record may have grounds to dispute the characterization above. The structural claim
is offered as a working hypothesis." This is honest hedge. But the next-to-last sentence
("Whether the construction is operationally feasible in the surveillance context is an
empirical question on which the Article does not take a position") immediately follows
"The cryptographic literature on revocable encryption suggests that some forms of
collection can be made constructively reversible." The hedge is doing work the prior
sentence undercuts. **Fix: cut the revocable-encryption sentence or move it to a
footnote; the Article cannot say "cryptography suggests it's possible" and then say
"we take no position."**

**§3 AUMF lines 432-441.** "The political content of this case study is not the
Article's subject. The Article does not take a position on the merits of any particular
use of force... The structural claim is the narrower one: that the original AUMF's grant
of unbounded authority is a clear instance of the ratcheting pattern." Calling AUMF "a
clear instance of the ratcheting pattern" while disclaiming a position on the merits is
defensible but tight; a reviewer will read "clear instance" as a substantive judgment.
**Fix: change "is a clear instance" to "exhibits the structural pattern this Article
identifies" to match the §1 phrasing.**

## 6. Hedge stacking

The post-Wave-2 paper does not stack "this Article suggests" with "on a defensible
reading" with "the better view" because the latter two phrases do not appear. The closest
to a stacked-hedge passage is §3.1 lines 99-105 (the *Preußen contra Reich* accommodation
paragraph), which combines "must accommodate that ruling," "the accommodation is that,"
"in the sense that," "is consistent with the weaker structural reading but inconsistent
with a strong claim that..." Four hedges in five lines. This reads as careful rather than
insecure, but the passage is dense. **Fix optional: tighten to "The structural absence
made the ratchet structurally available without making it textually entailed; *Preußen
contra Reich* shows the constitutional order's resistance was politically contested and
partially successful, which the weaker structural reading accommodates."**

## 7. §4 and §5 read in light of new §1/§2/§3

**§4 is still well-aligned.** §4's "discipline applied to the case studies" subsection
(lines 47-85) walks through Weimar, DMCA-Section 230, GDPR, FISA 702, and AUMF in the
same order Wave 2C expanded them in §3. The §4 summaries are tight and do not duplicate
§3's expanded substance. One small disconnect: §4 line 60 says "The DMCA-Section~230
takedown regime" as a compound term, but Wave 2B/2C now insist on the separation
(Section 230 is a liability shield, DMCA 512 is the takedown regime). **Fix: change §4
line 60 to "The DMCA 512 takedown regime and Section 230's incentive shadow" and adjust
the surrounding sentence to match the §3.2 framing.**

**§5 reads as disconnected from the expanded §3.** §5 (substrate) cites the parent paper
three times and uses the Lean-attestable vocabulary that §3 now consciously avoids.
This is acceptable - §5 is licensed to use the technical vocabulary because it is the
substrate sketch - but the transition from §3's hedged historical prose to §5's "$(T, C,
K)$" triple is jarring. §4 buffers this transition in principle, but §4 is also
abstract. **Fix optional: add one transitional sentence at the head of §5 acknowledging
that the substrate vocabulary will read as a register shift from the case-study chapter.**

**§7's Schmittian objection** (subsection lines 12-40) now partly duplicates §2.1's
newly-added Schmittian-defensible passage (lines 43-49) and §2.2's converse-Schmittian
position (lines 64-66). The duplication is not severe: §2 establishes that the
Schmittian view is normatively defensible; §7 treats the Schmittian objection as the
"most fundamental objection." **Fix: §7 line 14 should add a cross-reference: "as
canvassed in Part II.A" so the reader knows the ground has been prepared.**

## Voice verdict

The post-Wave-2 paper is voice-consistent. The three agents held the
no-em-dash rule, kept the "typed rollback witness" terminology stable, did not slip into
engineering-meta voice, and used compatible hedge vocabularies. The patches that betray
multi-agent surgery are minor and substantive rather than tonal: the Kershaw/Mommsen
hedge appears in three sections where two would suffice; §4's "DMCA-Section 230
takedown regime" compound noun pre-dates §3.2's separation and now reads as a category
slip §3.2 explicitly forbade; the §3.5 revocable-encryption sentence undercuts the
disclaimer that immediately follows it; and §7's Schmittian objection should
cross-reference §2 to avoid reading as a re-statement. None of these is voice
drift; they are stitch lines from independent edits that did not see each other. The
paper is in good shape for a law-journal submission cycle pending the §6 / §4 /
TODO citation harmonization Wave 3A/3C should pick up.
