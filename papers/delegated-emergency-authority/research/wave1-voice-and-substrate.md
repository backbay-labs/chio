# Wave 1D: Law-review voice + substrate-section discipline audit

## 1. Does the prose read as written by someone who reads law journals?

Largely yes, with one structural inconsistency and a handful of CS-flavored phrasings that need adjustment before submission.

**Article vs. article capitalization is mostly disciplined but not uniform.** "This Article" appears 28+ times capitalized for the paper itself. The collisions with lowercase "the article" referring to Article 48 are managed by saying "Article 48" or "the article" in case-study context, and both forms read correctly in isolation. One soft spot: §3.1 line 21 ("The drafters of the article, working within the constitutional convention at Weimar in 1919") and line 26 ("The historical trajectory of the article's use is well-documented") use lowercase "the article" to refer to Weimar Article 48. A T14 articles editor will read this as ambiguous on first pass because the paper has been referring to itself as "the Article." Fix: say "Article 48" or "the constitutional provision" in those spots.

**Part vs. Section cross-references are clean.** Every internal cross-reference in the prose uses "Part" (e.g., "Part~\ref{sec:pattern}", "Part~\ref{sec:cases}"). The shell renders these as Roman numerals via `\titleformat`. No instance of "Section X" referring to a Part was found. Good. The collisions with "Section 230" and "Section 702" are unavoidable (those are the names of the statutes) and are correctly typeset with `Section~230` so the non-breaking space prevents bad line breaks.

**Doctrinal engagement is competent but generic.** The case studies name the right cases (Google Spain, the 2011 Bates opinion implicitly, Reichstag Fire Decree) but the *first-mention parenthetical* convention — "Case C-131/12, *Google Spain SL & Google Inc. v. Agencia Española de Protección de Datos*, 2014 E.C.R. I-317 (May 13, 2014)" — does not appear in the prose. The prose says only "the *Google Spain* decision \cite{TODO_google_spain}." A law-review reader expects the full first-mention citation in-text or in a footnote with the date. Flag for the footnote-conversion pass.

**Hedging language is strong.** The paper says "this Article suggests," "the cleanest application," "on a defensible reading," "the Article is candid where the answer is contested," and explicitly hedges the AUMF and FISA claims. This is the right register and reads as someone who has read law reviews.

**Citation style** is the largest known conversion task: 47 `\cite{TODO_*}` inline citations need conversion to Bluebook footnotes. Plain `\bibliographystyle{plain}` with no `bib.bib` present produces inline numeric citations that are wrong for a YLJ submission. This is a known conversion task and the README flags it; the legal-references.md notes it under "bibliographic placeholders" item 4.

## 2. Footnote density

The current draft has **3 footnotes total** across 10,132 words of body prose (Part II at line 42, Part II at line 128, Part III at line 94). The shell uses `\usepackage{footmisc}` but no `\renewcommand{\footnoterule}` or footnote-conversion pipeline. A T14 article at 20 pages with 6 footnotes/page averages 120 footnotes; this draft has 2.5% of that target.

**Light-footnote sections requiring the most build-out:**

- **§3 Cases (2,668 words, 0 footnotes)**: highest priority. Every case study needs pinpoint cites for primary sources (the Weimar Reichsgesetzblatt entry; 47 U.S.C. § 230(c)(2); GDPR Recital 65–66 alongside Article 17(1)–(3); 50 U.S.C. § 1881a(c)(1)(A); Pub. L. No. 107-40 § 2(a)). Each "well-documented" or "documented at length" claim is a footnote stub. Estimate 35–45 footnotes for §3 alone.
- **§2 Pattern (1,285 words, 2 footnotes)**: needs Schmitt pinpoint (Schwab trans. p. 5 for the opening sentence); Agamben pinpoint; pinpoints for Ackerman, Posner-Vermeule, Sunstein. Estimate 15–20 footnotes.
- **§1 Introduction (1,193 words, 0 footnotes)**: needs the 250-invocations claim sourced (Mommsen or Caldwell, page-specific); the "eight named theaters" claim sourced to the Brennan Center's most recent count with year; the seventy-two-hour FISA claim sourced to § 1881a(c)(2). Estimate 12–15 footnotes.
- **§4 Grammar, §7 Limits**: lightest because they are argumentative rather than evidentiary; 10–15 each.
- **§5 Substrate**: should stay light deliberately (see §3 below).

Concentrate footnote-building on §3, then §2, then §1.

## 3. §5 substrate-section discipline

§5 is **disciplined and the strongest section voice-wise**. It does largely what the README promised. Some specific findings:

**Lean and type-theory vocabulary**: §5 uses "Lean theorem," "Lean 4 proofs," "Merkle-rooted citizenship roster," "fail-closed admission hook," "capability tokens," "backward refinement," and "predicate evaluation." Each appears once or twice and is explained in lay terms in the surrounding sentence. A law-review reader will skim past these as terms of art the cited parent paper develops. This is the right balance.

**Macros `\codepath` and `\thm`**: the `grep` for these macros returned **zero hits in any section file**. The macros are defined in `paper.tex` but never invoked in §5 prose (or anywhere). Good. This is the systems-paper red flag the parent task warned about, and the author has correctly kept them out.

**The cite-and-move-on discipline holds, mostly**: §5 cites `TODO_chio_parent_paper` three times and each citation is "developed in detail in the companion paper" or "a Lean theorem establishes." It does *not* re-derive. Closing paragraph (lines 83–91) is exemplary: "The substrate is not the Article's contribution. The substrate is cited as evidence that the grammar developed in Part~\ref{sec:grammar} is buildable. A legal-academy reader does not need to verify the Lean proofs..."

**Mild over-explanation in §5.1**: lines 25–32 walk through admission predicate evaluation in more detail than a cite-and-move-on requires. A law-review reader does not need to see "$K(r) = \text{accept}$" notation. Recommend collapsing §5.1 lines 25–32 to a single sentence: "Admission is decidable predicate evaluation; the substrate's runtime refuses any receipt for which the constitution's predicates do not all accept." The current eight-sentence treatment is on the edge of the line the README drew.

**The "$(T, C, K)$" triple notation at §5 line 12**: marginal. A reader who has not read the parent paper will not know what $T$ and $C$ are except by the immediate gloss. Consider whether the notation earns its keep in a legal-academy paper; it might be better as prose ("a receipt-admission scope, a citizenship roster, and a finite constitution of predicates").

## 4. §6 implementation discipline

**§6 violates the README's "one paragraph" promise materially.** At 858 words (vs. one paragraph of ~80–150 words a law-review reader expects), it runs roughly 5–7× over.

**Engineering-meta phrases that must come out**: §6 line 19 says "The implementation, drawn from a security platform that integrates with the substrate cited in Part~\ref{sec:substrate}." The phrase "security platform" and the parenthetical "endpoint detection and response" framing in lines 10–17 read as a systems-paper case study, not as a legal-article illustration. Most damaging are these technical specifics that have no business in a Yale Law Journal piece:

> "for a process suspension, the witness is the SIGCONT operation that restores the process to its running state; for an egress restriction, the witness is the network-policy reversion to the prior egress allowlist."

> "for high-severity actions (process termination, network isolation), the predicate requires the concurrence of a device-level signature and an operator-level signature within a specified time window."

These two sentences (§6 lines 28–33) are the centerpiece of an EDR systems paper. A legal articles editor reads them and concludes the author has imported a systems-paper case study into a law-review submission. Cut both. The SIGCONT mention is particularly damaging because it presupposes the reader knows UNIX signal vocabulary.

**The second observation block (lines 60–71)** about "operationally observable artifact: a receipt for each admitted action, signed by the admitting authority" is reasonable in substance but bloats the section. Compress to a single sentence in the footnote about audit visibility.

**Recommended cut**: collapse §6 to a single paragraph of ~120 words, structure: "One implementation exhibits the grammar against an operational workload distant from constitutional emergency powers. In a security-incident-response context, every containment action is constructed as a four-tuple: the substantive action, a time-to-live, a typed rollback witness, and a quorum predicate. The constructibility of the witness is an empirical feature of the operational regime, not an a priori feature of the action's category — a point that carries over to the legal domains of Part III. The implementation is an existence proof for the grammar's buildability; it is not an argument that the grammar should apply to the legal regimes the Article examines." Move SIGCONT, allowlist, severity tiers, and "device-level signature" detail to a single footnote that a legal reader can ignore.

The current §6 is the single highest-priority pre-submission fix.

## 5. The abstract

Length is right (323 words, well inside the YLJ 250–400 band). Structurally it nearly hits the "argues X, against backdrop Y, by means Z, concluding W" template — paragraph 1 supplies Y (the historical backdrop across five regimes), paragraph 2 supplies X (the ratcheting has a structural rather than political explanation) and Z (typed rollback witness), paragraph 3 supplies W (the structural absence is a defect for which the substrate provides a corrective). Good.

**Systems-paper residue a legal reader will need to translate:**

- "structural defect" (recurring) — acceptable, recurs in administrative-law literature, but front-loaded heavily.
- "the well-typed sense" (line 76) — alien to legal academy. The phrase "in the well-typed sense" will read to a constitutional scholar as jargon the paper has not earned. Replace with "as a matter of construction" or "by the construction's own terms."
- "fails to type-check" — same problem. The abstract uses it once (line 78); the body uses it eleven more times. Acceptable in the body once introduced, but in the abstract it should be paraphrased: "the construction itself fails."
- "proof-carrying programmable governance" (line 71) — this is a CS-research-area name. A legal reader will not recognize it. Replace with "recent work on machine-checkable governance receipts" or similar.
- "the Article develops the grammar against five case studies" (line 80) — "develops against" is systems-paper idiom for "evaluates on." Legal-academy register would be "the Article applies the grammar to five case studies" or "the Article tests the grammar against five case studies."

**Missing beat**: a YLJ abstract often gestures toward the normative payoff in its last sentence. The closing "where the structural grammar is available, its absence in current statutory practice is a defect for which the formal substrate provides a corrective" is structural-only. Consider one sentence flagging *what the corrective implies for current law*: "The Article's claim therefore is not abolition or expansion of any particular emergency authority but reformulation: any future grant should be enacted with the four-component grammar this Article specifies." That is the normative beat law-review readers expect.

## 6. Footnotes-vs-references coverage

Spot-checking 10 `\cite{TODO_*}` keys against legal-references.md:

| Key | In legal-references.md? |
|---|---|
| `TODO_weimar_const_art48` | Yes |
| `TODO_kershaw_hitler` | Yes |
| `TODO_caldwell_popular_sovereignty` | Yes |
| `TODO_mommsen_weimar` | Yes |
| `TODO_aumf_2001` | Yes |
| `TODO_brennan_center_aumf` | Yes |
| `TODO_chesney_aumf` | Yes |
| `TODO_jaffer_aumf` | Yes |
| `TODO_pclob_702_report` | Yes |
| `TODO_fisc_702_opinions` | Yes |

All 10 spot-checks cover. A full enumeration of the 30 unique `TODO_*` keys in the prose against the legal-references.md entries:

- **Covered**: all 30 keys are accounted for, including `TODO_section230`, `TODO_dmca_512`, `TODO_gdpr_art17`, `TODO_google_spain`, `TODO_keller_takedowns`, `TODO_goldman_section230`, `TODO_citron_intermediary_liability`, `TODO_urban_quilter_dmca`, `TODO_seng_dmca`, `TODO_kuner_gdpr_erasure`, `TODO_mantelero_gdpr_enforcement`, `TODO_fisa_702_statute`, `TODO_revocable_encryption_lit`, `TODO_schmitt_political_theology`, `TODO_agamben_state_of_exception`, `TODO_kahn_political_theology`, `TODO_ackerman_before_next_attack`, `TODO_posner_vermeule_terror`, `TODO_sunstein_sunset_clauses`, `TODO_jacobson_weimar_pdf`, `TODO_chio_parent_paper`.

- **Not actually cited in prose but listed in legal-references.md** (forward-coverage stubs): `TODO_scheppele_emergency`, `TODO_dyzenhaus_legality_legitimacy`, `TODO_gross_ni_aolain_law_in_emergency`, `TODO_donohue_fisa`, `TODO_war_powers_reports`. These are appropriate "should-cite" stubs the legal-references.md flags for the revision pass.

- **Gap**: the legal-references.md's "Categories the paper does not currently cite but probably should" section is honest: Hart's *Concept of Law*, Farber/Neely on Lincoln, French Article 16, Indian Article 356, and Brazilian estado de defesa. None of these are cited yet, none are claimed to be. This is acceptable for a draft at this stage; flag for the legal-scholar co-author pass.

Coverage is good. The references file is a complete enumeration of currently-cited keys plus a candid list of gaps. No orphan `\cite{}` calls were found.

## Bottom line

The paper is voice-wise close to submission-ready but **not** submission-ready in three pages. The first three pages — the title block, abstract, and §1 introduction's first 1.5 columns — currently carry two systems-paper tells: "the well-typed sense" and "proof-carrying programmable governance" in the abstract, and a mathematical-symbol-free but still terminology-heavy introduction that calls the structural defect "a missing typed rollback witness" before the reader has been told what "typed" means in a legal context. An articles editor at YLJ or Stanford reading the abstract first will form a "this is a CS paper wearing law-review prose" impression by sentence three. The Schmitt-Agamben backdrop helps, but it is in §2, not the abstract. The §6 implementation paragraph is the second-page reinforcement of the same impression — SIGCONT, egress allowlist, and process-suspension specifics will read as confirmation that this is a systems paper that imported a constitutional-law cover. Both must be fixed *before* the citation hardening starts. Footnote conversion takes 200+ hours; voice fixes are 6–10 hours of careful prose surgery and should come first because the citation work is wasted if the voice gets the paper rejected on the first page. The §5 substrate section is, by contrast, ready as-is modulo a small notation trim. Once the abstract is detoxed of two CS phrases and §6 is compressed back to one paragraph as the README promised, the paper reads as a cross-disciplinary law-review piece in the Lessig/Strahilevitz mold.
