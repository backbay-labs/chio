# Wave 5C: Final adversarial re-certification

Cold read performed as a YLJ articles editor with no prior exposure. Build state at read: 29 pages, 0 LaTeX errors, 0 bibtex misses, 0 undefined citations, 74 bib entries, abstract 389 words.

## 1. First-three-pages impression

The abstract reads as a constitutional-law article, not a CS paper. The opening sentence ("Delegated emergency authority has, across two thousand years of constitutional practice, exhibited a consistent failure mode") names the doctrinal object and a doctrinal phenomenon (ratcheting). The four worked examples appear before any formal vocabulary. The phrase "typed rollback witness" is introduced once, immediately glossed in legal terms ("requires that an authority cannot be exercised unless, at the moment of exercise, the actor demonstrates a constructible path back to the prior state"), and then anchored on the doctrinally familiar forbidden-vs-unconstructible move. The closing paragraph explicitly disclaims the implementation as "proof that the grammar is buildable, not as the centerpiece of the argument." That is the right move for the audience.

Introduction voice is YLJ-compatible. The first three paragraphs (Article 48 to 2001 AUMF) read as constitutional-law prose. I did not find a sentence that would prompt me to flip to the bio note. The closest near-miss is "the original grant of authority was made without a typed rollback witness" at line 104 of §1, but it sits in the apex paragraph of the structural diagnosis, where the formal vocabulary is doing real work and is appropriately framed.

Read-past-page-3 confidence: 8/10. Strong enough that a YLJ editor would route to a faculty reader rather than desk-reject.

## 2. The Wave 3A reject list -- closed

(a) **Abstract under 400 words.** Confirmed at 389 words (`awk` extract between `\begin{abstract}` and `\end{abstract}` on `paper.tex`). Under the YLJ band.

(b) **§4 leads with prose before math.** Confirmed. The §4 opening sentence is "The grammar this Article proposes formalizes a four-component requirement for any delegated emergency authority." The first 29 lines are pure prose laying out the four components in doctrinal vocabulary (substantive action, sunset, reversibility, authorization procedure) and connecting them to existing law. The displayed equation `a = (act, TTL, w, q)` appears at line 33 only after the legal framing is complete.

(c) **DSA Article 16 engaged in §3.4.** Confirmed. §3.4 lines 249-267 add the paragraph: "A more structurally proximate EU instrument is the Digital Services Act, Regulation (EU) 2022/2065, whose principal obligations applied to hosting providers from 17 February 2024 and to designated Very Large Online Platforms and Search Engines from 25 August 2023." The paragraph enumerates Article 16 (notice-and-action), 17 (statement of reasons), 20 (six-month internal complaint window), and 21 (out-of-court dispute settlement), and explicitly concedes that "the conjunction of these provisions ... comes structurally closer to what this Article calls a typed rollback witness than any regime examined above."

(d) **Hart engaged in §2.** Confirmed at §2 lines 136-158. The paragraph reads: "The conceptual move that distinguishes the typed rollback witness from a substantive prohibition on the underlying action has a defensible lineage in Hart's analysis of legal systems," develops primary/secondary rules, frames the typed witness as a secondary rule of change, and explicitly hedges: "The Article does not claim that Hart's framework entails the structural-grammar argument it advances; Hart did not address delegated emergency authority."

All three Wave 3A reject risks are closed.

## 3. Did Waves 5A and 5B land cleanly

**DSA paragraph (Wave 5A).** Reads as belonging in the surrounding text. It sits between the EDPB/Article 29 WP regulatory-guidance paragraph and the academic-literature footnote paragraph; the placement is a natural EU-instrument bridge. It does not overclaim: the language "comes structurally closer to" and "strengthens the structural case" is calibrated, and the closing observation ("the regime's confinement to intermediary content moderation illustrates the generalization gap this Article argues should be closed") turns a potential weakness (the DSA is closer to the corrective than the paper acknowledged) into a confirmation of the structural claim. The `\cite{TODO_dsa_2022}` invokes correctly. No surrounding-prose adjustment is needed; the preceding paragraph ends naturally and the following paragraph opens on the academic literature without redundancy.

**Hart paragraph (Wave 5B).** Reads as belonging. It sits at the end of the structural-reading subsection, after the substrate-discipline paragraph and before the case-studies preview. The placement is correct: it provides jurisprudential lineage for the forbidden-vs-unconstructible move *before* the case studies operationalize that distinction. The paragraph does not overclaim; the hedging sentence ("the application of his categories to typed witnesses is one this Article makes rather than one it inherits") is exactly the move a careful jurisprudence reader would expect. The "internal point of view" reference is technically correct and not gratuitous. `\cite{TODO_hart_concept_of_law}` resolves to the third-edition entry.

Both paragraphs land cleanly. Neither feels inserted.

## 4. What's still wrong after five waves

The voice is now consistent throughout. I did not find CS-jargon residue or engineering-meta phrasing. Footnote density is reasonable but on the thin side for YLJ (the paper carries roughly 3 footnotes outside cases; YLJ submissions typically run heavier, though the substantive citations are pushed into the bib). This is acceptable for a draft circulating for co-author review; it would not be acceptable for final submission, but that is the next pass.

Three substantive gaps a specialist would still flag:

- **Scheppele uncited.** `TODO_scheppele_emergency` is in the bib but never cited. For a paper sent to Kim Lane Scheppele as a candidate co-author, the absence of any engagement with her "International State of Emergency" or "Law in a Time of Emergency" work is conspicuous. Same for `TODO_gross_ni_aolain_law_in_emergency`.
- **Footnote 1 (Schmittian wrapper-content concession, §2 line 170)** is doing structural load-bearing work and might draw the comment that the wrapper-content distinction is itself contested in the Schmitt secondary literature (Kalyvas, McCormick). This is a footnote not a section, so it is recoverable in the co-author pass.
- **§3.4 (FISA 702) Hasbajrami treatment** says the Second Circuit treated querying as "a distinct Fourth Amendment event from the upstream acquisition." A 702 specialist (Donohue, Jaffer) may push back that *Hasbajrami* held querying might require a warrant in some configurations but the panel did not resolve the merits cleanly; the paper's characterization is defensible but tight. Flag for co-author check, not blocker.

No new redundancy from Wave 5 was introduced. The 50% growth across five waves was concentrated in §3 case studies and §2 conceptual scaffolding, both load-bearing.

Bib spot-check (3 random TODO entries):
- `TODO_kershaw_hitler` (book): publisher, year, address present. Bluebook-adequate for a draft. The legal-scholar co-author pass will firm up the volume designation (Hubris is volume 1 of 2).
- `TODO_weimar_const_art48` (statute/constitution): cites Reichsgesetzblatt 1919 S. 1383. Adequate.
- `TODO_clapper_v_amnesty_2013` (court opinion): 568 U.S. 398, 2013. Adequate; final Bluebook form would add the full date but the volume/reporter/page is correct.

Bib quality is defensible for a draft. The `TODO_` prefix on every key is correct convention for a working bib that will be promoted to final keys by the co-author pass.

## 5. The §4 grammar reorder verified

The Wave 4C reorder is real, not cosmetic. §4 opens with "The grammar this Article proposes formalizes a four-component requirement for any delegated emergency authority. At the moment an authority is exercised, the exercising actor must specify four things: the substantive action to be performed, a duration after which the authority lapses, a witness that the prior state remains constructively recoverable, and a predicate naming the actors whose concurrence is required to admit the action into the polity's history. The four components correspond to the doctrinal categories of substantive action, sunset, reversibility, and authorization procedure as those categories appear in existing constitutional and administrative law." Lines 6-17 are pure prose connecting to doctrine; the displayed `a = (act, TTL, w, q)` does not appear until line 33. The agent moved the math, not merely added prose around it.

## 6. Bib coverage and quality

Hart and DSA entries are well-formed (verified above). Coverage: of 74 entries, 6 are in-bib-not-cited (Scheppele, Gross/Ní Aoláin, Donohue, Goldman 2019 duplicate-key alias, Citron intermediary-liability duplicate-key alias, war_powers_reports aggregate). The duplicate-key aliases are intentional safety nets from Wave 3C. No \cite{} in any section file resolves to a missing key (verified by diff of cited keys against bib entries).

For a draft circulating to co-author candidates: bib is adequate. For final submission: the co-author pass will reduce alias duplicates, add the Scheppele/Gross citations the paper currently leaves in the bib, and firm up Bluebook formatting on statutes and court opinions.

## 7. The conclusion §8

§8 closes the argument cleanly. It does not overclaim ("The Article has not argued that any particular delegated emergency authority is desirable or undesirable on the merits"), does not underclaim (the central contribution is named: identification of the pattern, naming of the corrective, demonstration that the corrective is buildable). The three threads of further work are appropriate: constitutional-law detail, comparative analysis against sunset/reauthorization toolkit, and application to unexamined regimes (Lincoln habeas, French Article 16, Italian decree-law, Indian President's Rule, Brazilian state of defense). The final paragraph correctly subordinates the substrate to the structural argument. No adjustment needed.

---

**FINAL VERDICT: READY** to circulate to Walch, Huq, Scheppele, Keller, Jaffer. The paper is at a defensible posture for first-impression cold reads by all five named candidates. The strongest section is §2 (the pattern), which now carries both Schmitt-Agamben and Hart engagement and articulates the structural-vs-political distinction with the hedging a jurisprudence reader expects. Optional polish items the human author may want to address before sending: (a) add a citation to Scheppele's emergency-law work somewhere in §2 or §3.5 to acknowledge her scholarship before asking her to read it; (b) consider whether the Gross/Ní Aoláin `Law in Times of Crisis` reference belongs in the §2 framing or the §7.4 cross-disciplinary-asymmetry paragraph; (c) review §3.4 (FISA 702) `Hasbajrami` paragraph with a 702 specialist reader before circulating to Jaffer. None of these is a blocker; all three are co-author-pass items that the legal-scholar reader will naturally flag.
