# Wave 2B: §1 introduction and §2 pattern hedge fixes

This pass implements the seven framing hedges Wave 1 identified as needing to land before §3 case studies are read. All edits are confined to `sections/01-introduction.tex` and `sections/02-pattern.tex`.

## Fix A: Article 48 historiography hedge in §1 (Wave 1A finding 2 and 4)

(i) Original: "The transition from emergency power to instrument of dictatorship occurred along a continuous trajectory."

(ii) New: "The transition from emergency power to instrument of dictatorship occurred through a sequence of contested political decisions, each conducted within a constitutional grammar that did not require lapse-by-construction."

In addition, the §1 narrower-defensible-claim sentence at the end of the central-claim paragraph now carries the political-pressure hedge. Original tail: "and that its presence would have made the same pattern structurally unavailable." New tail: "and that its presence would have made the same pattern structurally unavailable, although the political pressure that produced the underlying decrees would have remained." (The "would have made decrees unconstructible" wording the brief quoted lives in §3.1, which was out of scope; the equivalent §1 sentence carries the hedge instead.)

(iii) Addresses Wave 1A findings 2 (Kershaw / Mommsen / Caldwell historiographical contestation) and 4 (strong-vs-weak ratchet slippage).

## Fix B: Schmitt as normatively defensible in §2.1 (Wave 1A finding 1)

(i) Original §2.1 closes the Schmitt-Agamben framing with: "The Article does not take a position on whether the political-theological reading of sovereignty is correct. It takes Agamben's empirical claim..."

(ii) New: adds three sentences immediately after that passage stating (a) for Schmitt the constitutive character of the decision is normatively defensible under conditions of genuine emergency, (b) this Article's structural argument is incompatible with that normative view rather than orthogonal to it, and (c) a Schmittian who accepts the constitutive sovereign decision will read the typed rollback witness and the disciplined wrapper as the Kelsenian-formalist disease the 1922 essay diagnosed, not as a corrective. Citation `\cite{TODO_caldwell_popular_sovereignty,TODO_dyzenhaus_legality_legitimacy}` added.

(iii) Addresses Wave 1A finding 1 (Schmittian normative position elided).

## Fix C: AUMF political-equilibrium hedge in §1 (Wave 1B finding 2)

(i) Original: "The pattern is not a failure of legislative will so much as a structural feature of the original grant... The political coalition required to enact a replacement is the same coalition required to enact a repeal, and that coalition has not assembled in twenty-five years."

(ii) New: "The pattern admits both a political and a structural reading. A run of bipartisan repeal-and-replace proposals, including Kaine-Young, Lee-Murphy, and the 2023 repeal of the 1991 and 2002 Iraq AUMFs that left the 2001 AUMF intact, demonstrates that the political coalition for repeal has at times assembled. What has not converged is agreement on a successor authority. The structural reading this Article advances does not displace the political account; it identifies an additional feature of the original grant that lowers the cost of continuation relative to replacement at each successive period." Citations `\cite{TODO_kaine_young_aumf,TODO_iraq_aumf_repeal_2023}` added.

(iii) Addresses Wave 1B finding 2 (internal inconsistency between political-equilibrium description and structural label).

## Fix D: Section 702 sub-provision disambiguation in §1 (Wave 1B finding 4)

(i) Original: "The Foreign Intelligence Surveillance Act's emergency authorization regimes, including the seventy-two hour emergency authorization in 50 U.S.C. §1881a(c) (Section 702), permit the Attorney General to authorize a surveillance program in advance of judicial approval..."

(ii) New: "Section 702 of FISA, codified at 50 U.S.C. §1881a, governs programmatic acquisition of foreign-intelligence information from non-US persons reasonably believed to be located abroad. The program is not itself an emergency authority, but §1881a(c)(2) contains a sub-provision permitting the Attorney General and Director of National Intelligence to authorize targeting prior to FISC approval of a new certification. That sub-provision, and its interaction with the broader §702 retention and querying framework documented in declassified FISC opinions and PCLOB reports, exhibits the structural pattern this Article identifies."

(iii) Addresses Wave 1B finding 4 (Section 702 program conflated with its emergency sub-provision).

## Fix E: Section 230 vs. DMCA 512 separation in §1 (Wave 1C finding 1)

(i) Original: "Section 230 of the Communications Decency Act, although not in its primary form a takedown regime, operates in conjunction with the Digital Millennium Copyright Act's notice-and-takedown procedure ... to produce content removals that share the structural shape of a time-bounded executive act."

(ii) New: separated paragraph that (a) characterizes §230(c)(1) as a liability shield and §230(c)(2) as a good-faith restriction safe-harbor, (b) identifies DMCA §512 as the formal notice-and-takedown regime and §512(g) counter-notice as a partial rollback mechanism, (c) reframes the structural claim as "Section 230's incentive shadow produces takedown-like behavior in platform self-regulation, though the statute itself does not authorize takedown," and (d) concedes that the Section 230 academy (Goldman, Citron, Keller) disputes the characterization. Citations `\cite{TODO_section230_shield,TODO_dmca_512g_counter_notice,TODO_goldman_section230_2019,TODO_keller_overremoval_2015}` added.

(iii) Addresses Wave 1C finding 1 (Section 230 conflated with DMCA 512, missing §512(g) counter-notice as actual rollback path).

## Fix F: GDPR Article 17 irreversibility hedge in §1 (Wave 1C finding 5)

(i) Original: "A search-engine index from which a result has been removed is not, in any practical sense, restored to its prior shape by the lapse of the order."

(ii) New: "A search-engine index from which a result has been removed is not, on the regulation's default operation, restored, although the underlying balance is re-evaluable and the controller may re-index where the supporting facts change."

(iii) Addresses Wave 1C finding 5 (irreversibility overclaim against CJEU re-evaluability).

## Fix G: Lift §3.1 historiography hedge into §2.2 (Wave 1A finding 2)

(i) Original §2.2 opens directly with: "Once the question is posed in structural terms, the historical record yields a recurring shape that does not appear to be reducible to political contingency alone."

(ii) New §2.2 opens with a hedge paragraph: names the Kershaw / Mommsen / Caldwell dispute on whether the 1930-32 Brüning emergency-rule period was structurally entailed by Article 48 or politically contingent on Hindenburg's preferences and SPD tactical toleration; restates the weaker claim that the absence made the outcome structurally available rather than inevitable; ties back to the Schmittian normative position canvassed in §2.1. Citations `\cite{TODO_kershaw_hitler,TODO_mommsen_weimar,TODO_caldwell_popular_sovereignty}` added.

(iii) Addresses Wave 1A finding 2 (hedge in §3.1 needs to land before structural argument is asserted).

## Build verification

`pdflatex -interaction=nonstopmode paper.tex` exits 1 with 12 `^!` undefined-control-sequence errors, all of which are pre-existing in `sections/04-grammar.tex` (uses of `\text{...}` without `amsmath` loaded) and unrelated to this pass. The §1 and §2 files compile cleanly, and the PDF generates: page count went from 19 to 20, consistent with the added hedge paragraphs. No em dashes were introduced. The systems-paper vocabulary is held to the paper's existing core terms ("typed rollback witness," "disciplined wrapper") and no new CS jargon ("payload," "well-typed," "type-check," "construct") was introduced into §1 or §2 prose by these edits.
