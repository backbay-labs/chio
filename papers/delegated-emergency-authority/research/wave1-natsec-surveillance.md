# Wave 1B: National-security + surveillance law audit

## 1. The AUMF "at least eight countries" claim

The intro states: "The authorization has been cited as legal basis in at least eight named theaters by 2024 \cite{TODO_jaffer_aumf}." §3.3 (Cases §3.5, on the file's numbering) repeats: "By 2024, the authorization had been cited as legal basis for armed action in at least eight named theaters."

The "eight" number is *defensible but the citation is wrong*. Jaffer's *Drone Memos* (2016) cannot support a 2024 country count by date alone. The authority the paper actually wants is the executive branch's own running list, plus CRS tracking:

- The Trump administration's December 2018 *Report on the Legal and Policy Frameworks Guiding the United States' Use of Military Force* (the "Section 1264 Report," following NDAA FY18 §1264) named seven countries where US forces operated under the 2001 AUMF: Afghanistan, Iraq, Syria, Yemen, Somalia, Libya, the Philippines, plus Niger and Kenya identified in earlier reports. CRS's *2001 Authorization for Use of Military Force: Issues Concerning Its Continued Application* (R43983, updated through 2023) tracks the running list and Matthew Weed / Heidi Peters' running tally puts the named theaters at 8–9 by the early 2020s once ISIS-affiliate operations in West Africa are added.
- The Biden administration's 2021 and 2023 War Powers Resolution §4(a)(1) periodic reports, transmitted to Congress under 50 USC §1543, are the load-bearing public document.

Proposed rewrite: replace `\cite{TODO_jaffer_aumf}` with `\cite{CRS_R43983_AUMF,DoD_1264_2018_report}` and either (a) lower the number to "at least seven, with named operations also reported in Niger, Kenya, and other African theaters" or (b) keep "at least eight" but anchor it to the 2018 Section 1264 Report plus subsequent War Powers Resolution transmittals. Do *not* cite Jaffer for the country count — cite him for the legal-theory critique.

## 2. "Structural-grammar failure not political failure"

The most aggressive sentence is in §1 introduction: "The pattern is not a failure of legislative will so much as a structural feature of the original grant... The political coalition required to enact a replacement is the same coalition required to enact a repeal, and that coalition has not assembled in twenty-five years." §3.5 of the case-studies section repeats this as "the equilibrium failure described in Part~\ref{sec:pattern}."

This is internally inconsistent. The paper *describes* the failure mode in political-equilibrium terms (the same coalition needed for repeal and replacement) and then *labels* it structural. The Kaine-Young AUMF Repeal Act (S.1228, 116th Congress, 2019; reintroduced repeatedly through the 119th), Lee-Murphy proposals, the bipartisan 2023 repeal of the 1991 and 2002 Iraq AUMFs (which Biden signed but which left the 2001 AUMF intact), and the Corker-Kaine 2018 framework all show that the political coalition for replacement has in fact partially assembled — it has just been unable to converge on a successor. That is a political-economy story, not a typed-grammar story.

Proposed hedge (replace the "not a failure of legislative will" sentence): "The pattern admits both a political and a structural reading. A run of bipartisan repeal-and-replace proposals — including Kaine-Young, Lee-Murphy, and the 2023 repeal of the 1991 and 2002 Iraq AUMFs — demonstrates that the political coalition for repeal has at times assembled. What has not converged is agreement on a successor authority. The structural reading we develop does not displace the political account; it identifies an additional feature of the original grant that lowers the cost of continuation relative to replacement at each successive period."

## 3. FISC opinions and PCLOB engagement in §3.5

§3.5 cites generically: "the declassified opinions of the Foreign Intelligence Surveillance Court \cite{TODO_fisc_702_opinions}" and "The Privacy and Civil Liberties Oversight Board's 2014 report on the Section~702 program \cite{TODO_pclob_702_report}." No specific docket, no specific recommendation number.

Essential additions:
- *In re DNI/AG 702(g) Certifications*, FISC Mem. Op. (Bates, J., Oct. 3, 2011), declassified August 2013 — the upstream-collection "MCT" opinion that found a Fourth Amendment violation and forced minimization changes.
- *Memorandum Opinion and Order*, FISC (Collyer, J., April 26, 2017) — the opinion that disclosed compliance failures in upstream "about" collection and led NSA to halt about-collection.
- *Memorandum Opinion and Order*, FISC (Boasberg, J., Oct. 18, 2018), declassified 2019 — querying-procedure compliance.
- *Memorandum Opinion and Order*, FISC (Contreras, J., April 21, 2022), declassified May 2023 — FBI query compliance findings cited in the 2023–24 reauthorization debate.
- PCLOB, *Report on the Surveillance Program Operated Pursuant to Section 702 of the Foreign Intelligence Surveillance Act* (July 2, 2014); PCLOB, *Recommendations Assessment Report* (Jan. 2017); PCLOB, *Report on the Section 702 Surveillance Program* (Sept. 2023).

## 4. Section 702-vs.-emergency-authorization conflation

The introductory paragraph reads: "The Foreign Intelligence Surveillance Act's emergency authorization regimes, including the seventy-two hour emergency authorization in 50 U.S.C. \S~1881a(c) (Section~702), permit the Attorney General to authorize a surveillance program in advance of judicial approval where the Attorney General determines that an emergency exists."

This sentence frames *Section 702 itself* as an "emergency authorization regime." That is wrong. Section 702 is a programmatic certification authority for targeting non-US persons abroad; it is reviewed annually by the FISC under §1881a(j). The seventy-two-hour mechanism in §1881a(c)(2) is a narrow within-section sub-provision that permits the AG and DNI to determine targeting prior to court approval of a *new* certification. The §3.5 heading "FISA Section 702: emergency surveillance authorizations" reproduces the conflation.

Proposed rewrite for §1: "Section 702 of FISA, codified at 50 U.S.C. §1881a, governs programmatic acquisition of foreign-intelligence information from non-US persons reasonably believed to be located abroad. The program is not itself an emergency authority, but §1881a(c)(2) contains a sub-provision permitting the Attorney General and Director of National Intelligence to authorize targeting prior to FISC approval of a new certification. That sub-provision, and its interaction with the broader §702 retention and querying framework documented in declassified FISC opinions and PCLOB reports, exhibits the structural pattern this Article identifies." Rename §3.5 to "FISA Section 702: programmatic acquisition and its emergency sub-provision."

## 5. "Irreversible by construction" against the actual retention regime

§1 says: "The information collected during the emergency window remains in the holdings of the collecting agency... The targets do not return to a prior state." §3.5 repeats: "The information collected under an emergency authorization remains in the holdings of the collecting agency even if the authorization is later determined to have been improperly granted... The collected information persists."

This elides four rollback-adjacent mechanisms in current law: (a) §1881a(i)(3)(B) deficiency-correction and destruction orders by the FISC; (b) 50 USC §1809(a)(2) criminal prohibition on use/disclosure of unlawfully acquired FISA information, which has been read to require purges; (c) the standard five-year retention default in NSA, FBI, and CIA §702 minimization procedures, with shorter defaults for US-person communications after the 2018 amendments; and (d) the 2023–2024 querying-procedure compliance regime requiring documented justification and audit of US-person queries.

Proposed hedge in §3.5: insert a paragraph: "Existing law contains rollback-adjacent mechanisms — FISC-ordered destruction of unlawfully acquired material under §1881a(i)(3), the §1809(a) criminal bar on use of unlawfully acquired information, the five-year retention defaults in approved minimization procedures, and the post-2018 querying procedures. These mechanisms are partial: they operate at the audit and lapse steps rather than at the admission step, they do not bind the upstream collection, and they are not constructively reversible witnesses in the sense Part~\ref{sec:grammar} develops. The structural claim we advance is not that the regime contains no reversibility apparatus, but that the apparatus it contains is not of the form a typed rollback witness would supply."

## 6. Public-record items the paper is missing

Essential to engage (the paper cannot ship to YLJ without these):
- *FISA Amendments Reauthorization Act of 2017* (Pub. L. 115-118) and *Reforming Intelligence and Securing America Act* / 2024 §702 reauthorization (Pub. L. 118-49) — the paper claims §702 has no rollback obligation while ignoring the two most recent reauthorization rounds where Congress *did* tighten querying procedures, abouts-collection prohibition (§103 of FRRA 2018), and FBI query audits.
- *Clapper v. Amnesty International USA*, 568 U.S. 398 (2013) — standing doctrine that has structured the entire §702 litigation landscape and frames why the "targets do not return to a prior state" claim is non-justiciable in the way the paper assumes.
- *United States v. Hasbajrami*, 945 F.3d 641 (2d Cir. 2019) — the only federal-appellate merits decision on §702 querying of US-person information; directly relevant to the rollback-mechanisms point in §5.

Nice-to-have:
- *Smith v. Obama*, 816 F.3d 1239 (9th Cir. 2016) and *ACLU v. Clapper*, 785 F.3d 787 (2d Cir. 2015) — these are §215 metadata cases, not §702 cases, but they bear on the "ratcheting after USA FREEDOM Act" sub-story the paper does not yet tell.

## Bottom line

The §3.5 FISA chapter would not survive a hostile review by a reader familiar with declassified FISC opinions in its current state, and the AUMF chapter's "structural not political" claim is exposed without the Kaine-Young hedge. Both sections are recoverable with bounded edits — the conflation of Section 702 with its sub-provision (item 4) and the elision of existing rollback-adjacent mechanisms (item 5) are the two issues most likely to draw a "the author has not read the FISC opinions" reviewer comment, and both fixes are paragraph-scale rather than rewrites. Add the 2018 Section 1264 Report and CRS R43983 for the country count, swap the Jaffer cite to a legal-theory citation rather than a head-count one, and add specific FISC docket numbers and the 2024 RISAA reauthorization, and §§3.3 and 3.5 reach a defensible posture. Without those edits, a Brennan Center or Lawfare reviewer would conclude that the structural framing was advanced without engaging the public record that constrains it.
