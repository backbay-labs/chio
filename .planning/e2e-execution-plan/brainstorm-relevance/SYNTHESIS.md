# Brainstorm Synthesis: Top Threads Across Logic / PL / DistSys / Mechanism Design

Date: 2026-05-19
Inputs: B1 logic-foundations, B2 pl-types-capability, B3 distsys-crypto, B4 mechanism-design

## Top 10 threads ranked by leverage

### #1 Cerise and Cerisier (capability-machine program logic in Iris)  [from B2]
- **Primary references**: Georges, Guéneau, Van Strydonck, Timany, Trieu, Devriese, Birkedal, "Cerise: Program Verification on a Capability Machine in the Presence of Untrusted Code," JACM 2024; "Cerisier: A Program Logic for Attestation in a Capability Machine," arXiv 2604.13638, 2026.
- **Bears on**: Parent paper §5 and §8; sensor-grounded paper §3 (attestation framing).
- **Action**: Cite both in the capability-OS paragraph of §8; one-sentence positioning of the runtime-receipt object against Cerise's program-logic object. Add Birkedal / Devriese to adversarial-reader pool.
- **Why this rank**: This is the single citation that lands on two papers in flight simultaneously and supplies the closest existing formal account of "what does an attested capability mean to a verifier?" Cerisier is brand new (2026) and directly attestation-shaped.

### #2 Sigstore CCS 2022 paper (Newman, Meyers, Torres-Arias)  [from B3]
- **Primary references**: Newman, Meyers, Torres-Arias, "Sigstore: Software Signing for Everybody," ACM CCS 2022, doi:10.1145/3548606.3560596.
- **Bears on**: Parent paper §8, transparency-and-supply-chain paragraph.
- **Action**: Add the CCS 2022 paper to bib.bib; cite immediately after the existing `sigstoreSecurity` reference. Surface Torres-Arias as adversarial-reader candidate.
- **Why this rank**: §8 currently leans on project documentation; this is a peer-reviewed primary citation that strengthens the supply-chain comparison without re-scoping any claim. Lowest cost, highest immediate paper impact.

### #3 Sigsum and the witness-cosigning tlog ecosystem  [from B3]
- **Primary references**: C2SP tlog-witness spec; Sigsum log + witness protocol; Syta et al., "Keeping Authorities Honest or Bust with Decentralized Witness Cosigning," IEEE S&P 2016 (CoSi).
- **Bears on**: Parent paper §5 (multi-lane anchor quorum) and §8 (supply-chain paragraph).
- **Action**: Add CoSi 2016 and the C2SP tlog-witness spec to bib.bib; cite in the multi-lane-anchor paragraph of §8.
- **Why this rank**: Parent paper's multi-lane anchor design is structurally a witness-quorum policy. The closest production analog is currently uncited. Cheap to add, names the design lineage.

### #4 Searle constitutive rules and the counts-as conditional (Hindriks, Grossi-Jones)  [from B1; cross-references B4 Thread 5]
- **Primary references**: Hindriks, "Constitutive Rules, Language, and Ontology," Erkenntnis 2009; Grossi & Jones, "Constitutive Norms and Counts-As Conditionals," Handbook of Deontic Logic vol. 1, 2013; Boella & van der Torre, "Regulative and Constitutive Norms in Normative Multiagent Systems," KR 2004.
- **Bears on**: Parent paper §7 (Hart framing) and §8.
- **Action**: Add Grossi-Jones 2013 and Hindriks 2009 to bib.bib; add one sentence to §7 noting that K is a counts-as conditional in the Searle-Hindriks sense.
- **Why this rank**: This is the single best terminology shift available: K-as-counts-as-conditional sharpens the Hart condition-(a) framing and broadens the audience to the deontic-logic / normative-MAS community without diluting the legal-positivist reading.

### #5 Judgment aggregation and the doctrinal paradox (List-Pettit, Dietrich)  [from B4]
- **Primary references**: List & Pettit, "Aggregating Sets of Judgments: An Impossibility Result," Economics and Philosophy 2002; Kornhauser & Sager, "Unpacking the Court," Yale L.J. 1986; Dietrich, "A Generalised Model of Judgment Aggregation," SCW 2007.
- **Bears on**: Parent paper §4 (treaty intersection) and §8.
- **Action**: Add a §8 paragraph framing treaty intersection as a degenerate premise-based aggregation; flag the discursive dilemma as the substrate's "two polities admit, conjunction rejects" warning.
- **Why this rank**: The treaty-intersection theorem is one of the four headline Lean results; pairing it with the canonical social-choice neighbor materially upgrades the paper's interdisciplinary reach.

### #6 Sunstein's incompletely theorized agreements  [from B4]
- **Primary references**: Sunstein, "Incompletely Theorized Agreements," Harvard L. Rev. 1995; Sunstein, Legal Reasoning and Political Conflict, OUP 1996.
- **Bears on**: Parent paper §7 and §8.
- **Action**: One sentence in §7 framing conjunctive admission as the substrate analog of incompletely theorized agreement; cite Sunstein 1995 in §8.
- **Why this rank**: Cleanest legal-theory import for the parent paper. Sunstein is read by both legal academics and CS reviewers, and the analogy ("agree on what to admit, disagree on why") is exact rather than performative.

### #7 FIDES and the LLMbda calculus (IFC for LLM agents)  [from B2]
- **Primary references**: Costa, Köpf, et al., "Securing AI Agents with Information-Flow Control," arXiv 2505.23643, 2025; "The LLMbda Calculus," arXiv 2602.20064, 2026.
- **Bears on**: Agentic-tool-safety workshop paper (entire related-work section); parent paper §6 selective-disclosure peripheral.
- **Action**: Add a paragraph to the workshop paper contrasting Chio's per-call signed admission with FIDES's label-propagating planner.
- **Why this rank**: NeurIPS workshop reviewers in this neighborhood will look for FIDES engagement; not having it is a credibility risk. Carries the workshop submission rather than the parent paper, but the deadline is the same week.

### #8 Morello-Cerise and CHERI formal semantics (upgrade existing cite)  [from B2]
- **Primary references**: Hammond, Almeida, Bauereiss, Campbell, Stark, Sewell, "Morello-Cerise: Strong Encapsulation for the Arm Morello Capability Hardware Architecture," 2025; Zaliva, Memarian, Almeida et al., "Formal Mechanised Semantics of CHERI C," ASPLOS 2024.
- **Bears on**: Parent paper §8.
- **Action**: Replace the generic CHERI cite in §8 with Morello-Cerise 2025 plus Zaliva ASPLOS 2024.
- **Why this rank**: §8 already cites CHERI; the existing reference is stale. Trivial cost, strictly better positioning of the hardware-capability vs receipt-emitted-admission contrast.

### #9 Verdi and Disel (verified distributed systems)  [from B3]
- **Primary references**: Wilcox et al., "Verdi: A Framework for Implementing and Formally Verifying Distributed Systems," PLDI 2015; Sergey, Wilcox, Tatlock, "Programming and Proving with Distributed Protocols" (Disel), POPL 2018.
- **Bears on**: Parent paper §8 (verified-systems enumeration); V2 tier-1 federation as adversarial-reader insurance.
- **Action**: Add Verdi and Disel to bib.bib; cite both in the §8 verified-systems sentence next to the existing IronFleet citation. Surface Wilcox and Tatlock as co-author candidates for the V2 companion paper.
- **Why this rank**: §8 currently enumerates verified-systems work; Verdi and Disel are conspicuously missing from a list that includes IronFleet. Closes a small but visible gap.

### #10 Daian-Kell Flash Boys 2.0 (MEV as governance attack)  [from B4]
- **Primary references**: Daian et al., "Flash Boys 2.0: Frontrunning, Transaction Reordering, and Consensus Instability in Decentralized Exchanges," IEEE S&P 2020, arXiv:1904.05234.
- **Bears on**: Parent paper §8 governance-comparison paragraph.
- **Action**: Add Daian-Kell 2020 to §8 alongside the existing compoundProposal289 citation; one sentence framing MEV as ordering-channel governance bypass that the amendment-refinement theorem is designed against.
- **Why this rank**: Makes the parent paper's amendment-refinement threat model explicit against the canonical published example. Cornell IC3 (Daian, Kell, Juels) is the reviewer pool for governance-attack claims; this is preemptive engagement.

## Cross-scout patterns

Three threads surfaced in two scout files independently, which is high signal:

- **Input/output logic (Makinson, van der Torre)**: B1 Thread 1 and B4 Thread 4 both name it. B1 frames it as the formal-logic ancestor of K (admission predicate); B4 frames it as the formal vocabulary for the Hart-sociological paper. Two independent scouts pointing at the same Luxembourg-Turin group is the strongest signal in the synthesis.
- **Van der Torre / Boella normative-MAS lineage**: B1 Thread 8 (constitutive rules) and B4 Thread 5 (normative multi-agent systems) both arrive at the same authors via different paths. Combined with the I/O-logic convergence, van der Torre is the most-named author across the brainstorm.
- **Searle / counts-as conditionals**: B1 Thread 8 (constitutive rules formalized) and B4 Thread 5 (constitutive norms in NMAS) both surface this. Hindriks 2009 and Grossi-Jones 2013 are the canonical citations.

Cross-scout pattern interpretation: the deontic-logic / normative-MAS community at Luxembourg-Turin is the single most consequential under-engaged audience for the parent paper. Van der Torre is the co-author candidate the brainstorm converges on.

## Co-author / adversarial-reader shortlist

| Name | Role | Best fit for | Reachability |
|---|---|---|---|
| Leendert van der Torre (Luxembourg) | Co-author / adversarial reader | Hart-sociological paper (paper 3); parent paper §7-§8 | High; continuous publication 2005-2025 in normative-MAS + I/O logic |
| Lars Birkedal (Aarhus) | Adversarial reader | Parent paper §5/§8; sensor-grounded paper | High; Cerise / Cerisier author group |
| Dominique Devriese (Vrije Universiteit Brussel) | Adversarial reader | Parent paper §5; capability-bounded dispatch | High; Cerise co-author |
| Justin Cappos (NYU) | Adversarial reader | Parent paper §8 supply-chain | High; in-toto lead, USENIX regular |
| Santiago Torres-Arias (Purdue) | Adversarial reader | Parent paper §8 | High; Sigstore CCS 2022 first author |
| Jeremy Avigad (CMU) | Adversarial reader | Parent paper §7 (Hart positivism, what mechanization buys) | Medium; CMU Philosophy + Math |
| Zachary Tatlock (UW) | Co-author / adversarial reader | V2 tier-1 / Paper 5 verified federation | Medium; Verdi, Disel co-author |
| James Wilcox (UW) | Co-author candidate | V2 tier-1 companion paper | Medium; Verdi PLDI 2015 first author |
| Chad Kell / Ari Juels (Cornell IC3) | Adversarial reader | Parent paper §8 governance-comparison | Medium; canonical MEV / governance-attack reviewers |
| Chelsea Komlo / Tim Ruffing | Co-author for V7 / Paper 5 | Future threshold-cosigning paper | Medium; FROST + ROAST authors |
| Guido Governatori (Data61) | Adversarial reader | Parent paper §7-§8; defeasible-deontic alternative | Medium; canonical defeasible-deontic author |
| Davide Grossi (Groningen) | Co-author candidate | Hart-sociological paper; parent §7 | Medium; counts-as conditional handbook chapter |

## What to do this week (concrete next-steps)

1. Add to bib.bib in a single commit: Newman-Meyers-Torres-Arias CCS 2022 (Sigstore), Carneiro 2024 (Lean4Lean), Grossi-Jones 2013 (counts-as), Hindriks 2009 (constitutive rules), List-Pettit 2002 (judgment aggregation), Sunstein 1995 (incompletely theorized agreements), Verdi 2015, Disel 2018, Morello-Cerise 2025, Zaliva ASPLOS 2024, Daian-Kell 2020, Syta CoSi 2016. This is one mechanical pass with a fixed citation list.
2. Edit §8 in two ranges: (a) replace generic CHERI cite with Morello-Cerise + Zaliva ASPLOS; (b) add CCS Sigstore + Syta CoSi + tlog-witness next to existing supply-chain cites; (c) add Verdi + Disel next to IronFleet; (d) one Daian-Kell sentence next to compoundProposal289.
3. Edit §7 in two short additions: (a) one sentence framing K as a counts-as conditional citing Grossi-Jones and Hindriks; (b) one sentence framing conjunctive admission as Sunstein-incompletely-theorized-agreement.
4. Draft the FIDES / LLMbda contrast paragraph for the agentic-tool-safety workshop submission. Same deadline week as the parent paper; do not let it slip.
5. Send a one-paragraph note to van der Torre's group at Luxembourg flagging the I/O-logic / counts-as conditional framing and asking whether they would be willing to read a draft. This is the highest-payoff outreach the brainstorm surfaced and the only one with two independent scouts converging on it.

## What to skip

- **Reverse mathematics and concrete incompleteness (B1 Thread 6)**: ranked but does not fit the USENIX submission. Hold Friedman as adversarial-reader for a future essay venue only.
- **Refinement types / RefinedRust / Flux (B2 Threads 7-8)**: ranked but explicitly sleeper-tier for a future verified-kernel paper. Do not pursue under the current portfolio's deadlines.
- **Multris / deadlock-free separation logic (B2 Thread 3)**: ranked but gated on revival of the trajectory-invariant POPL paper. Do not cite in current submissions.
- **Effekt / capability-as-effect (B2 Thread 10)**: hold for rebuttal use only.
- **TLA+ HotStuff / Tendermint, Ivy (B3 Threads 5, 7)**: V2 tier-1 design-memo material, not parent paper.
- **BLS aggregate signatures, Polygraph (B3 Threads 3-4, 8)**: V7 / Paper 5 future work; bibliography preparation premature for the current submission.
- **Public choice / Buchanan-Tullock (B4 Thread 7)**: tempting framing but adds an economics literature the parent paper does not currently engage; defer to a Hart-paper revival rather than pad §8.
- **Matching markets / Roth (B4 Thread 10)**: ranked but the analogy is decorative; "willing counterparty" reads cleanly without the Roth-Sotomayor citation, and adding it would invite imprecision objections about preference structure.

The scout file with the most consequential findings is **B2 (PL / types / capability / separation logic)**: Cerise / Cerisier alone lands on two papers in flight, and the FIDES thread carries the workshop submission. B3 (distsys / crypto) is a close second on §8 supply-chain density.
