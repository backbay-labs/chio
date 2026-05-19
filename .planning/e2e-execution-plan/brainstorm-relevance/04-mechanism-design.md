# Brainstorm B4: Mechanism Design + Computational Social Choice

Date: 2026-05-19
Scope: mechanism design, computational social choice, formal governance theory, normative multi-agent systems

## Threads found

### Thread 1: Judgment aggregation and the doctrinal paradox

- **Primary references**: List & Pettit, "Aggregating Sets of Judgments: An Impossibility Result," Economics and Philosophy 18 (2002); Kornhauser & Sager, "Unpacking the Court," Yale L.J. 96 (1986); Dietrich, "A Generalised Model of Judgment Aggregation," Social Choice and Welfare 28 (2007); Endriss, Grandi & Porello, "Complexity of Judgment Aggregation," J. of AI Research 45 (2012).
- **What the thread is about**: judgment aggregation generalizes Arrow-style social choice from preference orderings to logically-structured propositional verdicts. The premise-based vs conclusion-based dichotomy distinguishes "decide each premise by majority and entail the conclusion" from "decide each conclusion directly." Closure of judgment sets under intersection is precisely the meet operation on a Boolean lattice of admissible sets.
- **Bears on which Chio paper**: parent paper, treaty-intersection theorem (§4 model, §8 related work). The substrate's "joint admission predicate = intersection of constituent admission predicates" is structurally identical to a premise-based aggregation where each polity is a "premise voter" and admission of a receipt is the conjunctive conclusion. The discursive-dilemma result is the right warning sticker: predicate intersection can reject receipts every individual polity would admit individually, when the predicates are over different sub-claims.
- **Leverage**: cite-in-§8 (parent paper) plus discussion in §7 -- this is the natural social-choice neighbor and Chio's intersection is structurally a premise-based aggregation rule. Sleeper-tier for a future Hart-sociological paper (Paper 3) where the analog of "officials" is "polities aggregating verdicts."
- **One-line action**: add a §8 paragraph citing List-Pettit and Dietrich, framing treaty intersection as a degenerate premise-based aggregation where premises are independent polity predicates and conclusion is admission; flag the dilemma as the substrate's analog of "what if two polities admit a receipt but their conjunction does not."

### Thread 2: Ontology merging and logic aggregation as social choice

- **Primary references**: Porello & Endriss, "Ontology Merging as Social Choice: Judgment Aggregation under the Open World Assumption," CLIMA 2011 / JLC 24 (2014); Pigozzi, "Belief Merging and the Discursive Dilemma," Synthese 152 (2006); Endriss & Grandi, "Binary Aggregation by Selection of the Most Representative Voter," AAAI 2014.
- **What the thread is about**: when several agents bring logical theories (predicate sets) and need to produce a single merged theory, what aggregation rules are consistent? The "intersection" rule -- accept a formula iff every agent endorses it -- is one extreme of a spectrum of merging operators. The literature characterizes when intersection vs majority vs weighted merging is socially desirable.
- **Bears on which Chio paper**: parent paper §4 (model) and §8 (related work). The amendment-refinement lemma -- new predicate set must accept everything the old set accepted -- is literally a constraint that the merging operator be a refinement (subset on admitted-receipt extensions). Porello-Endriss is the right citation for "we are doing logic aggregation, here is the formal vocabulary."
- **Leverage**: cite-in-§8. Less than Thread 1 because it is the same neighborhood, but supplies the open-world-assumption framing which is closer to Chio's semantics than the closed-world political-vote framing of List-Pettit.
- **One-line action**: cite Porello-Endriss in §8 as the formal home for "predicate-set merging under intersection" and the open-world assumption their construction makes (formula not in any agent's theory ≠ formula rejected).

### Thread 3: Transaction-fee mechanism design and credible neutrality

- **Primary references**: Roughgarden, "Transaction Fee Mechanism Design," EC 2021 / arXiv:2106.01340; Buterin, "Credible Neutrality As A Guiding Principle," Nakamoto.com (2020); Chung & Shi, "Foundations of Transaction Fee Mechanism Design," SODA 2023; collusion-resilience follow-ups (Bahrani, Roughgarden et al., arXiv:2402.09321).
- **What the thread is about**: Roughgarden formalizes EIP-1559 as a mechanism-design problem with three incentive-compatibility conditions: user-side DSIC, miner-side MMIC (myopic miner incentive compatibility), and OCA-proofness (off-chain agreements). Credible neutrality is the dual property: "a mechanism is credibly neutral if you can read the mechanism and see it does not favor anyone."
- **Bears on which Chio paper**: parent paper §7 (discussion) and the delegated-emergency-authority paper. Chio's admission predicate is a credibility-neutral mechanism in Buterin's exact sense -- it can be inspected before any receipt arrives. The "fail-closed admission" property is a strong form of one-sided neutrality (rejection is mechanically determined, admission requires affirmative checks).
- **Leverage**: cite-in-§7-and-§8 for parent. Adversarial-reader insurance for paper 2: Roughgarden is the standard reference if a CS reviewer challenges the mechanism-design framing as imprecise.
- **One-line action**: add Roughgarden 2021 and Buterin's credible-neutrality essay to §8, framing the admission predicate as a credibly-neutral one-sided mechanism, contrasting with EIP-1559's two-sided fee market.

### Thread 4: Input-output logic for normative reasoning

- **Primary references**: Makinson & van der Torre, "Input/Output Logics," Journal of Philosophical Logic 29 (2000); Makinson & van der Torre, "Constraints for Input/Output Logics," JPL 30 (2001); Parent & van der Torre, "Input/Output Logic," in Handbook of Deontic Logic and Normative Systems Vol. 1 (College Publications, 2013); van der Torre et al., "Ten Philosophical Problems in Deontic Logic," NorMAS 2007.
- **What the thread is about**: a framework for "given inputs (facts, situations), what outputs (obligations, permissions) follow under a set of conditional norms?" Critically, the framework decouples "what the norms say to be obligatory" from "what is necessarily the case" -- exactly the separation Chio needs between "what a constitution says about admissibility" and "what is admissible at the runtime."
- **Bears on which Chio paper**: Hart-sociological paper (paper 3, sleeping) and parent paper §3-§4 (substrate, model). Input-output logic is the right formal vocabulary if the Hart paper develops the predicate-as-norm reading. Conditional norms with constraints are essentially what amendment witnesses are.
- **Leverage**: sleeper-tier-for-future-paper. Not load-bearing for the parent's USENIX-class submission but the natural foundation for the Hart paper if/when it is awoken. Could also be the bridge to a normative-MAS audience for the agentic-tool-safety paper.
- **One-line action**: park in the Hart-paper bibliography; do not cite in the parent paper unless §8 grows a normative-MAS subsection. Worth a brief mention if §7 expands the "predicates as norms not facts" point.

### Thread 5: Normative multi-agent systems and constitutive norms

- **Primary references**: Boella, van der Torre & Verhagen, "Introduction to Normative Multiagent Systems," Computational and Mathematical Organization Theory 12 (2006); Boella, Pigozzi & van der Torre, "Normative Systems in Computer Science -- Ten Guidelines for Normative Multiagent Systems," Dagstuhl Seminar Proceedings 09121 (2009); Hübner, Sichman & Boissier, "Moise+: Towards a Structural, Functional, and Deontic Model for MAS Organisation," SBIA 2002 / J. Auton. Agents 8 (2007); Boella & van der Torre, "Constitutive Norms in the Design of Normative Multiagent Systems," CLIMA 2006.
- **What the thread is about**: programmable institutions composed of agents whose behavior is shaped by explicit norms. The constitutive-vs-regulative norm distinction (Searle / Boella) is precisely Hart's primary-vs-secondary rule distinction in a CS-amenable formalism. MOISE+ supplies a deontic specification language for role hierarchies.
- **Bears on which Chio paper**: Hart-sociological paper (paper 3) and agentic-tool-safety paper. The constitutive-norm framing -- "this counts as a receipt of type T under polity P" -- is what the Hart paper would formalize as Hart's condition (a) operationally. MOISE+'s deontic-component language is a precedent for treating roles + obligations as a typed object.
- **Leverage**: co-author-candidate plus sleeper-tier-for-future-paper. Van der Torre (Luxembourg) and Boella (Turin) have published continuously in this space since 2005 and would be natural reviewers (or co-authors) for the Hart paper. Their handbook also overlaps with the agentic-tool-safety framing.
- **One-line action**: shortlist van der Torre and Boella as candidate co-authors / adversarial reviewers for paper 3 (Hart sociological). Do not cite in parent paper yet; the substrate predates the normative-MAS framing and the citation would be performative.

### Thread 6: Computational complexity of voting manipulation

- **Primary references**: Conitzer & Sandholm, "Universal Voting Protocol Tweaks to Make Manipulation Hard," IJCAI 2003; Conitzer, Sandholm & Lang, "When Are Elections with Few Candidates Hard to Manipulate?" J. ACM 54 (2007); Faliszewski & Procaccia, "AI's War on Manipulation: Are We Winning?" AI Magazine 31 (2010); Brandt et al., Handbook of Computational Social Choice (CUP, 2016), chapters 6-7.
- **What the thread is about**: Gibbard-Satterthwaite says every nondictatorial voting rule is manipulable; the CS response is to make manipulation NP-hard rather than impossible. The handbook is the canonical reference.
- **Bears on which Chio paper**: parent paper §7 (amendment governance) and the delegated-emergency-authority paper. Chio's amendment path requires a Lean refinement witness -- this is a mechanism that is not just hard to manipulate but unconditionally rejects manipulation when no proof obtains. The CS literature on voting manipulation is the obvious contrast class.
- **Leverage**: cite-in-§7. The framing claim -- "Chio's amendment is proof-bound rather than complexity-bound governance" -- is exactly the kind of mechanism-design contrast that strengthens the parent's narrative without overclaiming.
- **One-line action**: one paragraph in §7 contrasting proof-bound amendment with complexity-of-manipulation defenses; cite Conitzer-Sandholm 2007 and the handbook chapter.

### Thread 7: Public choice and the calculus of constitutional consent

- **Primary references**: Buchanan & Tullock, The Calculus of Consent (1962); Buchanan, The Limits of Liberty (1975); Brennan & Buchanan, The Reason of Rules (1985); Buchanan, "An Economic Theory of Clubs," Economica 32 (1965).
- **What the thread is about**: constitutional rules are different from in-system rules -- unanimity is more appropriate at the constitutional stage because it minimizes external cost across the indefinite future of decisions made under the rule. Club theory gives the voluntary-association case directly.
- **Bears on which Chio paper**: parent paper §7 (discussion of constitutional fork), delegated-emergency-authority paper (Sunset / unanimity / pre-commitment), and Hart paper (paper 3). The "treaty as voluntary join with full predicate intersection" is precisely a constitutional-stage unanimity rule with a club good (the federated receipt namespace). Polities that fork rather than federate are Buchanan-Tiebout sorting at the club boundary.
- **Leverage**: cite-in-§7-and-§8. Public choice is the missing economics frame for "why would two polities federate vs fork" and the delegated-emergency paper benefits from the Buchanan-Brennan rules-vs-discretion contrast.
- **One-line action**: add one paragraph to §7 framing the constitutional-fork / federation choice as Buchanan-club selection under unanimity, with Tiebout sorting as the exit valve; cite Buchanan-Tullock 1962 and Buchanan 1965 in §8.

### Thread 8: Schauer ruleness and the rules-vs-standards spectrum (cross-reference, not duplicate)

- **Primary references**: Schauer, Playing by the Rules (OUP, 1991) -- already in bib; Schauer, "Rules and the Rule of Law," Harvard JLPP 14 (1991); Schauer, "Profiles, Probabilities, and Stereotypes" (HUP, 2003); Sunstein & Ullmann-Margalit, "Second-Order Decisions," Ethics 110 (1999).
- **What the thread is about**: the rules-vs-standards literature gives a vocabulary for "ruleness" -- the degree to which a directive precommits the decider against case-by-case adjustment. Sunstein's second-order-decisions essay is the bridge: choosing when to use rules vs standards is itself a choice problem.
- **Bears on which Chio paper**: parent paper §7 (already cites Schauer) and delegated-emergency-authority paper (very directly -- whether to write a sunset clause is a second-order decision). Sunstein's incompletely-theorized agreements thread is separate and lives in Thread 9.
- **Leverage**: not-cite-worthy-as-new (already cited) but Sunstein-Ullmann-Margalit "Second-Order Decisions" is a useful add for the emergency paper.
- **One-line action**: add Sunstein-Ullmann-Margalit 1999 to the delegated-emergency-authority bib as the "meta-rule" reference where the Schauer ruleness scale gets normative bite.

### Thread 9: Sunstein's incompletely theorized agreements

- **Primary references**: Sunstein, "Incompletely Theorized Agreements," Harvard L. Rev. 108 (1995); Sunstein, "Incompletely Theorized Agreements in Constitutional Law," Soc. Res. 74 (2007); Sunstein, Legal Reasoning and Political Conflict (OUP, 1996).
- **What the thread is about**: people can agree on particulars without agreeing on the principle; constitutional stability comes from precisely such agreements. The relevance to Chio: two polities that disagree on the reasons their constitutions adopt a predicate may still federate under the intersection, which becomes the operational analog of an incompletely theorized agreement.
- **Bears on which Chio paper**: parent paper §7. Strongest fit: the treaty-intersection theorem is the substrate's machine-checkable analog of "agree on what to admit, disagree on why."
- **Leverage**: cite-in-§7. This is the single best framing import from constitutional theory for the parent paper -- Sunstein is read by both legal academics and CS people, and the analogy is clean.
- **One-line action**: one sentence in §7 framing the conjunctive admission semantics as the substrate's analog of Sunstein's incompletely-theorized-agreements; cite Sunstein 1995 (Harvard L. Rev.) in §8.

### Thread 10: Matching markets and Roth's "willing counterparty" framing

- **Primary references**: Roth, "The Economist as Engineer," Econometrica 70 (2002); Roth & Sotomayor, Two-Sided Matching: A Study in Game-Theoretic Modeling and Analysis (CUP, 1990); Gale & Shapley, "College Admissions and the Stability of Marriage," Amer. Math. Monthly 69 (1962); Roth, "Repugnance as a Constraint on Markets," J. Econ. Persp. 21 (2007).
- **What the thread is about**: stable matchings under preferences and the engineering of real-world matching markets (residency programs, kidney exchange, school choice). The "willing counterparty" framing in §7 echoes the deferred-acceptance setup: under the bilateral-admission contract Chio cannot force a counterparty to sign, the receipt graph emerges only from voluntary participation.
- **Bears on which Chio paper**: parent paper §7 (willing counterparty) and §10 (conclusion). The substrate's bilateral-admission semantics is exactly a degenerate one-tier matching where both sides have a yes / no preference over each candidate receipt rather than a complete preference order.
- **Leverage**: cite-in-§7. Reaches a different audience (economists, mechanism designers) than the cryptography lineage; offers Roth-Sotomayor as the standard reference if "willing counterparty" is challenged as imprecise.
- **One-line action**: short citation in §7 -- "the willing-counterparty constraint is the bilateral-matching analog of \cite{rothSotomayor1990}" -- and add to §8 in the political-and-legal paragraph alongside Ostrom and Hirschman.

### Thread 11: Walch and the "deconstructing decentralization" thread (verification of existing citation)

- **Primary references**: Walch, "The Path of the Blockchain Lexicon (and the Law)" -- already in bib as walch2017lexicon; Walch, "Deconstructing 'Decentralization': Exploring the Core Claim of Crypto Systems," in Cryptoassets: Legal, Regulatory, and Monetary Perspectives (OUP, 2019); Walch, "In Code(rs) We Trust: Software Developers as Fiduciaries in Public Blockchains," in Regulating Blockchain (OUP, 2019).
- **What the thread is about**: Walch's central critique is that "decentralized" functions as a liability shield; her newer essays push the developers-as-fiduciaries thesis. Chio's response -- every authority is local, typed, signed, and attackable -- is positioned exactly to defang the Veil of Decentralization argument.
- **Bears on which Chio paper**: parent paper §8 (already cited) -- but the cited entry is the 2017 lexicon paper, not the 2019 "Deconstructing" or "In Code(rs) We Trust" pieces, which are sharper.
- **Leverage**: cite-in-§8 (upgrade). The "Deconstructing" piece is the one the existing parent paper text most closely engages with; the lexicon paper is the supporting but less load-bearing reference.
- **One-line action**: add Walch 2019 "Deconstructing 'Decentralization'" and Walch 2019 "In Code(rs) We Trust" to bib.bib as upgrades to the existing walch2017lexicon citation; keep both because the lexicon paper is referenced specifically for vocabulary risk.

### Thread 12: Daian-Kell Flash Boys 2.0 and MEV as governance attack

- **Primary references**: Daian, Goldfeder, Kell, Li, Zhao, Bentov, Breidenbach & Juels, "Flash Boys 2.0: Frontrunning, Transaction Reordering, and Consensus Instability in Decentralized Exchanges," IEEE S&P 2020 / arXiv:1904.05234; Qin, Zhou & Gervais, "Quantifying Blockchain Extractable Value," IEEE S&P 2022; Buterin, "MEV-Boost and the New Order of Block Production" (essay, 2022).
- **What the thread is about**: MEV is the canonical proof that on-chain governance is captured by ordering not just by voting -- the priority-gas auction is a side-mechanism that overrides the apparent governance. Compound Proposal 289 (already in Chio bib) is the political-mechanism cousin: governance attack via concentrated stake.
- **Bears on which Chio paper**: parent paper §8 governance-comparison paragraph. Chio's amendment refinement and ladder-floor stability are designed against the analog attack (a governance vote that retroactively widens admission); citing Daian-Kell makes the threat model explicit.
- **Leverage**: cite-in-§8. Strengthens the contrast-class paragraph without overclaiming. Daian and Kell are also adversarial-reader candidates for the parent paper because Cornell IC3 is the canonical adversarial reviewer for governance-attack claims.
- **One-line action**: add Daian-Kell 2020 to §8 alongside the existing compoundProposal289 citation; one-sentence paragraph framing MEV as ordering-channel governance bypass that Chio's amendment refinement is designed against.

## What's NOT relevant

- **Classical Arrow / Gibbard-Satterthwaite paradoxes over preference orderings**: the substrate aggregates Boolean predicates, not orderings. Citing Arrow would be performative -- the right vocabulary is judgment aggregation (Thread 1), not preference aggregation.

- **Auction theory proper (Myerson optimal auctions, VCG, AGV)**: Chio's admission is not a revenue-extracting mechanism. Myerson's revelation principle is interesting philosophically but the substrate does not have private types or strategic bidders; treating admission as an auction would mis-frame the construction.

- **Tournament solutions, voting rules over candidate sets (Brandt-Brill-Harrenstein chapter of the handbook)**: rich literature, but predicates-over-receipts is not a candidate-selection problem. The tournament-theory abstraction does not buy anything Chio's lattice-of-predicates abstraction does not already give.

- **Coalition formation / cooperative game theory (Shapley value, core, nucleolus)**: tempting because polities federate, but Chio's federation is purely conjunctive and has no transferable utility. Citing cooperative game theory would invite the question "what is the characteristic function?" with no defensible answer.

- **Computational complexity of preference learning / bandit social choice**: active research area, but Chio's predicates are explicitly specified, not learned. Citing this would imply Chio is in the preference-learning regime, which it is not.
