# Brainstorm B1: Logic and Foundations

Date: 2026-05-19
Scope: reverse mathematics, dependent type theory, modal/deontic/dynamic logic, descriptive set theory / decidability

## Threads found

### Thread 1: Input/output logic for normative systems (Makinson and van der Torre)

- **Primary references**:
  - Makinson, D. and van der Torre, L. (2000). "Input/Output Logics." Journal of Philosophical Logic 29: 383-408.
  - Makinson, D. and van der Torre, L. (2001). "Constraints for Input/Output Logics." Journal of Philosophical Logic 30: 155-185.
  - Parent, X. and van der Torre, L. (2018). "Input/Output Logics without Weakening." Filosofiska Notiser 5: 119-131.
  - Steen, A. (2025). "A Reduction of Input/Output Logics to SAT." arXiv:2508.16242.
- **What the thread is about**: I/O logic models norms as ordered input-output pairs `(a, x)` rather than as modal sentences. Norms are not truth-valued; the system computes which outputs follow from which inputs under a generation operation, then applies a constraint to filter conflicts. Constrained I/O logics give non-monotonic normative reasoning without the standard deontic-logic paradoxes.
- **Bears on which Chio paper**: parent paper, §3 (substrate description of admission predicate K), §4 (treaty intersection theorem), §7 (Hartian framing). Chio's `K` evaluating a receipt to admit / reject is structurally an input-output operation: receipt bytes in, admission verdict out, with a constraint set that is the constitution's predicate list. Treaty intersection corresponds to composing two I/O systems and taking the consistent core.
- **Leverage**: cite-in-§8 and possibly co-author-candidate. Van der Torre's group at Luxembourg has worked on exactly the "norms as compositional functions over canonical inputs" framing Chio operationalizes; the recent SAT-reduction paper makes the connection mechanical rather than philosophical.
- **One-line action**: cite Makinson-van der Torre 2000 in §8 as the formal-logic ancestor of Chio's input-output admission, and note in §7 that the kernel-as-I/O-operation reading complements the Hartian (a)-condition reading.

### Thread 2: STIT logic and deontic agency (Belnap, Horty)

- **Primary references**:
  - Belnap, N., Perloff, M., and Xu, M. (2001). "Facing the Future: Agents and Choices in Our Indeterminist World." Oxford University Press.
  - Horty, J. F. (2001). "Agency and Deontic Logic." Oxford University Press.
  - Lorini, E. and Sartor, G. (2016). "A STIT Logic for Reasoning About Social Influence." Studia Logica 104: 773-812.
  - van Berkel, K. and Lyon, T. (2024). "Proof Theory and Decision Procedures for Deontic STIT Logics." arXiv:2402.03148.
- **What the thread is about**: STIT ("sees to it that") formalizes the agentive locution "agent i sees to it that phi". It composes naturally with deontic operators to express "i is obligated to see to it that phi" without collapsing into action-counting paradoxes that defeat naive deontic logic.
- **Bears on which Chio paper**: agentic-tool-safety paper (workshop). The position-paper claim that an agent tool-call is a reversible-action admission under a constitution is exactly a STIT obligation: the agent is admitted to see-to-it-that the tool effect occurs, conditional on the kernel evaluating the predicate to true. Also bears on §7 of the parent paper as a finer-grained operationalization of "who acts" inside a polity.
- **Leverage**: cite-in-§8 of the workshop paper, sleeper-tier for a follow-up "agentic tool calls as STIT obligations under a Lean-checked constitution" paper.
- **One-line action**: cite Horty 2001 and van Berkel-Lyon 2024 in the agentic-tool-safety paper's related-work; do not retrofit the parent paper.

### Thread 3: Lean kernel verification (Lean4Lean, Carneiro)

- **Primary references**:
  - Carneiro, M. (2024). "Lean4Lean: Verifying a Typechecker for Lean, in Lean." arXiv:2403.14064.
  - Carneiro, M. (2019). "The Type Theory of Lean." MS thesis, Carnegie Mellon University.
  - Anand, A. et al. (2025). "Lean4Less: Eliminating Definitional Equalities from Lean via an Extensional-to-Intensional Translation." ITP 2025.
- **What the thread is about**: Lean4Lean is a second typechecker for Lean 4, written in Lean and accompanied by a partial mechanization of Lean's metatheory. It is the strongest current evidence that Lean's kernel + the small set of admitted axioms (propext, choice, quot) does what it claims, independent of the C++ reference implementation.
- **Bears on which Chio paper**: parent paper, §3 (substrate trust statement: "only `propext` is used by the bounded model proofs"), §6 (evaluation: axiom-trace ledger). The kernel-axioms-only posture only buys what the kernel + axioms are themselves worth; Lean4Lean is the natural citation for that buy.
- **Leverage**: cite-in-§8, mandatory for anyone who reads the trust statement skeptically.
- **One-line action**: add Carneiro 2024 to bib.bib and cite at the first place §3 invokes the kernel-axioms-only posture; do not pad §8 beyond a one-sentence note.

### Thread 4: Avigad on understanding and formal verification

- **Primary references**:
  - Avigad, J. (2008). "Understanding, Formal Verification, and the Philosophy of Mathematics." Journal of the Indian Council of Philosophical Research 27: 161-197.
  - Avigad, J. (2024). "Mathematics and the formal turn." Bulletin of the AMS 61: 225-240.
  - Avigad, J. (2025). "The promise of formal mathematics" (Hoskinson Center inaugural lecture write-up).
- **What the thread is about**: Avigad argues that formal verification is not a strictly stronger replacement for informal mathematics; it shifts the locus of understanding and modifies what the proof is evidence of. The methodological posture overlaps almost exactly with the parent paper's discomfort with claiming more than condition (a) of Hart's rule of recognition.
- **Bears on which Chio paper**: parent paper, §1 (positioning), §7 (Hart discussion's reflexive caveat about what mechanization can and cannot displace). Also a defensive reference: an adversarial reviewer who asks "what philosophical work is your theorem doing" is asking an Avigad-shaped question.
- **Leverage**: adversarial-reader candidate (he is at CMU Philosophy + Math) and a cite-in-§7 sleeper. Probably not worth adding citation pressure to §8 which is already long.
- **One-line action**: keep Avigad as adversarial-reader target for §7; cite Avigad 2024 in §7 only if a reviewer pushes on the "what does the proof buy" question.

### Thread 5: Decidability via finite-model and bounded-model property

- **Primary references**:
  - Bednarczyk, B. and Rudolph, S. (2023). "Decidability of Querying First-Order Theories via Countermodels of Finite Width." LMCS / arXiv:2304.06348.
  - Reynolds, A. et al. (2024). "The Decision Problem for Regular First-Order Theories." arXiv:2410.17185.
  - Kirst, D. and Larchey-Wendling, D. (2020). "Trakhtenbrot's Theorem in Coq: A Constructive Approach to Finite Model Theory." arXiv:2004.07390.
- **What the thread is about**: A theory has decidable entailment if every false consequence has a finite-width or bounded-shape countermodel. The bounded-model property is sufficient for decidability for many "regular" theories that lack the finite-model property outright.
- **Bears on which Chio paper**: parent paper, §3 / §4 wherever a "decidable operations on (T, C, K)" claim is made; sensor-grounded paper for the witness-attestation predicate language. The Chio claim is constructive (predicates are concrete bounded programs), but the surrounding literature on bounded-model decidability gives an honest comparison class.
- **Leverage**: mentionable-but-not-cite-worthy unless reviewers ask "what decidability fragment is this". Most likely not needed; the predicates are concrete enough that no decidability result is being invoked.
- **One-line action**: hold in reserve. Cite only if a reviewer asks "what is the decidable fragment".

### Thread 6: Reverse mathematics and concrete incompleteness (Friedman, Simpson)

- **Primary references**:
  - Simpson, S. G. (2009). "Subsystems of Second Order Arithmetic." Cambridge University Press, 2nd ed.
  - Friedman, H. (2025). "Boolean Relation Theory and Incompleteness." Lecture Notes in Logic, ASL.
  - Cheng, Y. (2024). "Some Reflections on the Relationship Between Logical Incompleteness and Concrete Incompleteness." arXiv:2401.12531.
- **What the thread is about**: Reverse mathematics calibrates which set-existence axioms are required to prove a given theorem; the Big Five (RCA0, WKL0, ACA0, ATR0, Pi-1-1-CA0) classify most ordinary mathematics. Friedman's concrete-incompleteness program shows finitary statements requiring large-cardinal axioms.
- **Bears on which Chio paper**: parent paper, §3 trust statement. The methodological alignment is real: "only the axioms that are visible in the proof term are trusted" is the same posture as "calibrate which axioms a theorem needs". But the load-bearing connection is thin -- Chio's bounded-model proofs do not approach the ZFC frontier and would not benefit from a reverse-math classification.
- **Leverage**: adversarial-reader candidate (Friedman) for the "kernel-axioms-only" trust statement, but only in a position-paper or essay venue where the philosophical posture is the foreground. Not cite-worthy for the USENIX submission.
- **One-line action**: skip for the submission. Hold Friedman as adversarial-reader for a future essay or position venue; do not add to bib.bib.

### Thread 7: Dynamic logic / PDL for action-effect reasoning (Harel, Pratt, Kozen)

- **Primary references**:
  - Harel, D., Kozen, D., and Tiuryn, J. (2000). "Dynamic Logic." MIT Press.
  - Platzer, A. (2017). "Logical Foundations of Cyber-Physical Systems." Springer.
  - Bordeaux, L. and Cassez, F. (2024). "Dynamic Logic for Verifying Reactive Programs: A Decade Later." Formal Methods in System Design 64: 1-30.
- **What the thread is about**: PDL reasons about modal sentences of the form `[a]phi` ("after every execution of action a, phi holds"). The composition operators (`a;b`, `a + b`, `a*`, `phi?`) give a regular-expression algebra over actions and a natural fit for stepwise admission.
- **Bears on which Chio paper**: agentic-tool-safety paper (workshop), reversible-action paper (v0). The reversible-action composition theorem (rollback after action) is dynamic-logic-shaped: `[a; rollback(a)] (state = pre_state)`. If the rfl-check kills the reversible-action paper, the dynamic-logic framing is still the right ambient logic for the workshop paper.
- **Leverage**: cite-in-§related-work of the workshop paper; sleeper for the reversible-action paper if it survives the rfl-check.
- **One-line action**: cite Platzer 2017 in the agentic-tool-safety paper as the standard modern reference for dynamic logic over real actions; defer Harel-Kozen-Tiuryn to the reversible-action paper if it lives.

### Thread 8: Searle constitutive rules formalized (Hindriks, Boella-van der Torre)

- **Primary references**:
  - Searle, J. R. (1995). "The Construction of Social Reality." Free Press.
  - Hindriks, F. (2009). "Constitutive Rules, Language, and Ontology." Erkenntnis 71: 253-275.
  - Boella, G. and van der Torre, L. (2004). "Regulative and Constitutive Norms in Normative Multiagent Systems." KR 2004: 255-265.
  - Grossi, D. and Jones, A. J. I. (2013). "Constitutive Norms and Counts-As Conditionals." In Handbook of Deontic Logic and Normative Systems vol.1.
- **What the thread is about**: Constitutive rules have the form "X counts as Y in context C" and create institutional facts from brute facts. Formal treatments distinguish them from regulative rules (obligations / permissions / prohibitions) and give a counts-as conditional its own semantics.
- **Bears on which Chio paper**: parent paper, §7 Hart discussion. The Chio admission predicate K is precisely a counts-as conditional: "these bytes count as a member of the polity's history in context C". This is a much better fit than Hart alone for what the substrate does, and one of the few places where a small terminology shift could broaden the paper's audience.
- **Leverage**: cite-in-§7 and §8. Grossi-Jones 2013 is in the Handbook of Deontic Logic and is the canonical citation for the counts-as conditional reading of constitutive rules.
- **One-line action**: add Grossi-Jones 2013 and Hindriks 2009 to bib.bib; add one sentence to §7 noting that K is a counts-as conditional in the Searle-Hindriks sense, which sharpens the Hart condition (a) framing.

### Thread 9: Defeasible deontic logic and norm conflict (Governatori, Sartor)

- **Primary references**:
  - Governatori, G., Olivieri, F., Rotolo, A., and Scannapieco, S. (2013). "Computing Strong and Weak Permissions in Defeasible Logic." Journal of Philosophical Logic 42: 799-829.
  - Olivieri, F. and Governatori, G. (2018). "Practical Normative Reasoning with Defeasible Deontic Logic." Springer Tutorial.
  - Liu, J. and Governatori, G. (2024). "A Defeasible Deontic Calculus for Resolving Norm Conflicts." arXiv:2407.04869.
- **What the thread is about**: Defeasible deontic logic adds defeaters and superiority relations to deontic rules, giving a tractable computational handle on norm conflicts. The "Practical Normative Reasoning" tutorial codes regulatory text into Defeasible Logic and runs compliance queries.
- **Bears on which Chio paper**: parent paper §7 (multi-jurisdiction asymmetry), agentic-tool-safety workshop paper (norm conflicts under joint constitutions). Chio's design admits only the conjunction of constitutions when treaties stack; defeasible deontic logic is the literature where "what to do when norms conflict" is the central question. The Chio answer (conjunctive admission, fail-closed) is one design point; Governatori-style defeasibility is another, and both are defensible.
- **Leverage**: cite-in-§8 of the parent paper, sleeper for a future treaty-design paper that explores defeasible composition.
- **One-line action**: cite Governatori et al. 2013 once in §8 as the canonical formalization of norm-conflict handling; explain in one sentence why Chio chooses conjunctive (fail-closed) over defeasible (priority-resolved).

### Thread 10: Runtime monitoring of temporal specifications (Bauer, Leucker, Schallhart)

- **Primary references**:
  - Pnueli, A. (1977). "The Temporal Logic of Programs." FOCS 1977: 46-57.
  - Bauer, A., Leucker, M., and Schallhart, C. (2011). "Runtime Verification for LTL and TLTL." ACM TOSEM 20(4): 14:1-14:64.
  - Basin, D., Klaedtke, F., and Zalinescu, E. (2017). "Scalable Offline Monitoring of Temporal Specifications." Formal Methods in System Design 49: 75-108.
- **What the thread is about**: Runtime monitoring synthesizes a deterministic automaton from an LTL or MTL specification that returns one of {true, false, inconclusive} on prefixes of a trace. The three-valued semantics is what lets a monitor commit before the trace is complete.
- **Bears on which Chio paper**: sensor-grounded paper (degraded-witness admission), parent paper §3 (admission as monitored predicate over receipt sequences). The Bauer-Leucker-Schallhart three-valued reading maps to "admit / reject / quarantine" in the sensor-grounded paper.
- **Leverage**: cite-in-§related-work of the sensor-grounded paper; mentionable in the parent paper but probably not worth the column-inch.
- **One-line action**: cite Bauer-Leucker-Schallhart 2011 in the sensor-grounded paper's related-work as the standard reference for monitored-predicate semantics over receipt streams.

## What's NOT relevant

- **Category theory of effects and effect handlers.** A genuine connection to algebraic effects exists in the agentic-tool-safety paper, but it is closer to PL semantics than to logic / foundations; route to brainstorm B2 (PL / types). Not pursued here.
- **Forcing, large cardinals, descriptive set theory above Borel.** Real connection to the Chio claim is zero. The (T, C, K) triple lives in the decidable-predicates fragment; nothing in the bounded model touches the analytical hierarchy. Mentioned only to record the rejection.
- **Linear logic / proof nets / geometry of interaction.** Tempting because Chio's resources are receipts (linear), but the connection is to substructural type systems (B2 territory), not to logic foundations. Not pursued.
- **Homotopy type theory / cubical Agda.** Real connection to Lean's type theory exists at the metatheoretical level, but Chio uses Lean 4 without univalence and the bounded-model proofs do not need higher inductive types. Pursuing the HoTT thread would import overhead with no theorem-level payoff. Not pursued.
- **Goedel's incompleteness and self-reference (Smullyan-style).** Frequently invoked rhetorically when "constitution + amendment" is on the table, but the parent paper's amendment-refinement theorem is first-order in a bounded universe and does not engage with diagonal arguments. Pursuing this thread would add gloss without substance. Rejected.
