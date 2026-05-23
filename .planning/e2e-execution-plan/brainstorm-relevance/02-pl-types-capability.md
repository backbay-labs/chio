# Brainstorm B2: PL / Types / Capability / Separation Logic

Date: 2026-05-19
Scope: capability calculi, linear / affine / refinement / effect types, separation logic and concurrent program logics, language-based information flow

## Threads found

### Thread 1: Cerise and Cerisier (capability-machine program logic in Iris)

- **Primary references**:
  - Georges, Guéneau, Van Strydonck, Timany, Trieu, Devriese, Birkedal. "Cerise: Program Verification on a Capability Machine in the Presence of Untrusted Code." Journal of the ACM, 2024.
  - "Cerisier: A Program Logic for Attestation in a Capability Machine." arXiv 2604.13638, 2026 (follow-up).
  - Georges. "Designing and Proving Robust Safety of Efficient Capability Machine Programs." Aarhus PhD thesis, 2023.
- **What the thread is about**: A step-indexed Kripke logical relation, mechanized in Iris/Coq, that reasons about programs running on a capability machine alongside untrusted code. The follow-up Cerisier paper extends Cerise to attestation, which is the load-bearing mechanism for the sensor-grounded paper. Capability safety is proven as a semantic property of the machine, not a syntactic invariant of a single program.
- **Bears on which Chio paper**: Parent paper §5 (kernel capability-bounded dispatch) and §8 (related work). Sensor-grounded paper directly: Cerisier's attestation framing is the closest existing formal account of the question "what does an attested capability mean to a verifier?"
- **Leverage**: cite-in-§8 (high). Cerisier is also adversarial-reader material: a Birkedal / Devriese group reviewer would want Chio's capability-bounded dispatch story explained against Cerise's logical relation.
- **One-line action**: Add Cerise and Cerisier citations to the capability-OS paragraph in §8; one sentence positioning the runtime-receipt object against Cerise's program-logic object.

### Thread 2: FIDES and the LLMbda calculus (information-flow control for LLM agents)

- **Primary references**:
  - Costa, Köpf, et al. "Securing AI Agents with Information-Flow Control." arXiv 2505.23643, 2025. (Microsoft / FIDES system.)
  - "The LLMbda Calculus: AI Agents, Conversations, and Information Flow." arXiv 2602.20064, 2026.
  - "Permissive Information-Flow Analysis for Large Language Models." arXiv 2410.03055, 2024.
- **What the thread is about**: FIDES propagates confidentiality and integrity labels through agent planner loops, gates tool execution on label policy, and adds quarantined-LLM and constrained-decoding primitives. The LLMbda calculus is a lambda calculus extended with dynamic IFC that proves a termination-insensitive noninterference theorem over planner loops. Both target the prompt-injection threat model the Chio agentic-tool-safety paper addresses.
- **Bears on which Chio paper**: Agentic-tool-safety paper, the entire related-work section. Parent paper §6 selective-disclosure evaluation could reference IFC-label propagation as the upstream-policy analog of receipt-level redaction.
- **Leverage**: cite-in-related-work (high), adversarial-reader (high). NeurIPS workshop reviewers in this neighborhood will look for engagement.
- **One-line action**: Add a paragraph to the agentic-tool-safety paper contrasting Chio's per-call signed admission with FIDES's label-propagating planner: Chio's receipt is the consequence-of-admission artifact, FIDES's label is the precondition-on-admission property.

### Thread 3: Actris / Multris / deadlock-free separation logic

- **Primary references**:
  - Hinrichsen, Bengtson, Krebbers. "Actris: Session-Type Based Reasoning in Separation Logic." POPL 2020 (and Actris 2.0, LMCS 2022).
  - Hinrichsen, Jacobs, Krebbers. "Multris: Functional Verification of Multiparty Message Passing in Separation Logic." OOPSLA 2024.
  - Somers, Krebbers. "Verified Lock-Free Session Channels with Linking." OOPSLA 2024.
  - Jacobs, Hinrichsen, Krebbers. "Deadlock-Free Separation Logic: Linearity Yields Progress for Dependent Higher-Order Message Passing." POPL 2024.
- **What the thread is about**: Iris-based program logics for message-passing concurrency that combine separation logic with session types. Multris (2024) extends to multiparty protocols; the deadlock-free 2024 result connects linearity to progress. This is the live POPL-going line of work on protocol verification.
- **Bears on which Chio paper**: Trajectory-invariant POPL paper (sleeping) -- this is the audience and vocabulary. V2 tier-1 federation work: treaty intersection as bilateral protocol could be specified as a Multris-style protocol if the proof effort ever justifies migration from pure-Lean state.
- **Leverage**: sleeper-tier (high if POPL paper revives); co-author-candidate-adjacent (Krebbers group is the natural reviewer pool). Not currently cite-worthy for the parent paper.
- **One-line action**: Bookmark for the trajectory-invariant POPL paper revival; do not cite in current submissions.

### Thread 4: Robust safety of object-capability patterns (Devriese et al.)

- **Primary references**:
  - Swasey, Garg, Dreyer. "Robust and Compositional Verification of Object Capability Patterns." OOPSLA 2017.
  - Devriese, Birkedal, Piessens. "Reasoning about Object Capabilities with Logical Relations and Effect Parametricity." EuroS&P 2016.
- **What the thread is about**: Logical-relations account of why object-capability patterns provide robust safety against unknown / adversarial callers. Predates Cerise but underpins it. Treats attenuation as a semantic property of types rather than a runtime check.
- **Bears on which Chio paper**: Parent §5 (capability-bounded dispatch) and §8. The robust-safety framing is the right vocabulary for how Chio's kernel preserves invariants in the face of untrusted handlers.
- **Leverage**: cite-in-§8 (medium). One sentence framing Chio's runtime as enforcing-by-receipt what robust safety enforces-by-typing.
- **One-line action**: Add Swasey-Garg-Dreyer 2017 to §8 alongside Cerise.

### Thread 5: Capability-safe languages in production (Pony, Wyvern, Verona)

- **Primary references**:
  - Clebsch et al. "Deny Capabilities for Safe, Fast Actors." AGERE 2015 (Pony reference capabilities).
  - Microsoft Research Project Verona (capability-based memory ownership; design notes 2019-2024).
  - Steed. "A Principled Design of Capabilities in Pony." Imperial MEng thesis, 2016.
- **What the thread is about**: Pony's six reference capabilities (iso, val, ref, box, tag, trn) make object-capability discipline a typing problem and integrate with an actor runtime. Verona extends the line with regions and isolation for concurrent ownership. These are the live examples of "what does it look like when capabilities are a first-class language feature, not a library."
- **Bears on which Chio paper**: Parent §5 implementation chapter -- Chio's runtime makes the same design choice (capabilities as Rust values that the type system enforces non-forgeability of), and §8 should name Pony alongside CHERI as the language-level analog.
- **Leverage**: cite-in-§8 (medium-high). Reviewer with PL background will ask why Pony is not cited.
- **One-line action**: Add a Pony citation to §8 with one sentence on the differentiation: Pony attenuates references inside one runtime; Chio attenuates admissions across kernels and emits receipts.

### Thread 6: Morello-Cerise and CHERI formal semantics

- **Primary references**:
  - Hammond, Almeida, Bauereiss, Campbell, Stark, Sewell. "Morello-Cerise: A Proof of Strong Encapsulation for the Arm Morello Capability Hardware Architecture." 2025.
  - Zaliva, Memarian, Almeida, et al. "Formal Mechanised Semantics of CHERI C: Capabilities, Undefined Behaviour, and Provenance." ASPLOS 2024.
  - Park, Pai. "A Formal CHERI-C Semantics for Verification." CPP 2025 (POPL co-located).
- **What the thread is about**: The Cambridge group's progression from CHERI ISA semantics (in Sail) through CHERI C memory models to Morello-Cerise's strong-encapsulation proof for the Arm Morello hardware capability architecture. The 2024-2025 work is the load-bearing literature for "capability hardware is now formally verified at production scale."
- **Bears on which Chio paper**: Parent §8 already cites CHERI generically; should upgrade to cite the Morello-Cerise and ASPLOS 2024 papers specifically. The contrast Chio wants to draw (hardware-enforced capability vs receipt-emitted admission) is sharper with the modern references.
- **Leverage**: cite-in-§8 (high). Existing CHERI citation is stale.
- **One-line action**: Replace the generic CHERI cite in §8 with Morello-Cerise 2025 plus Zaliva ASPLOS 2024.

### Thread 7: Refinement types (LiquidHaskell, F*, generic refinement)

- **Primary references**:
  - Vazou et al. "Generic Refinement Types." POPL 2025 (PACMPL).
  - Lehmann et al. "Mechanizing Refinement Types." POPL 2024.
  - LiquidHaskell, F*, Dafny tool lineage.
- **What the thread is about**: SMT-decidable refinement-type systems with mechanized soundness proofs. Generic Refinement Types 2025 extends to higher-order specifications that abstract invariants over function contracts.
- **Bears on which Chio paper**: Speculative use for parts of the Chio substrate that Lean does not naturally express -- e.g., predicate budgets, monotonicity of evidence accumulation. The Lean-Rust pattern Chio uses could be augmented with refinement-typed Rust (Flux, Prusti, Creusot) at the kernel-dispatch boundary.
- **Leverage**: not-cite-worthy for current submissions; sleeper-tier for a future "verified Chio kernel" paper. Worth mentioning to the orchestrator as a future-work option, not a current citation.
- **One-line action**: No action on current papers. Record in future-work notes as a candidate tool for a verified-kernel companion.

### Thread 8: RefinedRust and verified-Rust toolchain (Flux, Creusot, Prusti)

- **Primary references**:
  - Gäher et al. "RefinedRust: A Type System for High-Assurance Verification of Rust Programs." PLDI 2024.
  - Flux (LiquidRust): Lehmann, Tymchuk, Mariano, Polikarpova. Various 2022-2024.
  - Creusot: Denis, Jourdan, Marché. 2022-2024.
- **What the thread is about**: Three independent live projects giving Rust a refinement / specification layer with proof obligations dischargeable in Iris (RefinedRust), SMT (Flux), or Why3 (Creusot). RefinedRust mechanizes in Iris and inherits the RustBelt model.
- **Bears on which Chio paper**: Parent paper §5 (implementation) and a hypothetical "verified-kernel" follow-up. The current Chio kernel is conventional Rust; the verification story rides on Lean modeling the abstract state machine. RefinedRust would close the spec-implementation gap if pursued.
- **Leverage**: sleeper-tier (high) for a future verified-runtime paper; not-cite-worthy for current submissions unless a reviewer asks "why not verified Rust?"
- **One-line action**: Prepare a one-paragraph response for the reviewer-rebuttal cache addressing "why isn't the kernel itself verified in RefinedRust / Flux?"

### Thread 9: Reversible communicating processes (sleeping; relevant to reversible-action paper)

- **Primary references**:
  - Lanese, Mezzina, Stefani. "Reversible Communicating Processes." Information and Computation, 2018 (and follow-up RCCS line).
  - Phillips, Ulidowski. "Reversing Algebraic Process Calculi." Journal of Logic and Algebraic Programming, 2007.
  - More recent: "Reversible computations are computations." arXiv 2510.06585, 2025.
- **What the thread is about**: The CCS-and-extensions line on reversibility in concurrent process algebra. Programmer-supplied compensation, causal-consistent reversibility, and the algebra of unwinding. This is the academic background for the saga-pattern engineering literature.
- **Bears on which Chio paper**: Reversible-action paper (v0). The rfl-check pending on rollback-amendment composition is essentially asking "does our reversibility relation satisfy causal consistency?" which is the established RCCS criterion.
- **Leverage**: cite-in-reversible-paper (high), adversarial-reader (high) for a reviewer who works on RCCS. Not relevant to the parent paper.
- **One-line action**: When the reversible-action paper unblocks, ground its model in causal-consistent reversibility from Lanese-Mezzina-Stefani; cite Phillips-Ulidowski as the algebraic-process-calculi root.

### Thread 10: Effect systems and capability-as-effect (Effekt, Frank, scoped resumptions)

- **Primary references**:
  - Brachthäuser, Schuster, Ostermann. "Effects, Capabilities, and Boxes" (Effekt language line, OOPSLA 2020 onward).
  - Xie, Cong, Sieczkowski, Leijen. "First-class names for effect handlers" / OPLSS 2025 algebraic effects course notes.
  - "A Calculus for Scoped Effects and Handlers." arXiv 2304.09697, 2023.
- **What the thread is about**: Effekt's line treats capabilities and effects as duals: an effect is a request to a capability holder. This is the cleanest type-theoretic vocabulary for what Chio's kernel-handler dispatch does at runtime. Effekt's lexical scoping of handlers makes attenuation a typing property.
- **Bears on which Chio paper**: Speculative for the parent paper. Useful if a reviewer asks "what is the type-theoretic name for capability-bounded dispatch?" The answer is "lexically-scoped effect handlers with capability passing."
- **Leverage**: not-cite-worthy currently, but worth knowing for review responses. Possibly cite-in-§8 if the paragraph framing is shifted to "type-theoretic accounts of capability attenuation."
- **One-line action**: Hold for rebuttal use; do not add to §8 in current submission.

### Thread 11: Multi-kernel federation and distributed separation logic (Aneris, Trillium)

- **Primary references**:
  - Krogh-Jespersen, Timany, Ohlenbusch, Gregersen, Birkedal. "Aneris: A Mechanised Logic for Modular Reasoning about Distributed Systems." ESOP 2020.
  - Gregersen, Timany, Hriţcu, Birkedal et al. "Trillium: Higher-Order Concurrent and Distributed Separation Logic for Intensional Refinement." POPL 2024.
- **What the thread is about**: Iris-based logics for multi-node distributed systems. Aneris reasons about networks of nodes each running concurrent programs; Trillium adds intensional refinement so traces and consensus protocols can be specified. The natural setting for a multi-kernel federation correctness theorem.
- **Bears on which Chio paper**: V2 tier-1 federation work. Treaty intersection across two kernels is exactly what Aneris-style logic is designed to specify. If the federation correctness theorem ever needs more than the current Lean state-machine formulation, this is the path.
- **Leverage**: sleeper-tier (high) for V2 tier-1; adversarial-reader for the parent paper if a separation-logic-trained reviewer asks why federation is not specified in a distributed program logic.
- **One-line action**: Bookmark for V2 tier-1 planning. Prepare a one-paragraph defense of the pure-Lean modeling choice for the parent paper's reviewer-rebuttal cache.

### Thread 12: Language-based information-flow (Sabelfeld-Myers lineage, modernized)

- **Primary references**:
  - Sabelfeld, Myers. "Language-Based Information-Flow Security." IEEE JSAC 2003 (foundational).
  - Chong et al. "Fabric: A Platform for Secure Distributed Computation and Storage." SOSP 2009 (Jif descendant).
  - Recent: "Permissive Information-Flow Analysis for Large Language Models." arXiv 2410.03055, 2024.
- **What the thread is about**: The mature line on type-system enforcement of noninterference and declassification policies. The Fabric paper is the closest historical analog of "federated authority with information-flow types"; the 2024 LLM IFC line restarts the question for prompt-handling code.
- **Bears on which Chio paper**: Parent paper §6 (selective-disclosure evaluation), Agentic-tool-safety paper (declassification under tool admission).
- **Leverage**: cite-in-related-work for agentic-tool-safety (medium). Parent paper §6 currently frames selective disclosure as a cryptographic concern; an IFC framing exists but adds vocabulary cost.
- **One-line action**: Add Sabelfeld-Myers 2003 plus the 2024 LLM IFC paper to agentic-tool-safety related work.

## What's NOT relevant

Rejected sub-areas in the PL / types neighborhood:

- **Quantum reversible computation and reversible circuit synthesis** (e.g., Bennett 1973 line, Janus-style reversible imperative languages). The "reversible" in Chio's reversible-action paper is about typed inverses of state changes in a substrate, not energy-preserving computation. Conflating them would invite unhelpful adversarial reading.
- **Dependent type theory foundations** (CIC, observational type theory, cubical type theory). Chio uses Lean 4 as a tool, not as a research object. The Lean 4 papers cited via the existing `demoura2021lean4` entry are sufficient; further dependent-type-theory engagement is not load-bearing.
- **Gradual typing and gradual verification.** The Chio runtime is fully typed; there is no migration path from untyped to typed receipts that would benefit from gradual-typing vocabulary.
- **Smart-contract language verification beyond what is already cited** (Move Prover, Solidity verifiers). Already covered by `schneiderFMBC2025` in §8; further engagement returns diminishing leverage relative to the governance-comparison framing.
- **JavaScript / web-platform capability sandboxing** (the descendant lineage of Caja and SES). Practically interesting but does not change the academic positioning; capability-OS lineage (Cerise, CHERI, Pony) is the stronger reference set.

Sources:
- [Cerise (Iris project PDF)](https://iris-project.org/pdfs/2023-jacm-cerise.pdf)
- [Cerise (Journal of the ACM)](https://dl.acm.org/doi/10.1145/3623510)
- [Securing AI Agents with Information-Flow Control (FIDES)](https://arxiv.org/abs/2505.23643)
- [Microsoft FIDES GitHub](https://github.com/microsoft/fides)
- [Permissive Information-Flow Analysis for LLMs](https://arxiv.org/html/2410.03055v3)
- [POPL 2024 Deadlock-Free Separation Logic](https://popl24.sigplan.org/track/POPL-2024-popl-research-papers)
- [Multris OOPSLA 2024](https://research.tudelft.nl/en/publications/actris-session-type-based-reasoning-in-separation-logic/)
- [Morello-Cerise / Cambridge formal CHERI](https://www.cl.cam.ac.uk/~pes20/recent_abstracts.html)
- [A CHERI C Memory Model for Verified Temporal Safety (CPP 2025)](https://popl25.sigplan.org/details/CPP-2025-papers/8/A-CHERI-C-Memory-Model-for-Verified-Temporal-Safety)
- [Pony reference capabilities](https://tutorial.ponylang.io/reference-capabilities/index.html)
- [Generic Refinement Types (POPL 2025)](https://dl.acm.org/doi/10.1145/3704885)
- [RefinedRust (PLDI 2024)](https://iris-project.org/pdfs/2024-pldi-refinedrust.pdf)
- [Cerisier program logic for attestation](https://arxiv.org/html/2604.13638)
