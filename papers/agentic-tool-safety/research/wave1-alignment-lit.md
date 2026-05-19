# Wave 1A: Alignment-research literature audit

## 1. Constitutional AI (Bai 2022)

Quote (§7): "Constitutional AI cannot guarantee that a model never produces a destructive tool call; it shapes the prior. An admission-layer construction can guarantee that a destructive tool call is not executable without the typed witness."

Issue. Orthogonality is defensible at mechanism, and §7's "the two constitutions are not the same object and do not interfere" is clean. The slippage is in §2 (enumerates CAI deficits to justify a successor layer, a soft-displacement reading) and §1 ("regardless of what the model that issued the call wants"). The paper never names where CAI alone is sufficient.

Rewrite. Add to §2: "For obvious refusals a constitution enumerates, Constitutional AI is sufficient and admission discipline is redundant. The admission layer is load-bearing in the destructive, irreversible, or cross-polity tail." Tighten §1's "regardless of what the model wants" to "in addition to what the model has been trained to want."

## 2. Alignment-faking (Greenblatt / Hubinger 2024)

Quote (§6): "Alignment-faking changes nothing about the typed admission, because the typed admission is not a function of the model's claimed intent."

Issue. Correct at altitude, thin on specifics. The substrate defeats the BEHAVIOURAL CONSEQUENCE of alignment faking at the admission gate; it does not defeat alignment faking as a property of the model. A reviewer fresh on Greenblatt et al. 2024 will expect the deployment-vs-training-oracle scratchpad result cited by name.

Rewrite. Replace the closing sentence: "Alignment-faking changes the envelope distribution between training and deployment [cite Greenblatt 2024, deployment-oracle scratchpad result]; it does not change the substrate's admission predicate. Divergence in either regime is bounded above by what the typed envelope admits. Alignment-faking remains a model-internal property; the substrate bounds the operational consequence at the tool-call boundary."

## 3. Scalable oversight (Leike 2018, Christiano 2018, Bowman 2022)

Quote (§7): "A verdict says the model's output is acceptable. Admission says the substrate will execute this typed call. The two operations can be stacked."

Issue. Composes-orthogonally is correct. The unstated half is where oversight is NEEDED because substrate refusal is too coarse. The substrate type-checks SHAPE, not CONTENT; reversible admissible calls can still be wrong. A Bowman-lineage reviewer will expect this division of labour named.

Rewrite. Add to §7: "Scalable oversight remains the right instrument for admissible-but-wrong tool calls; admission handles the irreversible-without-witness case oversight cannot reach in time."

## 4. Deceptive alignment (Hubinger 2021)

§2 cites the 2021 paper. The substrate-defeats-behaviour-not-internal-scheming distinction is implicit in §6 but never explicit. A deceptively aligned mesa-optimizer whose objective survives training is still misaligned after deployment; the substrate bounds the consequence, not the objective.

Rewrite. Add to §6's factorisation paragraph: "The factorisation does not defeat mesa-optimisation as a model-internal phenomenon. It bounds the operational consequence, when expressed as a tool call, by the typed admission predicate. The model's internal state is the alignment community's problem; the substrate operates on its outputs."

## 5. Situational awareness (Berglund 2023)

§2 cites Berglund; §6 does not engage situational awareness as a distinct adversarial regime. A model that recognises the admission predicate and can introspect the class registry is strictly stronger than the generic misaligned model. Situational awareness is the precondition for the manipulable-registry attack §8 concedes.

Rewrite. Insert in §6 between alignment-faking and operator manipulation: "Survives: situational awareness. A model that recognises the admission predicate may construct envelopes that pass the typed check while achieving a non-reversible aggregate effect. The predicate is invariant to inferred deployment status; soundness against a situationally aware adversary depends on the registry being hardened. The structural check is sound; the registry is the trust frontier."

## 6. Anthropic primary contact framing

The pitch names Perez as primary. Perez's red-teaming targets adversarial ELICITATION; the substrate story is downstream of elicitation. The load-bearing relationship is to Hubinger / Greenblatt (the cited threat model, named four times in §6) and to Bowman (verdict-versus-admission in §7). The README's third-place ranking of Hubinger / Greenblatt under-sells citation-graph weight.

Recommendation. Re-order to Hubinger / Greenblatt first, Bowman second, Perez third. If Perez stays primary, prepare a response: "downstream-of-red-teaming, not red-teaming."

## 7. Missing engagements

(a) **Sleeper Agents (Hubinger / Greenblatt 2024)**. Empirical demonstration that safety training can fail persistently across fine-tuning. Belongs in §2 and §6: "Persistence of misalignment across safety training [Sleeper Agents] sharpens the case for an admission layer that does not depend on training succeeding."

(b) **Carlsmith, Scheming AIs (2023)**. Conceptual frame for the §6 threat model. The paper engages alignment-faking empirically without engaging Carlsmith conceptually.

(c) **Krakovna et al. on goal misgeneralization** (DeepMind). The typed envelope is invariant under the model's internal goal representation; a clean response and a DeepMind-side hook past the Anthropic-only frame.

## Bottom line

The paper survives a hostile read by Perez because the red-teaming framing IS the rhetorical dual the paper engages competently. It does NOT survive a hostile read by Hubinger or Greenblatt: §6 collapses the model-internal property (faking as scheming) into the model-external behaviour (the issued envelope) and claims to defeat the former when it only bounds the latter. The fix is local (separate behavioural and structural claims, cite the scratchpad result, add the mesa-optimisation disclaimer, insert the situational-awareness stanza, add Sleeper Agents, Carlsmith, and Krakovna) but load-bearing. Orthogonality itself is sound; §7 names composition explicitly. §1's "regardless of what the model wants" is the one drift toward displacement. With these changes the paper carries the alignment-research voice it claims.
