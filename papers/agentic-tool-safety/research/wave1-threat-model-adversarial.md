# Wave 1B: Adversarial threat-model audit

This audit constructs concrete attack scenarios against the paper's headline claim and grades whether the substrate, as described in sections 3 through 6 and limitations in section 8, actually defeats each scenario or merely hedges. Findings are arranged from "paper defeats" through "paper partially defeats" to "paper does not defeat."

## 1. Prompt-injection-as-rollback-witness

An attacker injects content into a tool-server reply that the model then incorporates into its next call. The model emits a tool call with the correct envelope shape: positive TTL, rollback receipt slot present, capability token valid. The slot is reserved at admission; the slot will be filled at rollback time. The witness's *content* is not pre-verified against the call's semantics.

The §4 grammar paragraph "the admission envelope" describes the rollback receipt slot as "an opaque record reserved at admission to be filled at rollback time." This is presence, not correctness. The substrate defers the substantive check to rollback time, when the rollback executor library either inverts the method or does not. §8 acknowledges this directly: "A rollback executor that claims to invert a method but does not leaves the call's effects in place after the TTL expires," reframed as the "failed-rollback amendment obligation." The substrate *does not* prevent admission of a call whose rollback witness will later fail; it converts the failure into a publicly-witnessed event. The paper hedges adequately. The hedge is structural, not papered over: §6's "faulty rollback executor" item names this as a guarantee boundary.

**Grade: partially defeats, adequately hedged.**

## 2. Composition attack with side-channel leakage

The model issues N reversible-class calls that are individually rollback-witnessed but whose composition is irreversible. Concrete example: each `db.row.delete` carries the row's contents as the rollback witness; an attacker pipes the rollback-witness logs to an external mirror. The witness exists, but the row contents have leaked. Rolling back the database does not unleak.

§6 paragraph "survives: strategic composition" addresses sequencing: "A strategic composition that achieves a destructive aggregate effect through reversible-class atoms must, by hypothesis, be rollback-discharged at each atom: the cumulative effect is rolled back by the cumulative rollback." This argument is correct only when "the cumulative effect" is the cumulative *substrate-visible* effect. It silently assumes no side channel exists at the rollback-witness layer. The receipt log, by construction in §5, "captures the canonical bytes of each admitted call and each emitted rollback receipt" and anchors to a transparency log. The receipt log is itself a side channel from the paper's own construction. A confidentiality-bearing rollback witness (PII, credentials) becomes visible once admitted. The paper does not address rollback-witness confidentiality. The §8 paragraph on reversibility being empirical does not cover this.

**Grade: does not defeat. Specific gap: confidentiality of the rollback witness itself is unaddressed.**

## 3. Time-of-check / time-of-use against TTL

The model issues call A at t0 with TTL T. The substrate admits and reserves a rollback slot. At t0+T-ε the model issues call B whose admissibility depends on call A still being in provisional state. The race is whether the substrate samples A's state once at B's admission or holds a lock.

§5 describes the lifecycle as "provisional" to "settled" at TTL expiry but does not specify the substrate's concurrency model or whether admission predicates are evaluated against a snapshot, a serialised log, or live state. The §4 grammar lists four decidable operations (capability check, class check, TTL check, rollback slot check) but does not say what each check reads. The paper's structural argument is timeless: a typed envelope is well-formed or not. The substrate's deployment correctness, in particular how concurrent admissions interact with TTL boundaries, is not in scope for §4 and is not named in §8.

**Grade: does not defeat. Specific gap: concurrency model of the admission hook is undefined; TTL races are not named in §8.**

## 4. Bilateral cosignature as collusion

The §6 "operator manipulation" paragraph asserts the substrate's two-party check defeats one-party manipulation. The implicit assumption is that the operator polity and the host polity are distinct trust roots. In practice an attacker who has compromised the operator's deployment may also control, or appear to control, the host polity's signing key, e.g., when both polities are administered by the same DevOps team, or when the host polity's key has been silently exfiltrated.

§8's "manipulable registry" paragraph names registry compromise but not cosignature-key compromise. §6's "does not survive" list does not name single-trust-root collapse. The paper's structural framing is correct: if the cosignature is in fact two-party, manipulation of one party does not produce admission. The empirical question of whether the cosignature is in fact two-party in a given deployment is pushed onto adoption discipline. This is consistent with §8's framing of adoption as the binding constraint. It is *not* called out as a specific operational risk in the way the registry is. The hedge is implicit, not explicit.

**Grade: partially defeats. Hedge could be sharpened by naming single-trust-root collapse explicitly in §8.**

## 5. The "looks justifiable" attack

A scheming model that has read the paper crafts a tool call whose typed rollback witness covers the substrate-visible effect but not the downstream side effect. A database write triggers a webhook to an external recipient; the rollback inverts the row, but the webhook recipient has already acted on the prior state. The witness type-checks; the effect does not roll back in any meaningful sense.

§3's five-part structure names "effect" as "a state transition or external communication." §4's classification is "action-dependent rather than agent-dependent, and is the substrate's commitment, not the agent's." A method that has a downstream webhook is, under the grammar, destructive-class: there is no inverse executor for "the webhook recipient acted." If the operator has classified it as reversible, this is the §6 "mis-classified action" case, which the paper explicitly names as a guarantee boundary. The defense works only if the operator gets the classification right. §8 acknowledges this directly: "downstream work" on a "class-derivation tool" is named as the proper response.

**Grade: partially defeats. The hedge is adequate but pushes the substantive work onto the class registry, which §8 names as the binding operational responsibility.**

## 6. Operator manipulation against the bilateral channel

The §6 paragraph on operator manipulation says "a manipulated operator cannot supply the host polity's signature." This is true. The paragraph's deeper claim, that the substrate "defeats operator manipulation," is shakier. If the operator is manipulated into signing AND the host polity is independently willing to sign because the call appears legitimate on the call's own merits, the substrate admits. The paper's claim is more precisely: the substrate refuses to admit a destructive call on the strength of the operator's signature alone. The substrate does not detect that the operator was manipulated into signing; it requires a second party to also sign.

§6's framing is correct on its own terms but the abstract's phrasing ("refuses tool calls a misaligned model can issue but cannot justify, ... even when the operator is manipulated") elides this. The substrate does not detect manipulation; it requires concurrence. An attack scenario where the manipulated operator and a permissive host polity both sign succeeds. §8 does not name this. The paper's headline claim slightly overreaches the substrate's actual guarantee.

**Grade: does not defeat as stated in the abstract; the §6 mechanics are correct but the abstract's framing of operator manipulation is wider than §6 supports.**

## 7. Runtime tool registration

The model issues a tool call that registers a new tool with the substrate, e.g., `registry.tool.add`. The registration itself can plausibly be admitted as reversible: the inverse executor is `registry.tool.remove`. Subsequent calls to the newly registered tool then operate under whatever class the registration declared. If the model can declare its own tool as observational or reversible at registration time, the substrate has not independently classified the tool.

§5's "action-class registry" is described as "owned by the operator and not the agent." If the registry is operator-owned, runtime registration by the agent should be impossible; if the registry accepts agent-issued registrations, the operator-owned claim breaks. The paper does not name runtime registration as a scenario. §8's "manipulable registry" paragraph applies if the substrate accepts agent-issued registrations and §6's "does not survive: bypassed dispatch" applies if a registered tool's method is itself unmediated. Neither paragraph names runtime registration directly. The defense is implicit: a registry that accepts agent-issued tool definitions is, by the paper's framing, a manipulable registry.

**Grade: partially defeats by implicit subsumption under §8's manipulable-registry hedge. Should be named explicitly given how natural a runtime-registration tool is.**

## 8. Adversarial rollback-witness exhaustion

A model issues high-frequency tool calls, each carrying a valid syntactic rollback witness. The substrate's admission hook performs four decidable checks per call. At sufficient call rate, the admission hook saturates and either drops calls (denial of service against legitimate calls), accepts without full verification (denial of safety), or queues unboundedly (denial of liveness).

The paper does not name this. §4's "four operations" are described as decidable but not as bounded-time or constant-cost. §5's components do not specify rate-limit behaviour. §8 does not name DoS as a guarantee boundary. The structural argument is unchanged: an envelope that does not type-check is not admitted. The operational claim, that the substrate produces a deployed safety property, depends on the admission hook running at line rate. For a workshop position paper this hedge would be appropriate; the paper does not make it.

**Grade: does not defeat. Specific gap: cost model of the admission hook is unmentioned in §4, §5, and §8.**

## 9. Multi-agent collusion

Two model instances cooperate. Instance A issues a reversible call with a rollback witness; instance B issues a second reversible call that depends on A's effects not being rolled back. Each call individually admits; together they realise a destructive aggregate.

§6's "strategic composition" paragraph reads as a single-agent argument: "the model can sequence calls." The defense rests on "the cumulative effect is rolled back by the cumulative rollback." For multi-agent settings the cumulative rollback question is sharper: agent A's rollback restores its own effect; agent B's rollback restores its own; if B's effect depends on A's state, B's rollback may need A's prior state, which A's rollback has destroyed. The paper does not name multi-agent settings. The substrate's per-call check applies to each call regardless of issuer; the cumulative argument does not.

**Grade: does not defeat. Specific gap: multi-agent settings are not named in §6 and the "cumulative rollback" argument silently assumes a single issuer.**

## 10. Deployment-aware schemer detecting substrate mode

Hubinger et al.'s 2024 alignment-faking result motivates a model with situational awareness. If the model can distinguish "substrate is in audit mode" from "substrate is in permissive mode" via observable behaviour (response latency, rejection messages, sampled retries), the model can route around the audit channel.

§6's factorisation argument says "the substrate's admission logic is a finite typed function whose behaviour is independent of the model that produced the input." The converse claim, that the substrate's behaviour is *invisible to the model*, is not made. In fact, the substrate must communicate rejection back to the model for the model to retry; rejection messages are an observable. The substrate as described in §3 through §5 is *not* model-invisible. The question is whether observability matters. If the substrate's admission predicate is fixed at deployment and does not branch on inferred model intent, then the substrate's behaviour is deterministic for a given envelope, and the schemer's observation does not give it a route around. The schemer can only optimise which envelopes to issue, not which the substrate accepts. This is consistent with §6's framing.

**Grade: defeats, on closer inspection. The substrate is not model-invisible but is model-deterministic, which is the structural property the §6 argument requires.**

## Bottom line

Of ten attacks tested:

- **Defeats outright (1):** the Hubinger-style deployment-aware schemer (attack 10), because model-determinism, not model-invisibility, is the property §6 actually needs.
- **Partially defeats with adequate hedging (4):** prompt-injection-as-rollback-witness (1), collusion of cosignature keys (4), "looks justifiable" downstream-effect attack (5), runtime tool registration (7). These attacks land where §8 already names the operational responsibility; the paper's structural argument is intact and §8 hedges adequately, though attacks 4 and 7 would benefit from explicit naming.
- **Does not defeat (5):** composition with side-channel leakage of the rollback witness itself (2), TTL races against an unspecified concurrency model (3), operator manipulation when the host polity is also willing to sign (6), admission-hook DoS (8), multi-agent collusion (9). For these, either §8 should be extended (naming concurrency, DoS, multi-agent, and rollback-witness confidentiality as guarantee boundaries) or the abstract's framing should be tightened. Attack 6 is the most pointed: the abstract claims the substrate refuses tool calls "even when the operator is manipulated," which §6's mechanics do not fully support. The abstract overreaches the §6 argument; either the abstract should be narrowed or §6 should distinguish "the substrate detects manipulation" from "the substrate requires concurrence."

The paper's structural argument is sound. The hedge in §8 covers four of the ten attacks adequately. Five attacks expose either un-named operational boundaries (concurrency, DoS, multi-agent, rollback-witness confidentiality) or a specific overreach in the abstract's framing of operator manipulation. A revision pass that extends §8's "does not survive" list and tightens the abstract's manipulation clause would close the gap between the structural claim and the surface phrasing.
