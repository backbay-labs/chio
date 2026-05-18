# Brainstorm Extension - What Else Bounded Executive Action Unlocks

The prior swarm landed on "bounded executive action with TTL plus rollback" as a contained primitive: a type-level wrapper around destructive endpoint response. That framing undersells it. The structural pattern - an authority enacts a reversible act under a mandatory expiry, carrying a typed proof of reversibility at construction time, with the absence of rollback before expiry as the violation - is a formal model of delegated emergency authority. The EDR application is one instance of many; several of the most defensible papers in the pipeline are downstream of the general form.

## The strongest direction (worth committing to): bounded executive action is delegated emergency authority

The EDR framing - quarantine, suspend, restrict-egress - is a special case. The underlying structure governs constitutional emergency powers (Lincoln's habeas suspension, Article 16 of the French Fifth Republic, Article 48 of Weimar), Section 230 takedowns, GDPR Article 17 erasure orders, FISA 702 emergency surveillance, AUMF drone authorizations, algorithmic moderation. Same shape: a reversible destructive act, a declared lifetime, the absence of timely rollback as the constitutional event, an implicit reversibility promise that almost never gets discharged.

The reframe: bounded executive action is not a security primitive. It is the formal grammar of any temporally-bounded emergency power. The TTL-plus-rollback discipline is the structural correction to the failure mode every emergency-powers system shares - emergency authorities ratchet. Lincoln's suspensions outlasted the war. Article 48 transitioned from emergency tool to instrument of dictatorship over twelve years. Section 230 takedown windows stretched. The defect is always the same: emergency powers were created with neither an enforced expiry nor a typed rollback obligation. The polity that admits an emergency act does not require the act to be constructible only with a proof of reversibility. Once admitted, the act has no built-in death.

What this unlocks: the parent paper's `treaty_admission_iff_predicate_intersection` and `amendment_admissible_iff_backward_refinement` cover one half of the constitutional structure - the rule-of-recognition side. Bounded executive action covers the other half - the emergency-power side that every existing constitutional theory names as the failure point and no formal substrate has captured. The theorem candidate: `emergency_amendment_safety : forall e, e.is_emergency -> e.ttl <= MAX_EMERGENCY_TTL ∧ exists rollback_witness, types_check(rollback_witness, e) ∧ requires_quorum(e)`. The polity cannot construct an emergency amendment lacking any of the three properties.

Cross-pollination: constitutional law and comparative-government theory. Agamben's State of Exception, Schmitt's Political Theology, Posner-Vermeule on emergency constitutions, Ackerman on the constitution-of-emergency. None has a formal grammar. The paper venue is law-and-tech (Yale JOLT, Harvard JOLT, Penn Law's tech issue), not USENIX. The systems paper N1 is the application; the law paper is the general claim.

Test: take the statutes for Article 48, Section 230, GDPR Article 17, FISA Section 702. Show each is structurally an emergency amendment under the proposed grammar with a missing TTL, missing rollback witness, or missing quorum predicate. Identify which historical failure mode the missing component explains. Four-page short paper, citable from every systems paper downstream.

Risk: legal scholars will say emergency powers are not formalizable because they encode irreducibly political judgments. Defense: the formalization is of the *wrapper*, not the *content*. Schmitt was wrong about exception being unanalyzable; the wrapper has structure even if the act inside does not.

Real legs. The only direction requiring no new engineering whose intellectual scope is larger than the parent paper.

## Direction two: the constitutional-crisis theorem and the failed-rollback amendment obligation

Chio's parent paper avoids the question of what happens when the kernel breaks its own rules in genuine emergency. The bounded-executive-action grammar answers the happy path. The interesting case is failure: TTL fires, rollback executor crashes, kernel was suspended, SIGCONT dropped, process stays suspended past TTL. What does the polity owe its citizens?

The naive answer is "retry the rollback." Operationally correct, constitutionally insufficient. A retry does not address that the polity admitted an act whose reversibility witness turned out false. The polity made a constitutional promise it cannot keep. The structural correction is not a retry but a constitutional amendment repairing the broken admission.

The theorem candidate: `rollback_failure_yields_amendment_obligation : forall a, rollback_failed(a) -> exists e : EmergencyAmendment, e.repairs(a) ∧ e.publishes_failure(a) ∧ e.bounded_by_max_repair_window`. A failed rollback is not an operational incident; it is an event the polity must respond to with a structural amendment publishing the failure as part of the constitutional history. The amendment may extend the original act's tolerated lifetime under additional quorum, amend the constitution to admit the permanent state, or schedule a higher-rank repair. What the polity may not do is silently continue. The failed rollback is a constitutional event by definition.

This unlocks a formal answer to a question the parent paper punts on: what happens when the system fails its own theorems? Failure is recoverable only as a publicly-witnessed amendment, not as an operational repair. Failure modes become public history.

Cross-pollination: Byzantine fault and software-fault tolerance literature - Castro-Liskov PBFT, Lamport's Paxos recovery, Raft log-divergence repair. None has a constitutional framing; none claims recovery is a constitutional act rather than a state-machine fixup. The reframe: fault-tolerant recovery in systems with public accountability is structurally a constitutional event.

Demo: controlled rollback-failure injection. The executor refuses to discharge a TTL on SuspendProcessTree. The polity emits an EmergencyAmendment receipt repairing the constitution under higher quorum. Anchored to Rekor and OTS. A 90-second proof that failure of the kernel's own promise produces a publicly-witnessed constitutional event rather than a silent retry.

Risk: over-formalization of exception handling. Defense: exception handling without a public artifact is indistinguishable from suppression. The amendment requirement distinguishes a polity that admits failures from one that hides them.

Has legs. Natural follow-on to direction one.

## Direction three: the operator-as-treaty-party reframe and meta-treaty admission

The peer's proposal that destructive actions require operator-plus-device cosignature makes the operator a treaty party with its own polity. The exploration: the operator polity has its own constitution and admits a destructive-action cosignature only if its admission predicate is satisfied. A real security team's predicate: "2 of 3 admin keys cosign within 30 minutes, none has cosigned more than two destructive actions in 24 hours, all are present on the tenancy directory at admission." Real predicate set. Expressible in `PredicateLang.lean`. Compiles.

What this unlocks is a primitive Chio's current model lacks: meta-treaty admission. The treaty intersection between device and operator polities is a treaty over treaties. Each party is a polity defined by its constitution; the cross-organization act is admitted by the intersection of two constitutions plus the meta-treaty binding them. The existing `treaty_admission_iff_predicate_intersection` covers the case where each polity has a flat predicate list. The meta-treaty case requires extension: intersection is taken over polities whose admission predicates are parameterized by the meta-treaty.

Theorem: `meta_treaty_admission : forall (m : MetaTreaty) (p_dev p_op : Polity) (a : Action), admits(intersect(p_dev[m], p_op[m]), a) iff admits(p_dev, a) under m ∧ admits(p_op, a) under m ∧ m.is_admissible_by_both`.

Cross-pollination: international-law treaty theory (Vienna Convention Article 30 on successive treaties, jus cogens), enterprise federation (SAML metadata trust, OIDC federation), SLSA / in-toto chains. None has the meta-treaty primitive.

Test: two operator constitutions (security team, platform team), one device constitution, a meta-treaty binding them for a destructive-action class. Show intersection holds at the meta level; an operator-team constitution change does not invalidate prior receipts because the meta-treaty's parameter binding was captured at admission. Two days Lean, one week paper.

Risk: collapses into notation. Defense: meta-treaty is the formal model of parametric trust patterns every enterprise federation implements ad-hoc. Naming the primitive lets the substrate prove invariants federation systems can only claim.

Legs: yes, smaller than one and two. Paper section, not paper.

## Direction four: degraded-state destructive admission requires re-attestation

Clawdstrike's `EndpointSensorState` includes a degraded mode. The polity may want to refuse destructive actions requested while a sensor was degraded, even retroactively. The intuition: an act enacted under degradation rests on a degraded evidence base; re-attestation after recovery should be required before the act is constitutionally settled.

Theorem: `degraded_state_destructive_admission_requires_re_attestation : forall a, a.class = destructive ∧ a.sensor_state = degraded -> exists r : ReAttestation, r.post_recovery ∧ r.confirms(a) ∨ a.is_marked_provisional`. A destructive admission under degraded sensor is provisional until post-recovery re-attestation confirms it. The polity owes confirm-or-revoke after recovery; the act sits constitutionally liminal until discharged.

What this unlocks: the parent paper's threat model names sensor degradation as a concern. The bounded-executive-action grammar plus re-attestation gives a formal answer for the destructive class: degraded admission is admissible only as provisional with a discharge obligation. Structurally stronger than the prior "partition-contingency mode" framing because it names a specific obligation rather than a mode.

Cross-pollination: medical informed-consent doctrine (consent under duress is provisional until renewal), legal evidence law (exigent-circumstance evidence requires post-hoc warrant or suppression hearing), financial trading audit (trades during market disruption require post-disruption confirmation). The pattern - act under degraded conditions becomes provisional pending normal-conditions re-attestation - is known in adjacent fields, has no formal substrate.

Demo: Chio fixture enacts a destructive action under simulated degradation, marks it provisional in the receipt graph, runs re-attestation after recovery, emits confirmation or retroactive denial. Six hours fixture, two pages paper section.

Risk: looks like engineering convention promoted to theorem. Defense: provisional-admission is novel in Lean. The grammar of constitutionally-liminal admission is not in any prior substrate.

Legs: yes, as section in systems paper N1 or short paper.

## Direction five: agentic AI tool calls are bounded executive actions

The largest commercial direction, underweighted by prior brainstorms. An LLM agent calling a tool is doing executive action on behalf of a user. Every tool call - reading a file, writing to a database, sending an email, executing code - is a bounded action that should be reversible within a TTL or constitute a violation. The model already exists; clawdstrike made it concrete for endpoint security. The reframe applies the grammar to every tool call.

The agent's tool-call envelope carries a TTL, rollback witness, and admission predicate, just like an EDR response action. The user's polity admits the call only if the envelope has a valid rollback witness. Write-actions without rollback witnesses are inadmissible. Read-actions are admissible without rollback because they are not destructive. The agent is treated as an executive authority bound by bounded-executive-action discipline.

What this unlocks: every AI agent system today has the structural defect of emergency-powers systems. Tool calls are enacted without typed rollback obligation. The agent that emails an HR memo to the wrong distribution list, the agent that drops a database table on a misread instruction, the agent that pushes a commit breaking production - each is an executive act without a constructible rollback witness. The substrate requiring every tool call to carry a rollback witness at construction time is a structural correction to the alignment failure mode that Hubinger 2024 alignment-faking literature names but does not formalize.

Theorem: `agent_tool_call_safety : forall (c : ToolCall), c.is_destructive -> exists r : Rollback, types_check(r, c) ∧ admits(user_polity, c)`.

Cross-pollination: Constitutional AI (Bai 2022) and alignment-faking (Hubinger 2024). Constitutional AI uses a constitution to shape reward; the reframe uses a constitution to shape admission. Anthropic's research direction has flagged this as adjacent. Bounded-executive-action grammar is the operational complement to Constitutional AI's reward complement.

Demo: MCP server wrapper requiring every destructive tool call to carry a rollback spec before admission. Rejects any destructive call without a rollback witness. Publishes a bilateral receipt for every admission. One agent, one tool, one rollback, 90-second video showing admission, destructive act, rollback receipt closing the TTL.

Risk: collapses into "log every tool call and add an undo button." Defense: the substrate is the difference between undo button and constitutional act. Undo is UX affordance; bounded-executive-action grammar is typed proof obligation that the act cannot be constructed without rollback. Substrate enforces what undo suggests.

Legs: yes, largest commercial scope of any direction. Paper N4, targeted at AAAI 2027 AI Safety or NeurIPS 2027 AI Alignment. Audience is AI safety researchers, not security. Same grammar, different framing.

## Weird and probably wrong but worth keeping

**Constitutional bankruptcy.** What if a polity admits so many emergency amendments that cumulative repair obligations exceed discharge capacity? The polity is structurally insolvent - public history contains more provisional admissions and failed-rollback obligations than it can ever discharge. There may be a theorem obligating a structural reset: a clean-slate amendment publishing the bankruptcy event and admitting a fresh constitution. The Argentine 2001 default has this shape - the sovereign defaulted on cumulative emergency-fiscal obligations and the recovery was structural amendment. Probably wrong in detail but worth keeping.

**The polity that admits its own end.** An emergency amendment could revoke the constitution entirely. What is the grammar of a polity admitting its own dissolution? Article V of the US Constitution permits amendments that abolish the Constitution. Is there a theorem that says a polity may admit dissolution iff the amendment carries a successor-polity witness? Almost certainly not a paper but worth a paragraph.

**Retroactive bounded executive action.** What if the TTL is in the past? An admission whose declared lifetime expired before admission is structurally retroactive emergency. The constitutional doctrine of ex post facto law prohibits this exact structure. Is there a theorem that retroactive bounded-executive admissions are constitutionally inadmissible by construction? The grammar would forbid an act whose TTL endpoint precedes the admission timestamp. Sounds trivial but no existing substrate names it. Footnote.

## What the prior brainstorm missed

The prior brainstorms - 02, 05, 06 - converged on the EDR application and the systems paper. They left three things on the table.

First, they did not extract the general claim. Bounded executive action is the grammar of delegated emergency authority, not a security primitive. The constitutional law paper is the larger contribution; the systems paper is the entry instance. The priority was inverted.

Second, they did not formalize the failure mode. TTL plus rollback is happy-path. The structural question is what the polity owes when the happy path fails. The failed-rollback amendment obligation is novel and unnamed.

Third, they underweighted the agentic-AI scope. The substrate's commercial center is not endpoint security. It is the universal grammar for bounded delegated authority, with AI tool calls being the largest emerging instance. Agentic AI was treated as an adjacent case; it is the principal case for the next decade.

## My single sharpest claim

Bounded executive action is not a security primitive and not an EDR feature. It is the formal grammar of delegated emergency authority - the structural correction to the failure mode every constitutional emergency-powers system has had for two thousand years. The endpoint application is one instance; the AI-agent application is another; GDPR Article 17 is a third; constitutional emergency powers is the fourth and unifying instance. The substrate's principal contribution is the discovery that emergency authority has a constructible grammar whose absence explains every historical ratcheting failure. The systems paper is the proof-of-concept; the constitutional paper is the theorem; the AI-safety paper is the most consequential application. Of the three, the constitutional paper is the one nobody else will write because nobody else has the substrate.
