# Anthropic co-author pitch (agentic-tool-safety paper)

This memo is the 1-page outreach pitch for the agentic-AI safety paper (`papers/agentic-tool-safety/`). It is intentionally sharper than the parent paper's outreach memo (`papers/programmable-sovereignty/swarm-notes/anthropic-coauthor-outreach.md`): where the parent paper carries the substrate's full apparatus (polity triple, Hartian framing, Montevideo positioning), this paper sits squarely inside the agentic-AI threat model and argues for a structural complement to Anthropic's alignment-research stack.

## Why this paper is a sharper Anthropic ask than the parent

The parent paper's framing engages legal-positivism, Montevideo, and political-theory literature; Anthropic's research team is not the natural audience. This paper restricts attention to one threat model (a possibly-misaligned model issuing tool calls) and one structural claim (a substrate-layer admission predicate composes orthogonally with training-time alignment). The claim is sized for an alignment-research reviewer.

The paper cites Constitutional AI~\cite{baiConstitutionalAI2022}, alignment-faking~\cite{hubingerAlignmentFaking2024}, situational-awareness~\cite{berglundSituationalAwareness2023}, red-teaming~\cite{perezRedTeaming2022}, scalable oversight~\cite{bowmanScalableOversight2022}, debate~\cite{christianoDebate2018}, and the Responsible Scaling Policy~\cite{anthropicRSP2023}. The intellectual debt is to Anthropic's published work; co-authorship aligns the citation graph with the institution that produced the prior art.

## Recommended primary target

**Ethan Perez** is the best primary contact for this paper. The argument is closest to red-teaming: a substrate that survives a misaligned model is the structural dual of a model that survives an adversarial evaluator. The paper's threat model assumes alignment training has failed and the model can compose calls strategically; that is the regime red-teaming explicitly targets.

Secondary targets:

- **Sam Bowman** (second choice): model-behaviour and scalable-oversight work; the verdict-versus-admission distinction in §7 is in his wheelhouse.
- **Evan Hubinger / Ryan Greenblatt** (third choice): alignment-faking is the cited threat model; co-authorship by one of the alignment-faking authors would carry the strongest credibility for the substrate-layer claim, but is the hardest ask cold because the paper does not extend their empirical work.
- **Roger Grosse** (fourth): interpretability adjacency is weaker for an admission-layer construction; not the natural target.

Skip Kaplan unless a technical co-author is already on board.

## Draft email (to Ethan Perez or selected target)

> Subject: Co-authorship inquiry (substrate-layer admission for agentic tool calls)
>
> Dear Ethan,
>
> I'm reaching out because your red-teaming work, particularly *Red Teaming Language Models with Language Models*, shaped the threat-model framing of a short paper I'm preparing for a NeurIPS / ICML safety workshop.
>
> The paper, *Tool Calls as Reversible-Action Admission: A Formal Grammar for Agentic AI Safety*, argues for an orthogonal layer in the agentic-AI safety stack. The training-time stack (Constitutional AI, RLHF) shapes what the model wants; the evaluation-time stack (oversight, debate, red-teaming) bounds what the model is likely to produce; an admission-layer construction shapes what the substrate is willing to execute. Every destructive tool call carries a typed rollback witness at admission with a positive TTL by construction; absence of typed rollback before TTL is structurally a violation. The substrate is the verifier, not the agent, so the admission predicate holds under model-side adversarial assumptions that training-time guarantees cannot match: a misaligned model, strategic composition across reversible-class atoms, alignment-faking during evaluation, an operator manipulated into approval. The structural backbone is a formalisation we have developed in a companion paper that discharges the underlying theorems in Lean 4.
>
> Where we would value your input (and what a co-authorship would add) is on the threat-model framing in §6 and the discussion of how admission-layer guarantees compose with red-teaming results in §7. Concretely: does the factorisation of model-side and substrate-side safety match how Anthropic's safety team thinks about the layered construction, and is the structural claim that admission survives alignment-faking the right way to position the substrate-layer contribution against the red-teaming threat model?
>
> Concretely we'd offer:
>
> - Co-author position on the workshop submission, scoped to the AI-safety framing in §1, §2, §6, and §7. The structural theorems and the substrate implementation remain in the companion paper and are cited rather than re-derived.
> - Lead-author position on a follow-up paper benchmarking admission-layer protected vs unprotected deployments against a misaligned-agent corpus, if that work is more directly aligned with your research direction.
> - All underlying artifacts (Lean source, Rust substrate, draft) under a permissive license and a 14-day embargo for collaborator review before any public pre-print.
>
> Happy to share the draft on request. The paper is approximately 4000 words; one focused read could be 45 minutes.
>
> Best,
> [Author name + affiliation]

## Differentiation from the parent paper's outreach

The parent paper's outreach memo proposed Anthropic co-authorship on a broader, longer paper grounded in legal-positivism and political theory. That memo ranked Bowman first because the parent paper's safety section (§7) is one section of twelve, and Bowman's evaluation work is the closest hook for a general-audience reviewer.

This paper's framing is different. It is a workshop paper in the AI-safety community's own voice, focused on a threat model the alignment-faking and red-teaming literature already takes seriously. Perez is the closer hook because his work targets the model-side adversarial regime the substrate-layer construction is designed to survive.

A co-author who engages with both papers would be ideal but is not required. The recommendation is: send the parent paper's outreach to Bowman (broader audience, evaluation framing) and this paper's outreach to Perez (sharper threat model, red-teaming adjacency). The two outreaches are independent.

## Sequencing

Send AFTER the parent paper's pre-disclosure embargo letters go out (or in parallel, if the parent paper is on a different track). The parent paper is the legal-policy and political-theory reviewer; this paper is the alignment-research reviewer. Both should see the manuscript before any public pre-print.

If Perez declines or does not respond within seven days, move to Bowman. If Bowman declines, move to Hubinger / Greenblatt. If all technical-track targets decline, proceed without an Anthropic co-author at the workshop tier. The paper is publishable at a top safety workshop without an Anthropic co-author; the co-author would change reviewer perception at the top-conference tier.

## Why this is not the autonomous cron's job

1. Cold outreach to a specific researcher is a relationship play; the cron has no Slack, Twitter, mutual-contact list, or institutional affiliation that would unlock an introduction.
2. The right introduction path is human-knowable: a mutual contact, a recent conference conversation, a co-cited paper. The repo does not carry that information.
3. The timing relative to the workshop deadline and the parent paper's pre-disclosure cycle is a strategic call that requires human judgment.

So the cron writes the memo and the draft email and stops here. The human selects a target, picks a real introduction, and sends.
