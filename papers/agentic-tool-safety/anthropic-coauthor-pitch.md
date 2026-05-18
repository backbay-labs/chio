# Anthropic co-author pitch (agentic-tool-safety paper)

This memo is the one-page outreach pitch for the agentic-AI safety
paper (`papers/agentic-tool-safety/`). It is intentionally sharper
than the parent paper's outreach memo
(`papers/programmable-sovereignty/swarm-notes/anthropic-coauthor-outreach.md`):
where the parent paper carries the full apparatus (polity triple,
Hartian framing, Montevideo positioning), this paper sits squarely
inside the agentic-AI threat model and argues for a structural
complement to Anthropic's alignment-research stack.

## Why this paper is the sharper Anthropic ask

The parent paper engages legal-positivism, Montevideo, and
political-theory literature; Anthropic's research team is not the
natural audience for that framing. This paper restricts attention to
one threat model (a possibly-misaligned model issuing tool calls)
and one structural claim (a substrate-layer admission predicate
composes orthogonally with training-time alignment). The claim is
sized for an alignment-research reviewer.

The paper cites Constitutional AI~\cite{baiConstitutionalAI2022},
alignment-faking~\cite{hubingerAlignmentFaking2024},
situational-awareness~\cite{berglundSituationalAwareness2023},
red-teaming~\cite{perezRedTeaming2022}, scalable
oversight~\cite{bowmanScalableOversight2022},
debate~\cite{christianoDebate2018}, and the Responsible Scaling
Policy~\cite{anthropicRSP2023}. The intellectual debt is to
Anthropic's published work; co-authorship aligns the citation graph
with the institution that produced the prior art.

## Recommended primary target

**Ethan Perez** is the best primary contact for this paper. The
argument is closest to red-teaming: a substrate that survives a
misaligned model is the structural dual of a model that survives an
adversarial evaluator. The threat model assumes alignment training
has failed and the model can compose calls strategically; that is
the regime red-teaming explicitly targets.

Secondary targets:

- **Sam Bowman** (second choice): scalable-oversight and
  model-behaviour work; the verdict-versus-admission distinction in
  §7 is in his wheelhouse. Bowman is the primary contact for the
  parent paper, so routing him here would double-book his attention;
  use only if Perez declines.
- **Evan Hubinger or Ryan Greenblatt** (third choice):
  alignment-faking is the cited threat model; co-authorship by one
  of the alignment-faking authors would carry the strongest
  credibility for the substrate-layer claim, but is the hardest ask
  cold because the paper does not extend their empirical work.
- **Roger Grosse** (fourth): interpretability adjacency is weaker
  for an admission-layer construction; not the natural target.

Skip Kaplan unless a technical co-author is already on board.

## Draft email (to Ethan Perez or selected target)

> Subject: Co-authorship inquiry on substrate-layer admission for
> agentic tool calls
>
> Dear Dr. Perez,
>
> I am reaching out because your red-teaming work, in particular
> *Red Teaming Language Models with Language Models*, shaped the
> threat-model framing of a short paper I am preparing for a
> NeurIPS or ICML safety workshop.
>
> *Tool Calls as Reversible-Action Admission: A Formal Grammar for
> Agentic AI Safety* argues for an orthogonal layer in the agentic
> safety stack. Training-time alignment shapes what the model wants;
> oversight, debate, and red-teaming bound what the model is likely
> to produce; an admission-layer construction shapes what the
> substrate is willing to execute. Every destructive tool call
> carries a typed rollback witness at admission with a positive TTL
> by construction; absence of typed rollback before TTL expiry is
> structurally a violation. Because the substrate is the verifier,
> the admission predicate holds under model-side adversarial
> assumptions that training-time guarantees cannot match: a
> misaligned model, strategic composition, alignment-faking during
> evaluation, an operator manipulated into approval. The underlying
> theorems are discharged in Lean 4 in a companion paper.
>
> The structural claim that would benefit most from your reading is
> in §6 and §7: whether the factorisation of model-side and
> substrate-side safety matches how Anthropic's safety team thinks
> about layered construction, and whether the claim that admission
> survives alignment-faking is the right way to position the
> substrate-layer contribution against the red-teaming threat model.
>
> Concretely the offer is co-authorship on the workshop submission,
> scoped to the safety framing in §1, §2, §6, and §7. The structural
> theorems are cited rather than re-derived. If a follow-up
> benchmarking admission-protected versus unprotected deployments
> against a misaligned-agent corpus is closer to your research
> direction, I would happily yield lead-author position on that
> follow-up to you.
>
> Materials available on request: the workshop draft (approximately
> 4000 words; one focused read of about 45 minutes), the companion
> paper, and the underlying machine-checked artifacts. All under a
> 14-day embargo for collaborator review before any public pre-print.
>
> Best,
> [Author name + affiliation]

## Differentiation from the parent paper's outreach

The parent paper's outreach memo proposes Anthropic co-authorship on
a broader, longer paper grounded in legal-positivism and political
theory. That memo ranks Bowman first because the parent paper's
safety section (§7) is one section of twelve, and Bowman's
scalable-oversight work is the closest hook for a general-audience
reviewer.

This paper's framing is different. It is a workshop paper in the
AI-safety community's own voice, focused on a threat model the
alignment-faking and red-teaming literature already takes seriously.
Perez is the closer hook because his work targets the model-side
adversarial regime the substrate-layer construction is designed to
survive.

A co-author who engages with both papers would be ideal but is not
required. The recommendation is: send the parent paper's outreach to
Bowman (broader audience, evaluation framing) and this paper's
outreach to Perez (sharper threat model, red-teaming adjacency). The
two outreaches are independent.

## Sequencing

Send when both (a) the workshop deadline is at least three weeks
away (so a positive reply has room to translate into actual
collaboration on §1, §2, §6, and §7), and (b) the human is ready to
commit to an Anthropic conversation (the cold email starts a clock;
declining to follow up after a positive reply is worse than not
sending at all).

This sequencing is decoupled from the parent paper's USENIX
submission and from the Walch pre-disclosure letter. If the parent
paper is on a different track, this outreach can move in parallel.

If Perez declines or does not respond within seven days, move to
Bowman (only if the parent-paper outreach has not already engaged
him) or to Hubinger / Greenblatt. If all technical-track targets
decline, proceed without an Anthropic co-author at the workshop
tier. The paper is publishable at a top safety workshop without an
Anthropic co-author; the co-author would change reviewer perception
at the top-conference tier.

## Why this is not the autonomous orchestrator's job

1. Cold outreach to a specific researcher is a relationship play;
   the orchestrator has no Slack, Twitter, mutual-contact list, or
   institutional affiliation that would unlock an introduction.
2. The right introduction path is human-knowable: a mutual contact,
   a recent conference conversation, a co-cited paper. The
   repository does not carry that information.
3. The timing relative to the workshop deadline and the parent
   paper's pre-disclosure cycle is a strategic call that requires
   human judgement.

The orchestrator writes this memo and stops here. The human selects
a target, picks a real introduction, and sends.
