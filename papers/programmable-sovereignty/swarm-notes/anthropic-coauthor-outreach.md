# Anthropic Co-author Outreach Memo

Action-plan item: "Court Anthropic as co-author (Bowman / Perez /
Grosse / Kaplan); needs human relationship; deferred."

Status: outreach draft only. The actual approach requires a human
to identify the right introduction path and time the ask correctly.
This memo gives the human a ready-to-send framing and a target
priority order. See also the agentic-tool-safety pitch at
`papers/agentic-tool-safety/anthropic-coauthor-pitch.md`, which
routes Perez as the primary contact for that paper.

## Why Anthropic

Section 7 of the paper grounds the constitutional-admission framework
in Constitutional-AI-style alignment work, and the AI-safety paragraph
cites Bai 2022 (Constitutional AI), Hubinger 2024 (alignment faking),
and Berglund 2023 (situational awareness). All three are
Anthropic-authored. A co-authorship aligns the paper's intellectual
debt with the institution that produced the underlying ideas, and
gives the substrate-side argument a credible alignment-research voice
for the USENIX reviewer distribution.

## Target priority order (parent paper)

1. **Sam Bowman** (primary). Scalable-oversight and model-behaviour
   evaluation work; the verdict-versus-admission distinction in §7 is
   in his wheelhouse. NYU ties also make him reachable through
   academic channels.

2. **Roger Grosse** (secondary). Interpretability and model-behaviour
   characterisation. Slightly further from the systems contribution,
   but a credible reviewer for §7 framing.

3. **Jared Kaplan** (escalation only). Co-founder, strategic; reach
   only after a technical co-author is already on board. Hard to land
   cold and likely to dilute rather than sharpen reviewer perception
   if landed without a technical anchor first.

Ethan Perez is intentionally NOT listed here as a parent-paper
target. He is the primary contact for the agentic-tool-safety paper
(separate memo); routing him to the parent paper would burn the
sharper handoff. If the agentic-tool-safety pitch lands first, his
endorsement there is the natural bridge into the parent paper rather
than a cold ask on §7.

## Draft email (to Bowman, or whichever target the human selects)

> Subject: Co-authorship inquiry on constitutional admission of agent
> receipts
>
> Dear Dr. Bowman,
>
> I am reaching out because your work on scalable oversight shaped
> how §7 of an in-flight paper of mine handles the
> verdict-versus-admission distinction. The paper is under review at
> USENIX Security 2026.
>
> *Programmable Sovereignty: Lean-Attestable Constitutions over
> Capability-Bounded Federated Receipts* models a polity as a triple
> (T, C, K): a closed receipt-admission scope, a Merkle-rooted
> citizenship roster, and a constitution expressed as a finite list
> of predicates evaluated by a runtime kernel and discharged by
> machine-checked Lean 4 proofs over a bounded model. Section 7
> situates the substrate against Bai 2022, Hubinger 2024, and
> Berglund 2023.
>
> The structural claim that would benefit most from your reading is
> in §7 and §10: whether the non-amendable axiom set we treat as the
> admission predicate is the right structural place to encode the
> alignment invariants Anthropic's safety team has separately argued
> a deployed system should preserve, and whether the substrate
> survives the regime alignment-faking research has documented.
>
> Concretely the ask is small. The primary request is that you read
> the manuscript under embargo (one focused read; the safety-relevant
> sections are §7 and §10) and contribute to those framings if the
> structural claim is credible. The secondary, lower-bar offer is
> co-authorship on a companion workshop paper my co-authors and I
> are preparing on agentic-tool-safety admission (separate
> threat-model framing; sized for a NeurIPS or ICML safety workshop).
> The workshop paper sits closer to the alignment-research literature
> and is the more natural home for an Anthropic co-author if the
> parent paper's framing is too far from your current direction.
>
> Materials available on request: the current draft, the
> machine-checked artifacts referenced in §3, and the workshop draft.
> All under a 14-day embargo for collaborator review before any
> public pre-print.
>
> Best,
> [Author name + affiliation]

## Sequencing

Send when both (a) the parent paper has been submitted to USENIX
(the manuscript is at a stable shape under venue review, so a
collaborator read is on a defined manuscript rather than a moving
draft), and (b) the human is ready to commit to an Anthropic
conversation (the cold email starts a clock; declining to follow up
after a positive reply is worse than not sending at all).

This sequencing is decoupled from the Walch pre-disclosure letter.
The Walch letter is a separate legal-policy review track and can
move on its own timeline.

If Bowman declines or does not reply within seven days, move to
Grosse. If both technical-track targets decline, skip Kaplan and
proceed without Anthropic co-authorship rather than chase the
strategic ask cold.

## Postscript: split routing recommendation

The action-plan item conflates two outreaches that should be
separated.

- **Parent paper (programmable sovereignty)**: Bowman primary,
  Grosse secondary. This memo.
- **Agentic-tool-safety workshop paper**: Perez primary, Bowman
  secondary, Hubinger / Greenblatt tertiary. See
  `papers/agentic-tool-safety/anthropic-coauthor-pitch.md`.

The two outreaches are independent and can be sent to different
people. Sending both pitches to the same person would force a
choice they should not have to make. If the human wants to make a
single ask, the recommendation is the agentic-tool-safety pitch to
Perez: it is the sharper threat-model framing, the citation graph
is denser on Anthropic-authored prior art, and the workshop tier
is a lower-bar collaboration commitment than a USENIX co-authorship.

## Why this is not the autonomous orchestrator's job

1. Cold outreach to a target individual is a relationship play; the
   orchestrator has no email account, no Twitter, no Slack, no
   in-person network.
2. The right introduction path (mutual contact, conference
   conversation, prior correspondence) is human-knowable, not
   discoverable from the repository.
3. The timing relative to the USENIX submission and the workshop
   deadline is a strategic call.

The orchestrator writes this memo and stops here. The human selects
a target, picks a real introduction, and sends.
