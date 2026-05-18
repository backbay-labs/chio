# Anthropic Co-author Outreach Memo

Action-plan item: "Court Anthropic as co-author (Bowman / Perez /
Grosse / Kaplan) — needs human relationship; deferred".

Status: outreach draft only. The actual approach requires a human
to identify the right introduction path and time the ask correctly.
This memo gives the human a ready-to-send framing and a target
priority order.

## Why Anthropic

§7 of the paper grounds the constitutional-admission framework in
Constitutional-AI-style alignment work, and the AI-safety paragraph
cites Bai 2022 (Constitutional AI), Hubinger 2024 (alignment
faking), and Berglund 2023 (situational awareness) — all
Anthropic-authored. The substrate Chio formalizes (machine-checked
admission predicates over capability-bounded receipts) is the kind
of governance scaffolding Anthropic's alignment team has separately
argued for. A co-authorship aligns the paper's intellectual debt with
the institution that produced the underlying ideas, and gives the
paper a credible AI-safety voice for the NDSS / USENIX reviewer
distribution.

## Target priority order

1. **Sam Bowman** — model behavior & evaluation work; if anyone at
   Anthropic has bandwidth for an outside collaboration on
   alignment-flavored systems work, it's probably here. Recent NYU
   ties make him reachable via academic channels.

2. **Ethan Perez** — red-teaming and adversarial-evaluation work
   most adjacent to the paper's threat-model construction. The
   adversarial-replay angle of paper 5 (next-paper pipeline) is in
   his wheelhouse.

3. **Roger Grosse** — interpretability and model-behavior
   characterization. Slightly further from the systems contribution,
   but his sign-off would carry weight with reviewers who want
   evidence the technical machinery is interpretability-relevant.

4. **Jared Kaplan** — co-founder, strategic. Reach only after a
   technical co-author is on board; Jared's name on the paper would
   change reviewer perception but is hard to land cold.

## Draft email (to whichever target the human selects)

> Subject: Co-authorship inquiry — formal substrate for constitutional admission of agent receipts
>
> Dear Dr. [last-name],
>
> I'm reaching out because your work on [Constitutional AI / alignment
> faking / red-teaming — pick one specific paper of theirs] shaped
> how we framed §7 of an in-flight paper we're preparing for NDSS
> 2026 / USENIX Security 2026.
>
> The paper, "Programmable Sovereignty: Lean-Attestable Constitutions
> Over Capability-Bounded Federated Receipts", introduces a substrate
> in which a polity is a triple (T, C, K) — a closed receipt-admission
> scope, a Merkle-rooted citizenship roster, and a constitution
> expressed as a finite list of predicates evaluated by a runtime
> kernel and discharged by machine-checked Lean 4 proofs over a
> bounded model. We prove theorems for treaty predicate intersection,
> ladder-floor stability, amendment refinement, and (in the v2
> direction) a trajectory-invariant constitutional-ratchet defense.
> The §7 framing draws explicitly on Bai 2022 / Hubinger 2024 /
> Berglund 2023.
>
> Where we'd value your input — and what a co-authorship would add —
> is on the alignment-side framing in §7 and §10: whether the
> constitutional substrate as we've formalized it is a credible
> structural answer to the alignment-faking and situational-
> awareness risks your team has documented, and whether the
> non-amendable axiom set we treat as the trust-store admission
> predicate is the right structural place to encode the alignment
> invariants you'd want to see preserved.
>
> Concretely we'd offer:
>
> - Lead-author position on a follow-up paper (next-paper pipeline
>   "Paper 5: adversarial-replay benchmark") if the systems
>   contribution there is more directly aligned with your work.
> - Co-author position on this submission if you'd like to contribute
>   to §7 and §10 in time for the [NDSS 2026 / USENIX 2026] deadline.
> - All the underlying machine-checked artifacts (Lean source,
>   Rust kernel, replay corpus) under a permissive license and a
>   14-day embargo period for collaborator review before public
>   pre-print.
>
> Happy to share the current draft on request. The repository is
> available under embargo to a small set of pre-disclosure
> collaborators; you would be the fifth.
>
> Best,
> [Author name + affiliation]

## Sequencing

Send AFTER the Walch pre-disclosure embargo letter goes out and the
14-day clock starts. The Walch letter is the legal-policy reviewer;
the Anthropic outreach is the alignment-research reviewer. Both
should see the manuscript before any external pre-print.

If Bowman / Perez declines or doesn't reply within seven days, move
to Grosse. If all technical-track targets decline, skip Kaplan and
proceed without Anthropic co-authorship rather than chase the
strategic ask cold.

## Why this is not the autonomous cron's job

1. Cold outreach to a target individual is a relationship play; the
   cron has no email account, no Twitter, no Slack, no in-person
   network.
2. The right introduction path (mutual contact, conference
   conversation, prior correspondence) is human-knowable, not
   discoverable from the repo.
3. The timing relative to the Walch embargo and the venue submission
   deadline is a strategic call.

So the cron writes this draft and the email above and stops here.
The human selects a target, picks a real introduction, and sends.
