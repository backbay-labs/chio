# Pre-Slack Outreach Memo

Action-plan item: "Pre-Slack to one of {IC3, Paradigm internal,
GovAI policy circle} — needs human relationship".

Status: outreach draft only. The choice of which of the three
circles to lead with is a strategic call about which reviewer
community the paper most needs friendly priors from.

## Target circles

| Circle               | Strength of fit                          | Cost of asking         |
|----------------------|------------------------------------------|------------------------|
| IC3                  | Academic-systems credibility; reaches Sirer, Juels, blockchain-systems committee members. Highest fit for the technical claims (DSSE, anchor quorum, tile-log substrate). | Public Slack workspace; easy to join but harder to get sustained attention. |
| Paradigm internal    | Crypto-VC-research credibility; reaches Walch's neighborhood and the policy-adjacent reviewers. | Closed; invite-only; high signal but small audience. |
| GovAI policy circle  | Policy / governance credibility; reaches Dafoe / Brundage neighborhood. Highest fit for §7 Hart and §10 willing-counterparty framing. | Closed; invite-only; the right audience for the paper's institutional claims. |

## Recommended sequencing

1. **First**: IC3. The blockchain-systems reviewer community has the
   sharpest priors about whether the bilateral-DSSE + multi-lane
   anchor design is a credible threat-model improvement. Get the
   sharpest critics warmed up first; their feedback de-risks the
   harder reviewers in step 3.
2. **Second**: GovAI. The §7 Hart paragraph and §10 willing-co-signing
   counterparty framing will get the policy-side priors. The
   alignment-research case-study pilot decision (UK AISI / AI
   cross-lab attestation) is the lead-in.
3. **Third**: Paradigm internal. Save for last because Walch is
   already on the Walch-letter list; double-touching Paradigm before
   the embargo period adds noise.

## Draft message (40-90 words, slack-flavored)

> hey [name] — quick heads-up on a paper we're about to put under
> 14-day embargo. it formalizes a substrate for agent-system
> governance (capability-bounded receipts, Merkle citizenship,
> Lean-attestable constitutions over a finite predicate set) and
> proves treaty intersection, ladder-floor stability, and
> trajectory-invariant amendment refinement. happy to share the
> draft if it's interesting; would value a sanity check on
> [section/claim relevant to their circle] before the submission
> deadline.

## What "Pre-Slack" actually does

The point is NOT to recruit reviewers, NOT to leak the paper, and
NOT to bypass venue policy. It is to give the most credible voices
in the target reviewer communities a one-week head start on the
manuscript so their early feedback is "in time to fix" rather than
"too late to act on". This is standard pre-submission hygiene; the
14-day embargo is the formal mechanism.

## Sequencing relative to Walch + Anthropic

- Walch letter ships first (formal embargo channel).
- IC3 Pre-Slack ships day +1 (systems community warm-up).
- Anthropic co-authorship inquiry ships day +3 once technical
  reviewer comments start flowing.
- GovAI Pre-Slack ships day +5 (policy framing locked).
- Paradigm internal Pre-Slack ships day +7 (last because Walch's
  there).

## Why this is not the autonomous cron's job

1. Slack workspace membership is the human's; the cron has no
   identity in any of these circles.
2. The right target individual within each circle is a
   relationship call.
3. The phrasing of the [section/claim relevant to their circle]
   placeholder requires picking the angle that resonates with the
   specific recipient, which is human-knowable.

So the cron writes this draft and the message above and stops here.
