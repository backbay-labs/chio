# Walch pre-arXiv embargo invitation (draft)

Draft of the cover letter for the round-3 strategic agent's pre-arXiv adversarial-disclosure embargo to Angela Walch. To be sent on the user's signature after final review.

---

**Subject**: Pre-arXiv adversarial-disclosure embargo invitation — "Programmable Sovereignty" preprint

Dear Professor Walch,

I am writing to invite your hostile pre-publication review of a forthcoming preprint, "Programmable Sovereignty: Lean-Attestable Constitutions Over Capability-Bounded Federated Receipts," with a 14-day embargo before posting to arXiv. Your 2017 *Review of Banking and Financial Law* article on the path of the blockchain lexicon is cited in §2 of the manuscript as a methodological constraint on the paper itself, and your subsequent work has been the most consistent academic check on technical communities' tendency to claim more than their substrates carry. The paper's argument deserves a serious test against that check before publication.

The paper makes a deliberately narrow positivist claim: that an agent runtime can instantiate condition (a) of Hart's rule of recognition (the criterion officials apply to identify which rules count as law of the system) over cross-organizational tool invocations, leaving conditions (b) practice-of-officials and (c) internal-point-of-view acceptance as sociological obligations the construction does not discharge. Sections 7, 8, and 9 acknowledge the methodological constraint your work imposes; section 2 cites your 2017 article in the failure-modes paragraph alongside Próspera, FTX, and Tornado Cash.

The construction itself is a Rust runtime with companion Lean 4 proofs, instantiated as a three-vendor buyer-closure replay artifact. Independent review across multiple revision rounds has surfaced and the paper now openly documents: (1) the Hartian framing's restriction to condition (a) only, (2) the Lean theorems' narrow proof obligation versus the broader Rust runtime, (3) the absence of a published interop profile, and (4) the regulator-accreditation gap that no current attestation framework cites Lean-attested receipt evidence.

I am inviting you to a 14-day pre-arXiv embargo so you can prepare a response on terms of your choosing. Two formats are on the table:

1. **Co-launched response.** You publish a written rejoinder, op-ed, or technical note that appears alongside the arXiv preprint. The paper cites your response prominently in §7 and §8.
2. **Private comments only.** You read the paper under embargo and respond by email; the response is not public.

Either is welcome. The point is that the paper benefits from a serious adversarial reading that it cannot itself supply, and the most credible version of that reading is yours.

Attached: the current manuscript draft and a one-page summary of the swarm-review findings the paper has already addressed. If you prefer to engage on a different timeline or with different framing, I would rather defer arXiv than skip your review.

Sincerely,
[Author signature]

---

## Cover-letter attachments (for reference; not part of the letter)

1. `papers/programmable-sovereignty/paper.pdf` — current manuscript
2. `papers/programmable-sovereignty/polish-diff.md` — revision history across five polish passes
3. `papers/programmable-sovereignty/swarm-notes/action-plan.md` — outstanding action plan with five-tier severity ranking
4. One-page summary: this draft document, with the substantive limitations §9 carries:
   - Hart claim scoped to condition (a) only
   - 109-vs-113 Lean declaration-count branch drift (decision to ship from main with 113)
   - Bibliography hygiene pass landed (seven WRONG entries re-derived from primary sources; six WOBBLE entries corrected)
   - Replay-corpus §6 prose honestly separates kernel-capability gate from unreplayed Chiodos buyer-closure
   - Figure 1 fail-closed bug fixed (malformed contexts now deny)
   - Walch / De Filippi / Hildebrandt cited as the methodological constraint on the paper's vocabulary

## Backup recipients if Walch declines

In priority order (each gets a tailored variant of the letter):

1. **Peter Van Valkenburgh** (Coin Center, Director of Research): the Tornado Cash legal-academic constituency. Likely to engage on the §2 failure-modes framing and the §7 declarative-statehood reading.
2. **Primavera De Filippi** (CNRS / Harvard Berkman Klein): cited as `defilippi2018blockchain` in §2. Likely to engage on the constitutive-recognition pushback in §7.
3. **Mireille Hildebrandt** (Vrije Universiteit Brussel): legal-informatics depth; would engage with the Hart paragraph in §7 and Schauer rules-vs-standards in §7.

Send to one at a time; do not parallel-send. The point is a sustained adversarial reading, not a survey of consent.

## Timing

Optimal week of send: as soon as the MUST-fix sprint is verified shipped (this branch). The 14-day embargo lands arXiv at most 21 days from send. NDSS 2027 (Aug 2026 deadline) and USENIX Security 2027 (Feb 2026 short-paper, Aug 2026 full) both accommodate an arXiv-then-submit timeline.
