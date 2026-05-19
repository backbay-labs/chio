# Wave 2C: Citations and discussion tightening

Scope: `bib.bib`, `sections/02-background.tex`, `sections/07-discussion.tex`. Three missing alignment-research citations added; three dormant capability-systems citations activated in §2; §7 composition pairs named precisely.

## 1. Three new bib entries

Added to the end of `bib.bib` (after the existing `anthropicRSP2023`):

- `hubingerSleeperAgents2024` (arXiv:2401.05566, Anthropic alignment team)
- `carlsmithSchemingAIs2023` (arXiv:2311.08379)
- `krakovnaGoalMisgeneralization2023` (arXiv:2210.01790, DeepMind alignment team)

Field values follow the standard arXiv records. Each entry carries a one-sentence `note` field naming what the citation is doing, so the eventual venue copy-edit pass can fold notes into prose if the venue style prohibits `note`. No collision risk: the three keys are distinct from any pre-existing entry and from the keys Wave 2A and 2B are expected to touch (those waves are concerned with §3 cases, §1 framing, abstract voice, not alignment-literature citations).

## 2. §2 background: alignment-literature engagement

The existing "Alignment-faking and situational awareness" paragraph was renamed to "Alignment-faking, scheming, and situational awareness" and extended. Carlsmith's scheming-AIs analysis is named as the comprehensive treatment of the threat model the construction defends against at the substrate boundary. Sleeper-agents experiments are cited as evidence that deceptive behaviour can survive RLHF, which is the sharpest motivation for a defence whose soundness does not depend on training having succeeded. Krakovna goal-misgeneralisation is cited at the end of the paragraph as the second motivation for a structural rather than specification-based defence: even when the specified objective is correct, deployed behaviour can pursue a misgeneralised goal the specification did not enumerate.

The closing sentence of the paragraph was tightened to name both regimes the paper's defence is invariant to: a regime where evaluation-time behaviour is not a reliable predictor of deployment-time behaviour, and a regime where training-time and specification-time defences cannot be assumed to hold uniformly at runtime.

## 3. §2 background: capability-systems backbone

The "gap" paragraph now contains the sentence: "The capability-systems literature (Capsicum, Miller's robust-composition framework) and verified OS kernels such as seL4 supply the formal-methods backbone for admission-time discipline; the substrate-layer story extends this work to the agentic-AI domain." This activates `watson2010capsicum`, `miller2006composition`, and `klein2009sel4`, all of which were dormant in the bib. Placement is deliberate: these are the formal-methods citations that should appear once the paper has stated the substrate-as-verifier framing, and the gap paragraph is where that framing first crystallises.

§2 grew from 406 words to 563 words (target was ~510; slight overshoot but well within workshop-position-paper tolerance for a section that survives a hostile alignment-research read).

## 4. §7 discussion: three composition pairs named precisely

A new "Three composition pairs, named precisely" paragraph sits immediately before the existing "Composition is the headline" paragraph and names:

1. Constitutional AI plus admission-layer. The failure mode of Constitutional AI alone, subtle violations the constitution does not enumerate, is caught by admission's structural reversibility requirement.
2. Scalable oversight plus admission-layer. Oversight is the right instrument where admission is too coarse (content correctness within the substrate-admitted set); admission catches the cases where oversight is unavailable or where structural irreversibility makes a verdict moot.
3. RSP commitments plus receipts. The RSP defines policy; receipts make policy-conformance auditable.

Citations: `baiConstitutionalAI2022`, `leikeScalableOversight2018`, `christianoDebate2018`, `bowmanScalableOversight2022`, `anthropicRSP2023`. The existing "Composition is the headline" paragraph is preserved unchanged as the coda; the new paragraph adds the precise mechanism statement Wave 1C asked for without displacing the existing closing.

## Build verification

```
errors: 0
bib misses: 0
undef cites: 0
Pages: 13
```

`pdflatex` clean across two passes; `bibtex` resolves all three new keys plus the three newly activated dormant keys; no em dashes in any edited file. House rules respected: anonymous author posture, workshop register, no engineering-meta voice.
