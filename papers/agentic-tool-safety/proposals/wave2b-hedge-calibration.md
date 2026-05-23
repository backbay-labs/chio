# Wave 2B: Hedge calibration

Five targeted edits to align surface phrasing with the substrate's actual guarantee, addressing Wave 1A's alignment-literature engagement gaps and Wave 1B's adversarial audit findings.

## 1. Abstract: operator-manipulation overreach

Wave 1B found the abstract listed "the operator is manipulated" alongside training failure, scheming, and alignment-faking as regimes the substrate defeats. §6's mechanics support only the weaker claim that the substrate requires bilateral concurrence, not that it detects a willing-signing manipulated operator.

Original (paper.tex, line 37): "This refusal holds even when alignment training has failed, the model schemes, the model fakes alignment, and the operator is manipulated, because the substrate is the verifier and not the agent."

New: "This refusal holds even when alignment training has failed, the model schemes, and the model fakes alignment, because the substrate is the verifier and not the agent. Operator manipulation is treated separately in Section~\ref{sec:threat}: the substrate requires bilateral concurrence on irreversible variants, but does not detect a manipulated operator who signs willingly."

Word-count delta: abstract grew from 196 to 202 words, inside the 180-210 target.

## 2. §1: "regardless of what the model wants" soft-displacement

Wave 1A flagged the introduction's framing as reading like training-layer replacement rather than composition.

Original (sections/01-introduction.tex, paragraph 3): "The substrate may decline to execute a tool call that does not carry a typed proof of reversibility, regardless of what the model that issued the call wants, regardless of whether the model successfully evaded its training signal, and regardless of whether the operator was manipulated into approving it."

New: "regardless of whether training-layer alignment has fully succeeded and regardless of whether the model has evaded its training signal. Admission-layer safety composes with training-layer safety rather than displacing it: a model whose preferences are well-shaped by training will, in the typical case, issue admissible envelopes, and the substrate's role is to bound the operational consequence in the cases where training has not held."

Word-count delta: paragraph grew by ~25 words; substrate-precedes-training framing replaced with explicit composition.

## 3. §6: alignment-faking depth

Wave 1A noted the existing "alignment-faking changes nothing about the typed admission" reads as evasive: the substrate constrains external behaviour, not internal scheming.

Original (sections/06-threat-model.tex, lines 12-13): three-sentence paragraph asserting the substrate's predicate "is not a function of the model's claimed intent."

New: 145-word paragraph naming the internal/external alignment-faking distinction, stating what the substrate constrains (external behaviour, specifically tool calls a misaligned model cannot constructively justify at admission), and citing the Hubinger et al. scratchpad finding by name with the deployment-aware response: the substrate refuses non-witnessable envelopes regardless of the model's deployment-awareness state.

Word-count delta: paragraph grew from ~70 to 145 words, inside the 100-150 target.

## 4. §6: deceptive alignment and situational awareness stanza

Wave 1A found §6 named neither Hubinger 2021 nor Berglund 2023 despite their citation in §2.

New paragraph (sections/06-threat-model.tex, inserted between alignment-faking and operator manipulation): names deceptive alignment as a mesa-optimisation failure (Hubinger 2021), situational awareness as the strategic precondition (Berglund 2023), and the model-state-invariance property: the admission predicate evaluates the emitted tool call, not the model's mesa-objective or deployment inference. A deceptively aligned model with situational awareness can issue admissible calls but cannot issue calls that are not.

Word-count delta: 119-word paragraph added, inside the 80-120 target.

## 5. §8: residual attack categories

Wave 1B's audit identified five attack categories the substrate does not defeat. §8 previously addressed only mis-classification, registry compromise, faulty rollback, and bypassed dispatch.

New paragraph (sections/08-limitations.tex, inserted before "Scope of the formal claim"): enumerates (1) composition with side-channel leakage of the rollback witness, (2) TTL races against an unspecified concurrency model, (3) operator manipulation when the host polity also signs willingly, (4) admission-hook denial of service, (5) multi-agent collusion. Frames downstream work: composition-aware admission predicates, a concurrency-bounded substrate model, multi-agent admission protocols.

Word-count delta: 175-word paragraph added, inside the 150-200 target.

## Build verification

```
errors: 0
undef cites: 0
Pages: 13 (was 12, +1 page as expected)
```

No em dashes introduced. All three new Hubinger/Berglund citation invocations resolve to existing bib keys (`hubingerAlignmentFaking2024`, `hubingerDeceptiveAlignment2021`, `berglundSituationalAwareness2023`). Three undefined-citation warnings observed on first build (`carlsmithSchemingAIs2023`, `hubingerSleeperAgents2024`, `krakovnaGoalMisgeneralization2023`) live in §2 outside this wave's scope and resolved on the multi-pass build.
