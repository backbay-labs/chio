# Sensor-Grounded Admission: Polity Receipts with Attested Substrate State

A formal-methods plus systems-security paper that conditions receipt admission on the substrate's signed claim about its own sensor health at decision time.

## Venue

USENIX Security 2027 is the primary target. The September 2026 cycle is the working deadline (full-length 13 page submission, anonymous review). NDSS 2027 (August 2026 deadline) is the backup if peer review schedule slips on the Lean side.

The decision rests on which threat model the program committees will weight more. USENIX Security publishes systems-security papers with a working adversary; NDSS publishes network-and-distributed-systems papers with a working measurement story. The paper aims at the first reading because its load-bearing claim is about adversarial substrate state, not transport.

## Status

The four Lean theorems carrying the paper's load-bearing claims are mechanized and compile under Lean 4 against the deployed substrate's Treaty modules, with axiom dependencies confined to the standard kernel axioms (`propext`, `Classical.choice`, `Quot.sound`). The proof status of each theorem is recorded in `lean/STATUS.md`; the build environment and `#print axioms` output are recorded in `lean/build-log.md`. The empirical chapter rests on an already-shipped sensor-state field in every receipt produced by a deployed admission kernel. No additional executor or scheduler must ship for the empirical claims to hold.

### Why the headline theorem is non-`rfl`

The parent paper's `amendment_admissible_iff_backward_refinement` discharges to `rfl` because the left side is defined as the right side. The headline here, `admission_predicate_separates_healthy_and_degraded_witnesses`, is an existence-of-witnesses claim over two receipts sharing identical body bytes but distinct sensor attestations. The proof must (1) construct a healthy attestation `a_h` and a degraded attestation `a_d` over the same body, (2) instantiate a constitution `K` requiring a sensor set `S` such that `S` is covered by `a_h` and not by `a_d`, and (3) discharge the admission predicate at distinct verdicts on the two receipts. The case analysis on the attestation constructor and the structural subset check between attested-healthy and required sets does not reduce to a definitional unfold.

The supporting theorem `partition_contingency_mode_iff_degraded_subset` is biconditional between a ladder mode (a finite tag) and a structural set-subset relation between attested-healthy providers and policy-required providers. The forward direction requires inducting on the provider list; the reverse requires constructing a witness provider whose absence triggers the mode flip. Neither direction is definitional.

The other supporting theorems (`healthy_attestation_required_for_destructive_admission`, `degraded_sensor_admission_requires_re_attestation`) lift the structural distinction to admission classes named in the parent paper's ladder (receipt-backed and above). Each composes the headline result with a class predicate; the case analysis bites.

### Empirical claims and their substrate

The sensor-state attestation is a real field carried by every signed receipt produced by the deployed admission kernel. The attestation lists each registered sensor's installed, active, healthy, and degraded flags, plus dropped-event and deadline-miss counts at the captured timestamp. The kernel signs the attestation with the same key it signs the receipt body, and the canonical-JSON subject digest covers both. A verifier who admits a receipt without evaluating its attestation has chosen to skip a check the substrate makes available.

The empirical chapter cites this deployment as the source of its measurements. No new code must land before the empirical claims hold. The headline theorem's healthy and degraded witnesses are constructed in `lean/SensorGroundedAdmission.lean`; the partition-contingency biconditional, the destructive-admission projection, and the amendment re-attestation theorem are proven in the same file.

### Submission readiness

The prose is in shape, the empirical chapter is grounded in a deployed kernel's signed sensor-state attestation, the four Lean theorems are mechanized, and the related-work survey covers the trusted-execution and attestation literature relevant to the construction.

### Anthropic co-author hook

The recommendation between this paper and the bounded-executive-action paper depends on what the Anthropic researcher is being asked to defend.

This paper's hook is sharper for an alignment-and-evaluation reader. The substrate state attestation is structurally close to the trust-and-faithfulness questions that Bowman, Perez, and the alignment-evaluation team work on: an attested kernel reporting on its own sensing posture is the operational substrate that lets an external reviewer distinguish silent degradation from non-detection. The bounded-executive-action paper, by contrast, is closer to formal-methods systems work and asks for an operational-security co-author (someone who has actually shipped a response engine in production).

The case against this paper is that the empirical chapter cites a third-party deployment that is not under Anthropic's control, and the relevant alignment-evaluation question is upstream of substrate attestation (it is about what the model is trying to do, not about which sensors observed it). Paper N1 (bounded-executive-action) has the same problem in the other direction: its empirical chapter cites OS executors whose engineering is also not under Anthropic's control.

On balance: this paper is the better hook for the Bowman / Perez / Grosse / Kaplan fit if the framing is "an attestable substrate is a precondition for behavioral oversight." The bounded-executive-action paper is the better hook if the framing is "human-in-the-loop authorization is treaty intersection." The first framing is closer to current alignment-evaluation work; the second is closer to current responsible-scaling-policy work. The first is also less hostage to executor work that has not shipped.

## Synopsis

Every signed receipt produced by an admission kernel embeds a signed claim about which sensors were installed, active, healthy, and degraded at decision time, with dropped-event and deadline-miss counts. The polity's admission predicate is conditioned on this attestation: a receipt whose attestation shows the constitution-required sensor set is healthy is admitted under the receipt-backed mode; a receipt whose attestation shows the required set is not healthy is admitted only under the partition-contingency mode, with explicit reconciliation obligations. Admission under a degraded substrate is structurally distinguishable from admission under a healthy substrate, and the structural distinction is decidable on the attestation field. The headline result is an existence-of-witnesses claim; the supporting results connect the structural distinction to the parent paper's five-mode ladder and to the destructive-admission floor. The retired assumption is the parent paper's "trust-store-honest-by-assumption" row: the substrate now attests its own sensor state, and the verifier's admission predicate evaluates that attestation rather than assuming honesty.

## Layout

- `paper.tex` is the LaTeX shell. It uses `\documentclass{article}` to keep build dependencies light.
- `sections/01-introduction.tex` through `sections/10-conclusion.tex` carry the prose.
- `lean/SensorGroundedAdmission.lean` carries the four mechanized theorems and their supporting definitions. It builds against the deployed substrate's `Chio.Treaty.PredicateLang` and `Chio.Treaty.Intersection` modules under Lean 4. Proof status per theorem is in `lean/STATUS.md`; build environment and axiom audit are in `lean/build-log.md`.

## Author voice

The paper describes what the substrate is and what its admission predicate does, not what an authoring team decided. It does not refer to code branches, project versions, internal artifact counts, fixture matrices, or release-engineering steps. Citations to runtime code use `\codepath{...}`. Citations to parent-paper theorems use `\thm{...}`.

## House rules

- No em dashes anywhere in the paper.
- Cite parent paper theorems by their inventory name with `\thm{...}`.
- Bibliography entries are primary-source citations in `bib.bib`.
