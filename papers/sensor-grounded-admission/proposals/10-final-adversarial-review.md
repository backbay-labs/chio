# Final Adversarial Review (termination check)

## Verdict: READY

The paper closes all open items from prior reviews. The fresh-eye pass against
the abstract / §1 / §4 / §6 / §8 / §9 / §10 reading order does not surface a
substantive finding that a sharp USENIX Security 2027 / NDSS 2027 / CSF 2027
PC reviewer would mark as a structural problem. The build gate is clean.
Termination is recommended.

## Verifications confirmed

1. **N1 disambiguation sentence.** Present in §8:23 (last sentence of the
   `Parent admission substrate.` paragraph): "The sensor-attestation
   construction is a fresh constitution rather than an amendment of the
   parent body-only constitution; the backward-refinement obligation applies
   to amendments within the new constitution, not to its introduction." The
   sentence closes the cycle-2 / cycle-3 amendment-vs-fresh-constitution
   ambiguity that lived at the inheritance boundary with the parent.

2. **§9 cosignature-party-independence paragraph.** Present at §9:24-25 as
   `\paragraph{Cosignature party-independence.}`, inserted between
   `Attestation-key isolation.` (§9:22) and `Cross-polity required sets.`
   (§9:27-28). The paragraph (117 words) inherits the parent's
   single-actor-collapse residual and ties it to quorum-required admission
   in §3:27 and §4:53.

3. **Theorem 1 rename complete in publication-targeted artifacts.**
   `grep -rn admission_under_degraded_state_distinguishable_from_healthy`
   returns zero hits across `paper.tex`, `sections/*.tex`,
   `lean/SensorGroundedAdmission.lean`, `lean/STATUS.md`,
   `lean/build-log.md`, and `README.md`. STATUS.md:15 and build-log.md:88
   carry the new name; README.md:17 has the new name in the
   why-headline-is-non-rfl paragraph.

4. **Stale `theorems.lean` at paper root is gone.**
   `ls papers/sensor-grounded-admission/theorems.lean` returns
   "No such file or directory". The packaging hazard the cycle-3 adversarial
   review (proposal 08, finding NF1) named is closed.

5. **Arithmetic consistency across §1 / §5 / §6 / §10.** All four sections
   read "six host-snapshot ... thirteen ... nineteen surveyed":
   - §1:21 `six host-snapshot emitter sites out of nineteen surveyed ...
     remaining thirteen covered by a placeholder`
   - §5:19 `six emitter sites consume it ... Thirteen sites consume the
     constant`
   - §6:12 `Six emitter sites consume it ... Thirteen further sites use
     a placeholder`
   - §10:6 `six host-snapshot emitter sites out of nineteen surveyed ...
     remaining thirteen attested by a placeholder`

   6 + 13 = 19 across the paper; the cycle-2-found arithmetic inconsistency
   that proposal 06 caught is gone.

6. **Build cleanliness.** Full `pdflatex / bibtex / pdflatex / pdflatex`
   chain run from `papers/sensor-grounded-admission/`: 0 errors, 0
   undefined citations, 0 BibTeX warnings, 18 pages.

7. **Lean compilation.** STATUS.md records all four theorems compile under
   Lean 4.28.0-rc1 with no `sorry`. `#print axioms` is confined to standard
   kernel axioms (`propext`, `Classical.choice`, `Quot.sound`); the
   axiom-by-theorem breakdown is at STATUS.md:154-160. Lean re-run not
   attempted in this fire (per task instructions); STATUS.md is the
   audit anchor.

## Findings (substantive)

None.

The fresh-eye sweep against the four hardest reading tests did not surface
a real reviewer flag:

- **Abstract --> §1 contributions --> §4 theorem statements --> §10
  conclusion.** The abstract's headline claim is "two receipts sharing
  identical body bytes whose distinct sensor attestations discharge the
  admission predicate to opposite verdicts." The §1 first bullet states
  this as Theorem 1; §4:34 states it formally as an existence claim with
  fixed witnesses; §10:6 first sentence delivers the same claim with
  `\thm{admission_predicate_separates_healthy_and_degraded_witnesses}`.
  The Lean theorem at SensorGroundedAdmission.lean:352-380 proves exactly
  the existence claim with the named witnesses. Honesty pass holds:
  §4:36 explicitly says "the headline itself does not induct over the
  provider list; it instantiates two fixed witnesses and rewrites," which
  matches what the Lean does. No reviewer can land a "the paper claims
  more than the proof delivers" hit.

- **§6 evaluation honesty.** §6:18 is the critical paragraph: "real in
  shape but synthetic in content" lexically separates the
  schema-conformance claim from the live-source claim. The empirical
  scope is explicitly bounded to the network-extension filter, the
  package-manager hooks, and the tool-preflight surface; ES-derived
  telemetry is named out of scope. §6:20 names what is withheld
  (Criterion latency, direct healthyProviderCount mutation,
  deployment-rate partition-contingency number, false-attestation rate).
  The empirical claim does not exceed what the substrate actually
  demonstrates.

- **Bib spot-check.** Three randomly chosen entries
  (`rfc9334RATS`, `sekarEAudit2024`, `yeh1996Boeing777`) match their
  authors / years / venues at the level a reviewer can verify against
  IETF / IEEE-Xplore / known conference programs. RFC 9334 is the RATS
  architecture, January 2023, authors Birkholz/Thaler/Richardson/
  Smith/Pan, all correct. eAudit appeared at IEEE S&P 2024 with the
  exact authors (Sekar/Kimm/Aich) and a valid IEEE DOI form. Yeh's
  triple-triple Boeing 777 PFC paper is at the 1996 IEEE Aerospace
  Applications Conference, well-known and correctly cited. The
  cycle-3 RESEARCH validation pass already spot-checked 12 entries
  (final-validation-pass.md:23-47); my three additional spot checks
  add no new findings.

- **§9 limitations honesty.** End-to-end read: the ledger covers
  substrate-honest strengthening (not elimination), required-set
  expressiveness, drop-and-miss action-specificity, within-window
  flapping, clock attestation, attestation-key isolation,
  cosignature party-independence, cross-polity required sets, theorem
  coverage (including both inert binders disclosed), operational
  observability, empirical chapter scope, and schema evolution
  inheritance from parent. The ledger lists ten residuals plus
  the inherited row; this is the right granularity for a contribution
  whose own bullet is "structural placement choice." No silent
  unacknowledged residual surfaced in the reading.

- **Voice check.** `grep -nE "checked-in|release-engineering|bless
  recipe|the codebase|the construction defended here|the live
  implementation|we extend|we introduce|v1/v2"` returns zero hits
  across `paper.tex` and `sections/*.tex`. Em-dash grep returns zero
  hits across paper, sections, and bib. The voice rules the user
  flagged repeatedly are held.

- **Theorem name promises.** Theorem 1's name promises witnesses that
  separate healthy and degraded; Lean delivers two named witnesses
  (`healthyWitness`, `degradedWitness`) and proves opposite verdicts.
  Theorem 2 promises a partition-contingency iff degraded-subset
  biconditional; Lean proves a strict-sublist iff length-strict-less
  bridge that matches the prose. Theorem 3 promises required-set
  coverage from admission; Lean projects the coverage Boolean out of
  the admission `Bool.and_eq_true` decomposition. Theorem 4 promises
  amendment-re-admission carries the partition-contingency
  improvement; Lean delivers `prev = true / next = false` on the same
  attestation bytes. STATUS.md honestly discloses that Theorems 3
  and 4 each carry one inert binder, and §9:31 disclose both. The
  promise-and-delivery alignment holds.

## Findings (non-substantive, noted but not blocking)

The following are editorial-grade items a careful reviewer might list
in the "minor comments" section of an Accept verdict; none rises to a
structural critique:

- §9:21-22's attestation-key-isolation paragraph and §3:21's
  TEE-rooted attestation-key separation paragraph share some
  citation overlap (Intel TDX, AMD SEV-SNP, Apple SEP, RFC 9334).
  Cycle-3 WRITE-A noted this and inserted a cross-pointer; the
  duplication is now restrained but a reader would notice the
  citations appear twice. Acceptable for a paper at this length.

- §1 contribution bullet 5 (`A canonical-JSON encoding deployed
  against six host-snapshot emitter sites out of nineteen surveyed
  in a working admission kernel`) is the closest §1 comes to an
  empirical claim; the language "working admission kernel" is
  bounded and matches §6's empirical scope. A picky reviewer might
  ask which kernel; the paper does not name it directly in §1
  (intentional, anonymity is preserved). Not a structural finding.

- §8 has one paragraph each on property attestation, trusted
  sensors, TEE attestation, kernel observability, aerospace
  redundancy, EDR, and the parent substrate. Seven paragraphs in
  765 words is the right density for the substrate's distance from
  each lineage. The TEE-vs-sensor paragraph (§8:11) is the load-
  bearing one and reads cleanly. A reviewer might want one more
  sentence on what makes sensor-grounded admission different from
  collective-device attestation (Asokan SEDA 2015 lifts to many
  devices; sensor-grounded admission lifts to many sensors on one
  kernel). The current framing "lifts them from the input layer ...
  to the substrate layer" is a sufficient one-line distinction.

## What the paper is now

The paper is a thirteen-page (formatted in a conference template;
eighteen pages under the development `article` class) formal-methods-
plus-systems-security paper. The contribution is a placement choice
and the formal predicate that follows from it: every signed receipt
carries a signed attestation of its kernel's sensing posture, and the
admission predicate is conditioned on that attestation. Four Lean
theorems mechanize the consequences. The empirical chapter cites a
working admission kernel that already ships the field. The substrate-
honest-by-assumption row in the parent paper is retired structurally
rather than as operational discipline. The strengthening is conditional
on an out-of-band sensor-coverage auditor whose existence the paper
explicitly names as future work.

The paper does what it says it does. The proofs deliver what their
names promise. The empirical chapter is honest about what it does
(verifier-side mutation rejection on a real receipt schema) and what
it does not (no Criterion bench, no live ES integration, no false-
attestation rate without an auditor). The bib is clean. The voice
holds throughout. The §9 limitations ledger is honest about ten
residuals plus the inheritance from the parent.

## Termination recommendation

**Terminate the cron; the paper is ready.**

Per the procedure stated in the task brief: this final adversarial
review returns zero substantive findings, and the build gate is clean
(0 errors / 0 undefined citations / 0 BibTeX warnings / 18 pages /
Lean compiles under standard axioms with no `sorry`). Write
`execution-complete.md` and call `CronDelete` on the recurring cron
job `f5c76fa9`.

The paper is at a state where the next reasonable activity is venue
submission preparation (USENIX Security 2027 Cycle 1, deadline August
25, 2026, per `research/venue-fit-submission-readiness.md`). Any
further iteration on the present paper is camera-ready polish, not
structural debt.
