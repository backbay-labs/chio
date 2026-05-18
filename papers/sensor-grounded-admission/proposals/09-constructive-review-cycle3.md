# Constructive Review (Cycle 3 closeout)

REVIEW agent B, final constructive pass. Sources: cycle-3 research notes
(`final-validation-pass.md`, `venue-fit-submission-readiness.md`),
`paper.tex` plus `sections/*.tex`, `lean/STATUS.md`,
`lean/SensorGroundedAdmission.lean`, `lean/build-log.md`, `README.md`,
`theorems.lean`, `bib.bib`, and the parent paper's
`sections/09-limitations.tex`. The cycle-3 RESEARCH ranked 11 findings (0
blocker, 2 major, 6 minor, 3 nit); this proposal supplies drop-in drafts
for each. The FIX cycle that follows is the final paper-modification fire
before termination.

## Major 1: N1 amendment disambiguation sentence

**Placement.** §8 related-work, end of the parent-admission paragraph
(`sections/08-related-work.tex:22-23`). The line that currently reads
`\thm{amendment\_admissible\_iff\_backward\_refinement} gains a paired
re-attestation obligation, as Section~\ref{sec:model} establishes.` is
the exact N1 source. Append the disambiguating sentence there; §8 is the
single place a reviewer asks "is this an amendment?" because §8 is where
the parent paper is named. §3 alternatives were considered and rejected:
§3:15 mentions the parent amendment cycle but reads as a forward pointer,
not a construction claim, and §3 is busy with substrate definitions.

**Drop-in sentence** (to be added at the end of §8:23, after
`\ldots as Section~\ref{sec:model} establishes.`):

> The sensor-attestation construction is a fresh constitution rather
> than an amendment of the parent body-only constitution; the
> backward-refinement obligation applies to amendments within the new
> constitution, not to its introduction.

Word count: 38. House-rule compliant (no em dashes, no engineering-meta
voice). Closes N1 by stating directly what cycle-3 RESEARCH's top finding
flagged: a reviewer reading §8:23 currently treats the sensor-attestation
predicate as an amendment to the parent's body-only predicate, which
under the parent's `BackwardRefines` would owe a backward-refinement
witness. The added sentence reframes the construction as a fresh
constitution; the parent's amendment discipline then applies only to
amendments within the new construction (which §3:15 already handles via
the required-set narrowing path), not to its introduction.

## Major 2: §9 cosignature party-independence inheritance row

**Placement.** New paragraph in `sections/09-limitations.tex`, inserted
after the existing `Attestation-key isolation.` paragraph (current
§9:21-22) and before the `Cross-polity required sets.` paragraph
(current §9:24-25). The neighbouring topics are key-isolation and
cross-polity admission; cosignature party-independence sits cleanly
between the two.

**Drop-in paragraph** (mirrors §9's existing `\paragraph{Title.}` voice
and the parent paper's table row at line 20):

> \paragraph{Cosignature party-independence.}
> A bilateral DSSE envelope and the sensor-state attestation are
> separable cryptographic outputs only when their signers are
> independent principals: a single actor controlling both keys
> collapses the bilateral primitive to one-of-one signing, regardless
> of envelope shape. The construction here treats cosigner attestations
> under quorum-required admission (Section~\ref{sec:model}) as joint
> authorization for cross-organizational admission; the residual is
> that a single-actor deployment whose body-signing and
> attestation-signing keys both rest with one principal recovers no
> cryptographic strengthening over single-key signing, only the
> structural strengthening of a falsifiable claim. The parent paper's
> assumption ledger names this collapse; the present construction
> inherits the residual without modification.

Word count: 117. Mirrors the parent §9 row at
`programmable-sovereignty/sections/09-limitations.tex:20` ("two-key DSSE
under a single actor collapses to one-of-one") and ties to the
sensor-grounded paper's `quorum-required` admission story in §3:27 and
§4:53. Closes cycle-3 RESEARCH finding 2 (cosignature
party-independence inheritance unacknowledged).

## Minor 3: Companion-document Theorem 1 rename propagation

Old name: `admission_under_degraded_state_distinguishable_from_healthy`.
New name (matches paper.tex and `lean/SensorGroundedAdmission.lean`):
`admission_predicate_separates_healthy_and_degraded_witnesses`.

Files and lines requiring rename (mechanical replacement):

- `lean/STATUS.md:15` -- section heading `## Theorem 1:
  \`admission_under_degraded_state_distinguishable_from_healthy\``.
- `lean/build-log.md:88` -- `#print axioms` output line
  `'Chio.Treaty.SensorAttestation.admission_under_degraded_state_distinguishable_from_healthy'
  depends on axioms: [propext,`. Either re-run `#print axioms` (the
  Lean file no longer carries this name, so the output is stale) or
  edit the captured output in-place.
- `README.md:17` -- prose paragraph: `The headline here,
  \`admission_under_degraded_state_distinguishable_from_healthy\`, is
  an existence-of-witnesses claim\ldots`. Replace the name; the
  surrounding prose remains valid.
- `theorems.lean:229` -- `theorem
  admission_under_degraded_state_distinguishable_from_healthy`. The
  file is the v0 draft with `:= sorry` placeholders and is superseded
  by `lean/SensorGroundedAdmission.lean`. Two options: (a) rename in
  place to match the proven version; (b) delete the file (it is
  `sorry`-stubbed and obsolete). RESEARCH note flagged this as a
  packaging hazard if `lean/` ships as USENIX supplementary material.
  Recommend deletion.

FIX-cycle dispatch: one agent runs four `sed`-style replacements, drops
the obsolete `theorems.lean`, and re-greps the tree for stragglers.
Estimated 15 minutes.

## Minor 4: Theorem 4 inert binder disclosure

Two options on the table:

**Option A (disclose in §9).** Extend the existing `Theorem coverage.`
paragraph at `sections/09-limitations.tex:27-28`, which already discloses
Theorem 3's inert `destructiveAdmissionFamily` binder. Append one
sentence after the current closing sentence (after
`\ldots retained as a structural hook for a strengthened statement.`):

> Theorem 4's \texttt{\_h\_prev\_decl} binder is similarly inert: the
> conclusion's structural-improvement claim is carried by the
> prior-mode hypothesis and the new-mode coverage, with the prior-decl
> lookup retained as a structural hook for a strengthened statement
> tying the prior declaration into the witness construction.

Word count: 48.

**Option B (remove the binder).** Drop the `_h_prev_decl` parameter from
the theorem signature in `lean/SensorGroundedAdmission.lean` and re-run
the build. The proof body does not use the binder; removal is mechanical
and the build should still go through. Side effects: STATUS.md's
description of Theorem 4 (lines 102-129) needs trimming to match.

**Recommendation: Option A (disclose).** Reasoning: the inert binder
mirrors a structural-hook pattern (cf. Theorem 3) the paper already
discloses; symmetric disclosure reads as the substrate honestly bounding
its mechanization rather than as a defect to be hidden. Option B leaves
the paper's claim narrower (the theorem no longer mentions
`declprev` lookup at all), which weakens the prose alignment in
§4:55-56. Option A pays the lower author-effort price and reads as the
honest-ledger move cycle-3 RESEARCH rewards.

## Minor 5: Schema-evolution inheritance

**Placement.** New paragraph in §9, inserted after the existing `Empirical
chapter scope.` paragraph (current §9:33-34) at end of file. Tying it to
the empirical chapter places it near the wire-format discussion that
cycle-3 deleted; the paragraph acknowledges what was retired without
re-opening it.

**Drop-in paragraph**:

> \paragraph{Schema evolution inherited from parent.}
> The parent paper carries a schema-evolution row covering version
> migration across vendor kernels with non-uniform schema upgrades.
> The sensor-attestation construction adds new wire fields (provider
> records, clock records) under the parent's canonical-JSON
> discipline; it inherits the parent's schema-evolution obligation
> without adding a sensor-grounded-specific extension, and a
> versioned-predicate compatibility profile remains the prerequisite
> for cross-kernel sensor-attested admission.

Word count: 68. Cites the parent's residual implicitly by structure
("inherited\ldots without adding"). No new bibkey. Closes cycle-3
RESEARCH finding 6.

## Minor 6: Theorem-inventory discipline

**Placement.** Extend the existing `Theorem coverage.` paragraph at
`sections/09-limitations.tex:27-28`. The paragraph already discusses the
four theorems; one sentence at the end acknowledges the inventory
obligation.

**Drop-in sentence** (appended after the Theorem 4 disclosure from
Minor 4, if Option A is taken):

> The four theorems are inventoried in
> \codepath{lean/SensorGroundedAdmission.lean}; inventory churn under
> refactoring or proof strengthening is a paper-side obligation, as in
> the parent paper's ledger.

Word count: 32. Picks up the parent's row at
`programmable-sovereignty/sections/09-limitations.tex:22` ("Lean theorem
inventory is maintained with code changes") and threads it into the
sensor-grounded paper's `\paragraph{Theorem coverage.}` without
expanding §9 by a full paragraph. Closes cycle-3 RESEARCH finding 7.

## Minor 7: `intelTDXSpec2023` citation coverage

**Diagnosis.** §3:21 reads: `Intel TDX Quoting Enclave keys are signed by
a Provisioning Certification Key derived from fused secrets`. The
`intelTDXSpec2023` bibkey is the TDX Module Base Architecture
Specification (348549-002US, TDX 1.5). This specification covers the
TDREPORT generation flow inside the TD module but the QE / PCK signing
chain is in Intel's DCAP / Quoting Service documents (notably the SGX
DCAP attestation infrastructure documentation, separate Intel
publications). Cycle-3 RESEARCH flagged this as a half-cover citation.

**Recommendation: tighten the prose** rather than add a supplementary
citation. Adding a DCAP citation expands the bib surface for a
parenthetical claim; tightening the prose keeps the citation honest and
closes the audit. The phrase `derived from fused secrets` already does
most of the work; the QE/PCK detail can be replaced with a wording that
the existing citation does support.

**Drop-in replacement** for the relevant clause at §3:21:

Current: `Intel TDX Quoting Enclave keys are signed by a Provisioning
Certification Key derived from fused secrets~\cite{intelTDXSpec2023};`

Proposed: `Intel TDX binds quote signing to a hardware-rooted
attestation-key path the TD cannot extract, with the TDREPORT and Quote
flow specified by Intel~\cite{intelTDXSpec2023};`

Word count delta: +6 words. Preserves the structural point (hardware-
rooted key the workload cannot extract) while citing only what the spec
itself covers. The §9:22 instance of `intelTDXSpec2023` (`Intel TDX
QE/PCK`) is similarly affected: replace `Intel TDX QE/PCK` with `Intel
TDX TDREPORT path` and leave the citation in place. Closes cycle-3
RESEARCH finding 8.

## Nit 8: §10 drops "three-conjunct shape" qualifier

`sections/01-introduction.tex:19` carries the "three-conjunct shape"
qualifier; `sections/10-conclusion.tex:6` describes the same theorem and
drops the qualifier. Drop-in: insert `, viewed through the admission
predicate's three-conjunct shape,` after `any admitted receipt` in
§10:6. Word count delta: +9. Optional; the conclusion reads slightly
stronger without it, but matching the introduction's phrasing closes the
internal-drift flag. Recommend land.

## Nit 9: §1:12 future-work pointer to §10

`sections/01-introduction.tex:12` points the sensor-coverage auditor to
§10; §10:8 references the auditor but §10:10 (the "natural continuation"
bullet) lists per-tenant, time-windowed, and behavioral-attestation
extensions without explicit auditor mention. The resolution is oblique
rather than exact. **Skip verdict: no action needed.** §10:8 mentions
the auditor by name; the §10:10 bullet describes related continuation
work and need not duplicate the §10:8 mention. The §1:12 pointer
resolves to §10:8 if read in order. Low-leverage fix for cycle 3's last
pass.

## Nit 10: §6:18 internal-contradiction first-scan

`sections/06-evaluation.tex:18` reads "ES does not call es_new_client;
\ldots drop and miss counts present" which scans as contradictory at
first read. The sentence two later resolves it (in-memory recorder). A
quick fix: lead with the resolution. Current text:
`The macOS \codepath{EndpointSecurity} system extension shipped with the
substrate does not call \codepath{es\_new\_client} or
\codepath{es\_subscribe}; its event source is an in-memory recorder.`
Proposed: `The macOS \codepath{EndpointSecurity} system extension
shipped with the substrate sources events from an in-memory recorder
rather than calling \codepath{es\_new\_client} or
\codepath{es\_subscribe}.` Word count delta: 0. Optional but reads
better. Recommend land.

## Nit 11 (cycle-3 RESEARCH finding 11): §6:18 same issue, listed twice

Cycle-3 RESEARCH counted finding 11 separately from nit 10 above; both
trace to `sections/06-evaluation.tex:18`. **Skip verdict: subsumed by
Nit 10.** Single rewrite closes both.

## Priority queue for the (hopefully final) FIX cycle

Ordered for one-day dispatch, highest leverage first:

1. **Major 1** -- N1 disambiguation sentence appended to §8:23. 38 words,
   one-line edit. ~5 min.
2. **Major 2** -- §9 cosignature party-independence paragraph inserted
   between key-isolation and cross-polity required-sets. 117 words, one
   paragraph add. ~10 min.
3. **Minor 3** -- Theorem 1 rename across `lean/STATUS.md:15`,
   `lean/build-log.md:88`, `README.md:17`; delete `theorems.lean`
   (obsolete v0 draft). Four-file mechanical replacement plus one file
   removal. ~15 min.
4. **Minor 4 (Option A)** -- Theorem 4 inert binder disclosed in §9's
   `Theorem coverage.` paragraph. 48 words, one-sentence extension. ~5
   min.
5. **Minor 6** -- Theorem-inventory discipline sentence appended to §9's
   `Theorem coverage.` paragraph (combine with Minor 4 in one paragraph
   edit). 32 words. ~5 min.
6. **Minor 5** -- Schema-evolution inheritance paragraph appended to §9.
   68 words, one paragraph add. ~5 min.
7. **Minor 7** -- §3:21 and §9:22 `intelTDXSpec2023` clause tightening.
   Two-clause swap. ~10 min.
8. **Nit 8** -- §10:6 "three-conjunct shape" qualifier insertion. 9
   words. ~3 min.
9. **Nit 10** -- §6:18 sentence reorder. Zero net words. ~3 min.

Items 9-11 of RESEARCH's ranking are either skipped (Nit 9) or subsumed
(Nit 11). All items above can be done in a single FIX agent's pass
without parallelism; sequential ordering above is fine.

## Estimated FIX-cycle time

**Roughly 1.5 to 2 person-hours of actual editing**, plus a build /
compile pass on the updated `paper.tex` (with the new §8 sentence and
the three new §9 paragraphs). Sub-day for a single agent. No new bibkeys
needed; no Lean changes needed (Option A on Minor 4 avoids the proof
rebuild path). Companion-doc rename plus `theorems.lean` deletion is
mechanical. The build and visual inspection passes add maybe 30 minutes.
Total wall-clock for the FIX cycle: under three hours including
verification, well within the "sub-day pass" framing cycle-3 RESEARCH
named.
