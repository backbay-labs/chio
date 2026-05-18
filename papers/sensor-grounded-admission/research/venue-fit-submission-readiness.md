# Venue Fit + Submission Readiness (cycle 3 RESEARCH)

Research note R-4, cycle 3 (final), May 2026. Strategic positioning brief for
the sensor-grounded-admission paper. No paper-file edits attempted; the REVIEW
phase decides which findings land.

## Recommended primary venue

**USENIX Security 2027, Cycle 1 (submission due Tuesday August 25, 2026).** The
paper is now a defensible systems-security submission with a substantial formal
spine. Three cycles of FIX / WRITE / RESEARCH / REVIEW have retired the cycle-1
adversarial review's most damaging objections: the §6 chapter no longer
overclaims a multi-month deployment, the six-of-nineteen emitter breakdown is
internally consistent, the §8 related-work survey is anchored to primary TEE
and eBPF sources, the §3 attestation-key-isolation extension paragraph and the
matching §9 limitation row name the structural-versus-cryptographic axis, and
the four Lean theorems compile clean with `#print axioms` reporting only
kernel axioms. Theorem 2's proper-sublist biconditional is the load-bearing
structural piece; Theorem 1 has been renamed to match its Sigma-construction
prose.

USENIX Security has historically accepted papers in the band the cycle-1
adversarial reviewer's own "minimum patch to make publishable" produced: one
substantive theorem, one worked example, a defensible related-work map. The
empirical chapter is thin by USENIX Security standards (one verifier-side
mutation-rejection test, no p50 / p99 latency numbers, the macOS ES sensor
honestly disclosed as stubbed), but it is now honestly thin rather than
dishonestly grand. The §9 "what is not measured" paragraph names the Criterion
bench as withheld; reviewers who reject on this basis tell program chairs the
paper belongs at CSF, not that the paper lies. Cycle 1 submission also leaves
USENIX Security cycle 2 (January 26, 2027) as a re-roll if the first attempt
misses. NDSS leans toward measurement; CSF leans toward proof-theoretic depth.
USENIX Security is the venue historically taking papers exactly in this band.

## Backup venues

1. **NDSS 2027 Summer cycle (verify exact deadline via the official call;
   Seoul, March 2027 dates).** NDSS has accepted attestation-and-systems papers
   in the IMA / SEDA / Sigstore lineage. The empirical chapter weakness is more
   conspicuous at NDSS because measurement bar is part of the venue identity;
   the formal spine pays less rent. Backup, not primary, because empirical
   thinness is precisely the axis NDSS weights.

2. **CSF 2027 (rolling deadlines, three cycles per year per CSF 2025
   pattern).** The natural home if the four-theorem core is the load-bearing
   contribution and the empirical chapter is acknowledged as anecdotal. The §6
   chapter at 481 words would be re-cast as a "Worked Example." Theorem 2's
   proper-sublist biconditional and the headline Sigma-construction become the
   center of gravity rather than the §8 related-work survey. Page limit is
   typically more forgiving at CSF; the 17-page article-class draft fits
   without the compression USENIX Security requires.

3. **CCS 2027 (cycle 1 deadline historically January, cycle 2 May).** ACM CCS
   accepts more diverse formal-methods work than USENIX Security and tolerates
   the formal-spine-plus-thin-empirical shape. Less ideal than USENIX Security
   because CCS reviewers historically write longer adversarial reviews; the
   §9 limitation rows would each be re-litigated.

HotSec 2027 is not recommended. The paper is 17 pages and four mechanized
theorems strong; HotSec's short-paper format would force discarding either
the Lean appendix or the §8 related-work depth, both of which are now
load-bearing assets.

## Abstract polish opportunities

The current abstract (paper.tex:22-23) is a dense ~320-word paragraph. It
states the headline theorem in plain language, retires the substrate-honest
assumption, and maps to the parent paper's five-mode trust ladder. Specific
tightening opportunities, none load-bearing for termination:

1. **The opening sentence buries the lead.** "A federated admission kernel
   decides whether to admit a signed receipt into its polity's history" reads
   as background; the contribution is in sentence three. USENIX Security
   reviewers triage on the first two sentences. Consider opening with the
   problem ("Existing admission constructions treat the substrate as
   honestly-sensing-by-assumption") and giving the headline second.

2. **"Silent" is jargon.** Here it means "produces a receipt indistinguishable
   from a healthy-substrate receipt." Cold-reading reviewers skim past the
   technical meaning. Define on use or replace with the unpacked version.

3. **The parent paper is named twice but never cited.** USENIX Security
   abstracts can carry one citation key; the parent paper deserves it if the
   framing is "strengthens [parent]'s admission predicate." Defers on
   whether the parent paper is published under the Chio name by submission.

4. **The empirical anchor is absent from the abstract entirely.** Consider
   one sentence: "An implementation instance ships canonical-JSON sensor-state
   attestations at six host-snapshot emitter sites within a working admission
   kernel." Honest, scoped, no overclaim.

5. **Length: in band for USENIX Security (200-350 words).** No cuts needed
   for length; tightening for legibility is optional.

The single highest-value polish suggestion is **opening with the problem
rather than the kernel definition**, moving the headline from sentence three
to sentence two and paying the heaviest dividend for cold-reading PC members.

## Submission readiness checklist

### Items requiring human action
- [ ] Co-author selection and de-anonymization decision (README "Anthropic
      co-author hook" notes the alignment-and-evaluation framing fits this
      paper; bounded-executive-action paper carries the parallel hook).
- [ ] USENIX Security submission account; HotCRP setup; COI declarations.
- [ ] Camera-ready template conversion: paper.tex uses `\documentclass[11pt]
      {article}`; USENIX Security 2027 uses the USENIX paper template (verify
      class name in the call). Page limit 13 of content excluding references
      and appendices. The 17-page article-class draft will compress to roughly
      12-13 under the two-column USENIX template.
- [ ] Operator decision on cycle 1 (August 2026) vs cycle 2 (January 2027).
      Recommendation: cycle 1 to leave cycle 2 as a re-roll.

### Items requiring more code or Lean work
- [ ] None blocking. Four theorems compile clean; bib.bib is 32 entries with
      zero orphans; `lake build` exits 0.
- [ ] Optional: Lean stub `sensor_attestation_marginal_trust_requires_separate_key`
      from `research/single-key-collapse.md`. Cycle-2 REVIEW recommended prose
      placement, not mechanization.
- [ ] Optional: Theorem 3's `_h_destructive` and Theorem 4's `_h_prev_decl`
      inert binders. Drop the binders or strengthen the proofs (half-day to
      one day each).

### Items requiring more writing
- [ ] §A Lean theorem appendix. Cycle-2 constructive review prepared a draft
      shell (~250 words plus four Lean signatures). Adds roughly one page.
      Strongest reviewer-facing artifact at lowest cost.
- [ ] Abstract polish per suggestions above. Optional.
- [ ] Anonymization pass: §5 and §6 cite Rust function symbols
      (`endpoint_sensor_state_from_macos_host`, `endpoint_sensor_state_content_hash`).
      For USENIX Security blind review, these need anonymization or schema-
      level labels. The substrate name "Chio" is also load-bearing in §8 and
      the title page and needs anonymization.

### Items requiring decision
- [ ] §A appendix: land or omit? Cycle-2 constructive review estimates +0.6
      page net; depends on USENIX Security camera-ready page budget after
      template conversion.
- [ ] Author voice: how complete the anonymization?

## Estimated gap to ready-to-submit

**Two to three person-weeks of dedicated work.** Breakdown:

- Template conversion (article -> USENIX): three days. Layout, figure
  placement, bibliography style, page-count rebalancing.
- Anonymization pass: two days. Function-symbol citations stripped, substrate
  name replaced, parent-paper citation key replaced with anonymous form.
- §A Lean appendix: one day. Draft shell exists.
- Abstract polish: half a day.
- Optional Lean strengthening (drop inert binders): one to two days.
- Final cite-check, PDF-validation, HotCRP submission: one day.

**Blockers vs optional.** Blockers are template conversion and anonymization;
both mechanical. Optional items are the appendix and the Theorem 3 / 4
hypothesis fixes. If cycle 1 deadline is tight, the appendix is first to
drop; if cycle 2 is the target, the appendix should land. The Theorem 3 / 4
inert-binder fix is honest-but-optional: the §9 row already names the issue.

## Recommended REVIEW phase intake from this research

1. **Termination decision.** Cycle-3 final adversarial review should weight
   that the paper now sits in the "minimum patch to make publishable" band
   per cycle-1's own minimum patch list. If the final review finds zero new
   substantive issues, terminate cycle 3 and write `execution-complete.md`.

2. **Abstract polish: optional, not blocking.** The single highest-value
   change (opening with the problem rather than the kernel definition) is a
   one-sentence rewrite. Cycle 3 FIX can land it or defer to camera-ready.

3. **§A appendix: defer to camera-ready.** Adds roughly one page; not
   blocking for cycle 3 termination. The Lean substrate, four theorem
   signatures, and `#print axioms` clean status are already documented in
   `lean/STATUS.md` and referenced in §9.

4. **Venue recommendation finalization.** Operator decision; this research
   recommends USENIX Security 2027 cycle 1 as primary, NDSS 2027 Summer as
   backup, CSF 2027 as the formal-methods alternative.

5. **Co-author and anonymization decisions.** Out of cycle 3 scope; flagged
   for the operator-side submission checklist.
