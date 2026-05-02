# M08 Research: Independent Crypto + Protocol Review (NCC Group or Trail of Bits)

**Trajectory:** trajectory-3
**Milestone:** M08
**Lane:** Wv (vendor calendar; runs parallel to all code waves)
**Release-gate anchor:** RELEASE_AUDIT
**Author:** research agent (m08)
**Date:** 2026-04-30

This document is the research-phase deliverable for M08. M08 is a
vendor-calendar lane: research is procurement, scoping, and reviewer-
handoff oriented rather than engineering oriented. The IMPLEMENT phase
will turn the recommendations here into populated tickets under
`.planning/trajectory-3/tickets/M08/P{0..5}.yml` and into the audit
doc seed under `.planning/trajectory-3/audits/M08-vendor-evidence.md`.

## Vendor candidate dossiers

D12 names NCC Group and Trail of Bits as the binding shortlist; the
other four are documented here so the IMPLEMENT phase has a substitute
ladder if both decline (halt trigger 13 mitigation per D07).

### NCC Group (primary candidate)

- Practice: NCC Group Cryptography Services (formerly iSEC Partners +
  Matasano + Intrepidus). Long-running protocol-review practice.
- Adjacent published reports: WireGuard protocol review (2018);
  Zcash Sapling cryptographic review (2018); Signal protocol audits;
  Whisper Systems / OWS double-ratchet reviews; Let's Encrypt
  protocol assessment; Bitwarden cryptography review (2023);
  Solana program audits.
- PQ + hybrid-signing experience: NCC has published on hybrid
  X25519 + ML-KEM and the relevant TLS / Noise integration patterns;
  the practice tracks the NIST PQC drafts.
- Capability-system / object-capability experience: published research
  on Tahoe-LAFS, Zcash transparent / shielded surfaces, and a
  smaller body of work on capability-token compromise (CapTP-adjacent).
- Typical engagement size: $80k-$300k for a 4-8 week protocol +
  crypto review with one to three named cryptographers.
- Lead time: typical 8-16 weeks from SOW signature to start. Calendar
  is the binding constraint, not capability.
- Public-report posture: NCC routinely publishes "Public Report" PDFs
  on their site; the customer holds remediation veto until publication.
- Named partners visible on prior public reports: Tom Ritter, Thomas
  Pornin, Eric Schorn, Aaron Grattafiori, Jennifer Fernick (alumna).

### Trail of Bits (primary candidate)

- Practice: ToB Cryptography practice plus Application Security and
  Blockchain practices. Strong in symbolic execution and fuzzing
  augmentation of human review.
- Adjacent published reports: Kubernetes audit series (CNCF);
  Curl audit; sigstore / cosign audits; PyTorch supply-chain;
  Ethereum 2.0 client audits; lots of crypto-token audits; Filecoin
  Lotus audits; Zoom E2EE protocol review (2020).
- PQ + hybrid-signing experience: published the `pq-crypto`
  audit-of-CIRCL / lib-oqs work; familiar with Ed25519 attack surface
  and ML-DSA-65 implementation pitfalls.
- Tooling differentiator: ToB augments human review with their own
  tools (Slither, Manticore, Semgrep, Echidna, Medusa). For a Rust
  protocol surface, Manticore-Rust is less mature; expect mostly
  manual review augmented by cargo-fuzz / proptest harness review.
- Capability-system experience: smaller direct corpus than NCC but
  strong distributed-systems review track record.
- Typical engagement size: $100k-$350k for a 4-8 week engagement;
  ToB tends to staff slightly larger teams (3-5 reviewers) for the
  same calendar.
- Lead time: typical 12-24 weeks from inquiry to start; ToB has
  visible booking pressure.
- Public-report posture: ToB publishes engagement reports on the
  Trail of Bits Publications page; remediation status is annotated.
- Named partners: Dan Guido (CEO), Trent Brunson, Opal Wright,
  Will Song, Filipe Casal.

### Substitute ladder (D12-amendment candidates if both decline)

- **Galois**: cryptography research firm (Cryptol / SAW); strongest
  for formal-methods-adjacent crypto review. Lead time 16-24 weeks.
  Engagement size $150k-$400k. Galois prefers engagements with
  formal-methods deliverables (good fit since M06 ships Apalache
  invariants); fit is high but calendar is the worst of the six.
- **Kudelski Security**: strong protocol + smart-card / TEE crypto
  review practice; done numerous PQ migration assessments. Lead
  time 12-20 weeks. Engagement size $120k-$280k. Geographic root
  in Switzerland; reporting-language and IP-jurisdiction questions
  add 1-2 weeks of contracting.
- **Cure53**: smaller boutique; fastest lead time of the six (4-8
  weeks). Engagement size $60k-$200k. Strongest in web-app +
  protocol review (audited Mullvad, NextDNS, Let's Encrypt CT
  surfaces). Crypto-primitive depth is shallower than NCC / ToB /
  Galois; would map to a smaller scope.
- **Cryptography Engineering LLC** (Matt Green's group): boutique
  academic-leaning practice. Best-fit for novel-primitive review
  (capability algebra, hybrid signing). Lead time 8-16 weeks.
  Engagement size $80k-$220k. Capacity is sometimes very limited
  because the team is small.

The IMPLEMENT phase should keep dossier rows for these four under
the audit doc Section 2 (vendor selection record) so a halt-13
substitution does not require fresh research.

## RFP package shape

The RFP is the single most leveraged document in P0; vendor reply
quality is bounded by RFP clarity. The IMPLEMENT phase should produce
a single document under `.planning/trajectory-3/audits/M08-RFP.md`
with the following sections.

1. **Executive summary**: one paragraph naming Chio, the cemented
   v3.0 surface, the release gate (RELEASE_AUDIT), and the calendar
   ask.
2. **Scope of work (SOW pre-image)**:
   - Crypto primitives in scope: Ed25519 (legacy), ML-DSA-65 (PQC),
     hybrid signing surface, X25519 + ML-KEM hybrid for transport,
     SHA-256 / SHA-3 / BLAKE3 use, AEAD selection.
   - Protocol surface in scope: spec/PROTOCOL.md sections 4-13
     (serialization + identity, capability contract, receipt
     contract, manifest contract, runtime surfaces, trust-control,
     portable trust + federation, A2A adapter, certification,
     observability).
   - Implementation surface in scope: chio-attest-verify
     (TEE quote handling, PQ signing wiring), chio-revocation-oracle
     (sparse-Merkle CRL-Lite), chio-kernel-core (capability algebra,
     async dispatch, anchor binding), chio-receipt-log.
   - Out of scope: trajectory-2 crates outside the cemented surface;
     mobile attestation surface (M07 is its own evidence lane);
     supply-chain (M06 + M09 cover); HITRUST-scoped operational
     surfaces (M09).
3. **Deliverables**:
   - Weekly status memo during active review (P2 + P3).
   - Preliminary findings memo at end of P3 (week 30).
   - Draft final report at week 40.
   - Final report PDF + remediation log appendix at week 44.
   - Public-report PDF cleared for publication on Chio docs site
     and on the vendor's public-reports page.
4. **Timeline**:
   - SOW signed by week 5 (vendor selection deadline).
   - Vendor scoping + onboarding weeks 6-14.
   - Active review weeks 15-30.
   - Remediation weeks 30-40.
   - Final report week 40-44.
5. **Materials provided to reviewer** (the M04/M05/M06 handoff;
   see "Threat model handoff" section below).
6. **IP terms**:
   - Chio retains copyright on the codebase.
   - Vendor retains copyright on the report deliverable.
   - Chio receives a perpetual license to publish the report on its
     site once cleared.
   - Vendor receives a perpetual license to cite the engagement on
     their public-reports page.
   - Findings on third-party dependencies are coordinated via
     responsible-disclosure norms (90 days default).
7. **Public-report clause**:
   - Default: report is public after remediation is complete.
   - Exception: critical-CVE findings (CVSS >= 9.0) follow a
     coordinated 90-day disclosure window; the public report
     redacts the CVE detail until the embargo lifts.
8. **Pricing requested**: vendor returns fixed-price plus T&M
   buffer; D07 budget posture is $150k-$250k. Quotes outside the
   band trigger D07-amendment review and possibly halt 13.
9. **Reply format**: vendor returns SOW redline within 21 days of
   RFP receipt; SOW signed by week 5.

Reference templates: NCC Group's own RFP intake form on
`https://www.nccgroup.com/us/contact-us/`; Trail of Bits' published
"How to Request a Security Review" guidance; sigstore / cosign RFP
under the OpenSSF cohort published on the OpenSSF site (good public
template for OSS-shaped review).

## Booking / procurement calendar

Realistic calendar per the verdict's scratchpad analysis. Chio-side
work is small (the heavy lift is on the vendor side and on
@bb-connor signing legal docs).

```
Week 0    Project kickoff / orchestrator opens vendor lane
Week 1    RFP draft v0 sent to @bb-connor for review
Week 2    RFP sent to NCC Group + Trail of Bits
Week 3    Vendor questions / clarifications
Week 4    Vendor quotes received + redlined SOWs
Week 5    Vendor selection (D12 final pick); SOW signed
Week 6    Vendor team allocation begins
Week 8    Onboarding session (vendor reads handoff package)
Week 12   Vendor scoping memo received
Week 14   SOW addenda finalized; active review pre-flight
Week 15   Active review begins (P2)
Week 20   First-half checkpoint (orchestrator answer cadence
          stable; no halts)
Week 22   P2 closes
Week 23   P3 begins
Week 28   Preliminary findings draft to Chio
Week 30   Preliminary findings final; P3 closes
Week 30   Remediation PR fan-out begins (P4)
Week 35   Mid-remediation checkpoint
Week 40   Remediation complete; draft final report received
Week 42   Chio review of draft; redline + factual corrections
Week 44   Final report published; remediation log committed; M08
          closes
```

Slip > 25% of any of these intervals triggers halt 13 per
AUTONOMOUS-PROMPT. The longest single interval is weeks 6-14
(8-week vendor booking lead); slip there is the most likely halt-13
event.

The orchestrator does not block on vendor responses. Vendor-wait
tickets are 0.25-day markers that flip status from "awaiting" to
"received" when an event lands; the orchestrator advances code
waves in parallel.

## Review scope (top-10 surfaces)

Ranked by load-bearing-ness for the trajectory-3 release gate. The
RFP "Scope of work" section enumerates each.

1. **Capability algebra** (PROTOCOL.md s5; chio-kernel-core
   capability module). Delegation depth, attenuation, revocation
   semantics, anchor binding, replay defense. Highest leverage
   because every other surface assumes the algebra is sound.
2. **Receipt contract + receipt log** (PROTOCOL.md s6;
   chio-receipt-log). Append-only log integrity, Merkle frontier,
   cross-tenant isolation, fork detection.
3. **PQ + hybrid signing** (PROTOCOL.md s4; chio-attest-verify).
   Ed25519 + ML-DSA-65 hybrid construction; downgrade defense;
   key-id binding; algorithm-agility surface.
4. **Anchor binding + portable trust** (PROTOCOL.md s10). Anchor
   trust establishment, federation cross-anchor verification, anchor
   rotation, BFT-anchor surface.
5. **Revocation oracle** (chio-revocation-oracle; sparse-Merkle
   CRL-Lite). Inclusion / exclusion proof correctness, oracle
   freshness, byzantine oracle behavior.
6. **TEE attest-verify** (chio-attest-verify; PROTOCOL.md s4 + s9).
   TEE quote validation, vendor PKI handling, rollback / TCB
   freshness, mock-TEE detection.
7. **Trust-control contract** (PROTOCOL.md s9). Allow / deny
   semantics, fail-closed verification, policy-load invariants,
   trust transitions.
8. **Manifest contract** (PROTOCOL.md s7). Manifest binding to
   capability + receipt; serialization invariants; signature scope.
9. **Federation + A2A adapter** (PROTOCOL.md s10 + s11). Cross-
   trajectory attestation; agent-to-agent capability transfer;
   adversarial-peer surface.
10. **Observability + certification contracts** (PROTOCOL.md s12 +
    s13). Information leakage through observability surfaces;
    certification-claim integrity.

The reviewer is asked to produce a finding-density estimate per
surface (Table A in the final report) and to highlight the three
highest-leverage findings overall.

## Threat model handoff (from M04 / M05 / M06)

Per the cross-milestone interactions section of the M08 narrative,
the reviewer cites M04, M05, and M06 evidence. The handoff package
is assembled at the end of P0 (week 5) with rolling addenda as
M04 / M05 / M06 close.

**From M04 (mutation + verdict matrix promotion):**

- Final mutation kill-rate per crate (target 80%; floor 65% per D08).
- Mutation operators applied; surviving mutants log (the "what we
  could not kill" register).
- Verdict matrix promotion delta: which conformance verdicts moved
  from advisory to gating.
- Cross-reference: M04 audit doc; M04 P3 final state.

**From M05 (threat-coverage closure):**

- Closed gaps: weights_hash_spoof (partial -> passing), dispatch_allow
  (placeholder replaced), M06 placeholder (evicted).
- Updated threat model JSON (`spec/security/chio-threat-model.v1.json`)
  with closure rows.
- Coverage table (`spec/security/coverage.yaml`) post-closure.
- Advisory threats classified but not closed (per D14 scope).

**From M06 (focused formal + supply-chain):**

- The 3-4 highest-leverage Apalache invariants per D04: delegation
  depth, revocation cut, async dispatch ordering, plus one TBD by
  M06 IMPLEMENT phase. Invariant statements + proof artifacts.
- cargo-vet adoption state; SBOM publication output (CycloneDX or
  SPDX); CVE-monitoring posture.
- Supply-chain attestations applicable to M08 surface.

**Static handoff (always provided):**

- Repo HEAD pin (commit hash) at start of active review; reviewer
  works against a frozen branch.
- spec/PROTOCOL.md v3.0 (cemented; no edits during P2-P3 per
  freeze policy).
- spec/security/SECURITY.md.
- AGENTS.md and the docs/README.md index.
- Build + test one-liner (cargo build/test/clippy/fmt).
- Threat model schema + corpus.
- Crate map (88-crate workspace per D05; consolidation deferred).
- Existing internal review notes from trajectory-2 close.

**Dynamic handoff (rolling during P2-P3):**

- Orchestrator fields reviewer questions on a 0.25-1 day cadence.
- Each question + answer logged in audit doc Section 3 with cross-
  ref to source artifact.
- Critical clarifications get the program-lead FTE involvement
  per the M08 narrative risk row 4.

## Findings classification + remediation policy

Severity scheme follows the CVSS 3.1 numeric convention with a
labelled overlay; the final report uses both.

| Label    | CVSS band | Remediation SLA           | Disclosure window     |
|----------|-----------|---------------------------|-----------------------|
| Critical | >= 9.0    | Hot-fix PR; halt 15 fires | 90-day coordinated    |
| High     | 7.0-8.9   | Patch within P4 (week 30-40) | 30 days post-fix |
| Medium   | 4.0-6.9   | Patch within trajectory-3 | At public-report time |
| Low      | 0.1-3.9   | Roadmap (trajectory-4 OK) | At public-report time |
| Info     | n/a       | Documented; no PR required | At public-report time |

Per the M08 narrative success criteria:

- All Critical findings remediated before report publication.
- Non-critical findings tracked in the remediation roadmap (audit
  doc Section 4 + appendix in published report).
- The remediation log includes the PR sha for every Critical / High
  fix; Medium / Low fixes carry the sha when shipped.

Remediation policy nuance: a Critical finding that requires
engineering work outside trajectory-3 scope (per the Risk register
below) escalates to a trajectory-4 candidate row; @bb-connor
authorizes the scope expansion via halt 15.

## Public report channel

Coordinate with M03 release artifact channel for publishing.

**Report layout** (modeled on NCC Group "Public Report" format):

- Cover page: vendor logo, Chio name, engagement title (e.g.
  "Chio v3.0 Cryptographic and Protocol Review"), report version.
- Executive summary (one page): scope, key findings, overall
  posture statement.
- Engagement details: dates, named reviewers, methodology,
  artifacts reviewed, threat-model citation (M05), formal-evidence
  citation (M06), mutation citation (M04).
- Findings register: one section per finding with Title, Severity,
  Description, Reproduction, Recommendation, Status (Fixed /
  Acknowledged / Roadmap), PR cross-reference.
- Appendix A: surface-by-surface finding density.
- Appendix B: methodology + tooling.
- Appendix C: remediation log (PR shas, dates, verifier identity).

**Publication channel** (M03 cross-link):

- PDF lives at `releases.toml` -> v3.0 final-report row + URL
  pointer to the `releases/` directory under the chio-docs surface.
- Hash of the PDF committed to the audit doc Section 5 closure
  attestations.
- The vendor's public-reports page links to the same PDF (or hosts
  a vendor-side mirror).

**Public attribution**: NCC and ToB both expect the vendor's name
on the cover and on any published Chio marketing using the report.
The IMPLEMENT phase coordinates marketing language with @bb-connor.

## Per-phase research findings (P0-P5, calendar-bound)

### P0 (weeks 1-5): RFP scoping + threat model package

**Research findings:**

- The RFP single-document approach (one Markdown file authored by
  Chio; PDF render attached when sending) beats the form-fill route
  on both vendor sides: it lets Chio frame the surface in its own
  language, reducing scoping-call cycles.
- Threat-model package (handoff bundle described above) should be a
  zip artifact + README; vendors strongly prefer one ZIP attachment
  over a directory crawl on a private repo.
- Chio's "cemented v3.0 surface" framing is uncommon and load-
  bearing; the RFP must explicitly state that the protocol surface
  is frozen during P2-P3 with remediation merged only after vendor
  sign-off.
- Vendor-side email-routing latency: NCC and ToB intake go through
  business development; expect 3-5 business-day initial response
  vs. cryptographer-direct latency of 1-2 days.

**Tickets to scaffold** (IMPLEMENT phase):

- P0.T1: RFP draft v0 (1 day, planning agent).
- P0.T2: Vendor dossier compile (0.5 day, vendor-coord agent).
- P0.T3: Threat-model package assembly (0.5 day, vendor-coord agent).
- P0.T4: RFP send to NCC Group (0.25 day, vendor-coord agent).
- P0.T5: RFP send to Trail of Bits (0.25 day, vendor-coord agent).
- P0.T6: Vendor-question response loop (0.25 day x N, vendor-coord
  agent; one ticket per inbound question).
- P0.T7: Vendor selection memo (0.5 day, planning agent + @bb-connor).
- P0.T8: SOW redline + signature (1 day, planning agent + @bb-connor).
- P0.T9: Audit doc seed (0.25 day, planning agent).

### P1 (weeks 6-14): Vendor booking + scoping + SOW addenda

**Research findings:**

- Vendor booking lead is the longest fixed interval; the orchestrator
  has minimal leverage here. The Chio-side work is responding to
  scoping questions and providing artifacts on request.
- An onboarding session in week 8 (or whenever the vendor team is
  allocated) is high-value; the program lead presents the cemented
  surface verbally and walks through the threat model.
- M04 mutation kill-rate finalizes between weeks 8-12 per the M04
  narrative; M05 threat closure between weeks 4-9; M06 invariants
  between weeks 12-22. The handoff package gets a P1-rolling
  addendum at each milestone close.

**Tickets to scaffold:**

- P1.T1: Onboarding session (0.5 day, program lead + @bb-connor).
- P1.T2: Vendor scoping question response loop (0.25 day x N).
- P1.T3: SOW addenda + final scoping memo (1 day, planning agent).
- P1.T4: Audit doc Section 2 fill (vendor selection record;
  0.25 day).
- P1.T5: Handoff package addendum (M04 partial; week 9, 0.5 day).
- P1.T6: Handoff package addendum (M05 partial; week 9, 0.5 day).
- P1.T7: Pre-flight check on cemented-surface freeze (0.25 day,
  end of P1).

### P2 (weeks 15-22): Active review (first half)

**Research findings:**

- Reviewer-question cadence is empirically 5-15 questions per week
  for a protocol-surface review of this scale. The orchestrator
  must cap question turn-around at 2 business days to keep the
  reviewer unblocked.
- Question categories: clarification (~50%), artifact request
  (~30%), reproduction help (~15%), policy / scope-confirmation
  (~5%). Clarification questions are the cheapest; artifact
  requests are the highest variance.
- Risk: program lead becomes the single-point bottleneck on
  question backlog (M08 narrative risk row 4). Mitigation: route
  artifact-requests to executor agents via the standard ticket
  pipeline; reserve program-lead time for clarification + scope
  questions.

**Tickets to scaffold:**

- P2.T1-N: Reviewer-question response tickets (0.25-1 day each;
  one per question; agent_role: vendor-coord).
- P2.T-checkpoint: Mid-P2 status memo (0.5 day, week 18).

### P3 (weeks 23-30): Active review (second half) + preliminary findings

**Research findings:**

- The same question-response pattern as P2.
- Preliminary findings memo arrives at week 28-30; Chio reviews and
  responds with factual corrections within 5 business days.
- This is the highest-risk window for halt 15 (Critical CVE filing);
  the orchestrator should pre-stage a hot-fix PR template.

**Tickets to scaffold:**

- P3.T1-N: Reviewer-question response tickets (continuation).
- P3.T-prelim: Preliminary findings receipt + factual-correction
  memo (1 day, planning agent + program lead).
- P3.T-halt15-template: Pre-staged Critical-CVE hot-fix template
  (0.5 day, planning agent).

### P4 (weeks 30-40): Remediation PR fan-out

**Research findings:**

- Remediation PR sizing: most findings are 0.5-2 days of engineering
  per the M08 narrative; a Critical finding could be a multi-week
  effort (Risk register row 1).
- The cemented surface freeze relaxes during P4: remediation PRs
  are merged with vendor sign-off (vendor confirms the fix
  addresses the finding before merge).
- Remediation PRs must cite the finding ID, the audit doc row, and
  the vendor sign-off receipt.

**Tickets to scaffold:**

- P4.T1-N: One remediation ticket per finding above the Medium
  threshold; sized 0.5-2 days; agent_role: gsd-executor with
  trust-boundary review.
- P4.T-rollup: Remediation log compile (1 day, planning agent;
  populates audit doc Section 4 fully).
- P4.T-vendor-signoff-loop: Vendor sign-off receipt collection
  (0.25 day per fix, vendor-coord agent).

### P5 (weeks 40-44): Final report received + remediation log committed

**Research findings:**

- Draft report arrives week 40; Chio review (factual + remediation-
  status confirmation) takes 1-2 weeks; final report at week 44.
- Publication channel coordination with M03: the release artifact
  channel publishes the PDF, hashes it, and updates `releases.toml`.
- Audit doc Section 5 closes the milestone with all closure
  attestations populated.

**Tickets to scaffold:**

- P5.T1: Draft report review (1 day, planning agent + @bb-connor).
- P5.T2: Final report receipt + hash (0.5 day, vendor-coord agent).
- P5.T3: Publication ticket (0.5 day; coordinates with M03 release
  artifact channel).
- P5.T4: Remediation log commit + audit doc closure (0.5 day,
  planning agent).
- P5.T5: M08 close memo (0.25 day, planning agent).

## Risk register

Inherited from the M08 narrative plus three additions surfaced by
this research.

1. **Both vendors decline or quote outside D07 budget band** (halt
   trigger 13). Mitigation: substitute ladder above; user picks
   substitute (Cure53, Galois, Kudelski, Cryptography Engineering)
   or descopes to a partial review.
2. **Critical CVE filed mid-review** (halt trigger 15). Mitigation:
   pre-staged hot-fix template (P3.T-halt15-template); immediate
   remediation PR with @bb-connor confirmation; review continues
   on a branched HEAD if needed.
3. **Vendor calendar slip > 25%** (halt trigger 13). Mitigation:
   surface to user; user decides accept / change vendors / descope.
   Most likely on weeks 6-14 (booking lead).
4. **Active-review questions exceed orchestrator throughput**.
   Mitigation: program-lead FTE coordinates question backlog;
   artifact-requests route through executor agents.
5. **Critical finding requires engineering outside trajectory-3
   scope.** Mitigation: trajectory-4 candidate row; @bb-connor
   authorizes via halt 15. Some classes of findings (re-design of
   the capability algebra, complete rewrite of the revocation
   oracle) cannot be remediated inside the M08 calendar.
6. **Vendor publishes a finding without coordinated disclosure.**
   Mitigation: RFP IP-terms section explicitly binds vendor to the
   coordinated-disclosure window; SOW redline rejects any term that
   weakens this.
7. **Cemented-surface freeze pressure from M01 / M02 customers.**
   Mitigation: customer milestones land their own surfaces above
   the protocol; protocol changes during P2-P3 require @bb-connor
   amendment + reviewer notification + (likely) re-scoping.

## Recommended ticket scaffold (vendor-coord agent role)

A new agent role is recommended for M08 (and shared with M09):
`vendor-coord`. The role's prompt template differs from
`gsd-executor` in key ways:

- Reads + writes only `.planning/trajectory-3/audits/M08-vendor-
  evidence.md` and `.planning/trajectory-3/audits/M08-RFP.md`;
  does not touch source code.
- Drafts vendor-facing prose; @bb-connor signs all outbound
  vendor communications.
- Logs every outbound + inbound vendor event in the audit doc
  active-review log table (Section 3).
- Status verbs: "awaiting", "received", "redlined", "signed",
  "answered", "deferred".

Ticket sizing per phase (reconciled with the M08 narrative):

- P0: ~9 tickets, ~0.25-1 day each, total ~5 days Chio-side over
  5 weeks.
- P1: ~7 tickets, ~0.25-1 day each, total ~3 days Chio-side over
  9 weeks.
- P2: 30-90 question-response tickets, ~0.5 day average; plus 1
  checkpoint. Estimate ~25-50 Chio-side days over 8 weeks.
- P3: 30-90 question-response tickets + preliminary-findings
  receipt + halt-15 template. Estimate ~25-55 Chio-side days
  over 8 weeks.
- P4: ~5-30 remediation tickets (one per finding above Medium);
  0.5-2 days each. Estimate ~10-60 Chio-side days over 10 weeks.
- P5: 5 tickets, ~0.5 day each, total ~3 days Chio-side over 4
  weeks.

Total Chio-side effort: 70-175 person-days spread across 44 calendar
weeks, comfortably inside the 5-FTE engineering + 1-PL + 0.5-SR
profile per D06. The variance is dominated by P4 (number of
remediation findings).

## Open questions for IMPLEMENT phase

1. **Vendor pre-shortlist conversations.** Should the IMPLEMENT
   phase recommend a 30-minute introductory call with each vendor
   before formal RFP send (week 0-1 instead of week 2)? Pro:
   filters out calendar-impossible quotes early. Con: adds 1-2
   weeks to P0.
2. **RFP private vs. public shape.** Should the RFP be a private
   document (sent to the two named vendors only) or a public RFP
   on the chio-docs site? Public RFP would attract substitute-ladder
   responses (Cure53, Galois) without explicit invitation, which
   may help halt-13 mitigation. Recommendation: private RFP for
   primary vendors per D12; consider public RFP only on substitute
   trigger.
3. **Coordinated-disclosure window.** Default 90 days is industry-
   standard. Should the RFP reduce to 60 days given the trajectory-
   3 close timeline? Risk: vendor pushback. Recommendation: 90 days
   is the right baseline.
4. **Report co-publication.** Should Chio publish a "response
   memo" alongside the vendor report (vendor's view + Chio's view)?
   Pro: showcases remediation discipline. Con: extra Chio-side
   effort. Recommendation: yes; ~2-day P5 ticket.
5. **Re-test after remediation.** SOW typically does not include
   a re-test pass. Should the M08 SOW pre-purchase a 1-week
   re-test on Critical / High findings (week 38-40)? Estimated
   incremental cost: $20k-$40k inside D07 band. Recommendation: yes;
   cleaner closure attestation.
6. **Anonymized-finding teaser.** Some vendors prefer to publish
   an anonymized teaser before the full report; Chio may prefer
   a single publication event. The IMPLEMENT phase should pin
   the publication semantics in the RFP.
7. **Bug bounty bridge.** Should M08 close trigger the standing-
   up of a public bug bounty (post-trajectory-3)? Out-of-scope for
   M08 itself but a natural follow-on. Note for trajectory-4
   roadmap.
8. **Cross-citation back-pressure.** M04 + M05 + M06 narratives
   need to know that they will be cited in the M08 final report;
   their authoring agents may want to shape evidence accordingly.
   The IMPLEMENT phase should send a cross-milestone notification
   at start of P2.
9. **Insurance coverage.** Some vendors require Chio to carry
   minimum E&O coverage; @bb-connor confirms posture before SOW
   signature. The IMPLEMENT phase should add a check to P0.T7.
10. **Right-of-reply on draft report.** Standard SOW grants Chio a
    factual-correction window on the draft; the IMPLEMENT phase
    should pin the duration (recommend 10 business days) in the
    SOW redline.

---

End of M08 research. The IMPLEMENT phase populates
`.planning/trajectory-3/tickets/M08/P{0..5}.yml` with the ticket
scaffold above and seeds
`.planning/trajectory-3/audits/M08-vendor-evidence.md` Sections 2-5
with placeholder rows.
