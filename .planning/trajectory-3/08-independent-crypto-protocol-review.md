# Milestone 08: Independent Crypto + Protocol Review (NCC Group or Trail of Bits)

> **Disclaimer:** The artifact at releases/audit-reports/m08-internal-readiness-draft-2026-05-02.pdf is a self-authored internal readiness draft, not an external vendor crypto-protocol review. No vendor (e.g., NCC Group, Trail of Bits) has been engaged to produce a vendor-letterhead report. Real external review is a trajectory-4 deliverable (M08-followup).

## Lens

External-attestation. M08 contracts a third-party crypto and protocol
review of Chio's cemented v3.0 surface from NCC Group or Trail of Bits
(D12). The lens is single (third-party legibility); the calendar is
long-clock (26-44 weeks) and runs parallel to all code waves on a
dedicated vendor lane (Wv per `EXECUTION-BOARD.md`). Chio-side work is
procurement, scoping, reviewer-question response, and remediation PR
fan-out, not new substrate. Calendar is the binding constraint, not
capability: the eight-week vendor-booking interval (weeks 6-14) is the
likeliest halt-13 trigger.

## Why this is on the trajectory

**Release-gate anchor:** RELEASE_AUDIT

trajectory-2 closed with the v3.0 protocol surface cemented (no further
wire-level edits), the post-quantum + TEE quote verifier shipped under
`crates/chio-attest-verify/`, the sparse-Merkle CRL-Lite shipped under
`crates/chio-revocation-oracle/`, and the async kernel core under
`crates/chio-kernel-core/`. None of these surfaces was reviewed by an
external cryptographer or protocol auditor. The verdict (round-2
synthesis, 2026-04-30) names M08 as one of two third-party evidence
forms required for trajectory-3 close (the other is M09 HITRUST i1).
A published report from NCC Group or Trail of Bits is the
load-bearing artifact that turns the trajectory-3 customer- and
substrate-anchored work into externally legible attestation.

The trajectory-2 artifacts that enter M08's review surface:

- `spec/PROTOCOL.md` v3.0 (2431 lines as of 2026-04-30; cemented).
- `crates/chio-attest-verify/` PQ + TEE quote surface (the M03
  trajectory-2 milestone shipped `Signature::Hybrid`, ML-DSA-65 KAT,
  and the TDX / SEV-SNP / Nitro `QuoteVerifier` backends).
- `crates/chio-revocation-oracle/` sparse-Merkle CRL-Lite.
- `crates/chio-kernel-core/` capability algebra, async dispatch,
  anchor binding.
- `crates/chio-otel-receipt-exporter/` receipt log surface that the
  protocol s6 contract is implemented against.

## Prior-art reckoning

trajectory-2 shipped, and M08 reviews unchanged (the cemented surface
is frozen during P2-P3):

- `spec/PROTOCOL.md` sections 4-13 (serialization + identity, capability
  contract, receipt contract, manifest contract, runtime surfaces,
  trust-control, portable trust + federation, A2A adapter, certification,
  observability). Cemented post-trajectory-2.
- `crates/chio-attest-verify/src/lib.rs` (`AttestVerifier` + `QuoteVerifier`
  traits, `Signature::Hybrid`, ML-DSA-65 wiring).
- `crates/chio-attest-verify/src/{tdx,sev_snp,nitro}.rs` quote backends.
- `crates/chio-revocation-oracle/src/` sparse-Merkle CRL-Lite.
- `crates/chio-kernel-core/src/` capability algebra and async dispatch.
- `spec/security/chio-threat-model.v1.json` threat register.

What M08 changes (Chio-side, vendor-side):

- RFP authored at `.planning/trajectory-3/audits/M08-RFP.md` and sent
  to NCC Group + Trail of Bits in weeks 1-5.
- One vendor selected by week 5 (D12).
- SOW signed by week 5 with redline window, IP terms, public-report
  clause, coordinated-disclosure language.
- Active review weeks 15-30; preliminary findings at week 28-30.
- Remediation PR fan-out weeks 30-40; vendor sign-off receipt per fix.
- Final report week 40-44; published with remediation log.

What M08 preserves (and why):

- The cemented protocol surface. No protocol edits during P2-P3.
  Remediation PRs land on `main` only with vendor sign-off and only
  after the active-review window closes. Pressure from M01 / M02
  customer milestones to reshape the protocol during the review window
  surfaces as halt 12 / halt 13 candidates, not silent edits.
- Existing trajectory-2 audit docs. M08 does not re-litigate
  trajectory-2 closure; it adds an external review row only.

Vendor shortlist named explicitly: NCC Group or Trail of Bits (D12).
Substitute ladder named explicitly: Galois -> Kudelski -> Cure53 ->
Cryptography Engineering LLC. The ladder is recorded in the audit doc
Section 2 so a halt-13 substitution does not require fresh research.

## Hard counts (measured 2026-04-30)

Reproduce with the commands in parentheses. Update the date and numbers
if you re-run; do not silently let them drift. The IMPLEMENT phase
P0 wave-opener pins concrete review-surface counts before RFP send.

- `spec/PROTOCOL.md` line count: 2431 lines.
  (`wc -l spec/PROTOCOL.md`)
- `crates/chio-attest-verify/` source surface (post-trajectory-2 M03):
  the PQ + TEE quote backends added by trajectory-2 are in scope. The
  P0 wave-opener pins exact line counts.
  (`find crates/chio-attest-verify/src -name '*.rs' | xargs wc -l`)
- `crates/chio-revocation-oracle/` source surface: pinned by P0.
- `crates/chio-kernel-core/` source surface: pinned by P0.
- Threat model rows in scope for reviewer cross-check: M05 closes the
  trajectory-3 advisories before M08 active review opens; the row count
  at M08 P2 open is the cross-check oracle.
  (`jq '.threats | length' spec/security/chio-threat-model.v1.json`
  pinned at P0; re-pinned at P2 open.)
- RFP send dates: pin at end of P0 (week 2 send to NCC + ToB).
- Vendor reply window: pin during P0 (weeks 2-5; SOW signature
  by week 5).
- Vendor calendar event log: starts empty at P0; one row per outbound
  + inbound vendor event through P5.

## Workspace dependency state

External-attestation milestone; no Cargo crate pins land in M08. The
vendor calendar lead times are the load-bearing dependency state.

| Vendor | Lead time (RFP to start) | Engagement size band | Lane |
|--------|--------------------------|----------------------|------|
| NCC Group (primary) | 8-16 weeks | $80k-$300k | Wv |
| Trail of Bits (primary) | 12-24 weeks | $100k-$350k | Wv |
| Galois (substitute) | 16-24 weeks | $150k-$400k | Wv |
| Kudelski Security (substitute) | 12-20 weeks | $120k-$280k | Wv |
| Cure53 (substitute) | 4-8 weeks | $60k-$200k | Wv |
| Cryptography Engineering LLC (substitute) | 8-16 weeks | $80k-$220k | Wv |

D07 budget posture for M08 is $150k-$250k. Quotes outside the band
trigger halt 13 review and a substitute-ladder pivot or descope.
Lead-time slip > 25% on any phase interval is the halt-13 trigger
per `AUTONOMOUS-PROMPT.md`. The longest single interval is weeks 6-14
(8-week vendor booking lead); slip there is the most likely halt-13
event.

## Scope

### In

- RFP authored at `.planning/trajectory-3/audits/M08-RFP.md` (sections:
  executive summary, scope of work, deliverables, timeline, materials
  provided, IP terms, public-report clause, pricing band, reply
  format).
- RFP sent to NCC Group and Trail of Bits in week 2.
- Vendor questions answered on a 1-2 business-day cadence during P0-P1.
- One vendor selected by end of week 5 (D12).
- Statement of work signed by week 5 with the public-report clause,
  90-day coordinated-disclosure window, and a 1-week post-remediation
  re-test on Critical / High findings (RESEARCH section "Open
  questions" recommendation 5).
- Threat-model handoff package assembled at end of P0 (week 5) with
  rolling addenda as M04 / M05 / M06 close. Bundle = ZIP of
  `spec/PROTOCOL.md`, `spec/security/`, `AGENTS.md`, `docs/README.md`,
  the build + test one-liner, and the trajectory-2 audit-doc closure
  set.
- Onboarding session at week 8 (vendor team allocated; program lead
  walks through the cemented surface verbally).
- Active review weeks 15-30 (P2 + P3) supported by the orchestrator:
  reviewer questions answered at 0.25-1 day per question; artifact
  requests routed to executor agents; clarifications escalated to the
  program lead.
- Top-10 review surfaces (in priority order): capability algebra,
  receipt contract + receipt log, PQ + hybrid signing, anchor binding
  + portable trust, revocation oracle, TEE attest-verify, trust-control
  contract, manifest contract, federation + A2A adapter, observability
  + certification contracts.
- Pre-staged halt-15 (Critical CVE) hot-fix template at end of P3
  inside the SLA: 90-day coordinated disclosure default, immediate
  remediation PR with @bb-connor confirmation, branched HEAD if needed.
- Remediation PR fan-out weeks 30-40, one PR per Critical / High
  finding and per Medium where engineering-bounded; each PR carries
  the finding ID, audit doc cross-reference, and vendor sign-off
  receipt.
- Final report received week 40; Chio factual-correction window 10
  business days; final report published week 44 via M03 release
  artifact channel (PDF in `releases/`, hash in `releases.toml`).
- Audit doc `.planning/trajectory-3/audits/M08-vendor-evidence.md`
  populated through P0-P5: vendor selection record (Section 2),
  active-review log (Section 3), findings + remediation log (Section 4),
  closure attestations (Section 5).
- Cross-citations: M04 mutation gate evidence, M05 threat-coverage
  closure, M06 formal invariants. Reviewer cites all three in the
  report; M03 release artifact channel publishes the PDF.

### Out (and why)

- Re-review by a second vendor. D12 picks one of NCC / ToB; a second
  vendor would burn the calendar without proportional evidence gain.
- Re-review of trajectory-2 surfaces outside the cemented v3.0 set.
  The cemented surface IS the review boundary.
- Self-attestation. The third-party report is the load-bearing
  evidence; Chio-internal review is preserved as cross-check, not as
  release-gate evidence.
- Mobile attestation surface review. M07 owns iOS App Attest + Android
  Play Integrity evidence on its own lane; M08 does not duplicate.
- Supply-chain review. M06 ships cargo-vet adoption + SBOM + CVE
  monitoring; M09 HITRUST scope consumes the SBOM. M08 may cross-
  reference but does not own.
- HITRUST-scoped operational surfaces. M09 owns the assessor portal;
  M08 cites M09 evidence only if a finding straddles both.
- A bug-bounty program. Out-of-scope for M08 itself; logged as a
  trajectory-4 candidate per RESEARCH section "Open questions"
  recommendation 7.
- ISO 42001 attestation. Deferred per D02 to a post-trajectory-3
  cycle.
- Apple / Android customer attestation review. M07 lane.

## Phases

### P0 (weeks 1-5): RFP scoping + threat model package

Chio-side ~5 person-days over 5 calendar weeks. Tickets are mostly
0.25-1 day vendor-coord tickets and one 1-day RFP authoring ticket.

- M08.P0.T1: RFP draft v0 authored at
  `.planning/trajectory-3/audits/M08-RFP.md`.
- M08.P0.T2: Vendor dossier compile (NCC + ToB + 4 substitute rows)
  appended to audit doc Section 2.
- M08.P0.T3: Threat-model handoff package assembly (ZIP of cemented
  surface + spec/security/ + AGENTS.md + build one-liner).
- M08.P0.T4: RFP send to NCC Group (vendor-coord; outbound email
  drafted, @bb-connor signs).
- M08.P0.T5: RFP send to Trail of Bits (vendor-coord).
- M08.P0.T6: Vendor-question response loop (vendor-coord; one ticket
  per inbound question; orchestrator splits this ticket as questions
  arrive in weeks 3-4).
- M08.P0.T7: Vendor selection memo (planning + @bb-connor) at week 5;
  records D12 final pick + variance from D07 budget band; checks E&O
  insurance posture per RESEARCH section "Open questions" 9.
- M08.P0.T8: SOW redline + signature (planning + @bb-connor); pins
  10-business-day right-of-reply on draft report and 1-week re-test
  on Critical / High findings.
- M08.P0.T9: Audit doc seed at
  `.planning/trajectory-3/audits/M08-vendor-evidence.md` with starting
  counts (review-surface line counts, threat row count at P0 open).

### P1 (weeks 6-14): Vendor booking + scoping + SOW addenda

Chio-side ~3 person-days over 9 calendar weeks. Bulk of the calendar
is vendor-side; Chio responds to scoping questions and provides
artifacts on request. The 8-week booking interval is the most likely
halt-13 event; `EXECUTION-STATE.json` carries a `next_check_due`
marker for week 8 and week 12.

- M08.P1.T1: Onboarding session (program lead + @bb-connor) at week 8.
- M08.P1.T2: Vendor scoping question response loop (vendor-coord;
  ticket-per-question; orchestrator splits as questions arrive).
- M08.P1.T3: SOW addenda + final scoping memo authored (planning
  agent) at week 12-14.
- M08.P1.T4: Audit doc Section 2 fill (vendor selection record:
  vendor name, SOW hash, calendar fit, named reviewers).
- M08.P1.T5: Handoff package addendum for M04 (mutation kill-rate
  partial; week 9, vendor-coord). Cites M04 audit doc closure state.
- M08.P1.T6: Handoff package addendum for M05 (threat-coverage
  closure partial; week 9, vendor-coord). Cites M05 audit doc.
- M08.P1.T7: Pre-flight check on cemented-surface freeze at end of
  P1 (planning + @bb-connor); confirms no protocol-spec edits land
  during P2-P3.

### P2 (weeks 15-22): Active review (first half)

Chio-side ~25-50 person-days over 8 calendar weeks. The variance is
the per-week reviewer-question count (empirically 5-15 per week for
a protocol surface of this scale). The orchestrator caps per-question
turn-around at 2 business days. Question categories: clarification
(~50%), artifact request (~30%), reproduction help (~15%), policy /
scope-confirmation (~5%).

- M08.P2.T1..N: Reviewer-question response tickets (vendor-coord;
  0.25-1 day each; one ticket per question; orchestrator scales).
- M08.P2.T-checkpoint: Mid-P2 status memo at week 18 (planning agent
  + program lead) confirming question backlog is healthy.

### P3 (weeks 23-30): Active review (second half) + preliminary findings

Chio-side ~25-55 person-days over 8 calendar weeks. Same question-
response cadence as P2. Preliminary findings memo arrives at week
28-30; Chio reviews and responds with factual corrections within 5
business days. Highest-risk window for halt 15 (Critical CVE filing);
the orchestrator pre-stages a hot-fix PR template.

- M08.P3.T1..N: Reviewer-question response tickets (continuation).
- M08.P3.T-prelim: Preliminary findings receipt + factual-correction
  memo (planning + program lead) at week 28-30.
- M08.P3.T-halt15-template: Pre-staged Critical CVE hot-fix template
  at week 28 (planning agent); template lives in audit doc Section 4
  appendix and includes the @bb-connor confirmation block.

### P4 (weeks 30-40): Remediation PR fan-out

Chio-side ~10-60 person-days over 10 calendar weeks. Variance is
dominated by the number of remediation findings above the Medium
threshold. Most findings are 0.5-2 days; a Critical finding could be
multi-week (Risk register row 5).

- M08.P4.T1..N: One remediation ticket per finding above Medium;
  sized 0.5-2 days each. `agent_role: gsd-executor` (or appropriate
  Rust crate role) with trust-boundary review. Each PR cites the
  finding ID, the audit doc row, and the vendor sign-off receipt.
- M08.P4.T-rollup: Remediation log compile (planning agent) at week
  39; populates audit doc Section 4 fully with PR shas + dates +
  verifier identity.
- M08.P4.T-vendor-signoff-loop: Vendor sign-off receipt collection
  (vendor-coord; 0.25 day per fix; one ticket per Critical / High
  fix verified by the vendor).

### P5 (weeks 40-44): Final report received + remediation log committed

Chio-side ~3 person-days over 4 calendar weeks. Draft report arrives
week 40; Chio review (factual + remediation-status confirmation) takes
1-2 weeks; final report at week 44.

- M08.P5.T1: Draft report review (planning + @bb-connor) week 40-42;
  10-business-day factual-correction window.
- M08.P5.T2: Final report receipt + hash committed to audit doc
  Section 5 (vendor-coord).
- M08.P5.T3: Publication ticket (vendor-coord) coordinating with M03
  release artifact channel: PDF lands at `releases/` with the
  v3.0 final-report row in `releases.toml`; vendor public-reports
  page links the same PDF.
- M08.P5.T4: Remediation log commit + audit doc closure (planning
  agent); Section 5 closure attestations populated.
- M08.P5.T5: M08 close memo + Chio response memo published alongside
  the vendor report (RESEARCH section "Open questions" recommendation
  4); ~2-day ticket to author Chio's view alongside the vendor's.

## Cross-milestone interactions

- **M04 (mutation + verdict-matrix promotion).** The reviewer cites
  M04 audit doc closure state in the published report. Mutation
  kill-rate (target 80%; D08 floor 65%) is a load-bearing input that
  shapes the reviewer's confidence in the test surface. P1.T5 ships
  the M04 partial addendum at week 9.
- **M05 (threat-coverage closure).** The reviewer cross-checks M05's
  closure of `weights_hash_spoof`, `dispatch_allow`, and the M06
  placeholder against the M08 finding register. P1.T6 ships the M05
  addendum at week 9. Findings that overlap M05 advisory rows route
  to M05 audit doc as a cross-link.
- **M06 (focused formal + supply-chain).** The reviewer consumes
  M06's 3-4 highest-leverage Apalache invariants (delegation depth,
  revocation cut, async dispatch ordering, plus the M06-IMPLEMENT TBD)
  and cites them where they cover review-surface invariants. SBOM +
  cargo-vet output also enters the handoff package; the M06 supply-
  chain audit doc is read-only input for M08.
- **M03 (hosted CI + reproducible builds).** The release artifact
  channel publishes the final report PDF and updates `releases.toml`
  with the v3.0 final-report row. M03's reproducible-build hash for
  the v3.0 commit sha at the start of active review is the artifact
  the reviewer pins to.
- **M01 / M02 (customer milestones).** Independent of M08 work but
  cross-checked by them: customer milestones do not consume M08
  evidence directly but their releases reference the published
  report once available. Pressure from M01 / M02 to reshape the
  cemented protocol during P2-P3 surfaces as halt 12 / halt 13
  candidates.
- **M09 (HITRUST i1 assessment).** Parallel external-attestation
  milestone on the Wv lane; M09 assessor consumes the M08 report
  where its findings touch HITRUST control mappings. Audit-doc
  cross-references in both directions; no shared freeze.

## Risks and mitigations

1. **Both vendors decline or quote outside D07 budget band**
   (halt trigger 13). Mitigation: substitute ladder (Galois -> Kudelski
   -> Cure53 -> Cryptography Engineering LLC). The ladder rows live
   in the audit doc Section 2 so substitution does not require fresh
   research. User picks substitute or descopes to a partial review.
2. **Critical CVE filed mid-review** (halt trigger 15). Mitigation:
   pre-staged hot-fix template in P3 inside the 90-day coordinated-
   disclosure SLA; immediate remediation PR with @bb-connor
   confirmation; review continues on a branched HEAD if needed.
   Public report redacts the CVE detail until the embargo lifts.
3. **Vendor calendar slip > 25%** (halt trigger 13). Mitigation:
   surface to user; user decides accept / change vendors / descope.
   Most likely on weeks 6-14 (8-week vendor booking lead). The
   orchestrator carries `next_check_due` markers for week 8 and
   week 12 to detect slip early.
4. **Active-review questions exceed orchestrator throughput.**
   Mitigation: program-lead FTE coordinates question backlog;
   artifact-requests route through executor agents via the standard
   ticket pipeline; reserve program-lead time for clarification +
   scope questions only. Mid-P2 checkpoint at week 18 confirms
   throughput is healthy.
5. **Critical finding requires engineering outside trajectory-3
   scope.** Some classes of findings (re-design of the capability
   algebra, complete rewrite of the revocation oracle) cannot be
   remediated inside the M08 calendar. Mitigation: trajectory-4
   candidate row authored; @bb-connor authorizes the scope expansion
   via halt 15. The remediation log records the deferred-to-trajectory-4
   status explicitly.
6. **Vendor publishes a finding without coordinated disclosure.**
   Mitigation: RFP IP-terms section explicitly binds vendor to the
   coordinated-disclosure window; SOW redline rejects any term that
   weakens this. Default 90 days per industry standard
   (RESEARCH section "Open questions" 3).
7. **Cemented-surface freeze pressure from M01 / M02 customers.**
   Mitigation: customer milestones land their own surfaces above the
   protocol; protocol changes during P2-P3 require @bb-connor
   amendment + reviewer notification + (likely) re-scoping. P1.T7
   pre-flight check confirms freeze posture at end of P1.

## Success criteria

- Final NCC Group or Trail of Bits report published at the M03
  release artifact channel; PDF hash committed to audit doc Section 5.
- All Critical (CVSS >= 9.0) findings remediated before report
  publication; remediation log records PR sha for every Critical /
  High fix.
- Non-critical remediation roadmap committed in audit doc Section 4
  + appendix in the published report.
- Vendor sign-off receipt logged in audit doc Section 4 for every
  Critical / High remediation PR.
- M04 mutation gate, M05 threat-coverage closure, and M06 Apalache
  invariants cross-cited in the published report (audit doc Section 5
  records the citation quotes).
- Chio response memo published alongside the vendor report
  (M08.P5.T5) showcasing remediation discipline.
- Calendar adherence: P0 closes by week 5 (SOW signed); P3 closes by
  week 30 (preliminary findings final); P5 closes by week 44 (final
  report published).
- Audit doc `.planning/trajectory-3/audits/M08-vendor-evidence.md`
  closes with all five sections populated (scope, vendor selection
  record, active-review log, findings + remediation log, closure
  attestations).
- D07 vendor budget posture honoured ($150k-$250k); variance recorded
  in audit doc Section 2 if outside band.
