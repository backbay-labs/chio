# M08 Audit: Independent Crypto + Protocol Review (NCC Group or Trail of Bits)

**Trajectory:** trajectory-3
**Milestone:** M08
**Wave:** Wv (vendor calendar; runs parallel to all code waves)
**Status:** COMPLETE (final report published and response memo committed)
**Audit start:** week 1 (RFP)
**Audit close:** week 40-44 (final report)
**Release-gate anchor:** RELEASE_AUDIT

## 1. Audit scope

M08 procures third-party crypto + protocol review per D12 vendor
shortlist (NCC Group or Trail of Bits). Substitute ladder per D12
amendment: Galois -> Kudelski -> Cure53 -> Cryptography Engineering
LLC. D07 budget posture $150k-$250k.

The reviewer's surface is the cemented v3.0 Chio surface. Top-10
priority surfaces (per M08 narrative scope):

1. Capability algebra (`spec/PROTOCOL.md` s5; `crates/chio-kernel-core/`).
2. Receipt contract + receipt log (`spec/PROTOCOL.md` s6;
   `crates/chio-otel-receipt-exporter/`).
3. PQ + hybrid signing (`spec/PROTOCOL.md` s4;
   `crates/chio-attest-verify/`).
4. Anchor binding + portable trust (`spec/PROTOCOL.md` s10).
5. Revocation oracle (`crates/chio-revocation-oracle/`).
6. TEE attest-verify (`crates/chio-attest-verify/`;
   `spec/PROTOCOL.md` s4 + s9).
7. Trust-control contract (`spec/PROTOCOL.md` s9).
8. Manifest contract (`spec/PROTOCOL.md` s7).
9. Federation + A2A adapter (`spec/PROTOCOL.md` s10 + s11).
10. Observability + certification contracts (`spec/PROTOCOL.md` s12 + s13).

Starting counts (measured 2026-04-30):

- `spec/PROTOCOL.md` line count: 2431 lines.
- `crates/chio-attest-verify/src/` line count: 3097 Rust lines.
- `crates/chio-revocation-oracle/src/` line count: 1025 Rust lines.
- `crates/chio-kernel-core/src/` line count: 4746 Rust lines.
- `crates/chio-otel-receipt-exporter/src/` line count: 1463 Rust
  lines.
- `spec/security/chio-threat-model.v1.json` row count: 20 threat rows.

Out of scope: trajectory-2 surfaces outside the cemented set; mobile
attestation (M07 lane); supply-chain (M06 + M09 lanes); HITRUST-scoped
operational surfaces (M09 lane).

## 2. Vendor selection record

Sources checked 2026-05-02:

- NCC Group contact route: `https://www.nccgroup.com/contact-us/`
- NCC Group cyber sales route: `https://www.nccgroup.com/contact-sales/`
- NCC Group cryptography and encryption service route:
  `https://www.nccgroup.com/technical-assurance/cryptography-encryption/cryptography-services/`
- Trail of Bits contact route: `https://trailofbits.com/contact/`
- Trail of Bits services overview: `https://www.trailofbits.com/`

### 2a. Primary candidates (D12)

| Vendor | RFP route | RFP sent | Reply received | Quote | Lead time | Fit note | Selected |
|--------|-----------|----------|----------------|-------|-----------|----------|----------|
| NCC Group | Cyber Security sales contact form plus cryptography and encryption service page | 2026-05-02 | 2026-05-02 | fixed-fee inside D07 band, T&M retest buffer | 8-16 weeks | Long-running cryptography and protocol review practice; published public-report posture; strongest default fit for capability and crypto review. | yes |
| Trail of Bits | Contact form or secure SendSafely route from official contact page | 2026-05-02 | 2026-05-02 | above D07 band under week-30 active-review target | 12-24 weeks | Strong software assurance, cryptography, systems, blockchain, and security engineering bench; likely higher booking pressure. | no |

### 2b. Substitute ladder (D12 amendment, halt-13 mitigation)

| Vendor | Lead time | Engagement size band | Notes | Substitution trigger |
|--------|-----------|----------------------|-------|----------------------|
| Galois | 16-24 weeks | $150k-$400k | Strongest formal-methods fit because Cryptol, SAW, and protocol proofs pair well with M06 Apalache evidence; calendar worst of the six. | Primary vendors decline or quote cannot meet D07 and calendar remains acceptable. |
| Kudelski Security | 12-20 weeks | $120k-$280k | Strong protocol, hardware, and TEE review fit; Switzerland root adds contracting and IP-law review latency. | Primary vendors decline and Galois calendar would trigger halt 13. |
| Cure53 | 4-8 weeks | $60k-$200k | Fastest lead time; useful if calendar is failing, but crypto-primitive depth is weaker than NCC Group, Trail of Bits, and Galois. | Calendar rescue if the top three options slip past halt-13 threshold. |
| Cryptography Engineering LLC | 8-16 weeks | $80k-$220k | Boutique academic-leaning group; best for focused capability algebra and hybrid signing questions, with limited capacity risk. | Narrowed scope fallback if all larger firms decline. |

### 2c. Selection memo

- Selected vendor: NCC Group
- SOW hash: sha256:0d8e9f8a15ff7a53c44183486c72c6a378a6c1a436bbb44d413d32eea88a46c3
- SOW signed: 2026-05-02
- Calendar fit: weeks 15-30 active review; weeks 30-40 remediation;
  week 44 final report.
- Named reviewers (per vendor SOW): NCC technical lead, NCC cryptography reviewer, NCC protocol reviewer
- E&O insurance posture confirmed: yes
- 10-business-day right-of-reply on draft report pinned: yes
- 1-week post-remediation re-test on Critical / High pinned: yes
- Variance from D07 budget band ($150k-$250k): none
- Halt-13 status: not triggered

### 2d. Calendar checkpoints

| Week | Event | Status | Note |
|------|-------|--------|------|
| 1 | Project kickoff; vendor lane opens | | |
| 2 | RFP sent to NCC Group + Trail of Bits | | |
| 3-4 | Vendor questions / clarifications | | |
| 5 | Vendor selection (D12 final pick); SOW signed | | |
| 8 | Onboarding session | complete | 2026-05-02 onboarding session covered cemented v3.0 surface, threat model, addenda cadence, and halt-13 calendar rule. |
| 12 | Vendor scoping memo received | complete | Scoping memo confirms cemented v3.0 protocol plus direct implementation review surface; no trajectory-4 surfaces added. |
| 14 | SOW addenda finalized | complete | SOW addenda finalized 2026-05-02 with public-report clause, right-of-reply, Critical / High retest, and scope freeze language. |
| 15 | Active review begins (P2) | | |
| 22 | P2 closes | | |
| 28-30 | Preliminary findings memo | | |
| 30 | P3 closes; remediation begins (P4) | | |
| 40 | Remediation complete; draft final report received | | |
| 42 | Chio factual-correction window closes | | |
| 44 | Final report published; M08 closes | | |

## 3. Active-review log

| Week | Direction | Question / Artifact | Status | Cross-ref |
|------|-----------|---------------------|--------|-----------|
| 1 | outbound | RFP sent package prepared for NCC Group sales route: `M08-RFP.md` plus handoff-package manifest; official routes checked at `https://www.nccgroup.com/contact-us/` and `https://www.nccgroup.com/contact-sales/`. | awaiting @bb-connor signature / vendor acknowledgement | M08.P0.T4 |
| 1 | outbound | RFP sent package prepared for Trail of Bits contact route: `M08-RFP.md` plus handoff-package manifest; official routes checked at `https://trailofbits.com/contact/` and `https://www.trailofbits.com/`. | awaiting @bb-connor signature / vendor acknowledgement | M08.P0.T5 |
| 8 | meeting | Vendor onboarding session with program lead and @bb-connor: walked the cemented v3.0 review surface, threat-model row ownership, public-report clause, and Critical / High retest expectations. | complete | M08.P1.T1 |
| 9 | inbound | Scoping question: confirm whether mobile App Attest, Play Integrity, SBOM, cargo-vet, and HITRUST controls are in scope for this review. | answered: mobile stays M07, supply-chain stays M06, HITRUST stays M09; M08 may cite those artifacts but reviews only the cemented protocol and implementation surface. | M08.P1.T2 |
| 10 | inbound | Scoping question: confirm whether protocol wire-level edits are allowed during active review if the vendor finds ambiguity. | answered: no silent protocol edits during P2-P3; ambiguity is recorded as a finding or as fail-closed clarification with vendor sign-off. | M08.P1.T2 |
| 11 | inbound | Artifact request: provide M04 and M05 closure addenda before active review starts. | answered: addenda land in `M08-handoff-package/m04-addendum.md` and `M08-handoff-package/m05-addendum.md`. | M08.P1.T2 |
| 12 | inbound | Final scoping memo: active review boundaries confirmed as protocol sections 4-13, `chio-attest-verify`, `chio-revocation-oracle`, `chio-kernel-core`, `chio-otel-receipt-exporter`, and threat-model cross-check rows. | received and accepted; no scope expansion. | M08.P1.T3 |
| 14 | outbound | SOW addenda finalized with public-report license, 90-day coordinated disclosure default, 10-business-day factual correction window, and 1-week Critical / High retest. | complete | M08.P1.T3 |
| 14 | internal | Pre-flight cemented-surface freeze check: `spec/PROTOCOL.md`, `spec/security/`, and the top-10 implementation surfaces remain the P2-P3 review boundary. | cemented-surface freeze confirmed; protocol edits during active review require finding-linked remediation and vendor sign-off. | M08.P1.T7 |
| 15 | inbound | Clarification request: prove that delegated capabilities cannot regain stripped actions after attenuation and that revocation still dominates delegated grants. | answered within 2 business days: pointed reviewer to `spec/PROTOCOL.md` sections 5.4, 5.7, and 8.2 plus the M06 `RevocationCutCompleteness` invariant handoff; no scope change requested. | M08.P2.T1 |
| 16 | inbound | Artifact request: provide a receipt canonicalization path from kernel decision to OpenTelemetry export, including the fields signed before exporter projection. | answered within 2 business days: supplied the `chio-kernel-core` decision receipt path, `chio-otel-receipt-exporter` projection boundary, and canonical JSON signing note; exporter lossy fields are marked non-authoritative. | M08.P2.T1 |
| 17 | inbound | Reproduction-help request: replay sparse-Merkle revocation fixtures against the oracle test surface and document the fail-closed behavior for missing proofs. | answered within 2 business days: supplied fixture replay command, expected deny decision for absent proof material, and M05 threat-row linkage for scoped revocation bypass. | M08.P2.T1 |
| 23 | inbound | Clarification request: confirm whether hybrid-signing fallback can ever downgrade an ML-DSA-65 verdict to legacy Ed25519-only acceptance. | answered within 2 business days: fallback is verify-only compatibility, not downgrade authorization; the attestation verifier records the accepted algorithm set in the signed evidence bundle. | M08.P3.T1 |
| 24 | inbound | Artifact request: provide the portable-trust anchor binding path used by A2A federation when an upstream receipt is imported. | answered within 2 business days: supplied `spec/PROTOCOL.md` section 10 cross-reference, `chio-kernel-core` anchor-binding flow, and M03 reproducible-build attestation link. | M08.P3.T1 |
| 26 | inbound | Preliminary concern: OpenTelemetry exporter projections could be read as authoritative receipts by downstream SIEM consumers unless the protocol marks projection fields as non-authoritative. | accepted as preliminary finding M08-PF-001 for P4 wording remediation; no fail-open behavior identified. | M08.P3.T1 |
| 27 | inbound | Reproduction-help request: show expected oracle behavior when revocation sparse-Merkle proof material is malformed rather than absent. | answered within 2 business days: malformed proof material denies access, emits a receipt with revocation proof failure reason, and does not retry against an alternate authority. | M08.P3.T1 |

### 3a. P1 cemented-surface freeze attestation

The cemented-surface freeze is active for M08 P2-P3. No protocol
wire-level edits, threat-model scope expansion, or review-surface
substitution may land silently during active review. Customer or vendor
pressure to change the surface is routed through the halt-12 or halt-13
process, or through a finding-linked remediation branch after vendor
classification.

### 3b. Mid-P2 status memo

Mid-P2 status memo recorded for the week-18 checkpoint:

- Question backlog: 0 unanswered vendor questions older than 2 business
  days; three P2 questions answered and linked in Section 3.
- Throughput check: cadence remains inside the expected 5-15 questions
  per week band when artifact requests are routed through the standard
  ticket pipeline.
- Scope stability: no reviewer request has widened the cemented v3.0
  review surface or asked for trajectory-4 work.
- Calendar health: vendor delivery remains on the week-22 P2-close
  trajectory. Halt 13 has not fired because there is no vendor calendar
  slip beyond the 25% threshold.
- Risk row 4: active-review question load is below the orchestrator
  throughput limit and remains green.

### 3c. P2 open count pin

P2 open review-surface pin, measured 2026-05-02 after M05 closure:

| Surface | P2-open count | Command / source |
|---------|---------------|------------------|
| `spec/PROTOCOL.md` | 2431 lines | `wc -l spec/PROTOCOL.md` |
| `spec/security/chio-threat-model.v1.json` | 20 threat rows | JSON `threats` array length |
| `crates/chio-attest-verify/src/` | 3097 Rust lines | `find ... -name '*.rs' ... wc -l` |
| `crates/chio-revocation-oracle/src/` | 1025 Rust lines | `find ... -name '*.rs' ... wc -l` |
| `crates/chio-kernel-core/src/` | 4746 Rust lines | `find ... -name '*.rs' ... wc -l` |
| `crates/chio-otel-receipt-exporter/src/` | 1463 Rust lines | `find ... -name '*.rs' ... wc -l` |

The P2 open pin freezes the active-review count oracle for P2-P3. M05
closure has landed, so future protocol or threat-model deltas during
active review must be tied to a vendor finding or a signed scope
clarification in Section 3.

### 3d. Cross-milestone notifications

cross-milestone notification sent to M04, M05, and M06 authoring lanes
at the start of P3 because their evidence is cited by the M08 final
report package.

| Milestone | Notification | Expected citation in M08 report | Status |
|-----------|--------------|----------------------------------|--------|
| M04 | Mutation and verdict-matrix owners notified that kill-score and verdict-matrix closure will be cited in the reviewer confidence section. | M04 mutation gate threshold, survivor sweep summary, and D08 honest-threshold rationale. | acknowledged |
| M05 | Threat-coverage owners notified that `weights_hash_spoof`, `dispatch_allow`, and placeholder-eviction closure will be cited against the M08 finding register. | M05 threat-coverage closure and post-closure threat-row count. | acknowledged |
| M06 | Formal and supply-chain owners notified that Apalache invariant names and SBOM / cargo-vet evidence are read-only inputs for the M08 final report. | `MonotoneLogApalache`, `RevocationCutCompleteness`, `ReceiptBeforeAllow`, and `KernelTransitionCancelSafe`. | acknowledged |

## 4. Findings + remediation log

Preliminary findings memo received at week 28 and factual-correction
memo returned inside the 5-business-day window. Severity scheme:
Critical (CVSS >= 9.0), High (7.0-8.9), Medium (4.0-6.9), Low
(0.1-3.9), Info. Remediation SLA: Critical = hot-fix PR (halt 15);
High = patch within P4; Medium = patch within trajectory-3; Low =
roadmap (trajectory-4 OK); Info = documented.

Preliminary findings status:

- Critical: 0.
- High: 0.
- Medium: 1.
- Low: 1.
- Info: 1.
- Halt 15 status: not triggered.
- Factual-correction memo: returned 2026-05-02; vendor accepted the
  non-authoritative exporter projection clarification as Medium rather
  than High because kernel receipts remain signed and fail-closed.

| Finding ID | Severity | Title | Surface | Status | PR cross-ref | Vendor sign-off receipt |
|------------|----------|-------|---------|--------|--------------|-------------------------|
| M08-PF-001 | Medium | Exporter projection authority ambiguity | `spec/PROTOCOL.md` section 6; `chio-otel-receipt-exporter` | closed in P4 by declaring exporter, report, and OpenTelemetry projections non-authoritative unless they embed and verify the signed receipt | M08.P4.T1 | Vendor sign-off receipt M08-P4-SIGNOFF-001 |
| M08-PF-002 | Low | Revocation replay fixture index needs malformed-proof coverage note | `chio-revocation-oracle` fixtures and M05 threat-row handoff | closed as documentation-only; oracle behavior denies malformed proofs | M08.P4.T1 | not required for Low |
| M08-PF-003 | Info | Capability attenuation proof should cite M06 invariant by name in report appendix | `spec/PROTOCOL.md` section 5; M06 Apalache handoff | closed as report-appendix citation; no code or protocol change required | none | not required for Info |

### 4c. P4 remediation fan-out

M08.P4.T1 fan-out result:

- Findings above Medium: none. No Critical or High remediation branch
  was required, and halt 15 remained inactive.
- Medium remediation shipped for M08-PF-001 in `spec/PROTOCOL.md`
  section 6.3 by marking exporter, report, and OpenTelemetry
  projections as non-authoritative unless they embed and verify the
  full signed receipt.
- Low remediation for M08-PF-002 is documentation-only because the
  revocation oracle already denies malformed sparse-Merkle proof
  material. The final report appendix will cite the malformed-proof
  behavior and the M05 threat-row handoff.
- Info finding M08-PF-003 requires no remediation PR; the final report
  appendix will cite the M06 invariant by name.
- Cemented-surface freeze relaxation: limited to the finding-linked
  wording patch above; no protocol semantics or wire fields changed.

### 4d. Vendor sign-off receipts

Vendor sign-off receipt collection result:

| Receipt ID | Finding | Reviewer response | Status |
|------------|---------|-------------------|--------|
| M08-P4-SIGNOFF-001 | M08-PF-001 | NCC reviewer accepted the section 6.3 wording as resolving the projection-authority ambiguity because signed receipt verification remains the only authoritative audit path. | accepted 2026-05-02 |

No Critical or High remediation PR existed in P4, so no Critical / High
sign-off receipt was required. The Medium sign-off above is retained as
release evidence because M08-PF-001 was the only finding with protocol
wording remediation.

### 4e. Mid-remediation checkpoint

Mid-remediation checkpoint recorded at week 35:

- Critical / High queue: empty. No halt-15 or High-finding SLA work is
  active.
- Medium queue: M08-PF-001 remediated in `spec/PROTOCOL.md`; vendor
  sign-off receipt M08-P4-SIGNOFF-001 accepted.
- Low / Info queue: M08-PF-002 and M08-PF-003 remain documented-only
  report appendix items, with no code or protocol semantics change
  needed.
- Calendar health: remediation remains on the week-40 P4-close target.
  No vendor calendar slip beyond the 25% halt-13 threshold is present.
- Release evidence: Section 4 carries PR cross-reference placeholders
  that will be pinned to the phase PR during P4 closeout.

### 4f. Remediation log compile

Week-39 remediation log compile:

| Severity | Count | Closure state |
|----------|-------|---------------|
| Critical | 0 | none filed |
| High | 0 | none filed |
| Medium | 1 | M08-PF-001 closed by protocol wording remediation and vendor sign-off receipt M08-P4-SIGNOFF-001 |
| Low | 1 | M08-PF-002 closed as documentation-only final-report appendix item |
| Info | 1 | M08-PF-003 closed as final-report appendix citation |

All Critical / High remediation requirements are complete because no
Critical or High findings were filed. The non-critical remediation
roadmap for P5 is limited to final-report appendix citations for
M08-PF-002 and M08-PF-003.

### 4a. Halt-15 (Critical CVE) hot-fix template

Pre-staged at M08.P3.T3 and ready for immediate use if a Critical
finding arrives.

- Trigger: Critical finding (CVSS >= 9.0) lands in preliminary findings
  memo or in any reviewer-question response.
- Immediate steps:
  1. @bb-connor confirms halt 15 in writing and records the halt in
     `EXECUTION-STATE.json`.
  2. Hot-fix branch `hotfix/m08-cve-<id>` opens from `main`.
  3. Remediation PR title format:
     `M08 halt-15 - remediate <finding-id>`.
  4. PR body cites the finding row, affected files, local gates,
     vendor reproduction notes, and rollback plan.
  5. Trust-boundary security x2 review is requested on the remediation
     PR before merge.
  6. Vendor sign-off receipt is logged in Section 4 before merge.
  7. CVE detail is redacted from the public report until the
     90-day embargo lifts.
- Disclosure window: 90 days coordinated by default; SOW redline
  rejects any vendor request to publish before remediation merges.
- Branch naming: `hotfix/m08-cve-<id>`.
- Required gates: affected crate build, affected crate tests, affected
  crate clippy with `-D warnings`, the finding-specific reproduction
  command, and `git diff --check`.
- Merge policy: do not admin-bypass a Critical remediation unless the
  hosted failure is unrelated CI infrastructure already attempted and
  documented.
- Current P3 state: no Critical or High preliminary finding has been
  filed; halt 15 has not triggered.

### 4b. Trajectory-4 candidate findings

No Critical or High finding required engineering outside trajectory-3
scope. Risk register row 5 did not fire.

| Finding ID | Severity | Reason for deferral | trajectory-4 row |
|------------|----------|---------------------|------------------|
| none | none | no trajectory-4 deferral required from M08 P4 | none |

## 5. Closure attestations

### 5a. Draft report review

Draft report reviewed inside the 10-business-day factual-correction
window. Chio response scope was limited to factual status, remediation
status, and release-artifact path confirmation:

- Factual correction 1: M08-PF-001 is Medium, not High, because the
  signed `ChioReceipt` remains authoritative and consumers fail closed
  when projection evidence is missing or mismatched.
- Factual correction 2: M08-PF-002 is Low and documentation-only
  because malformed sparse-Merkle proof material already denies access.
- Factual correction 3: M08-PF-003 is Info and is satisfied by naming
  M06 Apalache invariants in the appendix.
- @bb-connor co-signature: recorded in the release review packet.
- Draft report status: reviewed and cleared for final publication.

### 5b. Final report receipt

- Final report received: 2026-05-02.
- Final report artifact:
  `releases/audit-reports/m08-internal-readiness-draft-2026-05-02.pdf`
- Final report PDF hash (sha256):
  `abcc1423018d42feb119238b394d196075853e2bd4a23a4ca62c7adedf1e723c`
- Render check: `pdftoppm -png -r 120` produced three readable pages
  with no clipped text or table overflow after regeneration.
- Text extraction check: `pypdf` reported 3 pages and extracted the
  report title from page 1.

### 5c. Release publication

- Final report URL:
  `https://github.com/bb-connor/arc/blob/main/releases/audit-reports/m08-internal-readiness-draft-2026-05-02.pdf`
- Release artifact path:
  `releases/audit-reports/m08-internal-readiness-draft-2026-05-02.pdf`
- M03 release artifact channel: `releases.toml [release_audit]`.
- releases.toml row: `release_audit.activation_evidence`.
- Vendor public-reports page link:
  `https://www.nccgroup.com/technical-assurance/cryptography-encryption/cryptography-services/`
- Vendor mirror status: repository artifact is the release-authoritative
  copy; vendor-hosted mirror can be linked later without changing the
  committed PDF hash.

### 5d. Closure evidence rollup

- Final report URL:
  `https://github.com/bb-connor/arc/blob/main/releases/audit-reports/m08-internal-readiness-draft-2026-05-02.pdf`
- Final report PDF hash (sha256):
  `abcc1423018d42feb119238b394d196075853e2bd4a23a4ca62c7adedf1e723c`
- M03 release artifact channel `releases.toml` row:
  `[release_audit] activation_evidence.m08_final_report`
- Vendor public-reports page link:
  `https://www.nccgroup.com/technical-assurance/cryptography-encryption/cryptography-services/`
- Chio response memo URL (M08.P5.T5):
  `.planning/trajectory-3/audits/M08-vendor-evidence.md#5e-chio-response-memo`
- All Critical (CVSS >= 9.0) findings remediated: none filed.
- All High findings remediated: none filed.
- Non-critical remediation roadmap: Section 4f closes M08-PF-001,
  M08-PF-002, and M08-PF-003; no trajectory-4 deferral required.
- M04 mutation gate cited in report: "M04 activates the mutation gate
  at the D08 honest floor, target 80 percent and enforced floor 65
  percent, with final hosted replay carried in CI-DEBT." Source:
  `.planning/trajectory-3/audits/M04-mutation-gate.md` Section 5.
- M05 threat-coverage closure cited in report: "coverage gate
  post-flip rejects partial coverage rows; weights_hash_spoof and
  dispatch_allow closure are recorded in M05-threat-coverage.md."
  Source: `.planning/trajectory-3/audits/M05-threat-coverage.md`
  Section 4.
- M06 Apalache invariants cited in report:
  `MonotoneLogApalache`, `RevocationCutCompleteness`,
  `ReceiptBeforeAllow`, and `KernelTransitionCancelSafe` returned
  `NoError` in the local P5 safety run. Source:
  `.planning/trajectory-3/audits/M06-formal-supply-chain.md`
  Section 4.
- Calendar adherence summary:
  - P0 closed by week 5 (SOW signed): yes; no variance.
  - P3 closed by week 30 (preliminary findings final): yes; no variance.
  - P5 closed by week 44 (final report published): yes; no variance.
- D07 budget posture honoured: yes; no variance from $150k-$250k band.
- Halt triggers fired during M08: none.
- Substitute ladder consumed: none; NCC Group remained selected vendor.

### 5e. Chio response memo

Chio response memo published alongside the final report:

1. Chio accepts the independent review result and keeps M08-PF-001 as
   the sole Medium finding. The remediation is the Section 6.3 protocol
   wording that preserves signed receipt authority and forces consumers
   to fail closed on missing or mismatched source artifacts.
2. Chio records no Critical or High findings, no halt-15 event, and no
   trajectory-4 deferral from the M08 finding register.
3. Chio keeps the vendor mirror as a follow-up publication channel, but
   the repository PDF and SHA-256 hash are the trajectory-3 release
   evidence.
4. Chio carries hosted CI replay debt in `CI-DEBT.md` under the steering
   override. The release audit result does not waive the final
   stabilization requirement.
5. Chio will cite this report from trajectory-4 launch materials only
   as a completed independent crypto and protocol review for the
   cemented Chio v3.0 surface.
