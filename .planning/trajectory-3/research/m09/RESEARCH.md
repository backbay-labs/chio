# M09 RESEARCH: HITRUST i1 Assessment

**Status:** RESEARCH (research-phase output, not normative)
**Author:** trajectory-3 RESEARCH agent
**Date:** 2026-04-30
**Lens:** External-attestation, vendor-calendar lane (procurement + scoping)
**Pinned decisions:** D02 (HITRUST i1 over ISO 42001), D07 (vendor budget posture), D09 (Opus deployment as scope), D05 (M06 SBOM consumed by M09)
**Pinned freezes:** `m01-m09-audit-handoff` (audit-doc + export-schema handoff from M01.P3 to M01.P5)

---

## HITRUST i1 framework primer

HITRUST publishes a single Common Security Framework (CSF) and three
assessment "intensities" against it. The trajectory-3 verdict picked
the middle one.

- **HITRUST CSF.** The framework itself, currently v11.x. CSF is the
  control catalog (~2,000+ requirement statements aggregated across
  HIPAA, NIST 800-53 / 800-171, ISO 27001, PCI DSS, GDPR, AICPA Trust
  Services Criteria, CCM, CIS, and others). It is not an assessment;
  it is the dictionary the assessments quote from.
- **HITRUST e1 (essentials, 1-year).** ~44 controls. Foundational
  cyber-hygiene posture. Too narrow to satisfy the verdict's
  third-party-evidence ask (the Opus pilot is a healthcare workload;
  e1 is a checkbox).
- **HITRUST i1 (implemented, 1-year).** ~180 controls in CSF v11
  (typical published count is in the 180-220 range; v11.2 listed 182;
  v11.3 around 219). Threat-adaptive: HITRUST refreshes the i1 control
  set roughly annually based on observed threat-actor TTPs. **Validity
  is one year**; re-certification is required (lighter than the
  initial pass, but it is not free). i1 is fixed-scope: every
  certified entity assesses against the same set, no tailoring. This
  fits a trajectory-3 calendar.
- **HITRUST r2 (risk-based, 2-year).** Tailored control selection from
  the full CSF, scoped to the entity's risk profile. Typically
  300-2000 controls depending on factors. Validity is two years with
  an interim assessment at year one. Calendar lead time is 12-18
  months minimum; out of trajectory window per D02 alternatives.

**Why i1 for trajectory-3:**

1. Calendar fits. HITRUST publishes a typical i1 lead time of 90-120
   days assessor-side; the 12-36 week range in
   `09-hitrust-i1-assessment.md` (gap 8-14, remediation 14-24,
   engagement 24-32, issuance 32-36) is consistent with HITRUST's own
   guidance and with assessor-firm published case studies.
2. Opus design partner asked for it as a procurement gate (per D02
   rationale). The ask is named, not abstract.
3. i1 includes HIPAA-aligned controls; the Opus deployment is a
   Backbay healthcare workload. No standalone HIPAA audit is needed
   if the i1 scope properly covers PHI handling.
4. ISO 42001 was considered (alternatives_rejected in D02). 12-18
   month lead time. Defer to trajectory-4.
5. SOC 2 Type 1 was considered. Opus cluster already accepts SOC 2
   from peer vendors; differentiation is low; rejected per D02.

**One-year validity implication.** The certificate Chio receives
expires 12 months after issuance. Re-certification is a trajectory-4
or post-trajectory-3 cycle problem. The audit doc must record
expiration date so the orchestrator can surface a renewal trigger.

---

## Control families mapped to Chio surface

HITRUST CSF organizes requirement statements into 14 control
categories (sometimes called "control families" in i1 vendor docs).
The mapping below is RESEARCH-grade; the IMPLEMENT phase confirms
counts against the active CSF version with the assessor.

| HITRUST control category | Chio existing-evidence surfaces | Notes |
|--------------------------|----------------------------------|-------|
| 0. Information Security Management Program | Trajectory-3 README, audit docs, owners file | Governance posture; M09 P0 codifies. |
| 1. Access Control | Capability algebra, sender constraint, delegation attenuation, revocation | Strongest pre-existing surface. `spec/PROTOCOL.md` + `spec/SECURITY.md` Section 2.1 / 2.6. |
| 2. Human Resources Security | Org-wide HR policies; not Chio-source-tree | Out-of-tree; M09 P0 references Backbay HR posture. |
| 3. Risk Management | M05 threat-coverage table, threat-model JSON | `spec/security/chio-threat-model.v1.json` is the canonical asset. |
| 4. Security Policy | `docs/security/`, `spec/SECURITY.md` | Already shipped. |
| 5. Organization of Information Security | Trajectory-3 OWNERS.toml, freezes.yml | Codifies trust-boundary review. |
| 6. Compliance | This milestone (M09); related to SECURITY.md, PROTOCOL.md, COMPLIANCE-CERTIFICATE.md | Self-attesting via session-compliance-certificate v1. |
| 7. Asset Management | M06 SBOM (`supply-chain/**`), cargo-vet ledger | M06 P3 SBOM is load-bearing. |
| 8. Physical and Environmental Security | AWS/cloud provider inheritance | Inherited from AWS SOC 2 / FedRAMP for Opus deployment. |
| 9. Communications and Operations Management | M01 operator runbook, hosted CI (M03), receipts pipeline | Plus `spec/HTTP-SUBSTRATE.md`, `spec/WORKFLOW.md`. |
| 10. Information Systems Acquisition, Development and Maintenance | M03 reproducible builds, M06 cargo-vet, formal invariants (M06 P1-P2) | Code-signing via M03 third-party rebuild evidence. |
| 11. Information Security Incident Management | M05 threat-coverage table maps to incident response paths; M01 ops playbook | IMPLEMENT-phase ticket: incident runbook draft. |
| 12. Business Continuity Management | Opus tenant DR posture (out-of-tree); kernel revocation oracle (M06) | Inherited; M09 audit doc lists. |
| 13. Privacy Practices | `pii_phi_exposure` threat (SECURITY.md 2.8 area), receipt-redaction pipeline | HIPAA pre-condition; see HIPAA section. |

**Self-attesting surface (Chio-specific).** The session compliance
certificate (`spec/COMPLIANCE-CERTIFICATE.md`) is itself an evidence
type for several control statements: signature validity, scope
compliance, budget compliance, guard evidence, chain continuity. The
certificate's per-session output is a control-evidence stream the
assessor can sample.

**Cross-milestone evidence inheritance.** Roughly 40-60 of the i1
control statements have pre-existing trajectory-2 or trajectory-3
evidence sources; the remaining 120-160 land somewhere on the
spectrum from policy-only (HR, physical, BCM) to operations
(monitoring, key rotation, vulnerability scanning) and require gap
remediation in P2. IMPLEMENT phase produces the actual count via the
gap assessment.

---

## External Assessor candidate dossier

HITRUST publishes the Authorized External Assessor list. As of
2026-04-30 the firms below are commonly engaged for healthcare-tech
i1 work and fit the D07 budget posture (~$80-150k for M09).
IMPLEMENT phase RFPs three; D02 / D07 / D12 patterns suggest a
two-vendor RFP with named fallback.

| Firm | Notable for | Fit notes |
|------|-------------|-----------|
| Coalfire | Long-running HITRUST authorized assessor; large healthcare client base | High-volume; calendar may be tight; quote tends mid-band. |
| A-LIGN | HITRUST + SOC + ISO multi-attestation under one engagement | Cross-credentialing useful for trajectory-4. |
| Schellman | Healthcare + cloud-native; engagement portal mature | Likely upper end of D07 band. |
| BDO Digital (BDO USA) | Healthcare + larger consulting overlay | Higher cost; wider gap-remediation advisory. |
| 360 Advanced | HITRUST and SOC2 boutique | Often lower band of D07; smaller bench. |
| RSM US | HITRUST + audit cross-credential | Mid-band; healthcare experience. |
| Sensiba LLP / others | Smaller boutiques | Tighter calendars; price-competitive. |

**Engagement scale (research grade).** Typical i1 fixed-fee bands
published by these firms hover at $50-120k for a single-environment,
single-product i1 with limited scope; healthcare workload + cloud
substrate often pushes upper band. Gap-assessment retainers are
typically $15-40k separate from the certification engagement, or
bundled. The D07 ~$80-150k posture covers mid-to-upper-band
single-environment.

**Selection axes (mirror D12 pattern):**

1. Calendar fit (week 1 outreach -> week 7 contract).
2. Quote inside D07 band.
3. Healthcare-tech and cloud-native prior engagement.
4. MyCSF (HITRUST's evidence portal) facility; some firms have
   accelerator tooling that compresses P3-P4.
5. Reciprocity with Opus's existing audit posture (does the Opus
   tenant ops review already share artifacts with this firm? unlikely
   but checked in P0).

---

## Calendar realism (per realist)

Cross-checked against HITRUST published guidance and assessor-firm
case studies:

| Phase | Weeks | Realist signal | HITRUST/assessor signal |
|-------|-------|----------------|-------------------------|
| P0 Audit doc seed + scope + RFP | 1-7 | 6-7 weeks for RFP -> contract | HITRUST registration + readiness baseline typically 4-8 weeks; consistent. |
| P1 Gap assessment | 8-14 | 6-7 weeks | Assessor-firm case studies cite 4-8 weeks gap assessment; consistent (slight padding for Chio's thin policy surface). |
| P2 Remediation | 14-19 | 5 weeks | Firms cite 4-12 weeks; lower-band possible because Chio inherits trajectory-2 evidence. |
| P3 Evidence package finalized | 19-24 | 5 weeks | Firms cite 4-6 weeks for evidence package + MyCSF upload; consistent. |
| P4 Assessor engagement | 24-32 | 8 weeks | HITRUST published norm: 90-120 days assessor evaluation including QA round; 8 weeks is the lower bound. Risk surface here. |
| P5 Certificate issuance | 32-36 | 4 weeks | HITRUST QA (HITRUST Inc itself reviews the assessor's report) typically adds 4-8 weeks; 4-week assumption is aggressive. |

**Conclusion:** the 12-36 week band is realistic if everything runs
clean. Slack lives in P4 (assessor engagement) and P5 (HITRUST QA
review). If P4 stretches to 12 weeks (its upper realistic bound)
trajectory close slips by ~4 weeks. Halt trigger 13 (vendor calendar
slip > 25%) corresponds to slipping past week 45 (= 36 * 1.25).
IMPLEMENT phase records the assessor's contracted delivery dates so
the trigger can fire on observable slip rather than inference.

**Aggressive but defensible:** 12 weeks for a small-scope single-
environment i1 has been achieved (firms publish 90-day case studies)
when readiness is high. Chio's pre-existing evidence inheritance
makes the lower band feasible, not guaranteed.

---

## Scope: Opus deployment + v3.18 (D09)

**Per D09 (Opus cluster as M01 design partner):** the certificate
scope is strictly the Opus tenant deployment of Chio v3.18 (the
trajectory-3 close version). The scope-of-assessment boundary is the
single load-bearing artifact for the audit doc.

**In-scope (boundary):**

- Chio kernel binaries built at v3.18 with M03 reproducible-build
  evidence.
- The Opus tenant deployment configuration (single tenant, single
  cluster).
- The Opus tenant's audit-log export pipeline per the M01.P3 schema
  (`spec/audit-log/export-schema.v1.json`).
- The trust-boundary surfaces enumerated in `spec/SECURITY.md` Section
  1 (capability issuance, kernel admission, kernel-to-tool transport,
  receipt generation).
- The M06 SBOM and cargo-vet ledger as inventory evidence.
- Operator runbook + ops playbooks at the M01 P5 freeze state.

**Out-of-scope (explicit):**

- Other Chio tenants and clusters (the verdict + D09 bind scope to
  Opus only). Per D15, design-partner withdrawal halts M09; no other
  tenant substitutes.
- Future versions (v3.19+, trajectory-4 surfaces). Re-certification or
  extension is a separate engagement.
- The Backbay platform layer outside Chio (other clusters, BackbayOS
  desktop, bb-ui packages). The certificate names Chio v3.18 as the
  product surface, not Backbay broadly.
- Mobile patient-app extension (M07): the mobile MVP is too late in
  the calendar (week 12+) to be inside the assessor's scope by
  default; IMPLEMENT phase confirms whether it is included or
  separately attested.
- AWS Bedrock listing surfaces (M10): the marketplace listing is its
  own scope discussion (cloud-provider attestation inheritance);
  out-of-scope for M09 i1.
- ISO 42001 surfaces (D02 defers).
- Pre-v3.18 versions retroactively.

**Boundary diagram language for the audit doc (P0 deliverable):**
single-tenant, single-version, single-deployment-environment
certificate scope. The assessor needs this in writing before P1 starts
because the gap assessment scopes its sample population accordingly.

---

## Evidence collection automation (cross-milestone)

HITRUST i1 assessor evidence requests, mapped to source milestone /
location. The IMPLEMENT phase produces a one-row-per-control
spreadsheet under `compliance/hitrust/control-mapping.csv`; this
section is the source-of-truth pre-image for that mapping.

| Evidence item | Source milestone | Location | Notes |
|---------------|------------------|----------|-------|
| System Security Plan (SSP) | M09 P0 | `compliance/hitrust/ssp.md` | Net-new authoring; references everything below. |
| Network / data-flow diagrams | M01 + M09 P0 | M01 operator runbook + M09 SSP | Single-tenant Opus topology. |
| Control narratives | M09 P2 | `compliance/hitrust/narratives/<control-id>.md` | Net-new; one per i1 control. |
| Audit log export schema | M01 P3 | `spec/audit-log/export-schema.v1.json` | Frozen via `m01-m09-audit-handoff`. |
| Audit log samples (30-day) | M01 P5 (BOUNDED_OPERATIONAL_PROFILE) | Opus ops export | 30-day window from D09 BOP requirement. |
| Threat model + coverage | M05 | `spec/security/chio-threat-model.v1.json`, `docs/security/threat-coverage.md` | M05 closes carry-forward gaps. |
| Formal-method outputs | M06 P1-P2 | `formal/tla/**`, `formal/apalache/**` | 3-4 invariants (D04). |
| SBOM | M06 P3 | `supply-chain/**`, `.github/workflows/sbom.yml` output | CycloneDX format typical. |
| cargo-vet ledger | M06 P3 | `supply-chain/audits.toml` | Supply-chain attestation. |
| CVE monitoring evidence | M06 P3 | `.github/workflows/cve-monitor.yml` | Continuous evidence stream. |
| Reproducible-build verifier attestation | M03 P5 | M03 audit doc record (third-party rebuild + matched hash) | Per D13. |
| Hosted CI provenance | M03 | `.github/workflows/*` + SLSA-style provenance attestations | ubuntu-24.04 + macos-14. |
| Mutation kill-rate evidence | M04 | M04 audit doc | Floor-vs-target rule per D08. |
| Operator runbook | M01 P5 | `.planning/trajectory-3/audits/M01-opus-pilot.md` + ops repo | Frozen via M01.P5 close. |
| Incident response playbook | M09 P2 | `compliance/hitrust/ir-runbook.md` | Net-new authoring. |
| Encryption-at-rest / in-transit evidence | M01 + cloud provider | Mixed | TLS via SECURITY.md 2.2; at-rest via cloud provider. |
| Access reviews | Opus ops | Backbay HR/IT; out-of-tree | Quarterly cadence typical. |
| Penetration-test report | M08 | M08 audit doc | M08 NCC Group / Trail of Bits report; complementary not required for i1 but strong evidence. |

**Automation lever.** A `compliance/hitrust/build-evidence-pack.sh`
script (P3 deliverable) gathers the latest copies of the above into a
single dated bundle uploaded to the assessor's MyCSF portal. The
script is idempotent and dated so re-running produces a fresh bundle
on demand. This compresses P4 turnaround when the assessor requests
follow-ups.

---

## HIPAA pre-conditions

HITRUST i1 includes HIPAA-aligned controls; the Opus deployment is a
healthcare workload handling PHI. The pre-conditions below are
gating: if any are unmet at P0 close, the assessor will surface them
in P1 gap assessment as Sev-1 findings.

1. **Business Associate Agreement (BAA).** A BAA between Backbay (as
   Chio operator) and the upstream healthcare entity (the Opus
   cluster's provider customer base) MUST be executed before PHI
   touches the system. IMPLEMENT phase confirms the BAA chain:
   provider <-> Opus tenant <-> Backbay. If Chio is treated as a
   subcontractor of Opus, a Backbay-Opus BAA is required.
2. **PHI handling boundaries.** The `pii_phi_exposure` threat in
   `spec/SECURITY.md` (Section 2.8 area; covered in M05) indicates
   Chio's existing posture treats PHI as a guard concern. HIPAA Tech
   Safeguards (164.312) require: access control (Chio capabilities
   align), audit controls (Chio receipts align), integrity (signed
   receipts), authentication (capability + sender constraint),
   transmission security (TLS per SECURITY.md 2.2). Mapping is
   tractable.
3. **Breach notification.** HIPAA requires 60-day breach notification
   (45 CFR 164.404). Operator-side: Opus and Backbay must have a
   breach-notification runbook. M09 P2 deliverable: incident response
   runbook (`compliance/hitrust/ir-runbook.md`) referencing 45 CFR
   164.400-414.
4. **Minimum necessary standard.** Capability scoping naturally
   maps; document the policy explicitly in P2 narrative.
5. **De-identification posture.** If any analytics/telemetry leaves
   the PHI boundary, document de-id (Safe Harbor or Expert
   Determination per 45 CFR 164.514). IMPLEMENT phase: confirm
   whether Chio kernel telemetry includes any PHI surface; default
   posture is no-PHI-in-telemetry.
6. **Workforce training.** Backbay-side HR; out-of-tree but the
   audit doc references whether annual training has been completed
   for everyone touching the Opus tenant.

**Risk:** if BAA chain is incomplete at P0, the milestone halts
until contracts close. Halt trigger candidate (not in current
AUTONOMOUS-PROMPT trigger set; surface to user).

---

## Per-phase research findings (P0-P5, calendar-bound)

### P0: weeks 1-7 -- Audit doc seed + HITRUST scope + assessor shortlist

**Goal:** binding scope statement + assessor contract.

- T0.1: Open `compliance/hitrust/` directory; seed SSP outline,
  scope-of-assessment boundary diagram, control-mapping skeleton.
- T0.2: Author `.planning/trajectory-3/audits/M09-vendor-evidence.md`
  with assessor shortlist (3 firms), RFP status, BAA status,
  pre-conditions checklist.
- T0.3: Issue RFP to two named firms (D12 pattern: two-vendor
  primary, one fallback). Deadline week 4.
- T0.4: Pin scope statement against D09: v3.18 + Opus deployment;
  freeze under audit-doc lane.
- T0.5: Confirm BAA chain (HIPAA pre-conditions section above).
- T0.6: Contract assessor end of week 5; first kickoff week 6.
- Vendor-wait tickets (0.25-day) interleaved with 1-day evidence
  authoring tickets.

### P1: weeks 8-14 -- Gap assessment

**Goal:** assessor produces gap report against active i1 control set.

- T1.1: Assessor MyCSF tenant + portal access provisioned.
- T1.2: Initial readiness questionnaire completed (control narratives
  drafted at coarse grain).
- T1.3: Assessor walkthroughs (weekly cadence; 5-7 walkthroughs).
- T1.4: Inherited evidence pre-loaded: SECURITY.md, PROTOCOL.md,
  COMPLIANCE-CERTIFICATE.md, M01 runbook draft, M05 threat-coverage,
  M03 CI workflows.
- T1.5: Gap report received end of week 14. Categorize findings:
  remediable in P2, requires trajectory-4 (escalate via halt 14
  consideration).

### P2: weeks 14-19 -- Remediation work

**Goal:** every Sev-1 / Sev-2 gap closed; Sev-3 documented as
accepted risk if applicable.

- T2.1: Author missing control narratives (one per control statement
  flagged). Estimate: 1-day each, 30-60 narratives (research grade).
- T2.2: Operationalize missing controls (e.g., quarterly access
  review cadence formalized; key rotation schedule documented).
- T2.3: Incident response runbook authored.
- T2.4: Encryption-at-rest evidence collected from cloud provider.
- T2.5: Evidence-collection automation script seed
  (`compliance/hitrust/build-evidence-pack.sh`).

### P3: weeks 19-24 -- Evidence package finalized for assessor portal

**Goal:** every requested artifact uploaded; M06 SBOM consumed; M03
provenance consumed; M01 audit-log export schema consumed.

- T3.1: M06 P3 SBOM published (gating; M09 P3 cannot start until
  M06 P3 closes per `09-hitrust-i1-assessment.md` Risk 2).
- T3.2: Evidence-pack script run; bundle uploaded to MyCSF.
- T3.3: 30-day BOP window log samples extracted from M01 P5 export
  pipeline.
- T3.4: Assessor confirms package complete; sets P4 evaluation
  start date.

### P4: weeks 24-32 -- Assessor engagement (on-site / remote evaluation)

**Goal:** assessor completes their evaluation; produces draft
report.

- T4.1: Sample testing (assessor pulls receipt samples, audit-log
  samples, runbook excerpts, control-narrative spot checks).
- T4.2: Interviews with operators (Opus ops review).
- T4.3: Follow-up evidence requests; turnaround <= 5 business days
  (the build-evidence-pack script supports this).
- T4.4: Assessor draft report received end of week 32.
- T4.5: Findings dispute / clarification round if needed.

### P5: weeks 32-36 -- Certificate issuance + audit doc closure

**Goal:** HITRUST QA passes; certificate issued; audit doc closed.

- T5.1: Assessor submits final report to HITRUST Inc for QA.
- T5.2: HITRUST QA round (HITRUST itself reviews the assessor's
  report; can require revisions). Typical 2-6 weeks.
- T5.3: Certificate issued; PDF + entry in HITRUST's directory.
- T5.4: Audit doc records: assessor identity, certificate id, scope
  statement, expiration date, finding log with remediation
  cross-references, M01/M03/M05/M06 evidence-source pointers.
- T5.5: Renewal cadence trigger filed (1-year validity; trajectory-4
  candidate).

---

## Audit-handoff freeze (M01)

Per `freezes.yml` `m01-m09-audit-handoff`:

- **Path globs frozen:**
  - `spec/audit-log/export-schema.v1.json`
  - `.planning/trajectory-3/audits/M01-opus-pilot.md`
- **Window:** opens at M01.P3.T1 (schema negotiation begins);
  closes at M01.P5.T5 (ops sign-off).
- **Trust boundary:** yes.
- **Guard check:** `m01-audit-handoff-guard`.

**What M01 hands to M09 and when:**

| Artifact | Frozen at | M09 consumes at |
|----------|-----------|-----------------|
| `spec/audit-log/export-schema.v1.json` v1 | M01.P3 close | P0 (referenced in scope), P1 (assessor sees), P3 (uploaded). |
| Opus operator runbook | M01.P5 close | P3 (uploaded as evidence). |
| 30-day BOP audit log samples | M01.P5 close (BOP window completes) | P3 (sample pull) and P4 (assessor sample testing). |
| `.planning/trajectory-3/audits/M01-opus-pilot.md` final form | M01.P5 close | P3 (referenced), P4 (samples drawn). |

**Sequencing:** M09.P3 cannot complete until M01.P5 closes. The
trajectory orchestrator must confirm M01.P5.T5 has merged before
M09.P3.T2 (evidence-pack upload) opens. The audit-handoff freeze is
the trust-boundary mechanism that keeps the M01 surface stable
during the M09.P3 -> P4 transition.

**Risk if handoff slips:** every M09 phase past P3 stalls. Realist
calendar buffer is in P5 (HITRUST QA round); a 2-week M01.P5 slip is
absorbable, a 4-week slip pushes M09 close past week 36 and
approaches halt trigger 13.

---

## Risk register

| ID | Risk | Likelihood | Impact | Mitigation | Halt trigger |
|----|------|-----------|--------|------------|-------------|
| R1 | Assessor calendar slip past week 36 (P4 expansion or P5 QA stall) | Med | High (trajectory close slips) | RFP two firms; pick the one with shorter quoted P4 | 13 (vendor slip > 25%) |
| R2 | Gap assessment finds gaps requiring trajectory-4 controls | Med | Med | P1 categorizes by remediation depth; user decides at week 14 whether to descope or remediate | 14 (HITRUST readiness rejection) |
| R3 | HIPAA pre-conditions not met by Opus (BAA chain) | Low-Med | High (P1 stalls until contracts close) | P0 confirms BAA chain; surface to user | not currently in trigger set; new candidate |
| R4 | M06 P3 SBOM delays past M09 P3 start (week 19) | Low | Med (P3 stalls) | M06 P3 close is gating; track via cross-milestone wave | 13 if vendor slip; 14 not applicable |
| R5 | Opus design partner withdraws (D09 binding scope evaporates) | Low | High (M09 halts entirely) | per D15 + halt 12; no substitute tenant available | 12 (design-partner withdrawal) |
| R6 | Vendor quote outside D07 band ($80-150k) | Low-Med | Med | Three-firm RFP gives leverage; if all three quote out, surface for budget amendment | not currently in trigger set; surface to user |
| R7 | HITRUST QA round (P5) returns the assessor's report for revision | Med | Med (1-4 week slip) | Assessor accelerator firms have lower QA-rejection rates; selection axis | 13 if cumulative slip > 25% |
| R8 | Assessor MyCSF portal access friction (auth, federation, evidence-format mismatch) | Low | Low (1-2 week slip absorbable) | P1.T1 provisioning; CSV mapping format negotiated up front | not a halt trigger |
| R9 | M01 audit-handoff freeze breach (someone edits frozen path during freeze window) | Low | Med (M09 evidence corrupted) | `m01-audit-handoff-guard` GitHub required-check + freeze register enforcement | not a halt trigger; orchestrator auto-rejects |
| R10 | Certificate scope is interpreted differently by assessor than D09 | Low | High (mis-scoped certificate is unusable) | P0 scope statement signed by assessor before P1 starts | 14 candidate |

---

## Recommended ticket scaffold (vendor-coord agent role)

**Agent role:** vendor-coord (procurement + evidence-coordination
mindset; not a code-engineer mindset). Tickets are mostly 0.25-day
vendor-wait + 1-day evidence-authoring + 0.5-day cross-milestone
cross-reference.

Per-phase ticket counts (research grade; IMPLEMENT phase pins exact
counts):

| Phase | Tickets | Mix |
|-------|---------|-----|
| P0 | 5-7 | 2 RFP + scope, 2 SSP/audit-doc seed, 2 BAA/pre-condition, 1 contract close |
| P1 | 6-9 | 1 portal provisioning, 1-2 readiness questionnaires, 4-6 walkthroughs, 1 gap-report intake |
| P2 | 8-15 | One ticket per missing control narrative + 2-3 ops-runbook tickets + 1 evidence-pack script seed |
| P3 | 4-6 | M06 P3 dependency wait, evidence-pack run + upload, 30-day sample pull, assessor confirm |
| P4 | 8-12 | 5-7 follow-up vendor-wait tickets + 1-2 sample-pull tickets + 1 interview support + 1 draft-report intake |
| P5 | 4-6 | HITRUST QA wait, certificate issuance intake, audit doc closure, renewal trigger filing |

**Single-FTE-week budget:** the milestone is mostly program-lead work
(D06: 1 PL); engineering touches are SBOM + reproducible-build
verifier (already owned by M03/M06) + occasional control-narrative
authoring. Estimate 5-8 cumulative FTE-weeks engineering across the
36-week calendar; 24-32 PL-weeks (PL is the load-bearing role).

**Trust-boundary review (D06: 0.5 SR):** the SR reviews the SSP
draft + control narratives for accuracy against `spec/SECURITY.md`
and `spec/PROTOCOL.md` claims. Approx 2-4 SR-days across the
milestone.

---

## Open questions for IMPLEMENT phase

1. **Active CSF version at week 1.** HITRUST CSF v11.x; confirm the
   exact minor version published at trajectory-3 start. Control count
   varies (180-220) by minor version.
2. **Assessor shortlist final cut.** Three firms named in the
   dossier above; IMPLEMENT phase narrows to two RFP recipients +
   one fallback (D12 pattern). User input expected.
3. **BAA chain exact form.** Provider <-> Opus <-> Backbay layering
   needs legal review; IMPLEMENT phase confirms each contract is
   executed and references the others.
4. **Mobile (M07) inclusion in i1 scope.** Default no (out-of-scope
   per "Scope" section); explicit decision recorded in P0 audit doc.
5. **MCP / AWS Bedrock (M10) inclusion in i1 scope.** Default no;
   explicit decision recorded in P0.
6. **Halt-trigger candidate for HIPAA pre-conditions.** Currently not
   in AUTONOMOUS-PROMPT trigger set; should this be added or
   absorbed under trigger 14?
7. **Evidence retention period.** HITRUST typically requires 6-year
   retention for audit-log evidence (HIPAA-aligned); confirm Opus
   tenant retention posture supports this.
8. **Certificate display posture.** Does Backbay publish the
   certificate publicly (HITRUST directory entry is automatic;
   marketing language is separate)? Trajectory-3 close
   communications surface.
9. **Re-certification trigger filing.** 1-year validity; the
   trajectory orchestrator should produce a renewal trigger 60-90
   days before expiration. Cron / schedule configuration is a
   trajectory-4 problem but the trigger filing is a P5 deliverable.
10. **Vendor budget actual.** Quote-vs-band variance recorded in the
    audit doc per D07 consequences clause.
11. **Cross-credential opportunity.** Some assessor firms can issue
    SOC 2 Type 1 alongside i1 with marginal extra cost; trajectory-3
    declined SOC 2 (D02 alternatives) but trajectory-4 may want it.
    Note in P5 audit doc whether the chosen firm offers it for
    future engagements.
12. **Apalache / formal evidence framing.** M06 ships 3-4 invariants
    per D04. The assessor may not be familiar with TLA+/Apalache;
    P2 narrative needs a plain-English explanation of what the
    formal evidence asserts and how it maps to control statements.

---

**END RESEARCH.md**
