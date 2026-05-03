# Milestone 09: HITRUST i1 Assessment

> **Disclaimer:** This is a HITRUST i1 readiness package, not an issued certificate. No HITRUST-authorized External Assessor (e.g., A-LIGN, Coalfire, Schellman) has performed an audit. Real HITRUST i1 certification is a trajectory-4 deliverable (M09-followup).

## Lens

External-attestation. M09 procures a HITRUST i1 readiness + assessment
scoped to the M01 design-partner deployment of Chio v3.18 (D02 picks
HITRUST i1 over ISO 42001; D09 binds the scope). The lens is single
(third-party compliance attestation) and the calendar is long-clock
(12-36 weeks) running parallel to all code waves on the vendor lane Wv.
Tickets are predominantly vendor-coord (RFP, scoping, walkthroughs,
follow-up evidence requests) with a smaller engineering surface
(evidence-pack automation script, control-mapping CSV, narrative
authoring).

Trust-boundary: yes.

## Why this is on the trajectory

**Release-gate anchor:** QUALIFICATION

The trajectory-3 verdict names HITRUST i1 as the second of two
third-party-evidence forms for trajectory close. The healthcare
design partner asked for HITRUST i1 first as a procurement gate
(D02 rationale); ISO 42001 was considered but the calendar (12-18
months) does not fit the trajectory window. A HITRUST-authorized
assessor's certificate, scoped strictly to v3.18 + the M01
design-partner deployment, is the load-bearing artifact that turns
the QUALIFICATION release-gate from self-attestation into
externally-legible attestation.

The M09 deliverable consumes prior-art shipped by adjacent trajectory-3
milestones: the M01 operator runbook + audit-log export schema v1
(`spec/audit-log/export-schema.v1.json`), the M03 hosted CI workflows
plus SLSA-style provenance + reproducible-build hash, the M05 threat
model + threat-coverage closure table, and the M06 SBOM
(`supply-chain/**`) plus cargo-vet ledger. None of those are owned by
M09; M09 surfaces them through the assessor's MyCSF portal as
inherited evidence.

## Prior-art reckoning

trajectory-2 shipped:

- No HITRUST work. The trajectory-2 economic-layer milestone (M09 in
  trajectory-2 numbering) is unrelated; this M09 is trajectory-3.
- Existing inherited compliance posture is opportunistic-not-formal.
  `spec/SECURITY.md`, `spec/COMPLIANCE-CERTIFICATE.md`, and
  `spec/PROTOCOL.md` carry self-attesting language that maps to roughly
  40-60 of the i1 control statements but no external assessor has
  validated the mapping.

What M09 changes:

- Adds `compliance/hitrust/` with control-mapping CSV, control
  narratives, the System Security Plan (SSP), the incident response
  runbook, and the evidence-pack automation script.
- Adds `docs/external-attestation/hitrust-i1/` for the user-facing
  certificate landing surface (issuance announcement, scope statement,
  expiration).
- Adds assessor portal coordination (vendor-side) tracked through
  `.planning/trajectory-3/audits/M09-vendor-evidence.md`.

What M09 preserves:

- Existing operational posture (M01 runbook, M03 CI workflows, M06
  SBOM are read-only for M09).
- The cemented v3.18 protocol surface; the assessor evaluates the
  shipped state, not work-in-progress.
- The audit-log export schema v1 frozen via the
  `m01-m09-audit-handoff` freeze.

Vendor shortlist (HITRUST-authorized assessors named explicitly per
STYLE.md): Coalfire, A-LIGN, Schellman as the primary three; BDO
Digital, 360 Advanced, RSM US as named fallbacks. P0 narrows the
shortlist to two RFP recipients plus one fallback per the D12 pattern.

## Hard counts (measured 2026-04-30)

These are research-grade pre-images; P0 pins exact values once the
HITRUST CSF active-version is confirmed and the assessor signs the
scoping memo.

- HITRUST CSF active version at trajectory-3 start: v11.x (research
  signal v11.2 listed 182 controls; v11.3 around 219). P0 confirms
  exact minor version; control count varies 180-220.
  (`compliance/hitrust/control-mapping.csv` row count, post-P0)
- HITRUST i1 controls in scope (target estimate): 180-220.
  Pre-existing-evidence inheritance estimate: 40-60 controls
  (governance + threat model + spec self-attest + SBOM). Net new for
  P2 remediation: 120-160 controls.
  (`grep -c '^[A-Z0-9]' compliance/hitrust/control-mapping.csv` post-P1)
- Existing self-attesting surface line counts (Chio repo today):
  `spec/SECURITY.md` (load-bearing for control families 1, 3, 4, 6,
  9, 11, 13);
  `spec/PROTOCOL.md` (load-bearing for control family 1, 9, 10);
  `spec/COMPLIANCE-CERTIFICATE.md` (per-session evidence stream for
  control families 1, 6, 9).
  (`wc -l spec/SECURITY.md spec/PROTOCOL.md spec/COMPLIANCE-CERTIFICATE.md`)
- Cross-milestone evidence sources at trajectory-3 start:
  M01 `spec/audit-log/export-schema.v1.json` (frozen via
  `m01-m09-audit-handoff`); M03 `.github/workflows/*` reproducible-
  build pipeline + provenance; M05 `spec/security/chio-threat-model.v1.json`
  + `docs/security/threat-coverage.md`; M06 `supply-chain/**`
  (SBOM + cargo-vet ledger).
- Vendor calendar lead times pinned per the verdict band: 12-36 weeks
  end-to-end. P4 (assessor engagement) and P5 (HITRUST QA) are slack
  zones; halt-trigger 13 fires at week 45 (= 36 * 1.25).

## Workspace dependency state

Per HITRUST published guidance and assessor-firm case studies; the
12-36 week band is realistic for a small-scope single-environment i1
when readiness inheritance is high (Chio's case). Slack lives in P4
and P5.

- Audit doc seed + scope + RFP weeks 1-7 (P0)
- Gap assessment weeks 8-14 (P1)
- Remediation weeks 14-19 (P2)
- Evidence package finalized weeks 19-24 (P3)
- Assessor engagement (on-site / remote evaluation) weeks 24-32 (P4)
- Certificate issuance + audit doc closure weeks 32-36 (P5)

The calendar markers are the contractual delivery dates the assessor
signs at end-of-P0; halt trigger 13 (vendor calendar slip > 25%)
fires on observable slip past week 45 rather than inference. The
audit doc records the assessor's contracted dates for trigger-firing
purposes.

## Scope

### In

- HITRUST i1 assessment scoped strictly to v3.18 + the M01
  design-partner deployment per D09; non-design-partner scope
  explicitly excluded.
- Single-tenant, single-version, single-deployment-environment
  certificate scope (the boundary diagram in the SSP is the
  load-bearing scope artifact).
- Gap assessment with HITRUST-authorized assessor (one of the
  shortlisted firms; D12 pattern selects).
- Control mapping under `compliance/hitrust/control-mapping.csv`
  (one row per i1 control; columns: control id, family, narrative
  path, evidence sources, status).
- System Security Plan at `compliance/hitrust/ssp.md`.
- Control narratives at
  `compliance/hitrust/narratives/<control-id>.md`.
- Incident response runbook at `compliance/hitrust/ir-runbook.md`
  (HIPAA breach-notification 45 CFR 164.400-414 referenced).
- Evidence-collection automation
  (`compliance/hitrust/build-evidence-pack.sh`); idempotent shell
  script that gathers M01/M03/M05/M06 outputs into a dated bundle for
  upload to the assessor's MyCSF portal.
- Assessor portal coordination (vendor-side) tracked through the audit
  doc.
- HIPAA pre-conditions confirmation: BAA chain (provider <-> the
  design-partner tenant <-> Chio team), PHI-handling boundaries
  documented, breach notification runbook authored, minimum-necessary
  policy documented, de-identification posture confirmed for
  telemetry.
- Certificate issuance (one year validity) + audit-doc closure +
  renewal-trigger filing (1-year validity; trajectory-4 candidate).

### Out (and why)

- HITRUST r2 (risk-based, 2-year). Lead time 12-18 months minimum;
  out of trajectory window. (D02 rationale.)
- HITRUST e1 (essentials, ~44 controls). Too narrow to satisfy the
  design-partner procurement ask; healthcare workload context
  demands i1 at minimum. (Research findings.)
- ISO 42001. Lead time 12-18 months; deferred to trajectory-4 per
  D02 alternatives_rejected.
- SOC 2 Type 1. The design partner already accepts SOC 2 from peer
  vendors; differentiation is low. (D02 alternatives_rejected.)
- Non-design-partner deployment scope (other Chio tenants). D09
  binds scope; if the selected design partner withdraws, M09 halts
  via halt trigger 12 (D15: no substitute tenant available without
  user authorization).
- Future versions (v3.19+, trajectory-4 surfaces). Re-certification or
  scope extension is a separate engagement.
- Workspace surfaces outside the Chio product (sister projects, UI
  packages, unrelated clusters in the workspace). The certificate
  names Chio v3.18 as the product surface; broader workspace scope
  is out of bounds.
- Mobile patient-app extension (M07). The mobile MVP closes too late
  in the calendar (week 12+) to be inside the assessor's scope by
  default; P0 records the explicit decision.
- AWS Bedrock listing surfaces (M10). The marketplace listing is its
  own attestation discussion (cloud-provider inheritance); out-of-scope
  for M09 i1.
- Pre-v3.18 versions retroactively.
- M08 NCC Group or Trail of Bits report, while complementary, is not a
  substitute for i1 evidence and runs on its own vendor lane.

## Phases

### P0: weeks 1-7 - Audit doc seed + HITRUST scope + assessor shortlist

P0 turns the verdict-anchored brief into a contract: a binding scope
statement signed by the assessor, an RFP cycle with two firms (plus
one fallback), and a confirmed BAA chain so P1 gap-assessment does
not stall on missing healthcare-tech contracts. Tickets are
predominantly 0.25-0.5 day vendor-coord items plus 0.5-1 day audit-doc
authoring.

- M09.P0.T1: Open `compliance/hitrust/` directory with SSP outline,
  scope-of-assessment boundary diagram, control-mapping CSV skeleton.
- M09.P0.T2: Seed `.planning/trajectory-3/audits/M09-vendor-evidence.md`
  with assessor shortlist (Coalfire, A-LIGN, Schellman primary;
  BDO Digital, 360 Advanced, RSM US fallback), RFP status, BAA status,
  HIPAA pre-conditions checklist.
- M09.P0.T3: Confirm HITRUST CSF active version at trajectory start;
  pin v11.x minor version + control count in audit doc and SSP.
- M09.P0.T4: Author RFP and send to two named firms (D12 pattern:
  two-vendor primary, one fallback). Deadline week 4.
- M09.P0.T5: Pin scope statement against D09: v3.18 + the M01
  design-partner deployment; freeze under audit-doc lane. Mobile
  (M07) and Bedrock (M10) inclusion explicit-no per default; record
  the decision.
- M09.P0.T6: Confirm BAA chain (provider <-> the design-partner
  tenant <-> Chio team). Surface to user if any contract is
  unexecuted (HIPAA pre-condition; halt-trigger candidate).
- M09.P0.T7: Receive RFP responses; record quotes against D07 band
  ($80-150k); halt-trigger candidate if all quotes outside band.
- M09.P0.T8: Contract assessor end of week 5; first kickoff week 6.
  Assessor signs scope memo (R10 mitigation).

### P1: weeks 8-14 - Gap assessment

P1 is assessor-led: the contracted firm runs walkthroughs, ingests
inherited evidence, and produces a gap report against the active i1
control set. Tickets are 0.25-day vendor-wait at weekly cadence
interleaved with 1-day evidence-authoring (control-narrative coarse
drafts, readiness questionnaire responses).

- M09.P1.T1: Provision MyCSF tenant + portal access for the assessor;
  upload coarse-grain inherited evidence (SECURITY.md, PROTOCOL.md,
  COMPLIANCE-CERTIFICATE.md, M01 runbook draft, M05 threat-coverage,
  M03 CI workflows).
- M09.P1.T2: Complete initial readiness questionnaire; coarse-grain
  control narratives drafted alongside.
- M09.P1.T3 through M09.P1.T7: Five weekly assessor walkthroughs
  (0.25-0.5 day each: governance, access control, asset management +
  supply chain, ops + incident response, privacy + HIPAA). Tickets
  capture the calendar dependency and assessor question backlog.
- M09.P1.T8: Cross-milestone evidence inventory pull
  (M01/M03/M05/M06); flag missing artifacts that must close before
  P3.
- M09.P1.T9: Receive gap report end of week 14. Categorize findings:
  Sev-1/2 remediable in P2, Sev-3 documentable as accepted risk,
  trajectory-4 escalation if any (halt-trigger 14 candidate).

### P2: weeks 14-19 - Remediation work

P2 closes Sev-1/Sev-2 gaps. Most engineering effort lives here:
control-narrative authoring (one per gap), incident-response runbook,
formalized cadence policies (access reviews, key rotation), and the
seed of the evidence-pack automation script. Tickets are mostly 1-day
narrative authoring + 0.5-1 day ops-runbook items.

- M09.P2.T1: Author missing control narratives. Estimate 30-60 net-new
  narratives at 1-day each (research grade); orchestrator may split
  across `T1.a..T1.n` letter sub-tickets to stay under 2-day ticket
  cap.
- M09.P2.T2: Operationalize quarterly access-review cadence; document
  policy + first review cycle in `compliance/hitrust/policies/access-review.md`.
- M09.P2.T3: Document key-rotation schedule (capability signing keys,
  TLS, audit-log export keys); land
  `compliance/hitrust/policies/key-rotation.md`.
- M09.P2.T4: Author incident response runbook
  (`compliance/hitrust/ir-runbook.md`); reference 45 CFR 164.400-414
  (HIPAA 60-day breach notification).
- M09.P2.T5: Collect encryption-at-rest evidence from the cloud
  provider (AWS for the design-partner deployment); record
  provider-attestation pointers.
- M09.P2.T6: Seed `compliance/hitrust/build-evidence-pack.sh`:
  idempotent shell script that gathers M01 runbook + log-export
  schema, M03 provenance + workflows, M05 threat model + coverage
  table, M06 SBOM + cargo-vet ledger into a dated bundle under
  `compliance/hitrust/evidence-bundles/<YYYY-MM-DD>/`.
- M09.P2.T7: Author plain-English bridge for M06 formal evidence
  (TLA+/Apalache invariants) so the assessor can map it to control
  statements without specialist knowledge.
- M09.P2.T8: Document de-identification posture for kernel telemetry
  (default no-PHI-in-telemetry) per 45 CFR 164.514.
- M09.P2.T9: Audit-doc update with remediation log per gap; Sev-3
  accepted-risk register + cross-references.

### P3: weeks 19-24 - Evidence package finalized for assessor portal

P3 is gated by M01.P5 close (the `m01-m09-audit-handoff` freeze
end-trigger M01.P5.T5) and by M06.P3 SBOM publication. The evidence
pack runs once both upstreams have closed, then lands in the
assessor's portal. Tickets are mostly small but sequential.

- M09.P3.T1: Wait for M06.P3 SBOM publication (cross-milestone
  hard dep; vendor-wait status until M06.P3 closes).
- M09.P3.T2: Wait for M01.P5 close (audit-handoff freeze end trigger
  M01.P5.T5; vendor-wait status). Pull 30-day BOP audit-log samples
  via the M01 export pipeline.
- M09.P3.T3: Run `compliance/hitrust/build-evidence-pack.sh`; produce
  dated bundle; verify the bundle includes every artifact the assessor
  itemized in P1.
- M09.P3.T4: Upload bundle to MyCSF portal; record bundle hash in
  audit doc.
- M09.P3.T5: Receive assessor confirmation that the package is
  complete; assessor sets P4 evaluation start date. Vendor-wait
  ticket capturing the confirmation.
- M09.P3.T6: Audit-doc update: package upload date, bundle hash,
  assessor-confirmed P4 start date, M01 / M03 / M05 / M06 evidence-
  source pointers.

### P4: weeks 24-32 - Assessor engagement (on-site / remote evaluation)

P4 is assessor-led; throughput is dominated by 0.25-1 day vendor-wait
tickets handling follow-up evidence requests. The build-evidence-pack
script supports <= 5-business-day turnaround on follow-ups.

- M09.P4.T1: Sample testing support: assessor pulls receipt samples,
  audit-log samples, runbook excerpts, control-narrative spot checks.
  Vendor-wait + 0.5-day evidence-pull cadence.
- M09.P4.T2: Operator interviews (the design-partner ops team
  participates). Vendor-wait + scheduling coordination.
- M09.P4.T3 through M09.P4.T7: Five follow-up vendor-wait tickets
  (one per assessor evidence request, weekly cadence). Each runs
  the evidence-pack script with updated parameters and re-uploads.
- M09.P4.T8: Receive assessor draft report end of week 32.
- M09.P4.T9: Findings dispute / clarification round if needed
  (vendor-coord + 0.5-1 day narrative response).
- M09.P4.T10: Audit-doc update: draft report hash, finding log,
  remediation cross-references for any Sev-1 carry-over.

### P5: weeks 32-36 - Certificate issuance + audit doc closure

P5 is HITRUST-Inc-led: the assessor submits the final report to
HITRUST for QA review (typical 2-6 weeks). After QA passes, the
certificate is issued and the audit doc closes. Renewal-trigger
filing is a P5 deliverable so the trajectory orchestrator surfaces
the 1-year-validity expiration ahead of trajectory-4 planning.

- M09.P5.T1: Assessor submits final report to HITRUST Inc for QA;
  vendor-wait ticket.
- M09.P5.T2: HITRUST QA round (HITRUST Inc reviews the assessor's
  report; can require revisions). 2-6 week vendor-wait.
- M09.P5.T3: Certificate issued; PDF + entry in HITRUST's directory.
- M09.P5.T4: Audit doc final pass: assessor identity, certificate id,
  scope statement, expiration date (issuance + 12 months), finding
  log with remediation cross-references, M01 / M03 / M05 / M06
  evidence-source pointers, vendor-quote variance from D07 band.
- M09.P5.T5: File renewal cadence trigger (1-year validity); the
  trajectory orchestrator should produce a renewal trigger 60-90
  days before expiration (trajectory-4 candidate).
- M09.P5.T6: Land
  `docs/external-attestation/hitrust-i1/index.md` with the public-
  facing certificate landing page (scope statement, expiration date,
  HITRUST directory link).

## Cross-milestone interactions

- M09 consumes `spec/audit-log/export-schema.v1.json` (M01.P3 freeze
  end-trigger) plus the design-partner operator runbook and 30-day
  BOP audit samples (M01.P5 close). The `m01-m09-audit-handoff`
  freeze guards
  these paths from M01.P3.T1 open through M01.P5.T5 close;
  `m01-audit-handoff-guard` GitHub required-check enforces.
- M09 consumes M03 hosted CI workflows (`.github/workflows/*`) and
  SLSA-style provenance + reproducible-build hash per the M03 audit
  doc. P3 evidence pack pulls the latest provenance attestations.
- M09 consumes M05 threat-coverage table
  (`docs/security/threat-coverage.md`) and threat-model JSON
  (`spec/security/chio-threat-model.v1.json`). The coverage table
  must reach zero `partial` / `placeholder` rows before P3 close;
  the M05 milestone owns that closure.
- M09 consumes M06 SBOM (`supply-chain/**`) plus cargo-vet ledger and
  CVE-monitoring workflow output. M06.P3 close is gating for M09.P3
  start.
- M09 consumes M04 mutation-gate output (`.planning/trajectory-3/audits/M04-mutation-gate.md`)
  and M04 verdict-matrix promotion as ancillary evidence.
- M09 evidence is one of the two third-party evidence forms for
  trajectory-3 close (the other is M08 NCC Group or Trail of Bits).
  Both feed the trajectory close narrative.
- M09 does not gate W1/W2/W3 transitions; its evidence lands at
  trajectory close per the README wave plan.

## Risks and mitigations

1. **Assessor calendar slip past week 36** (P4 expansion or P5 QA
   stall). Likelihood medium, impact high (trajectory close slips).
   Mitigation: RFP two firms in P0; pick the firm with the shorter
   quoted P4. Halt trigger 13 fires at cumulative slip > 25% (week
   45). The audit doc records contracted delivery dates so slip is
   observable rather than inferred.
2. **Gap assessment finds gaps requiring trajectory-4 controls.**
   Likelihood medium, impact medium. Mitigation: P1.T9 categorizes
   findings by remediation depth; user decides at week 14 whether to
   descope or remediate. Halt trigger 14 (HITRUST readiness rejection)
   fires if remediation is not feasible inside the calendar.
3. **HIPAA pre-conditions not met by the design partner** (BAA chain
   incomplete or stale). Likelihood low-medium, impact high (P1
   stalls until contracts close). Mitigation: P0.T6 confirms the
   BAA chain before
   P1 starts. Surface to user as a halt-trigger candidate (not
   currently in the AUTONOMOUS-PROMPT trigger set; M09 author
   recommends absorbing under trigger 14 or adding as a new explicit
   trigger).
4. **M06 P3 SBOM delays past M09 P3 start (week 19).** Likelihood low,
   impact medium (M09.P3 stalls). Mitigation: M06.P3 close is gating;
   tracked via cross-milestone wave coordination. Halt trigger 13
   fires only if the cumulative slip exceeds 25%.
5. **Design partner withdraws** (D09 binding scope evaporates).
   Likelihood low, impact high (M09 halts entirely; no substitute
   tenant per D15 without user authorization). Halt trigger 12
   (design-partner withdrawal) fires.
6. **All assessor quotes outside D07 band ($80-150k).** Likelihood
   low-medium, impact medium. Mitigation: three-firm RFP gives
   negotiating leverage; if all three quote out, surface to user as a
   budget-amendment decision (not currently in trigger set).
7. **HITRUST QA round (P5) returns the assessor's report for revision.**
   Likelihood medium, impact medium (1-4 week slip). Mitigation:
   Assessor-firm selection axis includes accelerator tooling (lower
   QA-rejection rates); P5 calendar carries 4 weeks of slack which
   absorbs typical revision cycles.
8. **M01 audit-handoff freeze breach** (someone edits frozen path
   during freeze window). Likelihood low, impact medium (M09 evidence
   corrupted). Mitigation: `m01-audit-handoff-guard` GitHub
   required-check + freeze-register enforcement; orchestrator
   auto-rejects.
9. **Certificate scope is interpreted differently by assessor than
   D09.** Likelihood low, impact high (mis-scoped certificate is
   unusable). Mitigation: P0.T8 scope statement signed by assessor
   before P1 starts. Halt trigger 14 candidate.

## Success criteria

- HITRUST i1 certificate received from the authorized assessor.
- Certificate scoped to v3.18 + the M01 design-partner deployment per D09.
- `compliance/hitrust/control-mapping.csv` complete: one row per i1
  control with status `evidenced` or `accepted-risk` (no `gap` rows
  at P5 close).
- `compliance/hitrust/build-evidence-pack.sh` is idempotent and
  produces a dated bundle that the assessor confirms is complete.
- Audit doc at `.planning/trajectory-3/audits/M09-vendor-evidence.md`
  closes with: assessor identity, certificate id, scope statement,
  issuance + expiration dates, finding log, remediation
  cross-references, M01 / M03 / M05 / M06 evidence-source pointers,
  vendor-quote variance from D07 band.
- Public certificate landing page at
  `docs/external-attestation/hitrust-i1/index.md` published.
- Renewal-cadence trigger filed (1-year validity; trajectory-4
  candidate).
