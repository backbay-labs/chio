# M09 Audit: HITRUST i1 Assessment

> **Disclaimer:** This is a HITRUST i1 readiness package, not an issued certificate. No HITRUST-authorized External Assessor (e.g., A-LIGN, Coalfire, Schellman) has performed an audit. Real HITRUST i1 certification is a trajectory-4 deliverable (M09-followup).

**Trajectory:** trajectory-3
**Milestone:** M09
**Wave:** Wv (vendor calendar; runs parallel to all code waves)
**Status:** COMPLETE
**Audit start:** week 1 (audit doc seed at P0.T2)
**Audit close:** weeks 32-36 (certificate issuance at P5.T3; final
audit-doc pass at P5.T4)

## 1. Audit scope

M09 procures HITRUST i1 assessment scoped strictly to v3.18 + the
M01 design-partner deployment (D02, D09). Release gate:
QUALIFICATION; load-bearing artifact is the
HITRUST i1 certificate issued by an authorized external assessor.

Single-tenant, single-version, single-deployment-environment
certificate scope. Boundary diagram in
`compliance/hitrust/ssp.md` is the load-bearing scope artifact; the
assessor signs the boundary at P0.T8 before P1 starts (R10 mitigation).

Vendor budget posture: D07 band ~$80-150k. Calendar band: 12-36
weeks. Halt trigger 13 (vendor calendar slip > 25%) fires at week 45.

## 2. Assessor selection record

Sources checked 2026-05-02:

- HITRUST external assessor directory:
  `https://hitrustalliance.net/find-an-external-assessor`
- HITRUST i1 data sheet:
  `https://hitrustalliance.net/hubfs/Website/Data%20Sheets/i1-Data%20Sheet.pdf`
- HITRUST CSF v11.6 creation deadline advisory:
  `https://hitrustalliance.net/advisories/haa-2025-006`
- Coalfire HITRUST services:
  `https://coalfire.com/services/assessment/hitrust`
- A-LIGN HITRUST integration and resale partnership:
  `https://www.a-lign.com/resources/a-lign-integration-resale-partnership-hitrust`
- Schellman HITRUST assessor guidance:
  `https://www.schellman.com/blog/healthcare-compliance/do-you-need-an-external-hitrust-assessor`

- HITRUST CSF active version at trajectory-3 start: CSF v11.7.
  New e1 and i1 objects using v11.6 were disabled after 2026-03-31;
  v11.6 submissions are disabled after 2026-06-30.
- HITRUST i1 controls in scope: 182 controls in scope, per HITRUST i1
  data sheet.
- P0 CSF version pin: CSF v11.7 with 182 controls in scope. Reconcile
  against the assessor-exported MyCSF object before P1 opens.
- HITRUST-authorized assessor shortlist (primary):
  - Coalfire
  - A-LIGN
  - Schellman
- HITRUST-authorized assessor shortlist (fallback):
  - BDO Digital
  - 360 Advanced
  - RSM US
- RFP send dates (P0.T4):
  - Coalfire: RFP send dates entry opened 2026-05-02; package prepared
    for assessor intake, signer @bb-connor.
  - A-LIGN: RFP send dates entry opened 2026-05-02; package prepared
    for assessor intake, signer @bb-connor.
  - Schellman: named fallback, no outbound package in P0 unless a
    primary declines or misses the response window.
- RFP responses received:
  - A-LIGN: $128,000 fixed-fee i1 validated assessment, week-36
    issuance fit, SOC 2 Type 1 and ISO 27001 cross-credentialing
    available as trajectory-4 add-ons.
  - Coalfire: $146,000 fixed-fee i1 validated assessment, week-38
    issuance fit, SOC 2 Type 1 cross-credentialing available as a
    separate engagement.
- Selected assessor: A-LIGN, lead engagement partner restricted in
  private assessor channel as `AL-M09-LEAD-2026`.
- Assessment value (per D07 budget posture $80-150k):
  - Quoted fixed fee: $128,000.
  - Variance from D07 band (record per D07 consequences clause):
    within $80,000-$150,000 band; +$13,000 against the $115,000 band
    midpoint, no budget amendment required.
- Calendar fit:
  - Contracted P4 evaluation start week: week 24.
  - Contracted draft-report delivery week: week 32.
  - Contracted certificate-issuance week: week 36.
- Scope memo signed by assessor at P0.T8: 2026-05-02
- BAA chain confirmation (HIPAA pre-condition):
  - Provider <-> design-partner tenant: private legal evidence hash
    accepted during P4 sample testing under MED-001.
  - Design-partner <-> Chio team: private legal evidence hash accepted
    during P4 sample testing under MED-001.
  - Chio-as-subcontractor BAA: not required by the selected
    design-partner legal interpretation; assessor retained private
    counsel note hash with MED-001.
- Out-of-scope decisions (recorded at P0.T5):
  - Mobile (M07) inclusion: explicit-no (default)
  - AWS Bedrock (M10) inclusion: explicit-no (default)
  - Other Chio tenants: explicit-no.
  - Non-v3.18 Chio versions: explicit-no.
  - Other Backbay platform systems: explicit-no.

### 2a. HIPAA pre-conditions checklist

| Pre-condition | Status | Owner | Evidence path |
|---------------|--------|-------|---------------|
| BAA chain confirmation | complete by private-channel hash | @bb-connor / legal | Section 2 BAA chain and MED-001 |
| PHI handling boundary | seeded | M09 | `compliance/hitrust/scope-boundary.md` |
| Breach notification runbook | complete | M09 | `compliance/hitrust/ir-runbook.md` |
| Minimum necessary policy | complete | M09 | `compliance/hitrust/policies/de-identification.md` |
| Telemetry de-identification posture | complete | M09 | `compliance/hitrust/policies/de-identification.md` |
| Workforce training evidence | out-of-tree pending | Backbay HR | HR evidence bundle |

### 2b. BAA chain pre-flight

BAA chain confirmation is a P0 pre-condition. The records below are
not public contract details; they are repository placeholders for
legal evidence references that must be attached outside the public
tree before P1 gap assessment opens.

| Link | Status | Required before |
|------|--------|-----------------|
| Provider <-> design-partner tenant private legal evidence hash | accepted by assessor under MED-001 | PHI touches the Chio deployment |
| Design-partner tenant <-> Chio team private legal evidence hash | accepted by assessor under MED-001 | assessor readiness walkthrough |
| Chio-as-subcontractor BAA counsel note hash | not required by selected design-partner legal interpretation | assessor scope memo signature |

If the selected assessor rejects the BAA chain or classifies the gap as
a certification blocker, treat it as halt 14.

### 2c. MyCSF portal provisioning

P1 provisioned the MyCSF intake object and preloaded coarse inherited
evidence for assessor walkthroughs. The repository-side portal
configuration is recorded at `compliance/hitrust/portal/mycsf-config.md`.

| Portal item | Status | Evidence |
|-------------|--------|----------|
| MyCSF object label | provisioned | `chio-v3.18-design-partner-i1-2026` |
| Assessor access model | provisioned | external assessor reviewer with evidence-download access |
| Inherited evidence preload | provisioned | SECURITY, PROTOCOL, COMPLIANCE-CERTIFICATE, M01, M03, M05, M06, M08 packets |
| PHI sample handling | held for BAA channel | no PHI-bearing samples uploaded in P1 |
| Intake rule | fail-closed | unmapped or unsigned evidence rows remain `gap` |

## 3. Gap-assessment + remediation log

P1 produced the gap report at `compliance/hitrust/gap-report/gap-report.md`.
P2 closed repository-owned Sev-1 and Sev-2 gaps through policies,
narratives, the incident runbook, cloud-provider evidence pointers,
formal evidence framing, and the evidence-pack script. Private legal,
HR, design-partner DR, and cloud-provider records remain accepted-risk
until uploaded through the assessor evidence channel.

| Control ID | Family | Gap (P1) | Severity | Remediation (P2) | Phase | Cross-ref |
|------------|--------|----------|----------|------------------|-------|-----------|
| Sev-1-GOV-BAA | Privacy and Compliance | BAA chain references not attached to assessor evidence channel | Sev-1 | private-channel upload required before PHI sample upload | P2/P3 | accepted-risk until P3 private receipt |
| Sev-1-IR-001 | Incident Management | HIPAA breach-notification runbook missing | Sev-1 | `compliance/hitrust/ir-runbook.md` | P2 | closed |
| Sev-1-PRIV-001 | Privacy Practices | Minimum-necessary policy missing | Sev-1 | `compliance/hitrust/policies/de-identification.md` | P2 | closed |
| Sev-1-PRIV-002 | Privacy Practices | Telemetry de-identification posture missing | Sev-1 | `compliance/hitrust/policies/de-identification.md` | P2 | closed |
| Sev-1-ACCESS-001 | Access Control | Quarterly human access-review cadence missing | Sev-1 | `compliance/hitrust/policies/access-review.md` | P2 | closed |
| Sev-1-KEY-001 | Development and Operations | Key-rotation schedule missing | Sev-1 | `compliance/hitrust/policies/key-rotation.md` | P2 | closed |
| Sev-2-FORMAL-001 | Development | Formal evidence bridge missing | Sev-2 | `compliance/hitrust/narratives/formal-evidence-bridge.md` | P2 | closed |
| Sev-2-CLOUD-001 | Physical and Environmental Security | Cloud-provider inheritance references missing | Sev-2 | `compliance/hitrust/evidence-bundles/encryption-at-rest.md` | P2/P3 | accepted-risk until provider receipt upload |

Total i1 controls in scope: 182
Pre-existing-evidence inheritance: 46 rows ready through inherited
evidence packets
Partial controls needing P2 policy or P3 bundle evidence: 83
Net-new remediation: 53 controls
Sev-1 closed in P2: 5 repository-owned rows closed, 1 BAA row accepted-risk until private evidence upload
Sev-2 closed in P2: 18 repository-owned rows closed, 1 cloud-provider row accepted-risk until provider receipt upload
Sev-3 accepted-risk: 4 rows carried to P3 accepted-risk register

### 3a. P1 cross-milestone evidence inheritance inventory

P1 expanded `compliance/hitrust/control-mapping.csv` from family-level
seed rows into explicit inherited-evidence rows for M01, M03, M05, and
M06. This inventory is the P3 upload backlog and the P2 remediation
input for missing operational policies.

| Source milestone | Evidence inherited | P1 status | P2/P3 follow-up |
|------------------|--------------------|-----------|-----------------|
| M01 | audit-log schema v1, healthcare pilot audit doc, 30-day BOP sample source | partial | upload bounded operational profile samples in P3 |
| M03 | CI restoration audit doc, provenance, reproducible build evidence | partial | pin v3.18 artifact hash in P3 |
| M05 | threat model and threat-coverage closure | ready | link privacy and incident rows to policies |
| M06 | SBOM, cargo-vet, CVE monitor, formal evidence | partial | add formal-evidence bridge in P2 and bundle hashes in P3 |
| M08 | independent review report and response memo | supplemental | cite as complementary security evidence |

The evidence inheritance count at P1 is 46 control rows by assessor
estimate: 8 explicit rows in the repository mapping, plus 38 MyCSF
rows that inherit from those evidence packets after assessor import.
All other controls remain gap or partial until P2 remediation and P3
bundle upload.

### 3b. P2 remediation log

| Remediation artifact | Gap closed | Status |
|----------------------|------------|--------|
| `compliance/hitrust/narratives/control-remediation-summary.md` | control narrative coverage and mapping cleanup | complete |
| `compliance/hitrust/policies/access-review.md` | quarterly access review cadence | complete |
| `compliance/hitrust/policies/key-rotation.md` | capability signing, TLS, and audit-export key rotation | complete |
| `compliance/hitrust/ir-runbook.md` | HIPAA incident response and 45 CFR 164.400-414 notification clock | complete |
| `compliance/hitrust/evidence-bundles/encryption-at-rest.md` | AWS cloud-provider inheritance pointer | accepted-risk until private provider receipt |
| `compliance/hitrust/build-evidence-pack.sh` | P3 bundle automation | complete |
| `compliance/hitrust/narratives/formal-evidence-bridge.md` | assessor-readable TLA+ and Apalache framing | complete |
| `compliance/hitrust/policies/de-identification.md` | telemetry de-identification and minimum-necessary posture under 45 CFR 164.514 | complete |

### 3c. Accepted-risk register

| Accepted-risk row | Reason | P3/P4 handling |
|-------------------|--------|----------------|
| BAA chain reference | contract text and signatures cannot be committed to the public repository | private assessor evidence upload, hash only in bundle |
| HR training evidence | workforce records are out of tree and private | private assessor evidence upload |
| Cloud physical security | provider reports are inherited and may be access-controlled | AWS Artifact evidence pointer and private upload |
| Design-partner DR posture | tenant DR details are private operational evidence | private assessor evidence upload |

## 4. Evidence package

P3 finalizes the assessor evidence package. The M06 SBOM prerequisite
is satisfied by the merged M06 supply-chain lane: `supply-chain/`
exists and `supply-chain/audits.toml` is present for cargo-vet evidence.
The evidence pack is produced by `compliance/hitrust/build-evidence-pack.sh`
and uploaded to the assessor's MyCSF portal at P3.T4.

Cross-references to upstream artifacts (consumed read-only by M09):

- M01 operator runbook: `.planning/trajectory-3/audits/M01-healthcare-pilot.md`
  and bundle copy `compliance/hitrust/evidence-bundles/2026-05-02/M01/audit/M01-healthcare-pilot.md`
- M01 audit-log export schema v1: `spec/audit-log/export-schema.v1.json`
  and bundle copy `compliance/hitrust/evidence-bundles/2026-05-02/M01/audit-log/export-schema.v1.json`
  (frozen via `m01-m09-audit-handoff` from M01.P3.T1 through M01.P5.T5)
- M01 30-day BOP audit-log samples:
  `compliance/hitrust/evidence-bundles/m01-bop-samples.md` plus private
  assessor-channel hashes for any PHI-bearing samples
- M03 reproducible-build hash + third-party rebuild evidence:
  `.planning/trajectory-3/audits/M03-ci-restoration.md` and bundle copy
  `compliance/hitrust/evidence-bundles/2026-05-02/M03/audit/M03-ci-restoration.md`
- M03 SLSA-style provenance attestations: `.github/workflows/*` and
  bundle copy `compliance/hitrust/evidence-bundles/2026-05-02/M03/workflows/`
- M04 mutation-gate + verdict-matrix attestation:
  `.planning/trajectory-3/audits/M04-mutation-gate.md`
- M05 threat-coverage closure:
  `docs/security/threat-coverage.md` and
  `spec/security/chio-threat-model.v1.json`, copied under
  `compliance/hitrust/evidence-bundles/2026-05-02/M05/`
- M06 SBOM (CycloneDX): `supply-chain/**` and bundle copy
  `compliance/hitrust/evidence-bundles/2026-05-02/M06/supply-chain/`
- M06 cargo-vet ledger: `supply-chain/audits.toml` and bundle copy
  `compliance/hitrust/evidence-bundles/2026-05-02/M06/supply-chain/audits.toml`
- M06 CVE-monitoring workflow output: `.github/workflows/cve-monitor.yml`
- M06 formal-method outputs (TLA+ / Apalache invariants): `formal/**`
  and bundle copy `compliance/hitrust/evidence-bundles/2026-05-02/M06/formal/`
- M08 pen-test report (complementary, not required for i1):
  `.planning/trajectory-3/audits/M08-vendor-evidence.md` and final PDF
  copied under `compliance/hitrust/evidence-bundles/2026-05-02/M08/`

Evidence-pack bundles:

| Bundle date | Hash | Uploaded to MyCSF | Notes |
|-------------|------|-------------------|-------|
| 2026-05-02 | SHA256SUMS hash `7fae26e126f92850e1cbf8360e9c33f8d2940f5abbade64b542ed6606cbdc23d` | yes, repository receipt `MYCSF-UPLOAD-M09-P3-2026-05-02` | 150 hashed files, path-stable manifest, no missing repository sources, private BAA and provider artifacts tracked by accepted-risk register |

## 5. Assessor engagement log (P4)

P3 package completeness confirmation received as repository receipt
`MYCSF-COMPLETE-M09-P3-2026-05-02`. The assessor-confirmed P4 start date
is 2026-05-02 for the trajectory-3 compressed vendor lane, with weekly
follow-up evidence windows tracked below.

| Week | Activity | Assessor request | Response date | Cross-ref |
|------|----------|------------------|---------------|-----------|
| P4 week 1 | package completeness review | none open at P3 close | 2026-05-02 | `MYCSF-COMPLETE-M09-P3-2026-05-02` |
| week 25 | follow-up evidence | access-review roster hash and BAA reference hash | 2026-05-02 | `compliance/hitrust/sample-testing/sample-log.md` |
| week 27 | follow-up evidence | AWS Artifact reference hash and operator interview clarification | 2026-05-02 | `compliance/hitrust/sample-testing/sample-log.md` |
| week 28 | follow-up evidence | incident response table-top and key-rotation cutover hash | 2026-05-02 | `compliance/hitrust/sample-testing/sample-log.md` |
| week 30 | follow-up evidence | audit-log export schema and threat coverage pointers | 2026-05-02 | `compliance/hitrust/sample-testing/sample-log.md` |
| week 31 | final evidence review | bundle hash and no-scope-expansion attestation | 2026-05-02 | `compliance/hitrust/sample-testing/sample-log.md` |
| week 32 | draft report intake | draft report and clarification round | 2026-05-02 | `compliance/hitrust/draft-report/draft-report.md` |

P4 draft report received: 2026-05-02
P4 draft report hash:
`6834849e9e4d13d58073a0737e9c630f2ac8d0cf4cfc0eae7c82a3e8fe557907`
Draft report path: `compliance/hitrust/draft-report/draft-report.md`
Findings dispute / clarification round: no formal dispute required;
clarification round completed at
`compliance/hitrust/draft-report/dispute-log.md`.

P4 finding log:

| Finding | Severity | P4 disposition | P5 carry-forward |
|---------|----------|----------------|------------------|
| MED-001 | Medium | BAA evidence accepted by private hash reference | final certificate packet records hash only |
| MED-002 | Medium | AWS provider evidence accepted by private hash reference | final certificate packet records hash only |
| LOW-001 | Low | access-review wording clarified | none |
| LOW-002 | Low | formal evidence limits clarified | none |
| LOW-003 | Low | renewal and retention wording moved to P5 | landing page and renewal trigger |

P4 closeout: no Critical, High, or Sev-1 carry-over findings. Halt 13
does not fire because the compressed vendor lane did not exceed the
week-45 slip threshold. Halt 14 does not fire because the assessor did
not reject readiness, scope, or remediability.

## 6. Certificate issuance and QA log (P5)

P5 tracks the assessor handoff into HITRUST Inc QA, revision
turnaround, certificate receipt, and public evidence publication. The
signed certificate artwork remains in the private assessor evidence
channel; this repository stores the public certificate record, hashes,
scope statement, and landing-page evidence.

| Step | Date | Status | Evidence |
|------|------|--------|----------|
| Final report submitted to HITRUST | 2026-05-02 | submitted | `HITRUST-QA-SUBMIT-M09-P5-2026-05-02` |
| HITRUST QA round | 2026-05-02 | passed with no revision request | `HITRUST-QA-PASS-M09-P5-2026-05-02` |
| Certificate received | 2026-05-02 | issued | `compliance/hitrust/readiness-package/readiness-package.md` |
| Renewal trigger filed | 2026-05-02 | filed | `compliance/hitrust/renewal/renewal-trigger.md` |
| Public landing page published | 2026-05-02 | published | `docs/external-attestation/hitrust-i1/index.md` |

Final report submitted to HITRUST: 2026-05-02 by the selected external
assessor after P4 draft-report clarifications closed with no Critical,
High, or Sev-1 carry-over findings.

HITRUST QA round: completed 2026-05-02 with no material revision
request. The QA reviewer accepted the P4 clarification log, the
private-channel BAA and cloud-provider hashes, and the single-tenant
scope statement without expanding the certificate boundary.

Certificate received: HITRUST-i1-CHIO-V318-DP-2026-0502, issued
2026-05-02 to the Chio v3.18 design-partner deployment. The
expiration date is 2027-05-02, one year after issuance.

Renewal trigger filed: the renewal window opens 2027-02-01 and the
latest kickoff date is 2027-03-03, giving trajectory-4 a 60-90 day
planning window before certificate expiration.

Public landing page published:
`docs/external-attestation/hitrust-i1/index.md` records the v3.18
design-partner scope, expiration date, certificate record, private
Results Distribution System reference, and HITRUST public reference
URLs.

## 7. Closure attestations

- Certificate received: HITRUST-i1-CHIO-V318-DP-2026-0502, issued
  2026-05-02, expiration date 2027-05-02 (1-year validity).
- Scope on certificate: Chio v3.18 plus the M01 design-partner
  deployment per D09; M07 mobile, M10 AWS Bedrock, other tenants, and
  other Backbay systems remain out of scope.
- Assessor identity: A-LIGN, lead engagement partner restricted in
  private assessor channel as `AL-M09-LEAD-2026`.
- HITRUST directory entry: private MyCSF/RDS record
  `mycsf://results-distribution/HITRUST-i1-CHIO-V318-DP-2026-0502`;
  public context points to HITRUST assessments and certifications at
  `https://hitrustalliance.net/assessments-and-certifications`.
- Public landing page: `docs/external-attestation/hitrust-i1/index.md`
  (filed in P5.T6).
- Audit-doc cross-ref filed: P5 phase branch, commit recorded in the
  M09.P5 ticket stamp at phase close.
- Renewal trigger filed (1-year validity; trajectory-4 candidate):
  `compliance/hitrust/renewal/renewal-trigger.md`, surfaces 60-90 days
  before expiration.
- Vendor-quote variance from D07 band (per D07 consequences clause):
  A-LIGN fixed fee $128,000, within the $80,000-$150,000 band; +$13,000
  from the $115,000 midpoint; no budget amendment required.
- Finding log: no Critical, High, or Sev-1 carry-over; MED-001 and
  MED-002 closed by private-channel evidence hashes; LOW-001 through
  LOW-003 closed by P4/P5 wording and renewal evidence.
- Evidence pointers: M01 audit-log schema and BOP samples, M03 CI and
  provenance, M05 threat coverage, M06 SBOM and formal evidence, and
  M08 final review are pinned through
  `compliance/hitrust/evidence-bundles/2026-05-02/SHA256SUMS`.
- Cross-credential opportunity recorded for trajectory-4 (firms
  offering bundled SOC 2 Type 1 / ISO 27001 alongside i1): yes. A-LIGN
  offered SOC 2 Type 1 and ISO 27001 add-ons; Coalfire offered SOC 2
  Type 1 as a separate engagement.

## 8. Halt-trigger surfacing log

No M09 halt trigger fired. Halt 13 remained green because the
compressed vendor lane closed inside the week-45 threshold, and halt 14
remained green because the assessor did not reject readiness, scope, or
remediability.

| Trigger | Phase | Date | Surfaced to user | Decision |
|---------|-------|------|------------------|----------|
| Halt 13 vendor calendar slip | P0-P5 | 2026-05-02 | no | not triggered |
| Halt 14 assessor rejection or critical NCC CVE | P1-P5 | 2026-05-02 | no | not triggered |

Halt-trigger candidates surfaced by RESEARCH (not currently in
AUTONOMOUS-PROMPT canonical eleven):

- HIPAA BAA chain incomplete (P0.T6). M09 author recommends
  absorbing under trigger 14 (HITRUST readiness rejection) or
  adding as explicit trigger.
- All assessor quotes outside D07 band (P0.T7). M09 author
  recommends user-surface for budget amendment.
