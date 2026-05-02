# M09 Audit: HITRUST i1 Assessment

**Trajectory:** trajectory-3
**Milestone:** M09
**Wave:** Wv (vendor calendar; runs parallel to all code waves)
**Status:** TEMPLATE (M09 milestone agent fills as phases close)
**Audit start:** week 1 (audit doc seed at P0.T2)
**Audit close:** weeks 32-36 (certificate issuance at P5.T3; final
audit-doc pass at P5.T4)

## 1. Audit scope

M09 procures HITRUST i1 assessment scoped to v3.18 + Opus deployment
(D02, D09). Release gate: QUALIFICATION; load-bearing artifact is the
HITRUST i1 certificate issued by an authorized external assessor.

Single-tenant, single-version, single-deployment-environment
certificate scope. Boundary diagram in
`compliance/hitrust/ssp.md` is the load-bearing scope artifact; the
assessor signs the boundary at P0.T8 before P1 starts (R10 mitigation).

Vendor budget posture: D07 band ~$80-150k. Calendar band: 12-36
weeks. Halt trigger 13 (vendor calendar slip > 25%) fires at week 45.

## 2. Assessor selection record

[TODO M09 milestone agent fill at P0:]

- HITRUST CSF active version at trajectory-3 start: <v11.x minor>
  (research signal: v11.2 = 182 controls; v11.3 = ~219 controls).
- HITRUST-authorized assessor shortlist (primary):
  - Coalfire
  - A-LIGN
  - Schellman
- HITRUST-authorized assessor shortlist (fallback):
  - BDO Digital
  - 360 Advanced
  - RSM US
- RFP send dates (P0.T4):
- RFP responses received:
  - <firm>: <quote, calendar fit, cross-credentialing notes>
  - <firm>: <quote, calendar fit, cross-credentialing notes>
- Selected assessor: <firm + lead engagement partner>
- Assessment value (per D07 budget posture $80-150k):
  - Quoted fixed fee:
  - Variance from D07 band (record per D07 consequences clause):
- Calendar fit:
  - Contracted P4 evaluation start week:
  - Contracted draft-report delivery week:
  - Contracted certificate-issuance week:
- Scope memo signed by assessor at P0.T8: <date>
- BAA chain confirmation (HIPAA pre-condition):
  - Provider <-> Opus: <status, contract reference>
  - Opus <-> Backbay: <status, contract reference>
  - Backbay-as-subcontractor BAA: <status>
- Out-of-scope decisions (recorded at P0.T5):
  - Mobile (M07) inclusion: explicit-no (default)
  - AWS Bedrock (M10) inclusion: explicit-no (default)

## 3. Gap-assessment + remediation log

[TODO M09 milestone agent fill phase-by-phase. P1 produces the gap
report (week 14); P2 closes Sev-1 / Sev-2; Sev-3 documented as
accepted risk.]

| Control ID | Family | Gap (P1) | Severity | Remediation (P2) | Phase | Cross-ref |
|------------|--------|----------|----------|------------------|-------|-----------|
| | | | | | | |

Total i1 controls in scope: <P0 count>
Pre-existing-evidence inheritance: <P1 count, target 40-60>
Net-new remediation: <P1 count, target 120-160>
Sev-1 closed in P2: <P2 count>
Sev-2 closed in P2: <P2 count>
Sev-3 accepted-risk: <P2 count + cross-ref to risk register>

## 4. Evidence package

[TODO M09 milestone agent fill at P3 close. The evidence pack is
produced by `compliance/hitrust/build-evidence-pack.sh` and uploaded
to the assessor's MyCSF portal at P3.T4.]

Cross-references to upstream artifacts (consumed read-only by M09):

- M01 operator runbook: `.planning/trajectory-3/audits/M01-opus-pilot.md`
- M01 audit-log export schema v1: `spec/audit-log/export-schema.v1.json`
  (frozen via `m01-m09-audit-handoff` from M01.P3.T1 through M01.P5.T5)
- M01 30-day BOP audit-log samples: <Opus tenant export bundle path>
- M03 reproducible-build hash + third-party rebuild evidence:
  `.planning/trajectory-3/audits/M03-ci-restoration.md`
- M03 SLSA-style provenance attestations: `.github/workflows/*`
- M04 mutation-gate + verdict-matrix attestation:
  `.planning/trajectory-3/audits/M04-mutation-gate.md`
- M05 threat-coverage closure:
  `docs/security/threat-coverage.md` and
  `spec/security/chio-threat-model.v1.json`
- M06 SBOM (CycloneDX): `supply-chain/**`
- M06 cargo-vet ledger: `supply-chain/audits.toml`
- M06 CVE-monitoring workflow output: `.github/workflows/cve-monitor.yml`
- M06 formal-method outputs (TLA+ / Apalache invariants): `formal/**`
- M08 pen-test report (complementary, not required for i1):
  `.planning/trajectory-3/audits/M08-vendor-evidence.md`

Evidence-pack bundles:

| Bundle date | Hash | Uploaded to MyCSF | Notes |
|-------------|------|-------------------|-------|
| | | | |

## 5. Assessor engagement log (P4)

[TODO M09 milestone agent fill across P4 weekly cadence.]

| Week | Activity | Assessor request | Response date | Cross-ref |
|------|----------|------------------|---------------|-----------|
| | | | | |

P4 draft report received: <date>
Findings dispute / clarification round: <Y/N + summary>

## 6. Closure attestations

[TODO M09 milestone agent fill at P5 close.]

- Certificate received: <id, issuance date, expiration date>
  (1-year validity; expiration = issuance + 12 months)
- Scope on certificate: v3.18 + Opus deployment per D09
- Assessor identity: <firm + lead engagement partner>
- HITRUST directory entry: <URL>
- Public landing page: `docs/external-attestation/hitrust-i1/index.md`
- Audit-doc cross-ref filed: <commit sha>
- Renewal trigger filed (1-year validity; trajectory-4 candidate):
  <ticket / cron entry reference; surfaces 60-90 days before
  expiration>
- Vendor-quote variance from D07 band (per D07 consequences clause):
  <amount + +/- band>
- Cross-credential opportunity recorded for trajectory-4 (firms
  offering bundled SOC 2 Type 1 / ISO 27001 alongside i1): <Y/N + notes>

## 7. Halt-trigger surfacing log

[TODO M09 milestone agent fill if any halt-trigger candidate fires.]

| Trigger | Phase | Date | Surfaced to user | Decision |
|---------|-------|------|------------------|----------|
| | | | | |

Halt-trigger candidates surfaced by RESEARCH (not currently in
AUTONOMOUS-PROMPT canonical eleven):

- HIPAA BAA chain incomplete (P0.T6). M09 author recommends
  absorbing under trigger 14 (HITRUST readiness rejection) or
  adding as explicit trigger.
- All assessor quotes outside D07 band (P0.T7). M09 author
  recommends user-surface for budget amendment.
