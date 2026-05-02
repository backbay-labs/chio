# Chio M09 RFP: HITRUST i1 Readiness and Assessment

**Trajectory:** trajectory-3
**Milestone:** M09
**Date:** 2026-05-02
**Framework target:** HITRUST CSF v11.7 i1
**Control population:** 182 controls in scope
**Assessment scope:** Chio v3.18 plus M01 healthcare design-partner deployment
**Primary RFP recipients:** Coalfire, A-LIGN
**Named fallback:** Schellman

## Executive summary

Chio is seeking a HITRUST-authorized external assessor for an
Implemented, 1-year HITRUST i1 readiness and validated-assessment
engagement. The requested scope is the single-tenant Chio v3.18
healthcare design-partner deployment, including capability-mediated
access control, audit-log export, receipt evidence, threat coverage,
build provenance, SBOM, and operational runbook evidence.

## Scope

The assessment should cover:

- Chio v3.18 only.
- One healthcare design-partner tenant.
- One production deployment environment.
- Audit-log export schema v1 and 30-day evidence samples after M01.P5.
- M03 CI, reproducible-build, and provenance evidence.
- M05 threat-model and threat-coverage closure evidence.
- M06 SBOM, cargo-vet, CVE-monitoring, and formal-invariant evidence.
- HIPAA-aligned BAA chain and PHI handling boundaries.

The assessment should not cover:

- Other tenants or deployments.
- Other Chio versions.
- Mobile M07 surfaces.
- AWS Bedrock or MCP marketplace M10 surfaces.
- ISO 42001, SOC 2 Type II, HITRUST r2, or unrelated Backbay platform
  systems.

## Requested services

- P0 scoping review and signed scope memo.
- HITRUST i1 readiness assessment.
- MyCSF portal setup guidance and evidence-object creation.
- Gap assessment against the active i1 control set.
- Remediation advisory limited to the signed scope.
- Validated assessment execution.
- HITRUST QA support through certificate issuance.
- Final certificate evidence package and scope statement.

## Calendar requested

| Window | Target |
|--------|--------|
| P0 | RFP response, quote, scope memo, and contract by week 7 |
| P1 | Gap assessment during weeks 8-14 |
| P2 | Remediation support during weeks 14-19 |
| P3 | Evidence package finalization during weeks 19-24 |
| P4 | Assessor evaluation during weeks 24-32 |
| P5 | HITRUST QA and certificate issuance during weeks 32-36 |

Please return any known delivery risk if the assessor calendar would
push final issuance beyond week 36 or beyond the halt-13 threshold at
week 45.

## Budget posture

D07 budget posture for M09 is $80k-$150k. Please return:

- Fixed fee for readiness and validated assessment.
- Separate HITRUST portal, report, or submission fees.
- Any gap-remediation advisory retainer.
- Any bridge, rapid-recertification, or renewal assumptions.
- Optional cross-credentialing notes for SOC 2 Type I, ISO 27001, or
  related trajectory-4 opportunities, clearly separated from this RFP.

## Reply format

Please respond with:

- Confirmation that your firm is a HITRUST-authorized external assessor.
- Proposed engagement lead and delivery team.
- Earliest kickoff date.
- MyCSF object creation path and evidence export expectations.
- Scope memo redline.
- Quote and fee assumptions.
- BAA or confidentiality requirements.
- HITRUST QA support model.
- Expected certificate issuance path and artifact list.

## BAA chain pre-flight

The design-partner deployment may involve PHI. Before P1 opens, Chio
must confirm:

- Provider to design-partner tenant BAA.
- Design-partner tenant to Chio or Backbay BAA.
- Chio-as-subcontractor posture if the design partner treats Chio as a
  subcontractor.

If any BAA path is missing, the engagement should classify it as a P0
scope blocker rather than a P1 remediation item.

## Security review requested (M09 trust-boundary)

The requested assessment binds external compliance evidence to a
trust-boundary deployment. Any ambiguous scope, inherited-evidence,
PHI, access-control, audit-log, or BAA statement should be marked as
unverified until backed by signed evidence.
