# Chio HITRUST i1 RFP Template (Draft, Not Sent)

> **Status: forward-looking draft.** This is a request-for-proposal
> TEMPLATE for engaging a HITRUST-authorized external assessor in the
> future. It has NOT been sent to any assessor. No assessor has been
> selected or engaged. The recipient list below is a set of candidate
> firms, not a record of any outreach.

**Framework target:** HITRUST CSF v11.7 i1
**Intended assessment scope:** Chio single healthcare design-partner deployment (this assessed release)
**Candidate assessor firms:** any HITRUST-authorized external assessor (for example Coalfire, A-LIGN, or Schellman)

## Executive summary

If and when Chio engages an assessor, this template would request a
HITRUST-authorized external assessor for an Implemented, 1-year (i1)
readiness and validated-assessment engagement. The requested scope is
the single-tenant Chio healthcare design-partner deployment,
including capability-mediated access control, audit-log export, receipt
evidence, threat coverage, build provenance, SBOM, and operational
runbook evidence.

## Scope

The assessment would cover:

- This assessed Chio release only.
- One healthcare design-partner tenant.
- One production deployment environment.
- Audit-log export schema v1 and post-deployment evidence samples.
- CI, reproducible-build, and provenance evidence.
- Threat-model and threat-coverage evidence.
- SBOM, cargo-vet, CVE-monitoring, and formal-invariant evidence.
- HIPAA-aligned BAA chain and PHI handling boundaries.

The assessment would not cover:

- Other tenants or deployments.
- Other Chio versions.
- Mobile patient-app surfaces.
- AWS Bedrock or MCP marketplace surfaces.
- ISO 42001, SOC 2 Type II, HITRUST r2, or unrelated operator systems.

## Requested services

- Scoping review and signed scope memo.
- HITRUST i1 readiness assessment.
- MyCSF portal setup guidance and evidence-object creation.
- Gap assessment against the active i1 control set.
- Remediation advisory limited to the signed scope.
- Validated assessment execution.
- HITRUST QA support through certificate issuance.
- Final certificate evidence package and scope statement.

## Reply format

A responding firm would be asked to provide:

- Confirmation that the firm is a HITRUST-authorized external assessor.
- Proposed engagement lead and delivery team.
- Earliest kickoff date.
- MyCSF object creation path and evidence export expectations.
- Scope-memo redline.
- Quote and fee assumptions, including any separate HITRUST portal,
  report, or submission fees.
- BAA or confidentiality requirements.
- HITRUST QA support model.
- Expected certificate issuance path and artifact list.

## BAA chain pre-flight

The design-partner deployment may involve PHI. Before any assessment
opens, Chio would confirm:

- Provider to design-partner tenant BAA.
- Design-partner tenant to Chio BAA.
- Chio-as-subcontractor posture if the design partner treats Chio as a
  subcontractor.

If any BAA path is missing, it would be treated as a scope blocker
rather than a remediation item.

## Trust-boundary note

A future engagement would bind external compliance evidence to a
trust-boundary deployment. Any ambiguous scope, inherited-evidence, PHI,
access-control, audit-log, or BAA statement should be treated as
unverified until backed by real evidence.
