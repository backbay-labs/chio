# Chio HITRUST i1 System Security Plan

**Trajectory:** trajectory-3
**Milestone:** M09
**Version:** P0 seed
**Date:** 2026-05-02
**Framework target:** HITRUST CSF v11.7 i1
**Control count target:** 182 controls in scope

## System overview

Chio is a secure, attested tool-access protocol for AI agent systems.
The runtime kernel mediates every tool call, validates capability
tokens, evaluates guards before data crosses trust boundaries, and
signs decisions into an append-only receipt log.

The M09 assessment scope is intentionally narrow: a single Chio v3.18
deployment for the M01 healthcare design-partner tenant. Other tenants,
other versions, mobile extensions, and AWS Bedrock listing surfaces are
outside this HITRUST i1 certification boundary unless a signed assessor
scope memo says otherwise.

## Assessment scope

- Assessment type: HITRUST Implemented, 1-year (i1) Validated
  Assessment and Certification.
- Framework version: HITRUST CSF v11.7.
- Control population: 182 HITRUST-curated i1 controls.
- Deployment boundary: single tenant, single version, single deployment
  environment.
- Product version: Chio v3.18 at trajectory-3 close.
- Evidence portal: MyCSF or assessor-designated equivalent.
- Assessor: to be selected during M09.P0.

## Boundary summary

In scope:

- Chio kernel binaries for v3.18.
- Capability authority, kernel admission, guard pipeline, tool-server
  mediation, and receipt-log export.
- M01 audit-log export schema v1 and 30-day design-partner audit-log
  samples after M01.P5 closes.
- M03 hosted CI restoration, reproducible-build, and provenance
  evidence.
- M05 threat-model and threat-coverage closure evidence.
- M06 SBOM, cargo-vet, CVE-monitoring, and formal-invariant evidence.

Out of scope:

- Non-design-partner tenants.
- Versions earlier or later than v3.18.
- M07 mobile patient-app extension unless later signed into scope.
- M10 AWS Bedrock and MCP marketplace listing surfaces.
- Backbay platform systems outside the Chio product boundary.
- ISO 42001, SOC 2 Type II, and HITRUST r2.

## Control family scaffold

The P0 control-mapping CSV carries one seed row per HITRUST control
family and will expand to one row per i1 control after the assessor
confirms the exact MyCSF object. Family ownership starts as follows:

| Family | Chio source of evidence | P0 posture |
|--------|-------------------------|------------|
| Information Security Management Program | trajectory-3 README, freezes, audit docs | Seeded |
| Access Control | capability algebra, revocation, sender constraints | Strong inherited evidence |
| Human Resources Security | Backbay HR policy corpus | Out-of-tree evidence needed |
| Risk Management | threat model, M05 coverage closure | Inherited plus P2 narratives |
| Security Policy | `spec/SECURITY.md`, `docs/security/` | Inherited |
| Organization of Information Security | OWNERS and trust-boundary review policy | Seeded |
| Compliance | this SSP, audit docs, certificate scope | Net-new |
| Asset Management | M06 SBOM and cargo-vet ledger | Pending M06 |
| Physical and Environmental Security | cloud-provider inheritance | Out-of-tree evidence needed |
| Communications and Operations Management | M01 runbook, CI, receipts pipeline | Pending M01/M03 |
| Systems Acquisition, Development, and Maintenance | M03 provenance, M06 supply chain, formal evidence | Pending M03/M06 |
| Incident Management | M09 incident runbook | Net-new P2 |
| Business Continuity Management | design-partner DR posture plus revocation oracle | Out-of-tree evidence needed |
| Privacy Practices | PHI handling, telemetry de-identification, receipt redaction | Net-new P2 |

## Evidence inheritance

M09 consumes these artifacts read-only:

- `.planning/trajectory-3/audits/M01-healthcare-pilot.md`
- `spec/audit-log/export-schema.v1.json`
- `.planning/trajectory-3/audits/M03-ci-restoration.md`
- `docs/security/threat-coverage.md`
- `spec/security/chio-threat-model.v1.json`
- `supply-chain/**`
- `formal/**`
- `.planning/trajectory-3/audits/M08-vendor-evidence.md`

## Fail-closed compliance rule

If an evidence row cannot be tied to a signed artifact, frozen audit
doc, assessor request, or explicit out-of-tree control owner, the row
remains `gap` and cannot be promoted to `ready`.

## Security review requested (M09 trust-boundary)

The SSP is a trust-boundary artifact because assessors will use it to
scope evidence. Any ambiguous scope, BAA, PHI, access-control, logging,
or inherited-evidence statement must be narrowed or marked as a gap.
