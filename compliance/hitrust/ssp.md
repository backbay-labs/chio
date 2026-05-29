# Chio HITRUST i1 System Security Plan (Readiness Draft)

> **Status: internal self-assessment / readiness.** No external HITRUST
> assessment has been performed; no assessor is engaged; no certification
> is claimed. This System Security Plan is internal, self-authored
> readiness material describing intended scope and the security controls
> Chio actually implements today, alongside honest gaps.

**Framework target:** HITRUST CSF v11.7 i1
**Product version:** This assessed release
**Control count target:** the i1 control set (exact count is fixed by HITRUST when a MyCSF object is created)

## System overview

Chio is a secure, attested tool-access protocol for AI agent systems.
The runtime kernel mediates every tool call, validates capability
tokens, evaluates guards before data crosses trust boundaries, and
signs decisions into an append-only receipt log.

The intended assessment scope is deliberately narrow: a single Chio
deployment (this assessed release) for a single healthcare design-partner tenant. Other
tenants, other versions, mobile extensions, and AWS Bedrock listing
surfaces are outside this intended HITRUST i1 boundary.

## Assessment scope (intended)

- Target assessment type: HITRUST Implemented, 1-year (i1) Validated
  Assessment and Certification.
- Framework version: HITRUST CSF v11.7.
- Control population: the HITRUST-curated i1 control set. The exact count
  is determined by HITRUST when a MyCSF object is created; this document
  does not assert a specific count.
- Deployment boundary: single tenant, single version, single deployment
  environment.
- Product version: this assessed release.
- Evidence portal: MyCSF or assessor-designated equivalent (not yet
  created).
- Assessor: none selected or engaged.

## CSF version note

This readiness material targets CSF v11.7. The authoritative control set
and count are established only when a HITRUST-authorized assessor creates
a MyCSF object; until then this document treats the published i1 control
set as the target and maps controls to the evidence that exists today.

## Boundary summary

In scope:

- Chio kernel binaries (this assessed release).
- Capability authority, kernel admission, guard pipeline, tool-server
  mediation, and receipt-log export.
- Audit-log export schema v1 and design-partner audit-log samples.
- Hosted CI, reproducible-build, and provenance evidence.
- Threat-model and threat-coverage evidence.
- SBOM, cargo-vet, CVE-monitoring, and formal-invariant evidence.

Out of scope:

- Non-design-partner tenants.
- Other Chio releases (earlier or later than this assessed release).
- Mobile patient-app extension unless later added to scope.
- AWS Bedrock and MCP marketplace listing surfaces.
- Operator platform systems outside the Chio product boundary.
- ISO 42001, SOC 2 Type II, and HITRUST r2.

## Control family posture

The `control-mapping.csv` carries one row per HITRUST control family with
an honest posture flag. Each row maps to evidence that actually exists in
this repository, or is marked as a gap. Posture by family:

| Family | Chio source of evidence | Posture |
|--------|-------------------------|---------|
| Information Security Management Program | spec, security docs, repository governance | Partial; governance is documented in-repo, formal review cadence is a gap |
| Access Control | capability algebra, revocation, sender constraints (kernel crates, formal proofs) | Implemented and evidenced |
| Human Resources Security | none in repository | Gap; out-of-tree HR evidence required |
| Risk Management | threat model and coverage | Implemented and evidenced |
| Security Policy | `spec/SECURITY.md`, `docs/security/` | Implemented and evidenced |
| Organization of Information Security | `formal/OWNERS.md`, repository review conventions | Partial |
| Compliance | this SSP, scope boundary | Partial (self-assessment only) |
| Asset Management | SBOM and cargo-vet ledger (`supply-chain/`) | Implemented and evidenced |
| Physical and Environmental Security | none in repository | Gap; cloud-provider inheritance evidence required |
| Communications and Operations Management | audit-log schema, CI, receipts pipeline | Partial; production operational samples are a gap |
| Systems Acquisition, Development, and Maintenance | provenance, supply chain, formal evidence | Implemented and evidenced |
| Incident Management | `compliance/hitrust/ir-runbook.md` | Documented; first-cycle execution evidence is a gap |
| Business Continuity Management | none in repository | Gap; DR evidence required |
| Privacy Practices | PHI boundary, telemetry de-identification, receipt redaction (`crates/chio-log-redact/`) | Partial; policy documented, BAA and PHI handling is out-of-tree |

## Evidence inheritance

This readiness material relies on these in-repository artifacts (all
exist today):

- `spec/audit-log/export-schema.v1.json`
- `spec/PROTOCOL.md`, `spec/SECURITY.md`
- `docs/security/threat-coverage.md`
- `spec/security/chio-threat-model.v1.json`
- `supply-chain/` (cargo-vet `audits.toml`, `imports.lock`, SBOM/CVE workflows)
- `formal/` (TLA+, Apalache, Lean, Kani evidence; see `formal/MAPPING.md`)
- `.github/workflows/` (CI, reproducible build, SLSA, SBOM, CVE monitor)

## Fail-closed compliance rule

If a control row cannot be tied to evidence that actually exists in this
repository or to an explicit out-of-tree owner, the row remains a `gap`
and is not represented as satisfied.

## Honesty rule

This SSP states only what is true. Where a control is implemented in the
codebase, the mapping cites the real file. Where it is not, the row is an
honest gap. No external assessment, assessor engagement, walkthrough, or
certification is asserted anywhere in this package.
