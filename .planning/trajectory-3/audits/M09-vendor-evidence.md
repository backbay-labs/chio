# M09 Audit: HITRUST i1 Readiness Package

> **Disclaimer:** This is a HITRUST i1 readiness package, not an issued
> certificate. No HITRUST-authorized External Assessor has performed an
> audit. Real HITRUST i1 certification is a trajectory-4 deliverable
> (`M09-followup`).

**Trajectory:** trajectory-3
**Milestone:** M09
**Wave:** Wv (readiness lane)
**Status:** readiness-draft
**Readiness record date:** 2026-05-02

## 1. Readiness Scope

M09 records a repository-side readiness package for a future HITRUST i1
validated assessment scoped to Chio v3.18 plus the M01 healthcare
design-partner deployment. The load-bearing trajectory-3 artifact is
`compliance/hitrust/readiness-package/readiness-package.md`; it is not a
certificate, assessor report, MyCSF export, or HITRUST Results
Distribution System record.

Mobile M07, AWS Bedrock M10, other tenants, non-v3.18 versions, and
other Backbay platform systems remain out of scope for this readiness
record.

## 2. Assessor Planning Record

Sources checked 2026-05-02 for future trajectory-4 planning:

| Source | URL |
|--------|-----|
| HITRUST external assessor directory | `https://hitrustalliance.net/find-an-external-assessor` |
| HITRUST i1 data sheet | `https://hitrustalliance.net/hubfs/Website/Data%20Sheets/i1-Data%20Sheet.pdf` |
| HITRUST CSF version advisory | `https://hitrustalliance.net/advisories/haa-2025-006` |
| Coalfire HITRUST services | `https://coalfire.com/services/assessment/hitrust` |
| A-LIGN HITRUST integration reference | `https://www.a-lign.com/resources/a-lign-integration-resale-partnership-hitrust` |
| Schellman HITRUST assessor guidance | `https://www.schellman.com/blog/healthcare-compliance/do-you-need-an-external-hitrust-assessor` |

No assessor has been selected, contracted, granted portal access, or
authorized to issue a report for trajectory-3. References to assessor
firms are planning inputs only. The target assessment type for future
work is HITRUST Implemented, 1-year (i1) Validated Assessment against
the active CSF version at engagement start.

## 3. Readiness Gap Log

The repository-owned readiness work completed in trajectory-3 covers
policy, control-mapping, incident-response, key-rotation,
de-identification, formal-evidence framing, and evidence-pack assembly.
Private legal, HR, design-partner DR, cloud-provider, and PHI-bearing
records are not committed to this public repository and remain future
assessor-channel inputs.

| Readiness row | Status | Evidence |
|---------------|--------|----------|
| Incident-response narrative | ready | `compliance/hitrust/ir-runbook.md` |
| Minimum-necessary and telemetry de-identification | ready | `compliance/hitrust/policies/de-identification.md` |
| Quarterly access review cadence | ready | `compliance/hitrust/policies/access-review.md` |
| Key-rotation schedule | ready | `compliance/hitrust/policies/key-rotation.md` |
| Formal evidence bridge | ready | `compliance/hitrust/narratives/formal-evidence-bridge.md` |
| Cloud-provider inheritance | pointer only | `compliance/hitrust/evidence-bundles/2026-05-02/M09/encryption-at-rest.md` |
| BAA chain evidence | private-channel future input | hash-only placeholder, no public contract text |
| HR training evidence | private-channel future input | out of repository |
| Design-partner DR posture | private-channel future input | out of repository |

The readiness package must fail closed if it is cited as an issued
certificate, external assessor finding, final report, or MyCSF/RDS
record.

## 4. Evidence Package

The evidence pack is assembled by
`compliance/hitrust/build-evidence-pack.sh` and summarized by
`compliance/hitrust/evidence-bundles/2026-05-02/SHA256SUMS`. The bundle
contains repository artifacts only. It does not prove assessor upload or
HITRUST QA acceptance.

Key trajectory-3 repository inputs:

| Input | Evidence |
|-------|----------|
| M01 healthcare pilot audit | `.planning/trajectory-3/audits/M01-healthcare-pilot.md` |
| M03 CI restoration | `.planning/trajectory-3/audits/M03-ci-restoration.md` |
| M05 threat coverage | `docs/security/threat-coverage.md`, `spec/security/chio-threat-model.v1.json` |
| M06 SBOM and formal evidence | `supply-chain/**`, `formal/**` |
| M08 internal readiness draft | `.planning/trajectory-3/audits/M08-vendor-evidence.md` |
| M09 public readiness package | `compliance/hitrust/readiness-package/readiness-package.md` |

The M09 readiness package content is pinned in `releases.toml` with
`package_sha256`:

`a41918aacd4ae06a94a3b05fdb1718cece732a68c42bab7c2802cd58e20bef90`

## 5. Release Evidence Use

The authoritative release row is
`[release_audit] activation_evidence.m09_hitrust_i1_readiness_package`.
The row is a readiness-package pointer only. It must not be used as a
certificate id, external-assessor report, HITRUST QA receipt, or renewal
clock.

`scripts/check-release-inputs.sh` enforces the readiness-only posture by
checking the package hash and rejecting stale issued-certificate wording
in the M09 release evidence files.

## 6. Trajectory-4 Exit Criteria

Before this readiness package can be replaced by real HITRUST i1
certification evidence, trajectory-4 must record:

| Requirement | Required evidence |
|-------------|-------------------|
| External assessor engagement | signed SOW or engagement letter |
| MyCSF/RDS object | non-secret object reference and export hash |
| Assessment boundary | assessor-approved scope statement |
| Private evidence handling | hash-only receipt for BAA, HR, provider, and PHI-bearing artifacts |
| HITRUST QA result | official QA or certification outcome |
| Public artifact | public landing page updated from readiness-only to issued-certificate posture |

Until those artifacts exist, all M09 claims remain readiness-only.
