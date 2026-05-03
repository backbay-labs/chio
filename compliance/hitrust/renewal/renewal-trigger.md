# HITRUST i1 Renewal Trigger

**Certificate id:** HITRUST-i1-CHIO-V318-DP-2026-0502
**Issuance date:** 2026-05-02
**Expiration date:** 2027-05-02
**Renewal window opens:** 2027-02-01
**Latest renewal kickoff:** 2027-03-03
**Owner:** trajectory-4 compliance planning
**Status:** filed

## Trigger Rule

Open the HITRUST i1 renewal planning item 90 days before expiration
and require an owner by 60 days before expiration. The renewal scope
must start from the same fail-closed boundary used by M09: Chio v3.18
plus the M01 design-partner deployment only, unless trajectory-4
explicitly amends the scope.

## Required Inputs

- Current readiness-package record:
  `compliance/hitrust/readiness-package/readiness-package.md`
- M09 audit doc:
  `.planning/trajectory-3/audits/M09-vendor-evidence.md`
- Evidence bundle manifest:
  `compliance/hitrust/evidence-bundles/2026-05-02/SHA256SUMS`
- Private-channel BAA, HR, provider, and design-partner evidence
  references from the M09 assessor channel.

## Trajectory-4 Candidate

Evaluate whether to pair the i1 renewal with SOC 2 Type 1 or ISO 27001
based on the A-LIGN and Coalfire cross-credentialing notes recorded in
the M09 audit doc. Do not widen the public release gate until an
external assessor signs the amended scope.
