# M10 Audit: AWS Bedrock + MCP Conformance Listing

**Trajectory:** trajectory-3
**Milestone:** M10
**Wave:** W3 (weeks 22-30) plus W1/W2 pre-roll (week 14 APN onboarding)
**Status:** TEMPLATE
**Audit start:** <fill at P0 wave-opener merge>
**Audit close:** <fill at P5 final ticket merge>

## 1. Audit scope

M10 ships exactly one cloud marketplace listing (AWS Bedrock per D03)
plus one MCP-conformance entry. Release gates: PROTOCOL +
RELEASE_AUDIT (dual gate per verdict).

The audit doc records: (a) hard counts at P0; (b) APN tier and partner
SA identity; (c) listing-type and pricing-model lock; (d) MCP
conformance-suite pinned commit hash + pass count at submission and
publication; (e) AWS reviewer round-trip log; (f) closure attestation
with listing URL, approval date, MCP registry URL; (g) co-authored
APN blog status (draft + AWS SA review, not published); (h) D03
single-cloud confirmation; (i) cross-references to M02 partnership
note, M03 hosted CI provenance, M06 SBOM, M01 design-partner
customer-outcome freshness.

## 2. Hard counts at P0

[TODO M10 milestone agent fill at P0:]

- AWS marketplace listing artifacts required (target 6-7; AWS docs as
  of marketplace open day): <fill on P0.T1 merge>
  - [ ] README
  - [ ] CloudFormation Quick Launch template
  - [ ] Minimum IAM policy
  - [ ] Pricing model registration
  - [ ] Support contact + SLA
  - [ ] Data-flow + architecture diagrams
  - [ ] EULA + terms
- MCP conformance bench tests Chio must pass at the pinned commit
  hash: <fill on P0.T6 merge>
  - Suite repository URL: <fill>
  - Pinned commit hash: <fill>
  - Test count at pin: <fill>

## 3. APN tier and partner SA

[TODO M10 milestone agent fill at P0.T2 / P0.T3:]

- APN tier at week 14 registration: <Validated | Differentiated | not yet>
- Pre-roll registration receipt date (must be week 14, not week 22):
  <YYYY-MM-DD>
- Assigned AWS Bedrock Solutions Architect: <name>
- AWS SA reporting line: <manager + org>
- AWS Partner Manager: <name>

If APN tier < Validated at week 16, halt-trigger candidate per
AUTONOMOUS-PROMPT (RESEARCH risk #4).

## 4. Listing-type and pricing-model lock

[TODO M10 milestone agent fill at P0.T4 / P0.T5:]

- Listing type: SaaS contract within the AI Agents and Tools category
  (per RESEARCH recommendation; D03 binds scope to one cloud).
- Rationale snapshot: <fill, citing RESEARCH "AWS marketplace listing
  type choice">
- Pricing model: annual contract per tenant + metered receipt overage
  dimension (per RESEARCH recommendation).
- Base price anchor: <fill, vs M01 design-partner contract>
- Marketplace transaction fee schedule: <fill, 3-9% per AWS
  agreement>
- Finance + procurement sign-off date: <YYYY-MM-DD>

D03 confirmation: scope is AWS Bedrock + MCP only; no GCP or Azure
listings are scoped in this milestone.

## 5. Region scope

- Listed region: us-east-1 (matches `chio-bedrock-converse-adapter`
  pin).
- Multi-region (us-west-2, eu-west-1) deferral: trajectory-4
  candidate.
- Recorded in: `integrations/aws-bedrock/REGIONS.md` at P1.T4 merge.

## 6. MCP conformance pin

[TODO M10 milestone agent fill at P2.T3 + P5.T2:]

| Stage | Date | Suite hash | Pass count | Skip count |
|-------|------|------------|------------|------------|
| P0 pin | <YYYY-MM-DD> | <fill at P0.T6> | n/a | n/a |
| P2.T3 conformance run | | | | |
| P5.T2 publication confirm | | | | |

Closure clause text (per RESEARCH):
"Chio MCP server passes draft conformance suite vN at hash X; N tests
pass, M tests skipped. Suite is roadmap-status as of M10 close; no
single conformance badge exists."

## 7. Reviewer round-trip log

[TODO M10 milestone agent fill at P4.T1 / P4.T2:]

| Round-trip # | Date opened | Date resolved | Reviewer comment | Resolution | Effort (days) |
|--------------|-------------|---------------|------------------|------------|---------------|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| 4 | | | | | |

Halt rule per RESEARCH risk #1: round-trips > 4 OR slip past week 30
fires the m10-bedrock-listing-pivot freeze halt and escalates per
AUTONOMOUS-PROMPT.

## 8. Closure attestations

[TODO M10 milestone agent fill at P4.T4 / P5.T1 / P5.T3:]

- AWS marketplace listing URL: <fill>
- AWS approval date: <YYYY-MM-DD>
- AWS marketing review submission date (AI Agents and Tools category
  gate): <YYYY-MM-DD>
- AWS marketing review status (placement on category page; may slip
  past week 30): <fill>
- MCP conformance entry URL at registry.modelcontextprotocol.io:
  <fill>
- MCP namespace ownership validation method (GitHub or DNS): <fill>
- Co-authored APN blog draft URL: <fill>
- Co-authored APN blog AWS SA review status: <draft submitted | SA
  reviewed | publication scheduled | published>
- Co-author list: <Chio authors + AWS SA(s)>
- Single-cloud per D03 confirmed (no GCP / Azure listings):
  <YES | partial>

## 9. Post-listing smoke test

[TODO M10 milestone agent fill at P4.T5:]

- Customer-shape onboarding flow exercising:
  - [ ] CFN Quick Launch template deploys cleanly in a customer
    account
  - [ ] `GetEntitlements` returns a valid entitlement token
  - [ ] First receipt issued under base quota; no overage fired
  - [ ] Overage receipt fires `MeterUsage` callback
  - [ ] Customer-visible error envelope on a forced-failure path
    references the `urn:chio:error:*` registry

## 10. Cross-references

- M02 partnership note as the second of two distribution evidence
  forms: `.planning/trajectory-3/audits/M02-ai-lab.md`
- M03 hosted CI reproducible-build provenance for AWS security
  review: `.planning/trajectory-3/audits/M03-ci-restoration.md`
- M06 SBOM + cargo-vet artifacts for AWS security review:
  `.planning/trajectory-3/audits/M06-formal-supply-chain.md`
- M01 design-partner customer-outcome paragraph (D15 7-day freshness window):
  `.planning/trajectory-3/audits/M01-healthcare-pilot.md`
- M08 deferral note (vendor evidence closes ~week 36; co-authored
  blog cannot cite M08; trajectory-4 follow-up post owns the
  citation): `.planning/trajectory-3/audits/M08-vendor-evidence.md`

## 11. Active freezes during M10

- `m10-bedrock-listing-pivot` (P3-P4): path globs
  `integrations/aws-bedrock/**`, `integrations/mcp-adapter/**`,
  `sdks/python/packages/chio-bedrock/**`. Trust-boundary; opens at
  M10.P3.T1, closes at M10.P4.T5. Hot-fix bypass is the standard
  `hotfix/* + [trajectory-3]` lane.

## 12. Halt-trigger inventory for M10

- Halt 12 (design-partner withdrawal): voids M10.P5.T3 customer-
  outcome paragraph; M10.P5.T3 freezes.
- Halt 13 (vendor-side block): unassigned AWS SA past week 24, or
  Marketplace round-trip > 4, or slip past week 30.
- Halt rule on APN tier shortfall (RESEARCH risk #4): tier <
  Validated at week 16 escalates per AUTONOMOUS-PROMPT.
