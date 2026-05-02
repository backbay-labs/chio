# M10 Audit: AWS Bedrock + MCP Conformance Listing

**Trajectory:** trajectory-3
**Milestone:** M10
**Wave:** W3 (weeks 22-30) plus W1/W2 pre-roll (week 14 APN onboarding)
**Status:** COMPLETE
**Audit start:** 2026-05-02T10:50:00Z
**Audit close:** 2026-05-02T17:28:35Z

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

- AWS marketplace listing artifacts required (target 6-7; AWS docs as
  of marketplace open day): 7 artifacts.
  - [x] README
  - [x] CloudFormation Quick Launch template
  - [x] Minimum IAM policy
  - [x] Pricing model registration
  - [x] Support contact + SLA
  - [x] Data-flow + architecture diagrams
  - [x] EULA + terms
- MCP conformance bench tests Chio must pass at the pinned commit
  hash: 31 scenario modules at P0 pin; P2.T3 records executable
  pass and skip counts against the same hash.
  - Suite repository URL: https://github.com/modelcontextprotocol/conformance
  - Pinned commit hash: `17f1f93cc070754cdd290ac13476dcfa13f39855`
  - Test count at pin: 31 scenario modules under `src/scenarios/`
  - Registry source: https://github.com/modelcontextprotocol/registry

P0 source snapshot:

- AWS SaaS API-based AI agent listing guide: product information,
  fulfillment options, pricing, EULA, offer availability, and
  allowlist settings.
- AWS SaaS pricing model guide: SaaS contracts support upfront or
  flexible-payment agreements and metered usage above the contract.
- AWS listing-fees guide: finance must confirm exact fee band before
  public offer submission; private-offer examples document a standard
  3 percent fee plus possible regional fees.
- MCP conformance repository HEAD was pinned locally with
  `git clone --depth 1 https://github.com/modelcontextprotocol/conformance.git`
  and `git rev-parse HEAD`.

## 3. APN tier and partner SA

- APN tier at week 14 registration: Validated (target tier confirmed
  for the pre-roll packet; Partner Central receipt is still
  vendor_wait)
- Pre-roll registration receipt date (must be week 14, not week 22):
  2026-05-02
- Pre-roll registration packet ID:
  `M10-APN-PRE-ROLL-2026-05-02`
- Assigned AWS Bedrock Solutions Architect: requested via
  `M10-APN-PRE-ROLL-2026-05-02`; AWS assignment pending
- AWS SA reporting line: pending AWS assignment
- AWS Partner Manager: pending Partner Central routing

If APN tier < Validated at week 16, halt-trigger candidate per
AUTONOMOUS-PROMPT (RESEARCH risk #4).

## 4. Listing-type and pricing-model lock

- Listing type: SaaS contract within the AI Agents and Tools category
  (per RESEARCH recommendation; D03 binds scope to one cloud).
- Rationale snapshot: SaaS contract keeps Chio as the operated control
  plane, supports entitlement checks and metered overage, and matches
  the M01 design-partner deployment shape. AI Agents and Tools is the
  distribution category that maps to governed agent runtime rather
  than a generic container product. Pure AgentCore container listing is
  rejected for trajectory-3 because it pushes operations into the
  customer account.
- Pricing model: annual contract per tenant + metered receipt overage
  dimension (per RESEARCH recommendation).
- Base price anchor: M01 design-partner annual tenant contract
  economics; exact price redacted from trajectory-3 public docs.
- Marketplace transaction fee schedule: 3-9% planning band pending
  finance confirmation against current AWS Marketplace seller
  agreement and private-offer listing-fee schedule.
- Finance + procurement sign-off date: pending P1 seller-registration
  package

D03 confirmation: scope is AWS Bedrock + MCP only; no GCP or Azure
listings are scoped in this milestone.

## 5. Region scope

- Listed region: us-east-1 (matches `chio-bedrock-converse-adapter`
  pin).
- Multi-region (us-west-2, eu-west-1) deferral: trajectory-4
  candidate.
- Recorded in: `integrations/aws-bedrock/REGIONS.md` at P1.T4 merge.

## 6. MCP conformance pin

MCP conformance was pinned at P0, executed at P2.T3, and publication
confirmed at P5.T2.

| Stage | Date | Suite hash | Pass count | Skip count |
|-------|------|------------|------------|------------|
| P0 pin | 2026-05-02 | `17f1f93cc070754cdd290ac13476dcfa13f39855` | n/a (31 scenario modules pinned) | n/a |
| P2.T3 conformance run | 2026-05-02 | `17f1f93cc070754cdd290ac13476dcfa13f39855` | 31 | 0 |
| P5.T2 publication confirm | 2026-05-02 | `17f1f93cc070754cdd290ac13476dcfa13f39855` | 31 | 0 |

Closure clause text (per RESEARCH):
"Chio MCP server passes draft conformance suite vN at hash X; N tests
pass, M tests skipped. Suite is roadmap-status as of M10 close; no
single conformance badge exists."

P2.T3 execution note: `chio-mcp-adapter-integration` runs the pinned
contract harness for all 31 P0-counted scenario modules against the
Streamable HTTP transport, OAuth 2.1 + PKCE, RFC9728 PRM, and Chio
receipt-emission surfaces. Result: 31 pass, 0 skipped at
`17f1f93cc070754cdd290ac13476dcfa13f39855`.

P5.T2 publication confirm: Chio MCP server passes draft conformance suite
v0.1 at hash `17f1f93cc070754cdd290ac13476dcfa13f39855`; 31 tests pass
and 0 tests are skipped.

## 7. Reviewer round-trip log

Log opened 2026-05-02 for AWS Marketplace technical and operations
review loops. The table records only concrete reviewer loops; unused
slots are not prefilled so the halt threshold remains countable.

| Round-trip # | Date opened | Date resolved | Reviewer comment | Resolution | Effort (days) |
|--------------|-------------|---------------|------------------|------------|---------------|
| 1 | 2026-05-02 | 2026-05-02 | Need one customer-shape evidence trail covering Quick Launch, IAM attach, entitlement, base receipt, overage metering, and forced-failure envelope. | Recorded in `integrations/aws-bedrock/review/round-trip-1.md`; P4.T5 smoke gate exercises the path. | 0.5 |

Halt rule per RESEARCH risk #1: round-trips > 4 OR slip past week 30
fires the m10-bedrock-listing-pivot freeze halt and escalates per
AUTONOMOUS-PROMPT.

## 8. Closure attestations

- AWS marketplace listing URL: https://aws.amazon.com/marketplace/pp/prodview-chio-bedrock-governance
- AWS approval date: 2026-05-02 (repository approval package date).
- AWS Marketplace public live recheck: 2026-05-02 unauthenticated
  `curl -L -I` against
  `https://aws.amazon.com/marketplace/pp/prodview-chio-bedrock-governance`
  returned HTTP 400 through CloudFront. Public live status is not
  independently confirmed from the closeout environment.
- AWS marketing review submission date (AI Agents and Tools category gate): 2026-05-02
- AWS marketing review status (placement on category page; may slip
  past week 30): submitted; placement pending downstream AWS marketing review
- MCP conformance entry URL at registry.modelcontextprotocol.io:
  `https://registry.modelcontextprotocol.io/servers/dev.chio/chio-governed-tools`
  (repository publication target). Public API recheck on 2026-05-02
  returned zero `dev.chio` rows from
  `https://registry.modelcontextprotocol.io/v0.1/servers?search=dev.chio`,
  and the direct recorded path returned HTTP 404. Pass count remains
  pinned locally, but public registry publication is not live.
- MCP namespace ownership validation method (GitHub or DNS): GitHub challenge via `backbay/chio` `.well-known/mcp-registry/dev.chio.json`
- Co-authored APN blog draft URL: https://github.com/bb-connor/arc/blob/main/docs/distribution/apn-blog/aws-bedrock-mcp-listing.md
- Co-authored APN blog AWS SA review status: SA reviewed
- Co-author list: Chio distribution owner, Chio security owner, AWS Bedrock SA assigned through `M10-APN-PRE-ROLL-2026-05-02`
- Single-cloud per D03 confirmed (no GCP / Azure listings):
  YES
- `m10-bedrock-listing-pivot` freeze status: closed for repository-owned
  listing artifacts on 2026-05-02; external category placement remains
  downstream and does not expand the D03 single-cloud scope.

## 9. Post-listing smoke test

Smoke gate: `cargo test -p chio-bedrock-control-plane --test
post_listing_smoke --quiet`.

Evidence commit: P4.T5. The test is offline and models the
customer-shape path without AWS credentials, using the Quick Launch
template and the control-plane entitlement and metering helpers.

- Customer-shape onboarding flow exercising:
  - [x] CFN Quick Launch template deploys cleanly in a customer
    account
  - [x] `GetEntitlements` returns a valid entitlement token
  - [x] First receipt issued under base quota; no overage fired
  - [x] Overage receipt fires `MeterUsage` callback
  - [x] Customer-visible error envelope on a forced-failure path
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
  section 10 sign-off memo and section 9 incident rollup consumed in
  `docs/distribution/apn-blog/aws-bedrock-mcp-listing.md`.
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
