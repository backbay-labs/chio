# Milestone 10: AWS Bedrock + MCP Conformance Listing

## Lens

Distribution. M10 ships exactly one cloud marketplace listing (AWS
Bedrock per D03) plus one MCP-conformance entry. The lens is single
(distribution legibility). D03 binds scope to one cloud and one MCP
entry rather than the three-cloud spread originally considered. The
verdict-anchored question is whether a third party not in the project's
trust circle (an AWS Marketplace reviewer) and a community catalogue
(the Model Context Protocol registry) accept a Chio-shaped artifact at
their normal review thresholds. Anything tangential to that question is
out of scope by construction.

## Why this is on the trajectory

**Release-gate anchors:** PROTOCOL + RELEASE_AUDIT (dual gate per
verdict).

The trajectory-3 verdict names a cloud marketplace listing as one of
the two distribution evidence forms (the other is the M02 partnership
note). AWS Bedrock has the design-partner pull (Opus cluster runs on
AWS) and the MCP project's emerging conformance bench is the easiest
third-party evidence to procure inside the trajectory window. Three
clouds were rejected (D03 rationale); one credible AWS listing plus
one MCP entry is the M10 scope.

trajectory-2 shipped the substrate this milestone consumes:

- `crates/chio-bedrock-converse-adapter/` (trajectory-1 M07): batch +
  streaming Converse with `ProviderAdapter::lift/lower`, signed
  `iam_principals.toml`, 12 conformance fixtures, region us-east-1
  pinned. This is the Rust-side substrate; M10 wraps it for
  distribution rather than rewriting it.
- `crates/chio-mcp-edge/`, `crates/chio-hosted-mcp/`,
  `crates/chio-mcp-adapter/`, `crates/chio-openapi-mcp-bridge/`
  (trajectory-1 M07 / M08): MCP server + transport + adapter + bridge.
  M10 selects `chio-mcp-edge` as the listed-server crate (per RESEARCH
  P0 finding) and adds Streamable HTTP + OAuth 2.1 + PKCE per RFC9728.
- The trajectory-2 8-provider conformance matrix at
  `crates/chio-provider-conformance/`: provides the
  cross-provider verdict-equality oracle that the AWS listing's
  technical-review package cites.
- The trajectory-2 M01 `urn:chio:error:*` registry: customer-visible
  error envelopes inherit the registry rather than inventing M10-only
  shapes.
- The trajectory-2 receipt format and lineage spec: the Chio MCP
  server emits receipts in the registered format; the AWS Marketplace
  metering callback ties one billable event to one receipt.

What trajectory-3 milestones M10 hard-depends on:

- **M03 hosted CI** (week 15 close): AWS reviewers ask for build
  provenance on container images and CFN templates. M03 hosted CI
  artifacts plus M06 SBOM and reproducible-build hashes ARE the
  provenance evidence; M10 P3 starts week 27, so the dependency is
  satisfied with a 12-week margin.
- **M02 partnership note** (week 14 close): strengthens the AWS
  listing pitch (one of the two distribution evidence forms; the
  listing is the other). M02's eval-receipt format is consumed by the
  Chio MCP server's emitted receipts (M10 P2.T1).
- **M06 supply-chain v2** (week 22 close): SBOM + cargo-vet artifacts
  feed the AWS security review at P3. M06 closes the same week M10
  opens; the M06 audit doc is the input.
- **M01 Opus design-partner pilot** (week 30 close): P5.T3 customer-
  outcome paragraph in the co-authored APN blog requires Opus evidence
  inside the D15 7-day freshness window. Opus withdrawal fires halt
  trigger 12; M10 P5.T3 then freezes.

What is NOT a hard dependency:

- **M07 chio-kernel-mobile-mvp**: orthogonal; mobile substrate does
  not feed the Bedrock listing.
- **M08 independent crypto + protocol review** (week 36 close): closes
  past M10 P5 (week 30). The co-authored APN blog cannot cite M08;
  trajectory-4 follow-up post will. The audit doc records the deferral
  explicitly so the gap is legible.

## Prior-art reckoning

What trajectory-1 / trajectory-2 already shipped that overlaps M10:

- **`crates/chio-bedrock-converse-adapter/` (trajectory-1 M07)**:
  pinned `aws-sdk-bedrockruntime = 1.130.0`; region us-east-1 only;
  API marker `bedrock.converse.v1`. SDK bumps re-record fixtures.
  `ProviderAdapter::lift/lower` for batch Converse `toolUse` +
  `toolResult`; ConverseStream buffering with verdict at
  `contentBlockStart`. IAM principal disambiguation via signed
  `iam_principals.toml` + Sigstore bundle + STS `GetCallerIdentity`
  bootstrap. 12 conformance fixtures + cold-init budget evidence + 7-row
  error taxonomy with doctest enforcement. **Preserved.** M10 does
  NOT refactor the adapter; M10 wraps it for distribution.
- **`crates/chio-mcp-edge/`, `crates/chio-hosted-mcp/`,
  `crates/chio-mcp-adapter/`, `crates/chio-openapi-mcp-bridge/`
  (trajectory-1)**: present. **Preserved.** M10 extends
  `chio-mcp-edge` with Streamable HTTP transport and OAuth 2.1 + PKCE
  (RFC9728) and ships the MCP server as a registry-listed entry.
  `chio-mcp-adapter` (which wraps third-party servers) is NOT the M10
  surface. `chio-openapi-mcp-bridge` is a useful adjacency for AgentCore
  Gateway integration tests (P2.T5) but is not republished.
- **trajectory-2 M07 `arc mcp wrap` CLI subcommand**: shipped at
  `crates/chio-cli/src/cli/mcp.rs`. **Preserved.** M10 does not change
  the CLI; the CLI's wrap path is an operator-side surface, while the
  M10 listing is a Chio-hosted MCP server (the catalog entry IS the
  Chio-side surface, not a wrapper around third-party servers).
- **trajectory-2 M07 8-provider verdict-equality matrix** at
  `crates/chio-provider-conformance/`. **Preserved.** M10's listing
  cites the matrix as supporting evidence in the AWS technical review
  but does not extend it.
- **trajectory-2 M01 `urn:chio:error:*` registry** at
  `spec/errors/registry.yaml`. **Preserved.** Customer-visible error
  envelopes (the gap from RESEARCH section "Existing
  chio-bedrock-converse-adapter state") are constructed by mapping
  registry entries to AWS Marketplace SaaS API failure shapes; no new
  error namespace.

What is NOT preserved:

- The adapter today is a Rust crate consumed in-process. M10 changes
  the deployment shape: a SaaS-contract control plane fronts the
  adapter, exposes Marketplace SaaS APIs (`GetEntitlements`,
  `MeterUsage`, `BatchMeterUsage`), and tracks per-tenant state. The
  adapter source is unchanged; the *deployment* is new.
- The adapter is region us-east-1 only. M10 documents the region
  scope decision (P1.T4) and pins us-east-1 as the listed region for
  trajectory-3. us-west-2 / eu-west-1 surfaces are trajectory-4
  candidates.

This milestone is not a re-attack of any earlier work. It is a
distribution layer over the trajectory-1 Bedrock adapter and the
trajectory-1 MCP edge crate, plus calendar-bound external steps (APN
onboarding, marketplace review, MCP registry submission, co-authored
blog) that no prior trajectory has executed.

## Hard counts (measured 2026-04-30)

Reproduce with the commands in parentheses; update the date and
numbers on re-run.

- Bedrock-related Rust crates today (count and names):
  `crates/chio-bedrock-converse-adapter/` plus its conformance
  fixtures under `crates/chio-provider-conformance/fixtures/bedrock/`.
  One adapter crate; 12 fixtures (one per scenario in the trajectory-1
  M07 pack).
  (`ls crates/ | grep -E 'bedrock|aws'` and
  `ls crates/chio-provider-conformance/fixtures/bedrock/ | wc -l`)
- MCP-related Rust crates today (count and names):
  `crates/chio-mcp-adapter`, `crates/chio-mcp-edge`,
  `crates/chio-hosted-mcp`, `crates/chio-openapi-mcp-bridge`. Four
  crates.
  (`ls crates/ | grep mcp | wc -l`)
- Existing AWS marketplace integration directory: none. This milestone
  creates `integrations/aws-bedrock/` from empty.
  (`test -d integrations/aws-bedrock || echo "absent"`)
- Existing MCP adapter integration directory: none. This milestone
  creates `integrations/mcp-adapter/` from empty.
  (`test -d integrations/mcp-adapter || echo "absent"`)
- Existing Python SDK package for Bedrock: absent. This milestone
  creates `sdks/python/packages/chio-bedrock/` from empty (the
  OWNERS.toml owner glob is the source of truth).
  (`test -d sdks/python/packages/chio-bedrock || echo "absent"`)
- AWS marketplace listing artifacts required (typically 4-6 per
  RESEARCH; concrete count fills at P0.T1 from AWS docs as of
  marketplace open day): typically README, CloudFormation Quick Launch
  template, minimum IAM policy, pricing model registration, support
  contact + SLA, EULA + terms, data-flow diagram. **6 artifacts** is
  the target count; P0.T1 confirms.
  (audit-doc `## 2. Hard counts` row)
- MCP conformance bench tests Chio must pass: pinned at P0.T6 against
  a specific commit hash of the MCP conformance suite repository. As
  of 2026-04-30 the suite is roadmap-status (not v1.0); the audit doc
  records "passes draft suite vN at hash X, N tests pass" rather than
  an unconditional conformance claim per the RESEARCH closure rule.
  (audit-doc `## 2. Hard counts` row + `## 6. MCP conformance pin`)

## Workspace dependency state

Pinned by trajectory-1 / trajectory-2 and reused (do not re-pin):

- `aws-sdk-bedrockruntime = 1.130.0` (workspace pin from trajectory-1
  M07; the listed control plane consumes the same version the adapter
  uses).
- `serde`, `serde_json`, `tokio`, `thiserror`, `async-trait` workspace
  pins.
- `reqwest` workspace pin (used for the MCP Streamable HTTP transport).

Not pinned anywhere; this milestone adds them and pins versions on
M10 P0 open day:

- `aws-sdk-marketplaceentitlement` (Rust SDK; consumed by the
  Marketplace SaaS contract integration at P1.T3 for
  `GetEntitlements`).
- `aws-sdk-marketplacemetering` (Rust SDK; consumed at P1.T3 for
  `MeterUsage` + `BatchMeterUsage`).
- `aws-sdk-sts` (Rust SDK; cross-account assume-role for tenant
  onboarding; align with the trajectory-1 adapter's bootstrap path).
- (Python) `boto3` peer-dep range for `chio-bedrock` Python wrapper;
  pin a minor band, not a single patch.
- (Python) `mypy-boto3-bedrock-runtime`, `mypy-boto3-marketplace-*`
  for Python typing.
- (Tooling) AWS SAM CLI version recorded in `.tooling/sam.version` for
  CloudFormation Quick Launch template authoring (P3.T2).

External-vendor calendar lead times (no crate; documented here per
STYLE.md so the workspace state captures them):

- AWS APN tier qualification: 1-3 weeks, **must start week 14** (not
  week 22). Pre-roll ticket sits in the W2 M10-prep slot or a dedicated
  W1 M10-prep slot; recorded as M10.P0.T2 with `effort_days: 0.25` and
  `status: vendor_wait` until the registration receipt lands.
- AWS Marketplace seller registration: 1 week.
- AWS technical integration review: 3-5 weeks (full SaaS contract
  variant; the serverless variant takes 10-30 minutes but does not fit
  M10's per-tenant entitlement requirement).
- AWS security + architecture review: 2-4 weeks.
- AWS marketing review (AI Agents and Tools category gate): 1-2 weeks.
- Reviewer round-trips: 4-week buffer is the M10 baseline (2-3 round-
  trips typical per cold-reader-notes prediction 3).
- MCP registry submission: same-week round-trip; namespace ownership
  validated via GitHub or DNS challenge.
- Co-authored APN blog: 2-4 weeks of round-trip after draft
  submission; publication can slip into trajectory-4. Closure rule per
  RESEARCH: "draft submitted + AWS SA reviewed", not "published".

## Scope

### In

- `integrations/aws-bedrock/` package authored. Includes the
  CloudFormation Quick Launch template (deploys a Chio control-plane
  endpoint and wires Bedrock IAM via a customer-attached principal),
  a minimum-IAM policy doc, the data-flow diagram for AWS security
  review, and a customer-facing README.
- `integrations/mcp-adapter/` package authored. Hosts the
  registry-listed MCP server: extends `crates/chio-mcp-edge/` with
  Streamable HTTP + OAuth 2.1 + PKCE (RFC9728); emits Chio-format
  receipts on every `tools/call`; ships an integration test against
  Bedrock AgentCore Gateway as a consumer.
- `sdks/python/packages/chio-bedrock/` Python SDK authored. Wraps the
  Rust Bedrock adapter; surfaces `BedrockChioClient`,
  `issue_receipt`, `verify_receipt`, `metering_callback`. Pinned
  to `aws-sdk-bedrockruntime = 1.130.0` upstream and to the
  trajectory-2 receipt format.
- AWS Marketplace SaaS contract integration with custom dimensions:
  `GetEntitlements` at tenant onboarding; `MeterUsage` /
  `BatchMeterUsage` at overage; per-tenant receipts kept under a
  base-quota line; overage measured per-receipt.
- AWS marketplace listing artifacts submitted: README, CFN Quick
  Launch template, minimum IAM policy, pricing model registration,
  support contact + SLA, EULA + terms, data-flow + architecture
  diagrams. Six-to-seven artifacts; the exact count is pinned at
  P0.T1.
- AWS marketplace listing approved (review round-trips supported under
  a 4-week buffer; halt trigger if buffer exceeded).
- MCP project registry entry submitted at `registry.modelcontextprotocol.io`
  with namespace ownership validated; conformance pass-count recorded
  against a pinned suite commit hash.
- Co-authored APN blog draft + AWS SA review + AWS marketing review
  submission. Closure rule: "draft submitted + AWS SA reviewed", not
  "published". Publication slip into trajectory-4 is acceptable per
  RESEARCH.
- AWS APN partner-network onboarding kickoff at week 14 (pre-roll;
  recorded as M10.P0.T2 in W1/W2 schedule). APN tier confirm by week
  16; assigned AWS Solutions Architect named by P0.T3.

### Out (and why)

- GCP marketplace (D03 defers to trajectory-4; three half-listings
  beats one credible listing on observable distribution metrics is the
  rejected position, not the chosen one).
- Azure marketplace (D03 same rationale).
- Private-listing tier on AWS (public listing is the load-bearing
  evidence; private tier does not surface to AWS Marketplace search).
- Custom Bedrock model fine-tuning workflows (out of D03 scope; the
  listing wraps the existing converse adapter, not new training
  paths).
- Pure container product on Bedrock AgentCore Runtime (rejected per
  RESEARCH "AWS marketplace listing type choice"; container forces
  the customer to operate the workload, while SaaS preserves Chio's
  operational responsibility and matches the M01 Opus deployment).
- AWS marketing review final approval inside the trajectory-3 window
  (the AI Agents and Tools category may gate solution-page placement
  past week 30; closure attestation counts the listing as approved on
  AWS approval, not on category-page placement; placement is a
  trajectory-4 follow-up).
- Co-authored APN blog publication inside the trajectory-3 window
  (publication slips 2-4 weeks past technical submission per the Kong
  precedent in RESEARCH; closure is on draft-submitted + AWS SA
  reviewed, not published).
- M08 vendor evidence citation in the co-authored blog (M08 closes
  ~week 36, past M10 P5; trajectory-4 follow-up post cites M08).
- Custom HSM-backed entitlement signatures (Marketplace SaaS APIs
  already provide IAM-signed entitlement payloads; no second signature
  layer needed for the listing).

## Phases

### P0: weeks 22-23 - Audit doc + APN onboarding scoping

The pre-roll APN onboarding ticket (P0.T2) is calendar-anchored to
**week 14**, not week 22. P0 in W3 only opens once the registration
receipt is in hand; the W1 / W2 M10-prep slot owns the calendar work.

- M10.P0.T1: Open M10 audit doc; fill hard counts (artifacts required;
  MCP suite pinned-hash test count).
- M10.P0.T2: Pre-roll APN registration kickoff and tier confirm
  (vendor_wait status until receipt lands; calendar-anchored to week
  14).
- M10.P0.T3: Identify and name the assigned AWS Bedrock Solutions
  Architect; record reporting line.
- M10.P0.T4: Lock listing type (SaaS contract within the AI Agents
  and Tools category); record rationale per RESEARCH.
- M10.P0.T5: Lock pricing model (annual contract per tenant + metered
  receipt overage); record finance + procurement sign-off.
- M10.P0.T6: Pin MCP conformance-suite commit hash; record in audit
  doc.

### P1: weeks 23-25 - Bedrock integration package authored

- M10.P1.T1: Create `integrations/aws-bedrock/` directory; scaffold
  README, CFN Quick Launch template stub, IAM policy stub, data-flow
  diagram placeholder.
- M10.P1.T2: Author `sdks/python/packages/chio-bedrock/` Python SDK
  wrapping the Rust adapter. Surfaces: `BedrockChioClient`,
  `issue_receipt`, `verify_receipt`, `metering_callback`.
- M10.P1.T3: Marketplace SaaS contract integration. Wire
  `aws-sdk-marketplaceentitlement` (`GetEntitlements`) at tenant
  onboarding; wire `aws-sdk-marketplacemetering` (`MeterUsage`,
  `BatchMeterUsage`) at overage. Tenant onboarding test fixture
  asserts entitlement-token round-trip.
- M10.P1.T4: Pin region us-east-1 in the listing artifact set; record
  the multi-region decision deferral in `integrations/aws-bedrock/REGIONS.md`.
- M10.P1.T5: Author the data-flow diagram for AWS security review:
  customer VPC -> Chio control plane -> Bedrock; receipt at boundary;
  IAM principal trail. SVG + Markdown caption.

### P2: weeks 25-27 - MCP adapter authored against conformance bench

- M10.P2.T1: Create `integrations/mcp-adapter/` directory; extend
  `crates/chio-mcp-edge/` with Streamable HTTP transport. Verdict
  emitted on every `tools/call` consuming the trajectory-2 receipt
  format.
- M10.P2.T2: Implement OAuth 2.1 + PKCE per RFC9728 (Protected
  Resource Metadata) on the MCP server. Audit-log + policy-enforcement
  hooks per the MCP April 2026 roadmap.
- M10.P2.T3: Run the MCP conformance suite at the P0.T6-pinned commit
  hash. Record pass + skip + hash in the M10 audit doc; failure halts
  the phase.
- M10.P2.T4: Write the registry submission record (`server.json`):
  namespace, transport, OAuth scopes, capabilities, deps. Validate
  namespace ownership via GitHub challenge.
- M10.P2.T5: Integration test against AWS Bedrock AgentCore Gateway
  as a consumer. The MCP server exposes Chio-governed tools; AgentCore
  Gateway invokes them; round-trip asserts receipt emission.

### P3: weeks 27-28 - Marketplace listing artifact submission

Freeze m10-bedrock-listing-pivot opens at M10.P3.T1 and covers
P3-P4 per the freezes.yml rule.

- M10.P3.T1: Customer-facing README at
  `integrations/aws-bedrock/README.md` (the freeze opener).
- M10.P3.T2: Bundle the CloudFormation Quick Launch template with the
  listing; SAM-validated.
- M10.P3.T3: Minimum IAM policy doc (least-privilege; customer-attach
  shape) at `integrations/aws-bedrock/IAM_POLICY.md`.
- M10.P3.T4: Pricing model registration (per-tenant base + receipt
  overage dimension); upload to AWS Partner Central.
- M10.P3.T5: Support contact + SLA at
  `integrations/aws-bedrock/SUPPORT.md` + Partner Central support
  page.
- M10.P3.T6: Data-flow + architecture diagrams (P1.T5 outputs revised
  for AWS security-review intake).
- M10.P3.T7: EULA + terms; legal-reviewed.

### P4: weeks 28-30 - Reviewer round-trips + listing approval

- M10.P4.T1: Open the round-trip log table in the M10 audit doc.
- M10.P4.T2: Per round-trip, resolve reviewer comment + push patch
  (0.25-1 day each + reviewer SLA). Halt trigger if round-trips > 4
  or slip past week 30.
- M10.P4.T3: Marketing review submission (AI Agents and Tools
  category gate). The category-page placement is downstream and may
  slip into trajectory-4; the closure attestation does not require
  placement.
- M10.P4.T4: Closure attestation in the audit doc: listing URL +
  approval date. Freeze m10-bedrock-listing-pivot ends here.
- M10.P4.T5: Post-listing smoke test: customer-shape onboarding flow
  exercising the CFN template + entitlement + metering callback end
  to end. Asserts the published listing is functional, not just
  approved.

### P5: week 30 - MCP conformance entry published + co-authored partner blog

- M10.P5.T1: Submit MCP registry record at
  `registry.modelcontextprotocol.io`; capture URL in audit doc.
- M10.P5.T2: Confirm conformance-suite pass count at the as-of-
  publication commit hash; pin in the audit doc as
  "passes draft suite vN at hash X, N tests pass".
- M10.P5.T3: Co-authored APN blog draft + AWS SA review + AWS
  marketing review submission. 8-10 paragraphs, 1500-2000 words; one
  architecture diagram (Chio control plane + Bedrock + customer VPC,
  receipt at boundary); one config snippet (Chio policy YAML); one
  Bedrock Converse request snippet with Chio governance overlay; one
  Opus customer-outcome paragraph (gated on D15 7-day freshness
  window). Closure rule: "draft submitted + AWS SA reviewed", not
  "published". Co-authors: 1-2 AWS Bedrock SAs (the assigned partner
  SA from P0.T3) plus 1-2 Chio authors. Cross-link listing URL, MCP
  registry entry, M02 evaluation memo if M02 has closed by week 30.

## Cross-milestone interactions

Hard deps (other trajectory-3 milestones):

- **M03 hosted CI**. AWS reviewers ask for build provenance on
  containers and CFN templates. M03 hosted CI artifacts plus M06 SBOM
  and reproducible-build hashes ARE the provenance evidence. M03
  closes ~week 15; M10 P3 starts week 27. Encoded as `soft_deps`
  string sentence on M10.P3.T2 ("trajectory-3 M03.P5.T1 hosted-CI
  reproducible-build hash IS the provenance evidence consumed by AWS
  security review").
- **M02 partnership note**. Strengthens the listing pitch (one of two
  distribution evidence forms; the listing is the other). M02's
  eval-receipt format is consumed by the Chio MCP server's emitted
  receipts (M10.P2.T1). Encoded as `soft_deps` string sentence on
  M10.P2.T1 and M10.P5.T3.
- **M06 supply-chain v2**. SBOM + cargo-vet artifacts feed the AWS
  security review at P3. M06 closes ~week 22; M10 P3 starts week 27.
  Satisfied. Encoded as `soft_deps` string sentence on M10.P3.T6.
- **M01 Opus design-partner pilot**. P5.T3 outcome paragraph requires
  Opus evidence in D15 7-day window. Opus withdrawal fires halt
  trigger 12; M10.P5.T3 then freezes. Encoded as `soft_deps` string
  sentence on M10.P5.T3.

Freezes M10 owns:

- `m10-bedrock-listing-pivot` (P3-P4), per `freezes.yml`. Path globs:
  `integrations/aws-bedrock/**`, `integrations/mcp-adapter/**`,
  `sdks/python/packages/chio-bedrock/**`. Trust-boundary; opens at
  M10.P3.T1, closes at M10.P4.T5. Hot-fix bypass is the standard
  `hotfix/* + [trajectory-3]` lane.

Soft deps (string sentences; cross-trajectory or non-blocking):

- "trajectory-1 M07 (`crates/chio-bedrock-converse-adapter/`) is the
  Rust substrate; M10 wraps it for distribution and does not refactor
  the adapter source."
- "trajectory-1 M07 / M08 (`crates/chio-mcp-edge/` and the MCP
  edge / hosted / adapter / bridge crates) provide the MCP server
  surface; M10 P2.T1 extends `chio-mcp-edge` with Streamable HTTP +
  OAuth 2.1 + PKCE."
- "trajectory-2 M07.P4.T6 (cross-provider verdict equality, 8-provider
  matrix) is cited as supporting evidence in the AWS technical-review
  package without being modified."
- "trajectory-2 M01 `urn:chio:error:*` registry at
  `spec/errors/registry.yaml` is the source of customer-visible error
  envelopes; the Marketplace SaaS API failure shapes map to registry
  entries rather than introducing a new namespace."
- "trajectory-3 M08 vendor evidence (independent crypto + protocol
  review) closes ~week 36, past M10 P5; the co-authored APN blog
  cannot cite M08, and a trajectory-4 follow-up post owns the
  citation."

## Risks and mitigations

1. **AWS marketplace reviewer round-trips exceed 4-week buffer**
   (cold-reader-notes prediction 3; RESEARCH risk #1). Likelihood
   medium; impact: trajectory close slips. Mitigation: P3 schedules
   with explicit 4-week buffer; halt trigger fires if round-trips > 4
   or slip past week 30. M10.P4.T2 ticket spec carries the halt rule
   inline.

2. **MCP conformance suite changes mid-flight** (suite is
   roadmap-status as of April 2026, not v1.0). Likelihood medium;
   impact: conformance evidence weakens. Mitigation: pin commit hash
   at M10.P0.T6; record audit-doc clause "passes draft suite vN at
   hash X, N tests pass" rather than an unconditional conformance
   claim. The audit doc record is the load-bearing artifact, not a
   single badge.

3. **Bedrock pricing model rejected during Marketplace ops review**.
   Likelihood low; impact: repricing delays listing. Mitigation: pin
   pricing at M10.P0.T5 per the APN agreement; do not change during
   review. The CloudFormation Quick Launch template alongside the
   listing mitigates the AWS pushback on high-priced annual contracts
   without deployment-template support.

4. **APN tier prerequisite not met (Validated tier)**. Likelihood low;
   impact: adds 2-4 weeks to the pre-roll. Mitigation: M10.P0.T2
   confirms tier at week 14; if not met, escalate to halt trigger
   candidate per AUTONOMOUS-PROMPT.

5. **Co-author AWS SA unassigned**. Likelihood medium; impact: P5
   blog cannot ship inside the window. Mitigation: M10.P0.T3 names
   the SA; if unassigned by week 16, escalate to APN partner manager.
   The audit doc records the SA name + reporting line; an unassigned
   SA at week 24 fires halt trigger 13.

6. **OAuth 2.1 + PKCE flow rejected by AWS security review**.
   Likelihood low; impact: MCP transport must change. Mitigation:
   M10.P2.T2 implements the flow per RFC9728 verbatim, matching AWS
   expectations on agent-tool integrations as documented in the
   Bedrock AgentCore Gateway reference.

7. **Marketing review (AI Agents and Tools category) gates the
   listing past week 30**. Likelihood medium; impact: listing
   approves but is not surfaced on the category page until
   trajectory-4. Mitigation: closure attestation counts the listing
   as approved on AWS approval, not on category-page placement.
   Audit doc records the placement-deferral cleanly so the gap is
   legible.

8. **MCP registry namespace ownership challenge fails** (DNS or
   GitHub validation). Likelihood low; impact: submission rejected.
   Mitigation: M10.P2.T4 verifies namespace ownership before
   submission; the failure mode is a same-day fix.

9. **AWS introduces a new mandatory listing artifact mid-window**
   (precedent: 2025-10 AI Agents pricing-flex update). Likelihood
   low; impact: adds artifact; may add round-trip. Mitigation:
   track the AWS Marketplace what's-new feed weekly during P3-P4;
   the M10 audit doc records the inherited artifact set on the day
   P3 opens.

10. **Opus design-partner withdrawal voids P5.T3 customer-outcome
    paragraph**. Likelihood low; impact: blog draft must drop the
    Opus paragraph or freeze. Mitigation: D15 7-day freshness window
    governs the paragraph; halt trigger 12 fires on Opus withdrawal;
    M10.P5.T3 freezes per the AUTONOMOUS-PROMPT trigger.

## Success criteria

- AWS marketplace listing approved (the AWS approval IS the
  third-party evidence). Audit doc records listing URL + approval
  date.
- MCP project registry entry published at
  `registry.modelcontextprotocol.io` with conformance pass-count
  pinned at the suite commit hash. Audit doc records registry URL
  and pinned hash.
- `integrations/aws-bedrock/` directory present with the seven
  marketplace artifacts (README, CFN Quick Launch template, IAM
  policy doc, pricing model registration, support contact + SLA,
  data-flow + architecture diagrams, EULA + terms).
- `integrations/mcp-adapter/` directory present with the
  Streamable HTTP + OAuth 2.1 + PKCE MCP server, the registry
  submission record (`server.json`), and the AgentCore Gateway
  integration test passing.
- `sdks/python/packages/chio-bedrock/` Python SDK published locally;
  `pip install chio-bedrock` resolves; `pytest` passes; type stubs
  consume `mypy-boto3-bedrock-runtime`.
- AWS Marketplace SaaS contract integration green: tenant onboarding
  exercises `GetEntitlements`; overage exercises `MeterUsage` /
  `BatchMeterUsage`; the round-trip is asserted in
  `integrations/aws-bedrock/tests/`.
- Co-authored APN blog draft submitted + AWS SA reviewed (per
  RESEARCH closure rule). Publication slip into trajectory-4 is
  acceptable; trajectory-3 success does not require published.
- Audit doc at `.planning/trajectory-3/audits/M10-bedrock-mcp.md`
  records: (1) hard counts at P0; (2) reviewer round-trip log
  filled at P4; (3) listing URL + approval date; (4) MCP registry
  URL + pinned suite hash + pass count; (5) APN partner SA name +
  reporting line; (6) co-authored APN blog draft URL + AWS SA
  review status.
- Single cloud per D03 confirmed (no GCP / Azure listings shipped or
  scoped in this milestone). Audit-doc closure clause records the
  D03 confirmation explicitly.
