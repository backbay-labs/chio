# M10 Research: AWS Bedrock + MCP Conformance Listing

**Trajectory:** trajectory-3
**Milestone:** M10 (Wave W3, weeks 22-30)
**Research date:** 2026-04-30
**Phase:** RESEARCH (precedes IMPLEMENT)
**Decisions in force:** D03 (Bedrock + MCP only), D07 (~$10-20k vendor budget for AWS marketplace fees)

This document maps the external surface M10 must navigate so the
IMPLEMENT phase can populate `tickets/M10/P{0..5}.yml` with concrete
tickets. Every "MUST CONFIRM" and open question is for IMPLEMENT to
resolve.

## AWS Bedrock partner program calendar

The realist estimate of 12-16 weeks for AWS marketplace onboarding is
consistent with published guidance, but the distribution is bimodal:
SaaS-contract listings cluster at 4-8 weeks once integration is clean;
AI-Agents-and-Tools category listings (the newer surface) cluster at
8-16 weeks because the review path is still shaping and reviewers are
pickier on agent provenance, container hygiene, and OAuth flows.

Stage breakdown:

1. APN registration + tier qualification (1-3 weeks). The 2026
   Partner Central "validation agent" auto-processes docs and provides
   real-time feedback.
2. AWS Marketplace seller registration (1 week). Bank, tax, listing
   account.
3. Technical integration (3-5 weeks for full SaaS contract; 10-30
   minutes for the serverless variant). M10 needs the full variant
   for custom entitlement + receipt issuance per tenant.
4. Security + architecture review (2-4 weeks). Data-flow diagrams,
   IAM policies, API responses; for AI agents also container
   provenance, model-card disclosures, OAuth flow.
5. Listing draft + marketplace ops review (1-2 weeks). Pricing,
   support, EULA, README, screenshots.
6. Marketing review (1-2 weeks). AI Agents and Tools category gates
   solution-page placement on marketing review.
7. Reviewer round-trips (2-3 typical per cold-reader-notes prediction
   3; 4-week buffer is the M10 baseline).

**Calendar implication:** M10 runs weeks 22-30 (8 weeks). That window
only suffices if APN onboarding starts at week 14, not week 22.

**MUST CONFIRM at P0:** APN tier status. If not Validated, add 2-4
weeks to the pre-roll.

## Existing chio-bedrock-converse-adapter state

`crates/chio-bedrock-converse-adapter` is a Rust adapter, not a
listing. Today:

- Pinned `aws-sdk-bedrockruntime = 1.130.0`; region us-east-1 only;
  API marker `bedrock.converse.v1`. SDK bumps re-record fixtures.
- `ProviderAdapter::lift/lower` for batch Converse toolUse +
  toolResult; ConverseStream buffering with verdict at
  `contentBlockStart`.
- IAM principal disambiguation: signed `iam_principals.toml` +
  Sigstore bundle + STS `GetCallerIdentity` bootstrap.
- 12 conformance fixtures + cold-init budget evidence; cross-provider
  byte-equal verdict demo (OpenAI, Anthropic, Bedrock).
- 7-row error taxonomy with doctest enforcement.

**Gap between adapter and marketplace listing:**

| Adapter (have) | Listing (need) |
|----------------|----------------|
| Rust crate, in-process | Customer-deployable artifact (container or SaaS endpoint) |
| Cross-provider verdict equality | Bedrock-as-target with Chio governance overlay |
| Mock transport in tests | Live entitlement via Marketplace SaaS APIs (`GetEntitlements`, `MeterUsage`, `BatchMeterUsage`) |
| `iam_principals.toml` signed | Customer-side AWS onboarding via one-click CFN |
| us-east-1 only | Region-scope decision documented |
| Internal error doctest | Customer-visible envelopes, status page, runbook |

The adapter is the substrate; M10 wraps it for distribution.
IMPLEMENT MUST pick one of:
- Option A: SaaS contract product (Chio runs control plane; Bedrock is
  upstream; customer pays Chio per receipt or per tenant).
- Option B: AI-Agents-and-Tools container on Bedrock AgentCore Runtime
  (Chio ships a docker image running in customer VPC).

Trajectory-3 cannot afford both. See "AWS marketplace listing type
choice" below.

## MCP registry conformance landscape

As of April 2026 MCP has no single "conformance certification" badge.
Conformance is layered across three artifacts:

1. **MCP spec + roadmap.** Roadmap explicitly lists "conformance test
   suites" as future work (automated verification that clients,
   servers, SDKs correctly implement the spec). Suite is in flight;
   treating it as stable for 8 weeks carries minor schedule risk.
2. **Official MCP Registry** (`registry.modelcontextprotocol.io`).
   Open catalog launched Sept 2025; community-owned; contributors
   include Anthropic, GitHub, PulseMCP, Microsoft. Submission
   validates namespace ownership (GitHub or DNS challenge).
   Conformance-pass field is on the roadmap, not yet present.
3. **Microsoft `modelcontextprotocol/servers` + PulseMCP** curation.
   Reputational catalogues, not gates. Substantive conformance
   evidence right now: OAuth 2.1 + PKCE for remote multi-user servers
   (RFC9728 PRM mandatory); Streamable HTTP transport for remote;
   audit logging + policy enforcement per 2026 roadmap.

**M10 closure rule:** audit doc captures (1) registry URL of the Chio
MCP server, and (2) pass-count vs pinned conformance-suite commit
hash. If suite is still draft at week 30: "passes draft suite vN at
hash X, N tests pass."

**MUST CONFIRM at P0:** which crate hosts the listed server. Most
likely `chio-mcp-edge` (exposes Chio-governed tools as MCP server)
with `chio-hosted-mcp` as the Streamable HTTP transport.
`chio-mcp-adapter` wraps third-party servers (not the M10 surface).
`chio-openapi-mcp-bridge` is useful for AgentCore Gateway integration.
P2.T1 pins exact crate + registry namespace.

## AWS marketplace listing type choice

AWS Marketplace currently surfaces five listing types relevant to M10:

| Type | Fit for Chio | Why |
|------|--------------|-----|
| AMI product | poor | Chio is a control plane, not a VM image |
| Container product (ECS/EKS) | medium | Works, but loses the SaaS narrative |
| SaaS contract | high | Customer signs an annual contract with custom dimensions; Chio bills per tenant or per receipt |
| SaaS subscription | medium | Hourly metering; lower predictability for procurement |
| AI Agents and Tools (category overlay on container or SaaS) | high | Newer category (announced 2025-07; pricing flexibility update 2025-10); aligns with Bedrock AgentCore Runtime + Gateway |

**Recommended posture:** ship as SaaS contract within the AI Agents
and Tools category. Rationale:

- AI Agents and Tools maps to Chio's product (governed agent runtime),
  not generic SaaS.
- SaaS contract gives procurement legibility (Opus contract is annual).
- The newer category gets AWS MDF co-investment ($25k 2026 + existing
  $50k for qualifying partners), creating the natural co-authored blog
  opportunity (P5).
- Even as SaaS, the listing can declare AgentCore Gateway
  compatibility by exposing the MCP server with two-legged OAuth (no
  OpenAPI spec required per AWS docs).

**Rejected:** pure container on AgentCore Runtime. Forces customer to
operate the container; SaaS preserves Chio's operational responsibility
and matches the M01 Opus deployment.

## Pricing + billing model proposal

AWS Marketplace AI Agents and Tools (October 2025 update) supports
both contract-based and usage-based pricing with custom dimensions.
Three credible Chio pricing axes:

1. **Per receipt issued** (most aligned with the protocol; receipts
   are the load-bearing artifact). Fine-grained, but procurement
   teams find per-receipt unit economics hard to forecast.
2. **Per tenant per month** (procurement-friendly, predictable).
   Aligns with how design-partner contracts already work.
3. **Per API call** (closest to Bedrock's own pricing model; familiar
   to AWS buyers). Risk: ties Chio's revenue to API volume rather
   than governance value.

**Recommendation:** annual contract priced per tenant + metered
overage dimension for receipts above a per-tenant quota. Matches SaaS
contract listing type, gives procurement a stable line item, preserves
receipt as audit unit. Anchor base price to the M01 Opus contract; D07
$10-20k covers marketplace registration + transaction fees, not
price-setting.

**MUST CONFIRM at P0:** marketplace transaction fee schedule (3-9% of
contract value depending on type + tier). Caps margin.

**Risk:** AWS pushes back on high-priced annual contracts without
clear deployment-template support. Mitigation: CloudFormation Quick
Launch template alongside the listing.

## Co-authored technical-doc shape

AWS APN blog precedent for AI gateway + Bedrock co-authored posts:

- "Unlock Advanced AI Control with Kong AI Gateway And Amazon Bedrock"
  (APN blog) co-authored by Mohamed Salah and Amir Tarek (Senior
  Solutions Architects, AWS), Anuj Sharma (Principal SA, AWS), and
  Michel Zwarts (Partner Sales Technical Director, Kong). Shape: 8-12
  paragraphs, one architecture diagram, two code or config snippets,
  one customer-outcome paragraph.
- "Building an AI gateway to Amazon Bedrock with Amazon API Gateway"
  (AWS Architecture Blog) was authored by AWS but the underlying
  pattern was developed by Dynatrace; this is the "AWS owns the post,
  partner owns the pattern" variant.
- "Introducing Amazon Bedrock AgentCore Gateway" (AWS Machine Learning
  Blog) is the canonical reference for the Gateway integration shape,
  authored by AWS solutions architects.

**Recommended Chio post shape for P5:**

- 8-10 paragraphs, ~1500-2000 words; one architecture diagram (Chio
  control plane + Bedrock + customer VPC, receipt at boundary).
- One config snippet (Chio policy YAML or adapter configuration) and
  one Bedrock Converse request snippet with Chio governance overlay.
- One Opus design-partner outcome paragraph (gated on D15 7-day
  freshness window).
- Co-authors: 1-2 AWS Bedrock SAs (the assigned partner SA) plus 1-2
  Chio authors. Cross-link listing URL, MCP registry entry, M02
  evaluation memo (if M02 has closed by week 30).

**MUST CONFIRM at P0:** assigned AWS Solutions Architect. Without a
named SA, the co-authored blog cannot be scheduled.

## Per-phase research findings (P0-P5)

### P0 (weeks 22-23): audit doc + APN onboarding scoping

- T1: open `audits/M10-bedrock-mcp.md`; fill hard counts (artifacts
  required 4-6; MCP suite test count at pinned vN).
- T2: confirm APN tier + Marketplace seller registration.
- T3: identify assigned AWS Bedrock Solutions Architect.
- T4: pick listing type (SaaS contract + AI Agents and Tools); record
  rationale.
- T5: pin pricing model.
- T6: pin MCP conformance-suite commit hash.

**Pre-roll dependency:** APN onboarding kickoff MUST occur in week 14,
not week 22. P0.T2 records actual APN registration date.

### P1 (weeks 23-25): Bedrock integration package

- T1: create `integrations/aws-bedrock/` with CloudFormation Quick
  Launch template (deploys control plane endpoint; wires Bedrock IAM
  via `iam_principals.toml`).
- T2: create `sdks/python/packages/chio-bedrock/` wrapping the Rust
  adapter; surface `BedrockChioClient`, `issue_receipt`,
  `verify_receipt`, `metering_callback`.
- T3: SaaS contract integration: `GetEntitlements` at tenant
  onboarding, `MeterUsage` / `BatchMeterUsage` on overage. Crates:
  `aws-sdk-marketplaceentitlement`, `aws-sdk-marketplacemetering`.
- T4: pin region us-east-1 (matches adapter).
- T5: data-flow diagram for AWS security review.

### P2 (weeks 25-27): MCP adapter against conformance bench

- T1: extend `chio-mcp-edge` (or new `integrations/mcp-adapter/`).
  Transport: Streamable HTTP + OAuth 2.1 + PKCE.
- T2: implement OAuth 2.0 Protected Resource Metadata (RFC9728).
- T3: run MCP conformance suite at pinned commit; record pass + skip
  + hash in audit doc.
- T4: write registry submission record (`server.json`): namespace,
  transport, OAuth scopes, capabilities, deps.
- T5: integration test against AgentCore Gateway as consumer.

### P3 (weeks 27-28): marketplace listing artifact submission

- T1: customer-facing README.
- T2: CloudFormation Quick Launch template bundled with listing.
- T3: minimum IAM policy (least-privilege doc for customer attach).
- T4: pricing model registration (per-tenant + overage).
- T5: support contact + SLA.
- T6: data-flow + architecture diagrams.
- T7: EULA + terms.

4-week round-trip buffer starts here. Freeze
m10-bedrock-listing-pivot covers P3-P4.

### P4 (weeks 28-30): reviewer round-trips + listing approval

- T1: open round-trip log in audit doc.
- T2: per round-trip, resolve comment + push patch (0.25-1 day each
  + reviewer SLA).
- T3: marketing review submission (AI Agents and Tools gate).
- T4: closure attestation: listing URL + approval date.

**Halt trigger:** round-trips > 4 or slip past week 30 freezes
artifacts and escalates per AUTONOMOUS-PROMPT.

### P5 (week 30): MCP conformance entry published + co-authored partner blog

Tickets:

- T1: submit MCP registry record; capture URL.
- T2: confirm conformance-suite pass count at as-of-publication commit
  hash; pin in audit doc.
- T3: co-authored APN blog draft + AWS SA review + AWS marketing
  review submission. Per the Kong precedent this is 2-4 weeks of
  round-trip; trajectory-3 plan covers draft + submission within week
  30; final publication may slip into trajectory-4. Audit closure
  rule: "draft submitted + AWS SA reviewed", not "published"
  (IMPLEMENT confirms).

## Cross-milestone dependencies

- **M03 hosted CI.** AWS reviewers ask for build provenance on
  containers and CFN templates. M03 hosted CI artifacts + M06 SBOM +
  reproducible-build hashes ARE the provenance evidence. M03 closes
  ~week 15; M10 P3 starts week 27. Satisfied.
- **M02 partner conformance memo.** M02 AI-lab evaluation receipt
  format becomes part of MCP server's emitted receipts (P2.T1
  consumes it). M02 partnership note strengthens the listing pitch
  (one of two distribution evidence forms; listing is the other).
- **M08 independent crypto + protocol review.** M08 closes ~week 36,
  past M10 P5 (week 30). Co-authored blog cannot cite M08.
  Recommendation: publish without; cite M08 in a trajectory-4
  follow-up.
- **M01 Opus design-partner pilot.** P5.T3 outcome paragraph requires
  Opus evidence in D15 7-day window. Opus withdrawal fires halt
  trigger 12; M10 P5.T3 freezes.
- **M06 supply-chain v2.** SBOM + cargo-vet artifacts feed the AWS
  security review. M06 closes ~week 22; M10 P3 starts week 27.
  Satisfied.
- **M07 chio-kernel-mobile-mvp.** No dependency either direction.

## Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| 1 | AWS marketplace reviewer round-trips exceed 4-week buffer | medium | trajectory close slips | P3 schedules with explicit 4-week buffer; halt trigger if exceeded |
| 2 | MCP conformance suite changes mid-flight (suite is roadmap-status, not v1.0) | medium | conformance evidence weakens | Pin commit hash at P0; record audit-doc clause "passes suite vN at hash X" |
| 3 | Bedrock pricing model rejected during marketplace ops review | low | repricing delays listing | Pin pricing at P0 per D03 + APN agreement; do not change during review |
| 4 | APN tier prerequisite not met (Validated tier) | low | adds 2-4 weeks pre-roll | P0.T2 confirms tier; if not met, halt trigger candidate |
| 5 | Co-author AWS SA unassigned | medium | P5 blog cannot ship | P0.T3 names the SA; if unassigned, escalate to APN partner manager |
| 6 | OAuth 2.1 + PKCE flow rejected by AWS security review | low | MCP transport must change | P2 implements per RFC9728 to match AWS expectations on agent-tool integrations |
| 7 | Marketing review (AI Agents and Tools category) gates the listing past week 30 | medium | listing approves but is not surfaced on category page until trajectory-4 | Audit closure attestation ALL counts as "listing approved"; surface placement is downstream |
| 8 | MCP registry namespace ownership challenge fails (DNS / GitHub validation) | low | submission rejected | P2.T4 verifies namespace ownership before submission |
| 9 | AWS introduces a new mandatory listing artifact mid-window (precedent: 2025-10 AI Agents pricing-flex update) | low | adds artifact; may add round-trip | Track AWS Marketplace whats-new feed weekly during P3-P4 |

## Recommended ticket scaffold

Phase ticket counts proposed (IMPLEMENT phase finalizes):

- P0: 6 tickets (audit-doc opener, APN tier confirm, SA identification,
  listing-type lock, pricing-model lock, conformance-suite version pin).
- P1: 5 tickets (integrations/aws-bedrock dir, chio-bedrock Python SDK,
  marketplace SaaS APIs, region pin, data-flow diagram).
- P2: 5 tickets (MCP server wrap, OAuth PRM, conformance run, registry
  record, AgentCore Gateway integration test).
- P3: 7 tickets (README, deployment template, IAM policy, pricing
  registration, support contract, diagrams, EULA).
- P4: 4 tickets (round-trip log, per-round-trip resolution, marketing
  review, closure attestation).
- P5: 3 tickets (registry submit, conformance-pass pin, co-authored
  blog draft + submission).

Total: ~30 tickets. The IMPLEMENT phase will refine. This count is
consistent with the M10 README placeholder "Tickets: TBD" and the
README's effort estimate (6/9/13 weeks bull/base/bear).

## Open questions for IMPLEMENT phase

1. SaaS contract vs container as primary listing type. Recommended:
   SaaS in AI Agents and Tools. Confirm against Opus contract shape +
   AgentCore Runtime fit.
2. Pricing model: per-tenant annual + receipt overage vs per-receipt
   vs per-API-call. Recommended: per-tenant + overage. Finance to
   confirm.
3. MCP server crate: `chio-mcp-edge` vs `chio-hosted-mcp`. Confirm at P0.
4. Region scope: us-east-1 only vs us-west-2 / eu-west-1. Recommended:
   us-east-1 only in trajectory-3.
5. AWS Solutions Architect identity: confirm name + reporting line at
   P0.T3.
6. Conformance-suite commit hash to pin at P0; audit doc records
   as-of-publication hash.
7. Pre-roll ownership: APN onboarding starts week 14; pre-roll ticket
   sits in W2 or a dedicated W1 M10-prep slot.
8. Marketing review buffer: P4 sub-step (delays approval) vs P5 task
   (ships after approval).
9. Co-authored blog publish window: trajectory-3 (week 30) or
   trajectory-4. Recommended: draft + AWS submission by week 30;
   publication slips.
10. Whether to cite M08 in the blog. Recommended: trajectory-4
    follow-up.

## Sources

- AWS Marketplace listing AI agent products docs:
  https://docs.aws.amazon.com/marketplace/latest/userguide/listing-saas-ai-agents.html
- Amazon Bedrock AgentCore Runtime for AWS Marketplace docs:
  https://docs.aws.amazon.com/marketplace/latest/userguide/bedrock-agentcore-runtime.html
- AWS Partner Guide to AI Agents and Tools in AWS Marketplace (APN
  Blog): https://aws.amazon.com/blogs/apn/aws-partner-guide-to-ai-agents-and-tools-in-aws-marketplace/
- Powering Next-Level Partner Success: 2026 Innovations (APN Blog):
  https://aws.amazon.com/blogs/apn/powering-partner-success-2026-innovations/
- Step-by-Step Guide to SaaS Integration with AWS Marketplace:
  https://aws.amazon.com/blogs/awsmarketplace/step-by-step-guide-to-saas-integration-with-aws-marketplace/
- Best practices for SaaS contract listings (AWS Marketplace blog):
  https://aws.amazon.com/blogs/awsmarketplace/best-practices-guide-to-successfully-list-your-saas-contract-solution-in-aws-marketplace/
- AWS Marketplace pricing-model flexibility for AI agents and tools
  (2025-10): https://aws.amazon.com/about-aws/whats-new/2025/10/aws-marketplace-pricing-ai-agents-tools/
- Introducing AI agents and tools in AWS Marketplace (2025-07):
  https://aws.amazon.com/about-aws/whats-new/2025/07/ai-agents-tools-aws-marketplace/
- Unlock Advanced AI Control with Kong AI Gateway And Amazon Bedrock
  (APN Blog co-authored precedent):
  https://aws.amazon.com/blogs/apn/unlock-advanced-ai-control-with-kong-ai-gateway-and-amazon-bedrock/
- Introducing Amazon Bedrock AgentCore Gateway:
  https://aws.amazon.com/blogs/machine-learning/introducing-amazon-bedrock-agentcore-gateway-transforming-enterprise-ai-agent-tool-development/
- Building an AI gateway to Amazon Bedrock with Amazon API Gateway:
  https://aws.amazon.com/blogs/architecture/building-an-ai-gateway-to-amazon-bedrock-with-amazon-api-gateway/
- MCP Roadmap (conformance suite roadmap entry):
  https://modelcontextprotocol.io/development/roadmap
- Introducing the MCP Registry (2025-09 launch post):
  https://blog.modelcontextprotocol.io/posts/2025-09-08-mcp-registry-preview/
- Official MCP Registry: https://registry.modelcontextprotocol.io/
- MCP Authorization spec (OAuth 2.1 + PKCE):
  https://modelcontextprotocol.io/specification/draft/basic/authorization
- modelcontextprotocol/registry (registry source + namespace rules):
  https://github.com/modelcontextprotocol/registry
- modelcontextprotocol/servers (Microsoft-curated list):
  https://github.com/modelcontextprotocol/servers
