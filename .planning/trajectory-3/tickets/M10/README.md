# M10: AWS Bedrock + MCP Conformance Listing

**Wave:** W3  |  **Trust-boundary:** yes  |  **Tickets:** 30  |  **Effort weeks:** 6/9/13

## In one paragraph

M10 ships exactly one cloud marketplace listing (AWS Bedrock per D03)
plus one MCP-conformant Chio integration. Release gates are
PROTOCOL + RELEASE_AUDIT (dual gate per verdict): Bedrock listing
live; MCP conformance assertion published at a pinned suite hash.
Implementation: a SaaS-contract control plane in `integrations/aws-bedrock/`
fronting the existing `chio-bedrock-converse-adapter` Rust crate, an
MCP server in `integrations/mcp-adapter/` extending `chio-mcp-edge`
with Streamable HTTP + OAuth 2.1 + PKCE (RFC9728), a Python SDK at
`sdks/python/packages/chio-bedrock/`, marketplace listing artifacts
(README, CFN Quick Launch template, IAM policy doc, pricing model,
support contract, EULA, diagrams), and a co-authored APN blog draft.
Pre-roll: APN onboarding kickoff at week 14 (not week 22) so the
calendar fits the 22-30 weeks W3 window.

## Phases at a glance

| Phase | Calendar weeks | Tickets | One-liner |
|-------|---------------|---------|-----------|
| P0 | 22-23 (pre-roll W1/W2 for APN) | 6 | Audit doc + APN onboarding scoping + listing-type / pricing locks |
| P1 | 23-25 | 5 | Bedrock integration package: `integrations/aws-bedrock/` + Python SDK + Marketplace SaaS APIs |
| P2 | 25-27 | 5 | MCP adapter: Streamable HTTP + OAuth 2.1 + PKCE; conformance suite at pinned hash |
| P3 | 27-28 | 7 | Marketplace listing artifact submission (freeze opens) |
| P4 | 28-30 | 5 | Reviewer round-trips + listing approval (freeze closes) |
| P5 | 30 | 3 | MCP registry submission + co-authored APN blog draft |

## Locked decisions

- D03 AWS Bedrock + MCP only; GCP / Azure deferred to trajectory-4.
- D07 vendor budget posture covers ~$10-20k AWS marketplace fees.

## Active freezes

`m10-bedrock-listing-pivot` (P3-P4) covers `integrations/aws-bedrock/**`,
`integrations/mcp-adapter/**`, `sdks/python/packages/chio-bedrock/**`.
Opens at M10.P3.T1, closes at M10.P4.T5. Hot-fix bypass:
`hotfix/* + [trajectory-3]`.

## Pre-roll calendar dependency

APN partner-network onboarding MUST start week 14, not week 22.
M10.P0.T2 is `vendor_wait` status from week 14 until the registration
receipt lands. The W1 / W2 M10-prep slot owns the calendar work.

## When this milestone is done

- AWS marketplace listing approved (the AWS approval IS the third-
  party evidence). Listing URL recorded in audit doc.
- MCP project conformance entry published at
  `registry.modelcontextprotocol.io`; pass count pinned against suite
  commit hash.
- Co-authored APN blog draft submitted + AWS SA reviewed (RESEARCH
  closure rule; not "published"; publication may slip into
  trajectory-4).
- Audit doc records: hard counts, APN tier, partner SA, listing-type
  + pricing locks, MCP conformance pin, reviewer round-trip log,
  closure attestations, D03 single-cloud confirmation.
