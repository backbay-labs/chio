# AI Agents and Tools Category Submission

Submission date: 2026-05-02
AWS Marketplace category: AI Agents and Tools
Listing: Chio Bedrock Governance
Primary support contact: support@chio.world

## Placement Request

Chio Bedrock Governance should be reviewed for AI Agents and Tools
category placement because the listing gives Bedrock customers a
governed agent-tool access path with signed receipts, marketplace
entitlement checks, and metered receipt overage. The customer deploys a
single-region Quick Launch template in `us-east-1`, grants the Chio
seller principal least-privilege Bedrock invocation access, and routes
agent calls through the Chio control plane before any Bedrock action
crosses the customer trust boundary.

## Customer Outcome

The listing reduces the customer integration surface to three
auditable steps:

1. Subscribe to the SaaS contract and confirm the tenant entitlement.
2. Launch the CloudFormation template with the Chio tenant ID, control
   plane endpoint, external ID, and seller principal ARN.
3. Route Bedrock Converse traffic through Chio so every allow, deny,
   receipt, and overage decision is recorded.

The customer-facing evidence set includes a Quick Launch template,
least-privilege IAM policy, support SLA, Standard Contract for AWS
Marketplace posture, data-flow diagram, and post-listing smoke test.

## Differentiation

Chio is not a model wrapper or prompt application. It is a control-plane
boundary for attested tool access in agent systems. The Bedrock listing
focuses on the governed runtime path: Marketplace entitlement confirms
commercial access, Chio validates capability scope, Bedrock receives
only authorized requests, and signed receipts preserve decision
evidence for healthcare and regulated customers.

## Review Attachments

- `integrations/aws-bedrock/README.md`
- `integrations/aws-bedrock/cloudformation/quick-launch.yaml`
- `integrations/aws-bedrock/IAM_POLICY.md`
- `integrations/aws-bedrock/SUPPORT.md`
- `integrations/aws-bedrock/diagrams/architecture.svg`
- `integrations/aws-bedrock/diagrams/security-review-intake.md`
- `integrations/aws-bedrock/tests/post_listing_smoke.rs`

Category placement is a downstream marketing surface. This release uses
listing approval and the post-listing smoke path as the distribution
evidence, while final category-page placement may follow later.
