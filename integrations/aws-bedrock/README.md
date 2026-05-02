# Chio AWS Bedrock Integration

This package contains the trajectory-3 AWS Bedrock listing artifacts for
the Chio control plane. It wraps the existing
`crates/chio-bedrock-converse-adapter` Rust substrate for distribution and
keeps the adapter source unchanged.

## Scope

- Listing type: AWS Marketplace SaaS contract in the AI Agents and Tools
  category.
- Listed region: `us-east-1`.
- Bedrock runtime API: Converse and ConverseStream through the existing
  Chio Bedrock adapter.
- Marketplace APIs: `GetEntitlements` during tenant onboarding and
  `MeterUsage` or `BatchMeterUsage` for receipt overage.
- Receipt boundary: every Bedrock request is mediated by Chio and recorded
  as a Chio receipt before usage is metered.

Multi-region support is intentionally out of scope for trajectory-3. The
deferral is recorded in `REGIONS.md`.

## Contents

- `cloudformation/quick-launch.yaml`: customer account bootstrap template
  for the Chio Bedrock integration role and endpoint wiring.
- `IAM_POLICY.md`: minimum IAM policy for the customer-side integration
  role.
- `REGIONS.md`: region pin and trajectory-4 deferral.
- `diagrams/`: data-flow, IAM principal trail, and AWS security-review
  diagram sources.
- `control-plane/`: Rust control-plane crate for Marketplace entitlement
  and metering contract logic.

## Operator flow

1. Customer deploys the Quick Launch template in `us-east-1`.
2. The template creates the Chio integration role and stores the Chio
   control-plane endpoint parameter.
3. Chio checks Marketplace entitlements for the tenant before onboarding.
4. The Bedrock adapter mediates model calls and emits Chio receipts.
5. Receipt overage is reported through Marketplace metering APIs.

Fail-closed rule: if entitlement lookup, receipt issuance, or metering
preparation fails, the control plane denies the tenant action before any
unmetered Bedrock traffic is released.
