# AWS Security Review Intake

This intake package is submitted with the AWS Marketplace technical and
security review.

## Artifact set

- Customer-facing README: `integrations/aws-bedrock/README.md`
- Quick Launch template: `integrations/aws-bedrock/cloudformation/quick-launch.yaml`
- Minimum IAM policy: `integrations/aws-bedrock/IAM_POLICY.md`
- Customer attach policy JSON: `integrations/aws-bedrock/iam/customer-attach.json`
- Pricing dimensions: `integrations/aws-bedrock/pricing/dimensions.yaml`
- Support and SLA: `integrations/aws-bedrock/SUPPORT.md`
- EULA and terms: `integrations/aws-bedrock/EULA.md`,
  `integrations/aws-bedrock/TERMS.md`
- Data-flow and architecture diagrams: `integrations/aws-bedrock/diagrams/`

## Provenance and supply-chain evidence

- The hosted-CI reproducible-build hash is the build-provenance evidence
  consumed by AWS security review.
- The SBOM plus cargo-vet artifacts are the supply-chain evidence consumed
  by AWS security review.
- The evaluation memo and MCP conformance evidence support the
  technical-review narrative.

## Fail-closed claims

The control plane denies access before Bedrock invocation if entitlement,
IAM principal binding, policy evaluation, guard evaluation, receipt
issuance, or metering preparation fails.
