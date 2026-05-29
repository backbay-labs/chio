# Chio AWS Bedrock Integration

Chio for AWS Bedrock gives agent teams a governed Bedrock path without
moving the Chio control plane into the customer account. The customer uses
the Quick Launch template to create a least-privilege integration role in
`us-east-1`. Chio checks the AWS Marketplace SaaS entitlement, assumes the
role with the tenant-bound external ID, mediates each Bedrock Converse
request through Chio policy and guards, signs a receipt, and then reports
receipt overage through Marketplace metering.

The listing is scoped to AWS Marketplace SaaS contract in the AI Agents
and Tools category. It wraps the existing
`crates/chio-bedrock-converse-adapter` Rust substrate for distribution and
keeps the adapter source unchanged. The listed region is `us-east-1` only;
multi-region support is recorded as a future candidate in `REGIONS.md`.

## Quick Launch

Deploy `cloudformation/quick-launch.yaml` in the customer AWS account:

1. Confirm the stack region is `us-east-1`.
2. Provide the Chio tenant ID, Chio control-plane HTTPS endpoint, Chio
   seller account principal ARN, and tenant-specific external ID.
3. Review the role policy in `IAM_POLICY.md`.
4. Launch the stack and send the output role ARN to the Chio onboarding
   operator.
5. Chio verifies `sts:GetCallerIdentity`, binds the IAM principal to the
   tenant, checks `GetEntitlements`, and enables governed Bedrock traffic.

The template stores the Chio control-plane endpoint in SSM Parameter Store
and creates the integration role used by Chio. It does not grant
Marketplace entitlement or metering permissions in the customer account;
those APIs run from the Chio seller account.

## Listing artifacts

- `cloudformation/quick-launch.yaml`: Quick Launch template for the
  customer integration role and endpoint parameter.
- `cloudformation/parameters.json`: review-time parameter example.
- `IAM_POLICY.md` and `iam/customer-attach.json`: minimum customer-attach
  permissions.
- `pricing/dimensions.yaml` and `pricing/contract-template.md`: locked
  per-tenant base contract plus receipt-overage dimension.
- `SUPPORT.md`: support contact, SLA, and escalation terms.
- `EULA.md` and `TERMS.md`: Standard Contract for AWS Marketplace posture
  and Chio addenda.
- `diagrams/`: data-flow, architecture, and security-review intake
  evidence.
- `control-plane/`: Marketplace entitlement and metering contract logic.

## Runtime boundary

Every Bedrock request must cross Chio first. Chio validates the tenant's
Marketplace entitlement, evaluates policy, runs guards, signs the receipt,
and only then invokes Bedrock through the customer role. If entitlement
lookup, IAM principal binding, guard evaluation, receipt issuance, or
metering preparation fails, Chio denies the request before unmetered
Bedrock traffic is released.

Support: `support@chio.world`. Security contact: `security@chio.world`.
