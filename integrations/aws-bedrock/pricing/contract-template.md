# Contract Template

Listing type: AWS Marketplace SaaS contract.

Base dimension: `tenant_base`.

Overage dimension: `bedrock_receipt_overage`.

The contract grants one annual governed Bedrock tenant entitlement. Chio
checks `GetEntitlements` before tenant onboarding. Receipt volume above the
base contract is reported through `MeterUsage` or `BatchMeterUsage`.

The exact price is managed in Partner Central and redacted from
trajectory-3 public docs. The shape is fixed for review: per-tenant annual
base plus receipt overage. Repricing during P3/P4 is not allowed without
triggering the M10 pricing-review escalation path.
