# Terms

These terms supplement the Standard Contract for AWS Marketplace for the
Chio AWS Bedrock listing.

## Entitlement

The Marketplace contract grants one governed Bedrock tenant entitlement.
Chio validates `GetEntitlements` before onboarding and denies access when
the entitlement is missing, inactive, expired, or mismatched.

## Metering

The base contract is annual per tenant. Receipt overage is metered through
the `bedrock_receipt_overage` dimension and reported by the Chio seller
account through `MeterUsage` or `BatchMeterUsage`.

## Security posture

Chio follows fail-closed semantics. No Bedrock request is released when the
control plane cannot bind IAM principal identity, evaluate policy, run
guards, sign a receipt, or prepare metering evidence.

## Region

The listing is limited to `us-east-1`. Additional regions are future
candidates.
