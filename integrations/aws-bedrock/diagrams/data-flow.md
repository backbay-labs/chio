# AWS Bedrock Data Flow

1. The customer deploys the Chio integration role inside the customer VPC
   account in `us-east-1`.
2. The Chio control plane validates the Marketplace SaaS entitlement before
   tenant onboarding.
3. Agent traffic reaches the Chio control plane first. Chio evaluates
   policy, runs guards, and signs a receipt at the trust boundary.
4. The existing Bedrock Converse adapter invokes Amazon Bedrock Runtime
   through the customer role.
5. Receipt overage is transformed into Marketplace `MeterUsage` or
   `BatchMeterUsage` records from the Chio seller account.

The receipt is the security boundary artifact: no unmetered or unsigned
Bedrock request is released when entitlement, guard evaluation, or receipt
construction fails.
