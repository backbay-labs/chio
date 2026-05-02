# Minimum IAM Policy

The customer account role created by `cloudformation/quick-launch.yaml`
grants only the Bedrock runtime and identity calls needed by the Chio
control plane in `us-east-1`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokePinnedBedrockRuntime",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": "arn:aws:bedrock:us-east-1:${AWS::AccountId}:foundation-model/*"
    },
    {
      "Sid": "BindCallerIdentityForReceipts",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

The Chio control plane does not require customer-side permissions for
Marketplace entitlement or metering APIs. Those calls run from the Chio
seller account and are bound to the Marketplace SaaS contract.

Fail-closed behavior:

- If `sts:GetCallerIdentity` cannot bind the IAM principal, Chio denies
  onboarding and does not emit Bedrock traffic.
- If the role is deployed outside `us-east-1`, the template does not create
  the role.
- If entitlement lookup fails in the seller account, tenant onboarding is
  denied before the customer role is used.
