# CloudFormation Quick Launch

`quick-launch.yaml` creates the customer-side integration role for the
Chio AWS Bedrock listing. Deploy it in `us-east-1`.

## Parameters

- `ChioControlPlaneEndpoint`: tenant gateway URL supplied by Chio.
- `ChioTenantId`: Chio tenant identifier for stack naming and SSM pathing.
- `ExternalId`: tenant-specific external ID used for `sts:AssumeRole`.
- `ChioSellerAccountPrincipalArn`: Chio seller account root or role ARN.

## Validation

The validation gate checks the template with:

```bash
sam validate --template integrations/aws-bedrock/cloudformation/quick-launch.yaml --lint
```

The template intentionally grants only Bedrock runtime invocation and
`sts:GetCallerIdentity`. Marketplace entitlement and metering calls run
from the Chio seller account, not from the customer role.
