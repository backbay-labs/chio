# IAM Principal Trail

The AWS security-review package records the IAM principal trail for every
Bedrock request:

1. Customer deploys `ChioBedrockIntegrationRole` from the Quick Launch
   template.
2. Chio assumes that role with the tenant-specific external ID.
3. Chio calls `sts:GetCallerIdentity` before the Bedrock request.
4. The resolved IAM principal ARN and AWS account ID are written into the
   Chio receipt metadata.
5. Overage metering references the receipt ID and tenant identifier, while
   Marketplace API calls run from the Chio seller account.

The IAM principal trail is fail-closed. If the principal cannot be resolved
or does not match the signed tenant binding, Chio denies the request before
the Bedrock adapter invokes `Converse` or `ConverseStream`.
