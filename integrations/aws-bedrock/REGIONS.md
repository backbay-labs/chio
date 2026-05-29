# Region Scope

This release lists the AWS Bedrock integration in `us-east-1` only. This
matches the existing `chio-bedrock-converse-adapter` region pin and keeps
the AWS Marketplace security review tied to one deployable shape.

## Listed region

- `us-east-1`: supported in this release.

## Deferred regions

- `us-west-2`: future candidate.
- `eu-west-1`: future candidate.

Multi-region support is not a requirement for this release. Adding another
region requires a new fixture pass for IAM principal binding, receipt
hashing, Bedrock model availability, and Marketplace review artifacts.
