# Region Scope

Trajectory-3 lists the AWS Bedrock integration in `us-east-1` only. This
matches the existing `chio-bedrock-converse-adapter` region pin and keeps
the AWS Marketplace security review tied to one deployable shape.

## Listed region

- `us-east-1`: supported for trajectory-3.

## Deferred regions

- `us-west-2`: trajectory-4 candidate.
- `eu-west-1`: trajectory-4 candidate.

Multi-region support is not a trajectory-3 requirement. Adding another
region requires a new fixture pass for IAM principal binding, receipt
hashing, Bedrock model availability, and Marketplace review artifacts.
