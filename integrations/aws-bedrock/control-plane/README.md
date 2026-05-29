# chio-bedrock-control-plane

AWS Marketplace entitlement and metering contract helpers for Chio's Bedrock
listing. This crate models the fail-closed entitlement and metering contract
used by the SaaS listing. Its public APIs are deterministic and testable
without AWS credentials.

Production callers bind these decisions to `aws-sdk-marketplaceentitlement` and
`aws-sdk-marketplacemetering` clients at the process edge. The crate provides
the entitlement and metering logic; it does not itself call AWS.
