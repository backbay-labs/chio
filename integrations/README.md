# Integrations

This directory holds the packaging and distribution layers that wrap Chio's
core crates for specific third-party marketplaces and platforms. The runtime
logic lives in `crates/`; the code here is the thin contract, configuration,
and listing material that turns a core crate into a deployable, distributable
product on an external platform.

Two of the subdirectories are Cargo workspace members (declared in the root
`Cargo.toml`); the rest of the `aws-bedrock/` tree is non-code listing
collateral (IAM policies, CloudFormation templates, pricing, legal terms, and
diagrams) that has to ship alongside an AWS Marketplace listing.

## Member crates

- `aws-bedrock/control-plane/` (`chio-bedrock-control-plane`): the fail-closed
  AWS Marketplace entitlement and metering contract used by the Bedrock SaaS
  listing. Its public APIs are deterministic and testable without AWS
  credentials; production callers bind them to `aws-sdk-marketplaceentitlement`
  and `aws-sdk-marketplacemetering` at the process edge. The Bedrock request
  path itself wraps `crates/chio-bedrock-converse-adapter`.

- `mcp-adapter/` (`chio-mcp-adapter-integration`): the distribution packaging
  for Chio's registry-listed MCP server. It extends the core MCP edge transport
  with Streamable HTTP, OAuth 2.1 + PKCE, RFC 9728 Protected Resource Metadata,
  and receipt emission. The core MCP edge transport lives in
  `crates/chio-mcp-edge`.

These two crates live here rather than under `crates/` because they are
platform-specific distribution wrappers, not part of the core protocol
surface. Each builds on a canonical crate in `crates/` and adds only the glue a
particular marketplace requires.

## Listing collateral (non-code)

The `aws-bedrock/` directory also carries the material required to publish and
operate the AWS Marketplace SaaS listing. None of it is compiled:

- `cloudformation/`: customer Quick Launch template, review-time parameters,
  and its own README.
- `iam/` and `IAM_POLICY.md`: least-privilege customer-attach permissions.
- `pricing/`: locked per-tenant base contract plus the receipt-overage
  dimension.
- `marketing/`: AWS Marketplace category submission material.
- `review/`: marketplace review round-trip notes.
- `diagrams/`: data-flow, architecture, and security-review intake evidence.
- `EULA.md`, `TERMS.md`, `SUPPORT.md`, `REGIONS.md`: legal posture, support
  terms, and the listed-region note (`us-east-1` only today).

For the full listing narrative and runtime boundary, see
`aws-bedrock/README.md`.

## Conventions

- Code in this tree must keep the same fail-closed posture as the core crates:
  if entitlement, policy, guard, receipt, or metering steps fail, the request
  is denied before any unmetered platform traffic is released.
- Distribution wrappers should not fork core logic. They depend on the
  canonical crate under `crates/` and re-export or extend it.
