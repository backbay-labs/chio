# Chio Documentation

Entry points and maps for the Chio protocol documentation.

## Start here

- [Progressive Tutorial](start-here/PROGRESSIVE_TUTORIAL.md) - walk through Chio from scratch
- [Native Adoption Guide](start-here/NATIVE_ADOPTION_GUIDE.md) - how to adopt Chio in a production service
- [Vision](start-here/VISION.md) - what Chio is for and why
- [Migration Guide (v1 to v2)](start-here/MIGRATION_GUIDE_V2.md) - upgrade path from Chio v1 to v2

## Reference

### SDKs and bindings

- [SDK TypeScript Reference](reference/SDK_TYPESCRIPT_REFERENCE.md) - `@chio-protocol/sdk` package API for agent-side TypeScript
- [SDK Python Reference](reference/SDK_PYTHON_REFERENCE.md) - `chio-sdk` distribution for Python agents, receipt queries, and invariant checks
- [Bindings API](reference/BINDINGS_API.md) - frozen `chio-binding-helpers` boundary contract that SDKs build on

### Receipts and queries

- [Receipt Query API](reference/RECEIPT_QUERY_API.md) - HTTP and CLI surface for querying the signed tool receipt log
- [Receipt Dashboard Guide](reference/RECEIPT_DASHBOARD_GUIDE.md) - React SPA served by trust-control for receipt visualization
- [Claim Registry](reference/CLAIM_REGISTRY.md) - which formal claims Chio may make and the evidence boundary behind each

### Identity and trust

- [Agent Passport Guide](reference/AGENT_PASSPORT_GUIDE.md) - Chio agent passports, verifier infra, and portable issuance
- [DID Chio Method](reference/DID_CHIO_METHOD.md) - the `did:chio` method spec and its legacy-compatibility status
- [DPoP Integration Guide](reference/DPOP_INTEGRATION_GUIDE.md) - sender-constrained invocation profile bound to agent keypairs
- [Identity Federation Guide](reference/IDENTITY_FEDERATION_GUIDE.md) - OAuth bearer admission via JWT verification and introspection
- [Workload Identity Runbook](reference/WORKLOAD_IDENTITY_RUNBOOK.md) - supported operator boundary for SPIFFE and Azure attestation

### Interop and adapters

- [A2A Adapter Guide](reference/A2A_ADAPTER_GUIDE.md) - thin Chio bridge for the A2A v1.0.0 protocol
- [Chio Certify Guide](reference/CHIO_CERTIFY_GUIDE.md) - certification layer that signs conformance evidence into pass/fail artifacts
- [Credential Interop Guide](reference/CREDENTIAL_INTEROP_GUIDE.md) - narrow portable-credential interop and public identity-network contracts
- [Economic Interop Guide](reference/ECONOMIC_INTEROP_GUIDE.md) - makes governed receipts legible to IAM, finance, and partner systems
- [SIEM Integration Guide](reference/SIEM_INTEGRATION_GUIDE.md) - forwarding Chio tool receipts into external SIEM systems

### Economics and guards

- [Monetary Budgets Guide](reference/MONETARY_BUDGETS_GUIDE.md) - how operators cap agent spend on cost-bearing tools
- [Tool Pricing Guide](reference/TOOL_PRICING_GUIDE.md) - advisory pricing metadata in Chio tool manifests
- [Velocity Guards](reference/VELOCITY_GUARDS.md) - token-bucket rate limiting per capability and grant
- [Agent Economy](reference/AGENT_ECONOMY.md) - technical design for governed transaction controls and payment interop
- [Agent Reputation](reference/AGENT_REPUTATION.md) - local scoring, issuance gating, and reputation surfaces
- [Competitive Landscape](reference/COMPETITIVE_LANDSCAPE.md) - agent protocols, payment rails, and identity standards in the surrounding space

## Operations

- [Roadmap](operations/ROADMAP.md) - canonical execution roadmap synthesized from protocol, guard, and research docs
- [Strategic Roadmap](operations/STRATEGIC_ROADMAP.md) - milestone ladder and launch-hold context
- [Execution Plan](operations/EXECUTION_PLAN.md) - ordering, parallelism, and sequencing for roadmap delivery
- [Changelog](operations/CHANGELOG.md) - release notes across Chio versions
- [Conformance Harness Plan](operations/CONFORMANCE_HARNESS_PLAN.md) - cross-language conformance plan for JS, Python, and spec fixtures
- [Distributed Control Plan](operations/DISTRIBUTED_CONTROL_PLAN.md) - shipped shared-control rewrite of the trust-plane architecture
- [HA Control Auth Plan](operations/HA_CONTROL_AUTH_PLAN.md) - HA replication, shared budget, and hosted auth-server plan
- [Bindings Core Plan](operations/BINDINGS_CORE_PLAN.md) - strategy for TypeScript, Python, and Go SDKs without a sprawling ABI
- [SDK Parity Execution Roadmap](operations/SDK_PARITY_EXECUTION_ROADMAP.md) - short-horizon plan to make multi-language SDK parity real

## Guides

- [Migrating From MCP](guides/MIGRATING-FROM-MCP.md)
- [Economic Layer](guides/ECONOMIC-LAYER.md)
- [Web Backend Quickstart](guides/WEB_BACKEND_QUICKSTART.md)

## Conformance

- [Conformance Suite (Standalone Consumer Guide)](conformance.md) - external-implementer flow for the Chio cross-language conformance harness (`cargo install chio-conformance`, `chio conformance fetch-peers`, `chio conformance run`)

## Fuzzing

- [Continuous Fuzzing Runbook](fuzzing/continuous.md) - layered strategy (in-tree `cargo +nightly fuzz` matrix, ClusterFuzzLite bridge, OSS-Fuzz primary), GHA budget enforcement, target inventory, local-dev and triage flow
- [Fuzz Crash Triage Runbook](fuzzing/triage.md) - severity bands (Critical, High, Medium, Low), dedupe rules (sha256 plus crash-type/target/call-site), time-to-fix SLOs (24h ack, 7d Critical, 14d High, 30d Medium), promotion to regression test, regression-deletion guard

## Protocol and architecture

- Canonical spec: [spec/PROTOCOL.md](../spec/PROTOCOL.md)
- [Architecture](architecture/)
- [ADRs](adr/)
- [Standards](standards/)
- [Protocols](protocols/)
- [Guards](guards/)
- [Compliance](compliance/)

## Research

- [Research notes](research/) - exploratory work and prior-art surveys

## SDKs

- [SDK docs](sdk/) - deep dives per language (Go, Python, TypeScript, Platform)

## Archive

- [Archived docs](archive/) - historical roadmaps and superseded plans
