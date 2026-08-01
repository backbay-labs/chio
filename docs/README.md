# Chio Documentation

Entry points and maps for the Chio protocol documentation. The canonical
normative specification lives at [spec/PROTOCOL.md](../spec/PROTOCOL.md);
everything in this tree is supporting material organized by audience.

## Start here

- [Progressive Tutorial](start-here/PROGRESSIVE_TUTORIAL.md) - walk through Chio from scratch
- [Native Adoption Guide](start-here/NATIVE_ADOPTION_GUIDE.md) - how to adopt Chio in a production service
- [Vision](start-here/VISION.md) - what Chio is for and why
- [Proof Room Quickstart](start-here/PROOF_ROOM_QUICKSTART.md) - run the checked-in Proof Room fixture bundle locally or via Docker
- [Historical v2 Migration Draft](start-here/MIGRATION_GUIDE_V2.md) - archived internal draft notes, not current protocol guidance

## Large document status

Tracked Markdown documents over 1,000 lines are classified here so readers can
separate live contracts from reference material and historical roadmaps.

| Document | Category | Currentness |
| --- | --- | --- |
| [Final Architecture](architecture/CHIO_FINAL_ARCHITECTURE.md) | Live contract | Current architecture target; verify line-number evidence before using it as implementation state. |
| [Human in the Loop Protocol](protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md) | Reference | Protocol design reference. |
| [Data Layer Integration](protocols/DATA-LAYER-INTEGRATION.md) | Reference | Protocol integration reference. |
| [Agent Economy](reference/AGENT_ECONOMY.md) | Reference | Economics reference surface. |
| [Code Execution Guards](guards/13-CODE-EXECUTION-GUARDS.md) | Reference | Guard-family reference. |
| [Structural Security Fixes](protocols/STRUCTURAL-SECURITY-FIXES.md) | Reference | Security design reference. |
| [Agent Framework Integration](protocols/AGENT-FRAMEWORK-INTEGRATION.md) | Reference | Ecosystem integration reference. |
| [Agent Reputation](reference/AGENT_REPUTATION.md) | Reference | Reputation reference surface. |
| [SaaS Communication Integration](protocols/SAAS-COMMUNICATION-INTEGRATION.md) | Reference | Protocol integration reference. |
| [Envoy Ext Authz Integration](protocols/ENVOY-EXT-AUTHZ-INTEGRATION.md) | Reference | Protocol integration reference. |

## Install and distribution

- [Install guide](install/README.md) - how to obtain and run Chio
- [Binary Distribution](install/BINARY_DISTRIBUTION.md) - prebuilt binary channels
- [Homebrew](install/homebrew.md) - Homebrew tap and formula
- [Publishing](install/PUBLISHING.md) - release publishing workflow
- [Verify](install/VERIFY.md) - verifying downloaded artifacts

## Release

The primary live release documents. Auditors and operators start here.

- [Qualification](release/QUALIFICATION.md) - what the release qualifies and the evidence behind it
- [Release Audit](release/RELEASE_AUDIT.md) - audit of release claims against evidence
- [Release Candidate](release/RELEASE_CANDIDATE.md) - release-candidate gate checklist
- [GA Checklist](release/GA_CHECKLIST.md) - general-availability readiness
- [Partner Proof](release/PARTNER_PROOF.md) - partner-facing proof of capability
- [Risk Register](release/RISK_REGISTER.md) - tracked release risks
- [Operations Runbook](release/OPERATIONS_RUNBOOK.md) - bounded-release operating procedures
- [Observability](release/OBSERVABILITY.md) - metrics, logs, and alerting surface
- [Compliance Evidence Export Plan](release/COMPLIANCE_EVIDENCE_EXPORT_PLAN.md)
- [Chio Rename Migration](release/CHIO_RENAME_MIGRATION.md) - operator guidance for the ARC-to-Chio rename
- Comptroller runbooks and proofs: [Operator Runbook](release/CHIO_COMPTROLLER_OPERATOR_RUNBOOK.md), [Partner Contracts](release/CHIO_COMPTROLLER_PARTNER_CONTRACTS.md), [Federated Proof](release/CHIO_COMPTROLLER_FEDERATED_PROOF.md), [Market Position Proof](release/CHIO_COMPTROLLER_MARKET_POSITION_PROOF.md)
- Universal control plane: [Runbook](release/CHIO_UNIVERSAL_CONTROL_PLANE_RUNBOOK.md), [Partner Proof](release/CHIO_UNIVERSAL_CONTROL_PLANE_PARTNER_PROOF.md)
- Web3 release set: [Interop Runbook](release/CHIO_WEB3_INTEROP_RUNBOOK.md), [Operations Runbook](release/CHIO_WEB3_OPERATIONS_RUNBOOK.md), [Deployment Promotion](release/CHIO_WEB3_DEPLOYMENT_PROMOTION.md), [Mainnet Cutover Checklist](release/CHIO_WEB3_MAINNET_CUTOVER_CHECKLIST.md), [Partner Proof](release/CHIO_WEB3_PARTNER_PROOF.md), [Readiness Audit](release/CHIO_WEB3_READINESS_AUDIT.md)
- Service runbooks: [Anchor](release/CHIO_ANCHOR_RUNBOOK.md), [Link](release/CHIO_LINK_RUNBOOK.md), [Settle](release/CHIO_SETTLE_RUNBOOK.md), [Pheromone Relay](release/CHIO_PHEROMONE_RELAY_RUNBOOK.md)

## Reference

### SDKs and bindings

- [SDK TypeScript Reference](reference/SDK_TYPESCRIPT_REFERENCE.md) - `@chio-protocol/sdk` package API for agent-side TypeScript
- [SDK Python Reference](reference/SDK_PYTHON_REFERENCE.md) - `chio-sdk` distribution for Python agents, receipt queries, and invariant checks
- [Bindings API](reference/BINDINGS_API.md) - frozen `chio-binding-helpers` boundary contract that SDKs build on

### Receipts and queries

- [Receipt Query API](reference/RECEIPT_QUERY_API.md) - HTTP and CLI surface for querying the signed tool receipt log
- [Receipt Dashboard Guide](reference/RECEIPT_DASHBOARD_GUIDE.md) - React SPA served by trust-control for receipt visualization
- [Claim Registry](reference/CLAIM_REGISTRY.md) - which formal claims Chio may make and the evidence boundary behind each
- [Policy Analysis](reference/POLICY_ANALYSIS.md) - static rule findings and policy refinement witnesses

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

## Protocol and architecture

- Canonical spec: [spec/PROTOCOL.md](../spec/PROTOCOL.md)
- [Architecture notes](architecture/) - [Final Architecture](architecture/CHIO_FINAL_ARCHITECTURE.md), [Runtime Boundaries](architecture/CHIO_RUNTIME_BOUNDARIES.md), [Workspace Structure](architecture/WORKSPACE_STRUCTURE.md)
- [Architecture Decision Records](adr/README.md) - numbered ADRs (ADR-0001 through ADR-0018)
- [Reliability program](architecture/reliability/README.md) - RFC and PLAN series for the fail-closed reliability, durability, and control-plane replication-soundness work (hot-path deadlines, post-admission unwind, dispatch-intent journal, storage hot path, observability wiring, and replication quorum)
- [Transparency program](architecture/transparency/README.md) - the ordered plan for closing the `spec/PROTOCOL.md` section 6.5 append-only gate (real Merkle consistency proofs, claim and child-receipt completeness, declared verifier policy, witness cosigning)
- [Protocol integration notes](protocols/) - framework, transport, and ecosystem integration designs (Temporal, LangGraph, Envoy, AWS Lambda, K8s, and more), plus the [Trust Model and Key Management](protocols/TRUST-MODEL-AND-KEY-MANAGEMENT.md)
- [Standards profiles](standards/) - qualification profiles and JSON conformance matrices (anchor, federation, automation, extension, bounded operational profile, cross-protocol matrix)

## Guards

- [Guards design set](guards/) - guard system landscape, WASM runtime plan, hot reload, and the [0.1 to 0.2 migration](guards/MIGRATION-0.1-to-0.2.md)

## Security

- [Threat coverage](security/threat-coverage.md) - mapped threats and mitigations
- [Expected identity migration](security/expected-identity-migration.md) - migrating expected-identity assertions
- [Public witness semantics](security/public-witness-semantics.md)
- [Corpus minimization](security/corpus-minimization.md)

## Compliance

- [Compliance mappings](compliance/) - control mappings for [NIST AI RMF](compliance/nist-ai-rmf.md), [ISO 42001](compliance/iso-42001.md), [EU AI Act Article 19](compliance/eu-ai-act-article-19.md), [OWASP LLM Top 10](compliance/owasp-llm-top-10.md), [PCI DSS v4](compliance/pci-dss-v4.md), and [Colorado SB 24-205](compliance/colorado-sb-24-205.md)

## Operator runbooks

- [Operator runbook index](operator-runbook/index.md) - tenant-shaped operating rules layered on the bounded release runbook
- Topics: [onboarding](operator-runbook/onboarding.md), [incidents](operator-runbook/incidents.md), [rotations](operator-runbook/rotations.md), [quota](operator-runbook/quota.md), [SLO](operator-runbook/slo.md), [topology](operator-runbook/topology.md), [PagerDuty](operator-runbook/pagerduty.md), [PHI policy](operator-runbook/phi-policy.md), [bounded profile](operator-runbook/bounded-profile.md)

## Products built on Chio

- [Chio-Wall documentation suite](chio-wall/README.md) - companion product recording tool-boundary control evidence for information-domain separation
- [Proof Room](start-here/PROOF_ROOM_QUICKSTART.md) - companion product that verifies a Chio proof bundle and serves its dashboard, with the displayed verdict bound to the bundle's verifier report

## Operations and planning

- [Changelog](operations/CHANGELOG.md) - internal pre-release notes, not public protocol version history
- [Conformance Harness Plan](operations/CONFORMANCE_HARNESS_PLAN.md) - cross-language conformance plan for JS, Python, and spec fixtures
- [HA Control Auth Plan](operations/HA_CONTROL_AUTH_PLAN.md) - HA replication and shared budget plan

## Guides

- [Migrating From MCP](guides/MIGRATING-FROM-MCP.md)
- [Economic Layer](guides/ECONOMIC-LAYER.md)
- [Web Backend Quickstart](guides/WEB_BACKEND_QUICKSTART.md)

## Integrations

- [Hermes Integration](integrations/HERMES.md) - wire Chio into the Hermes Agent via MCP server (Path A) or the native `chio-hermes` plugin (Path B)
- [chio-adapter-base Integration](integrations/CHIO-ADAPTER-BASE.md) - shared security and receipt primitives every Chio Python adapter depends on
- [Choosing the Redaction Boundary](integrations/CHOOSING_REDACTION_BOUNDARY.md) - decision tree for pre-evaluation vs post-tool-call redaction
- [Adapter Migration Guide](integrations/MIGRATION_GUIDE.md) - adapter-author migration recipe for `chio-adapter-base 0.1.x` to `0.2.0`
- [chio-adapter-base 0.2.0 Release Notes](integrations/RELEASE_NOTES_v0.2.0.md)

## Conformance and replay

- [Conformance Suite (Standalone Consumer Guide)](conformance.md) - external-implementer flow for the Chio cross-language conformance harness
- [Verdict matrix](conformance/verdict-matrix.md) - expected verdicts across conformance scenarios
- [Replay CLI](replay-cli.md) - replaying recorded sessions from the command line
- [Replay compatibility](replay-compat.md) - replay format compatibility across versions
- [Release evidence](release-evidence.md) - how release evidence is collected and signed

## CLI

- [Arena](cli/arena.md) - the `chio arena` subcommand
- [Replay](cli/replay.md) - the `chio replay` subcommand

## Migrations

- [Delegation migration](migrations/delegation-migration.md)
- [Async kernel migration](migrations/async-kernel-migration.md)
- [Kernel embedder surface migration](migrations/kernel-embedder-surface.md)
- [Attest-verify migration](coordination/attest-verify-migration.md)

## Custody and weights

- [Passkey issuer](custody/passkey-issuer.md) - hardware-backed passkey issuance for custody
- [Model cards](weights/model-cards.md) - model card records for governed weights

## Trust boundary

- [Trust boundary: browser signing](trust-boundary-browser-signing.md) - where signing happens for browser-originated requests

## Formal verification

- [Formal verification docs](formal/README.md) - index for the review and planning set
- [Current state](formal/CURRENT_STATE.md) - the six evidence lanes (Lean 4, Aeneas, Creusot, Kani, TLA+/Apalache, diff-tests), governance layer, and CI cadence as surveyed 2026-07-09
- [Gap analysis](formal/GAP_ANALYSIS.md) - the six load-bearing gaps (G1-G6) with evidence
- [Hygiene pass](formal/HYGIENE_PASS.md) - fifteen mechanical fixes with exact edits
- [Roadmap](formal/ROADMAP.md) - waves, dependencies, and claims impact for the 23 plan specs under [docs/formal/plan/](formal/plan/)

## Fuzzing

- [Continuous Fuzzing Runbook](fuzzing/continuous.md) - layered fuzzing strategy (in-tree matrix, ClusterFuzzLite bridge, OSS-Fuzz primary), CI budget enforcement, target inventory
- [Fuzz Crash Triage Runbook](fuzzing/triage.md) - severity bands, dedupe rules, time-to-fix SLOs, promotion to regression test
- [Mutation testing](fuzzing/mutants.md) - mutation-testing runbook

## SDKs

- [SDK deep dives](sdk/) - per-language references: [Go](sdk/GO.md), [Python](sdk/PYTHON.md), [TypeScript](sdk/TYPESCRIPT.md), [Platform](sdk/PLATFORM.md), [C++ SDK roadmap](sdk/CPP_SDK_ROADMAP.md)

## CI and billing

- [CI billing runbook](runbooks/ci-billing.md) - CI cost accounting and budget controls
