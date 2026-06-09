# Launch Artifact Registry

Status: canonical planning registry
Confidence: high for naming conventions, moderate for final crate placement.

## Naming Rules

The repo already treats signed artifact schema IDs as a fail-closed compatibility boundary. `spec/PROTOCOL.md` says every signed artifact schema ID accepted by a verifier must be listed in `spec/schemas/registry.json`, and verifier builds expose the same IDs through `KNOWN_SIGNED_ARTIFACT_SCHEMAS`.

Launch planning must therefore use stable schema IDs, not casual feature names.

Rules:

1. Use `schema` for signed or verifier-facing artifact identifiers, matching `spec/schemas/registry.json`.
2. Use dot-separated domain groups and hyphenated artifact names.
3. Do not use underscores in schema IDs.
4. Put new signed artifacts in `spec/schemas/registry.json` before any verifier accepts them.
5. Treat raw agent draft and review names as source notes. The canonical names below supersede draft and review naming drift.

## Canonical Schema IDs

| Domain | Canonical schema ID | Role | Registry requirement |
| --- | --- | --- | --- |
| Transaction | `chio.transaction-passport.v1` | Signed root over a transaction proof graph | Required |
| Transaction | `chio.transaction.evidence-graph.v1` | Typed DAG of evidence nodes and proof edges | Required |
| Transaction | `chio.transaction.claim-set.v1` | Machine-readable launch claim inventory | Required |
| Transaction | `chio.transaction.verifier-policy.v1` | Policy declaring required claims and omissions | Required |
| Transaction | `chio.transaction.verifier-report.v1` | Deterministic verification result | Required |
| Commerce | `chio.commerce.order-context.v1` | Replayable order aggregate | Required |
| Commerce | `chio.commerce.event-log.v1` | Append-only commerce event log | Required |
| Commerce | `chio.commerce.order-passport.v1` | Reviewer-facing order summary | Required |
| Commerce | `chio.commerce.provider-admission.v1` | Provider passport, reputation, and federation gate result | Required if commerce fixture uses provider selection |
| Commerce | `chio.commerce.settlement-packet.v1` | Dispatch-ready settlement instruction package | Required if settlement is claimed |
| Swarm | `chio.swarm.task-graph.v1` | Signed recursive task authority graph | Required for swarm claim |
| Swarm | `chio.swarm.continuation-token.v1` | Child execution context | Required for swarm claim |
| Swarm | `chio.swarm.delegation-witness-chain.v1` | Per-hop attenuation proof chain | Required for recursive delegation claim |
| Swarm | `chio.swarm.join-receipt.v1` | Multi-parent fan-in proof | Required for fan-in claim |
| Swarm | `chio.swarm.route-plan-receipt.v1` | Signed cross-protocol route choice | Required for routed execution claim |
| Swarm | `chio.swarm.budget-pool.v1` | Graph-level budget pool and lease state | Required for metered swarm claim |
| Disclosure | `chio.disclosure.capsule.v1` | Transaction-bound selective disclosure package | Required for selective disclosure claim |
| Disclosure | `chio.bbs-projection.manifest.v2` | BBS message-slot manifest | Required if BBS is used |
| Disclosure | `chio.lineage.signed-subgraph.v1` | Redacted signed lineage DAG | Required for lineage claim |
| Disclosure | `chio.disclosure.leakage-ledger.v1` | Machine-readable leakage accounting | Required for privacy profile claim |
| Disclosure | `chio.disclosure.verifier-privacy-profile.v1` | Required, forbidden, and hidden predicate policy | Required for selective disclosure claim |
| Settlement | `chio.web3-settlement-proof-bundle.v1` | Public web3 settlement proof bundle | Required for web3 settlement claim |
| Settlement | `chio.anchor-proof-bundle.v1` | Anchor inclusion and checkpoint evidence | Required if anchoring is claimed |
| Settlement | `chio.oracle-conversion-evidence.v1` | FX or asset conversion evidence | Required if conversion is claimed |
| Settlement | `chio.public-settlement-verifier-report.v1` | Public settlement verifier report | Required for public settlement claim |
| Risk | `chio.risk.comptroller-report.v1` | Reconciled risk control-plane projection | Required for risk or insurance claim |
| Risk | `chio.risk.facility-state-report.v1` | Facility lifecycle replay result | Required for facility claim |
| Risk | `chio.risk.coverage-decision.v1` | Coverage binding result | Required for insurance claim |
| Risk | `chio.risk.claim-case-file.v1` | Claim evidence and decision package | Required if claims are shown |
| Risk | `chio.risk.claim-appeal.v1` | Appeal over adjudication, payout mismatch, settlement mismatch, reserve slash, or closure dispute | Required if appeals can block payout, release, slash, or closure |
| Risk | `chio.risk.sanction-reserve-ledger.v1` | Reserve slash, market slash, hold, reverse slash, and consumed reserve id ledger | Required for any slashing or reserve-control claim |
| Risk | `chio.risk.portfolio-reconciliation-report.v1` | Cross-claim facility reconciliation by currency and state | Required for portfolio reserve claim |
| Risk | `chio.risk.capital-adequacy-report.v1` | Reserve and capital adequacy report | Required for autonomous pricing claim |
| Risk | `chio.risk.actuarial-backtest-report.v1` | Actuarial model evidence and observed-vs-predicted claim performance | Required for premium adequacy or autonomous pricing claim |
| Proof Room | `chio.proof-room.bundle.v1` | Static proof-room bundle manifest | Required for launch demo |
| Proof Room | `chio.proof-room.verifier-report.v1` | UI-normalized verifier report | Required for launch demo |
| Agent Web | `chio.agent-web-proof-envelope.v1` | Detached external proof envelope | Required for interop claim |
| Agent Web | `chio.agent-web.external-projection-manifest.v1` | Protocol-specific projection rules | Required for interop claim |
| Agent Web | `chio.agent-web.interop-verifier-report.v1` | External projection verifier report | Required for interop claim |

## Noncanonical Names To Avoid

The following names appeared in draft material or early integrated docs and should not be used in canonical plans:

- `chio.transaction_passport.v1`
- `chio.transaction.passport.v1`
- `chio.transaction-proof-package.v1`
- `chio.transaction.proof-package.v1`
- `chio.evidence_graph.v1`
- `chio.passport_verifier_report.v1`
- `chio.swarm_task_graph.v1`
- `chio.swarm_continuation_token.v1`
- `chio.swarm_join_receipt.v1`
- `chio.route_plan_receipt.v1`
- `chio.disclosure_capsule.v1`
- `chio.lineage-subgraph-export.v1`
- `chio.disclosure-leakage-ledger.v1`
- `chio.risk_comptroller_report.v1`
- `chio.agent_web_proof_envelope.v1`
- `chio.proof_room_bundle.v1`

## Implementation Impact

Every plan that creates a verifier-facing signed artifact must include:

1. a schema file under `spec/schemas`;
2. a registry entry in `spec/schemas/registry.json`;
3. a refreshed `spec/schemas/MANIFEST.sha256` entry;
4. coverage in `scripts/check-chio-schema-registry.sh` if the schema lives in a new root;
5. a Rust constant or generated binding reachable from `KNOWN_SIGNED_ARTIFACT_SCHEMAS` when verifier code accepts the signed artifact;
6. a `crates/chio-core-types/tests/signed_artifact_schema.rs` assertion for fail-closed unknown-schema behavior when the core registry changes;
7. claim and proof-manifest rows in `spec/registries/claim-registry.v1.json` and `spec/registries/proof-manifest.v1.json` when the artifact carries a public claim;
8. a positive schema fixture;
9. a negative unknown-schema fixture;
10. a verifier path that rejects unknown schema IDs before trusting the artifact body.

## Candidate Debate Additions

These third-wave debate candidates are not canonical until the registry owner accepts them. They should be used for planning and scoping, not implementation constants.

| Domain | Candidate schema IDs |
| --- | --- |
| Runtime security | `chio.runtime.execution-lease.v1`, `chio.runtime.tool-server-ack.v1`, `chio.runtime.revocation-freshness-proof.v1`, `chio.runtime.sandbox-attestation.v1`, `chio.policy.activation-receipt.v1`, `chio.runtime.attack-simulation-report.v1`, `chio.runtime.chaos-run-report.v1` |
| Commerce payments | `chio.commerce.payment-lifecycle.v1`, `chio.commerce.mandate-allowance-ledger.v1`, `chio.commerce.dispute-recovery-ledger.v1`, `chio.commerce.fraud-assessment.v1`, `chio.commerce.currency-liquidity-ledger.v1`, `chio.commerce.recurring-agent-commerce.v1` |
| Crypto and trust | `chio.crypto.verification-context.v1`, `chio.trust.key-state.v1`, `chio.trust.revocation-snapshot.v1`, `chio.transparency.inclusion-proof.v1` |
| Workflow simulation | `chio.workflow.preflight-plan.v1`, `chio.workflow.preflight-report.v1`, `chio.workflow.what-if-delta.v1`, `chio.workflow.rehearsal-run.v1`, `chio.workflow.replay-capsule.v1`, `chio.workflow.model-provider-conformance.v1`, `chio.workflow.approval-gate.v1` |
| Enterprise evidence | `chio.enterprise.telemetry-projection.v1`, `chio.enterprise.data-governance-report.v1`, `chio.enterprise.policy-pack-manifest.v1`, `chio.enterprise.approval-case.v1`, `chio.enterprise.access-decision-report.v1`, `chio.enterprise.evidence-export-bundle.v1`, `chio.enterprise.control-evidence-map.v1`, `chio.enterprise.incident-review-case.v1`, `chio.enterprise.regulator-review-bundle.v1` |
| Trust-market context | `chio.commerce.provider-discovery-snapshot.v1`, `chio.commerce.provider-selection-report.v1`, `chio.trust.scorecard-snapshot.v1`, `chio.trust.reputation-import-report.v1`, `chio.commerce.sla-commitment.v1`, `chio.commerce.sla-performance-report.v1`, `chio.risk.collateral-position-report.v1`, `chio.risk.capital-commitment-snapshot.v1`, `chio.risk.guarantee-decision.v1`, `chio.risk.adjudication-jurisdiction-receipt.v1` |
| Agent Web automation | `chio.agent-web.automation-transcript.v1` only if browser or RPA transcripts become Chio-signed verifier inputs. First webhook, CloudEvents, GraphQL, identity, Kubernetes, and OCI slices should use the existing Agent Web envelope IDs. |
