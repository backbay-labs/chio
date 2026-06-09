# Chio Launch System Map

Status: architecture map
Confidence: high for dependency order, moderate for exact crate boundaries.

## Product Shape

Chio should launch as a proof system, not as a pile of adapters. The public product shape is:

1. A kernel mediates governed actions and emits signed receipts.
2. A Transaction Passport binds receipts into a typed evidence graph.
3. Commerce order context, swarm authority, lineage, disclosure, settlement, and risk reports attach to the passport as typed subgraphs.
4. The Agent Web Proof Envelope projects the passport into external protocols and standards.
5. The Proof Room lets reviewers verify and inspect the result.

## Dependency Order

| Layer | Must exist before | Reason |
| --- | --- | --- |
| Receipt coverage and canonical schemas | Transaction Passport | The passport cannot root unverifiable or inconsistent artifacts. |
| Transaction Passport and evidence graph | Proof Room, external envelope | Every launch surface should point to one proof root. |
| Commerce order context | Settlement, risk, commerce launch demos | Settlement and risk need an order subject. |
| Swarm authority graph | Multi-swarm launch claim | Recursive action must be graph-bound before it is marketable. |
| Lineage and disclosure capsule | Private cross-boundary review | Privacy claims need verifier-enforced disclosure rules. |
| Public settlement proof bundle | Web3 launch claim | Chain/payment facts must be independently recomputable. |
| Risk comptroller report | Insurance and underwriting launch claim | Coverage and reserves need reconciled state. |
| Agent Web Proof Envelope | Partner interop claim | External protocols need sidecar proof semantics. |
| Proof Room | Homepage credibility | Buyers must see a working proof, not docs alone. |

## Canonical Artifact Families

### Root Proof

- `chio.transaction-passport.v1`
- `chio.transaction.evidence-graph.v1`
- `chio.transaction.verifier-policy.v1`
- `chio.transaction.verifier-report.v1`

### Runtime Authority

- governed action receipt;
- capability proof;
- guard evaluation;
- policy hash;
- receipt signature and key material;
- trust root bundle.

### Recursive Delegation

- `chio.swarm.task-graph.v1`
- `chio.swarm.continuation-token.v1`
- `chio.swarm.delegation-witness-chain.v1`
- `chio.swarm.join-receipt.v1`
- `chio.swarm.route-plan-receipt.v1`
- `chio.swarm.budget-pool.v1`

### Commerce And Settlement

- `chio.commerce.order-context.v1`
- `chio.commerce.event-log.v1`
- `chio.commerce.order-passport.v1`
- AP2 mandate refs;
- x402 challenge/verify/settle transcripts;
- ACP-Commerce delegated-payment binding;
- web3 settlement proof bundle;
- dispute and reconciliation state.

### Lineage And Privacy

- `chio.lineage.signed-subgraph.v1`
- `chio.disclosure.capsule.v1`
- `chio.bbs-projection.manifest.v2`
- `chio.disclosure.verifier-privacy-profile.v1`
- `chio.disclosure.leakage-ledger.v1`

### Risk And Insurance

- `chio.risk.comptroller-report.v1`
- `chio.risk.facility-state-report.v1`
- `chio.risk.coverage-decision.v1`
- `chio.risk.claim-case-file.v1`
- `chio.risk.capital-adequacy-report.v1`

### External Proof

- `chio.agent-web-proof-envelope.v1`
- `chio.agent-web.external-projection-manifest.v1`
- `chio.agent-web.interop-verifier-report.v1`

## Launch Claim Gates

The system can support the homepage copy only if the public proof shows:

1. A user can run `chio proof verify` against a fixture bundle and reproduce the same verdict.
2. The verifier report names every missing or invalid proof element.
3. A single-agent action can be verified without external services.
4. A commerce transaction can be verified from order context through settlement context.
5. A recursive swarm action can be verified through all child action authority.
6. A selective disclosure proof can fail closed for excess disclosure.
7. A risk comptroller report can reconcile reserve and claim state.
8. External protocol projections identify what the external protocol proves and what Chio proves.

## Architectural Provocation

The main launch risk is not that Chio lacks ambitious features. It is that Chio may have too many ambitious features that do not meet in one public proof. The engineering priority should be ruthless: make the Transaction Passport the join point, make every domain report attach to it, and make the verifier the judge.
