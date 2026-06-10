# Launch Source Map

Status: research index
Confidence: moderate. This file maps the agent campaign's repo observations, but it is not a fresh full-code audit.

## Proof, Receipts, And Passports

Existing assets:

- `chio-core` and `chio-core-types` define shared receipt and signing structures.
- `chio-kernel` and `chio-kernel-core` mediate runtime calls and emit receipts.
- `chio-control-plane` contains evidence export and passport verifier primitives.
- Protocol specs already discuss canonical JSON, receipt structure, governed transactions, and selective disclosure.

Launch gap:

- No canonical `chio.transaction-passport.v1` artifact.
- No typed evidence graph root that joins receipts, lineages, policies, disclosures, commerce state, settlement state, and risk state.
- No one-command verifier that emits a buyer-readable report for the complete transaction.

Planned artifacts:

- `chio.transaction-passport.v1`
- `chio.transaction.evidence-graph.v1`
- `chio.transaction.verifier-policy.v1`
- `chio.transaction.verifier-report.v1`

## Commerce And Settlement

Existing assets:

- Commerce examples and web3 examples demonstrate agent buying, provider matching, settlement, escrow, and proof concepts.
- `chio-settle`, `chio-market`, `chio-credit`, `chio-metering`, `chio-link`, and adjacent crates cover parts of pricing, markets, settlement, anchoring, and metering.
- Payment bridge work exists for x402-style flows and delegated payment style flows.

Launch gap:

- No canonical order context or replay ledger.
- Settlement observer evidence can explain what happened after the fact, but it should not be the sole gate for dispatch.
- Provider passport, reputation, federation, budget, quote, mandate, and settlement facts are not yet one fail-closed commerce state machine.

Planned artifacts:

- `chio.commerce.order-context.v1`
- `chio.commerce.event-log.v1`
- `chio.commerce.order-passport.v1`
- `chio.commerce.provider-admission.v1`
- `chio.commerce.settlement-packet.v1`

## Recursive Delegation And Swarms

Existing assets:

- Capability attenuation, nested flow receipts, route selection, and cross-protocol discovery already exist in parts of the repo.
- MCP, A2A, ACP-Client, HTTP/OpenAPI, and local runtime routes can participate in orchestration.

Launch gap:

- Recursive delegation is not yet represented as a graph-level authority contract.
- Multi-hop attenuation needs explicit per-hop witnesses.
- Deferred task resume needs fresh continuation validation, revocation epoch checks, and live budget allocation.
- Route metadata is observability, not authority.

Planned artifacts:

- `chio.swarm.task-graph.v1`
- `chio.swarm.continuation-token.v1`
- `chio.swarm.delegation-witness-chain.v1`
- `chio.swarm.join-receipt.v1`
- `chio.swarm.route-plan-receipt.v1`
- `chio.swarm.budget-pool.v1`

## Lineage And Selective Disclosure

Existing assets:

- `chio-selective-disclosure`, BBS projection work, federation verifier policy structures, evidence export, and lineage structures exist.
- Attest-buyer and passport verifier code can already reason over parts of disclosure.

Launch gap:

- Kernel runtime does not consistently emit BBS-signed runtime receipts.
- Projection v1 is too thin and has spec/implementation divergence risk.
- Evidence export is a full audit package, not a privacy disclosure package.
- Verifier policy cannot yet reject excess disclosure or evaluate hidden predicates.

Planned artifacts:

- `chio.bbs-projection.manifest.v2`
- `chio.disclosure.capsule.v1`
- `chio.lineage.signed-subgraph.v1`
- `chio.disclosure.leakage-ledger.v1`
- `chio.disclosure.verifier-privacy-profile.v1`

## Public Runtime And Web3 Proof

Existing assets:

- Internet-of-Agents web3 demo material, escrow/registry/bond concepts, oracle conversion evidence, anchoring, and proof narratives exist.
- There are settlement, link, anchor, and market primitives that can support public verification.

Launch gap:

- Public web3 proof must recompute chain state from anchored evidence, not trust a demo transcript.
- Registry roots, escrow state, bond state, transaction hashes, block/finality, oracle conversion evidence, and dispute posture need one proof bundle.
- Chio identities and EVM addresses must be separated and bound by explicit proofs.

Planned artifacts:

- `chio.web3-settlement-proof-bundle.v1`
- `chio.anchor-proof-bundle.v1`
- `chio.oracle-conversion-evidence.v1`
- `chio.public-settlement-verifier-report.v1`

## Risk, Comptroller, And Insurance

Existing assets:

- `chio-underwriting`, `chio-appraisal`, `chio-reputation`, governance, settlement, facility, bond, reserve, claim, and slashing concepts appear across repo assets.

Launch gap:

- No canonical risk comptroller report.
- Facility lifecycle must be the launch contract for insurance and reserve behavior.
- Claim payout, reserve release, reserve slash, and market slash must not accidentally spend the same reserve twice.
- Autonomous insurer pricing claims require actuarial backtests and capital adequacy evidence.

Planned artifacts:

- `chio.risk.comptroller-report.v1`
- `chio.risk.facility-state-report.v1`
- `chio.risk.coverage-decision.v1`
- `chio.risk.claim-case-file.v1`
- `chio.risk.claim-appeal.v1`
- `chio.risk.sanction-reserve-ledger.v1`
- `chio.risk.portfolio-reconciliation-report.v1`
- `chio.risk.capital-adequacy-report.v1`
- `chio.risk.actuarial-backtest-report.v1`

## Proof Room And Developer Experience

Existing assets:

- CLI, examples, evidence review pages, docs, and demos exist.

Launch gap:

- A launch reviewer needs one command and one visual room, not a treasure hunt.
- Release/package truth is currently a risk: public artifacts must reflect actual package and release state.

Planned artifacts:

- `chio proof collect`
- `chio proof verify`
- `chio proof explain`
- `chio proof fixture generate`
- `chio proof serve`
- `chio proof export`
- `chio proof doctor`
- `chio.proof-room.bundle.v1`
- `chio.proof-room.verifier-report.v1`

## External Standards

Existing assets:

- Adapters and edges exist for MCP, A2A, ACP-Client, AG-UI, OpenAPI, and commerce/payment surfaces.
- The project can align with VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE as projection and envelope standards.

Launch gap:

- There is no single external "Agent Web Proof Envelope" standard to cite as if it already exists.
- The acronym `ACP` is ambiguous and should be qualified every time.
- Chio should project proof into protocol-specific metadata or sidecar references without pretending external protocols natively enforce Chio authority.

Planned artifacts:

- `chio.agent-web-proof-envelope.v1`
- `chio.agent-web.external-projection-manifest.v1`
- `chio.agent-web.interop-verifier-report.v1`
- copy lint banning ambiguous external-standard claims.
