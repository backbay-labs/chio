# Launch Source Map

Status: research index
Confidence: moderate. This file maps the agent campaign's repo observations, but it is not a fresh full-code audit.

## Compose-First Outcome

The launch implementation remains compose-first. The first implementation
home is still the existing protocol, economy, trust, platform, and product
crate that already owns the behavior. A new crate is accepted only when the
launch verifier boundary became durable enough to need its own tests, schemas,
and owner note.

Accepted PR #937 extraction boundaries:

- Transaction Passport: `crates/platform/chio-transaction-passport/DESIGN.md`
  documents the verifier root over existing receipt, policy, runtime, and
  evidence graph data.
- Commerce order context: `crates/platform/chio-commerce-order/DESIGN.md`
  documents the replay verifier over existing market, payment, settlement, and
  mandate evidence.
- Swarm authority: `crates/kernel/chio-swarm-authority/DESIGN.md` documents
  the offline verifier surface while runtime admission stays in the kernel and
  runtime paths.
- Disclosure lineage: `crates/trust/chio-disclosure-lineage/DESIGN.md`
  documents the disclosure verifier boundary over selective disclosure and
  lineage evidence.
- Risk comptroller: `crates/platform/chio-risk-comptroller/DESIGN.md`
  documents the report verifier over underwriting, credit, capital, and
  settlement evidence.
- Agent Web interop: `crates/platform/chio-agent-web-interop/DESIGN.md`
  documents projection verification over existing protocol adapters.
- Enterprise export: `crates/platform/chio-enterprise-export/DESIGN.md`
  documents evidence export verification over SIEM, telemetry, control, and
  disclosure sources.
- Trust-market context: `crates/platform/chio-trust-market-context/DESIGN.md`
  documents marketplace context verification over market, reputation, credit,
  governance, and settlement sources.
- Proof Room product: `crates/products/chio-proof-room/DESIGN.md` documents
  the product binary boundary. It consumes verifier outputs and does not own
  proof semantics.

The rows below preserve the original source mapping and now distinguish
implemented durable homes from remaining launch gaps. Future work should update
this file when a schema or crate boundary moves, folds into an existing owner,
or is explicitly scoped out.

## Proof, Receipts, And Passports

Existing assets:

- `chio-core` and `chio-core-types` define shared receipt and signing structures.
- `chio-kernel` and `chio-kernel-core` mediate runtime calls and emit receipts.
- `chio-control-plane` contains evidence export and passport verifier primitives.
- Protocol specs already discuss canonical JSON, receipt structure, governed transactions, and selective disclosure.

Launch gap:

- Remaining gaps are verifier-policy breadth, graph inspectability, and
  completeness of named negative fixtures. The root, evidence graph, claim-set,
  policy digest, and one-command verifier surfaces are implemented.

Planned artifacts:

- `chio.transaction-passport.v1`
- `chio.transaction.evidence-graph.v1`
- `chio.transaction.verifier-policy.v1`
- `chio.transaction.verifier-report.v1`

Durable home: `crates/platform/chio-transaction-passport` plus `chio-cli`
commands for collection, verification, explanation, serving, and export.

## Commerce And Settlement

Existing assets:

- Commerce examples and web3 examples demonstrate agent buying, provider matching, settlement, escrow, and proof concepts.
- `chio-settle`, `chio-market`, `chio-credit`, `chio-metering`, `chio-link`, and adjacent crates cover parts of pricing, markets, settlement, anchoring, and metering.
- Payment bridge work exists for x402-style flows and delegated payment style flows.

Launch gap:

- Remaining gaps are commerce replay depth, dedicated provider-admission
  schema policy, and broader payment projection fixtures. Order context, event
  replay, mandate, payment lifecycle, risk binding, and settlement binding have
  dedicated verifier surfaces.

Planned artifacts:

- `chio.commerce.order-context.v1`
- `chio.commerce.event-log.v1`
- `chio.commerce.order-passport.v1`
- `chio.commerce.provider-discovery-snapshot.v1`
- `chio.commerce.provider-selection-report.v1`
- `chio.commerce.settlement-packet.v1`

Durable home: `crates/platform/chio-commerce-order`, composed with economy,
market, credit, settlement, and risk evidence.

## Recursive Delegation And Swarms

Existing assets:

- Capability attenuation, nested flow receipts, route selection, and cross-protocol discovery already exist in parts of the repo.
- MCP, A2A, ACP-Client, HTTP/OpenAPI, and local runtime routes can participate in orchestration.

Launch gap:

- Remaining gaps are deeper fan-out conformance and observability detail.
  Recursive delegation, continuation validation, witness-chain binding,
  revocation epoch checks, route-plan receipts, and budget lease checks now
  have dedicated verifier coverage.

Planned artifacts:

- `chio.swarm.task-graph.v1`
- `chio.swarm.continuation-token.v1`
- `chio.swarm.delegation-witness-chain.v1`
- `chio.swarm.join-receipt.v1`
- `chio.swarm.route-plan-receipt.v1`
- `chio.swarm.budget-pool.v1`

Durable home: `crates/kernel/chio-swarm-authority`, with runtime admission
enforcement in kernel and runtime paths.

## Lineage And Selective Disclosure

Existing assets:

- `chio-selective-disclosure`, BBS projection work, federation verifier policy structures, evidence export, and lineage structures exist.
- Attest-buyer and passport verifier code can already reason over parts of disclosure.

Launch gap:

- Remaining gaps are runtime BBS mode depth and privacy export packaging.
  BBS projection manifest v2, signed lineage, disclosure capsule, leakage
  ledger, crypto context, hidden predicate, and excess disclosure verifier
  paths are implemented for the launch proof surface.

Planned artifacts:

- `chio.bbs-projection.manifest.v2`
- `chio.disclosure.capsule.v1`
- `chio.lineage.signed-subgraph.v1`
- `chio.disclosure.leakage-ledger.v1`
- `chio.disclosure.verifier-privacy-profile.v1`

Durable homes: `crates/trust/chio-selective-disclosure` and
`crates/trust/chio-disclosure-lineage`.

## Public Runtime And Web3 Proof

Existing assets:

- Internet-of-Agents web3 demo material, escrow/registry/bond concepts, oracle conversion evidence, anchoring, and proof narratives exist.
- There are settlement, link, anchor, and market primitives that can support public verification.

Launch gap:

- Remaining gaps are online readback scope and richer Proof Room settlement
  exploration. The launch fixture now requires independent head evidence,
  block-hash reorg checks, anchor proof bundles, settlement execution binding,
  and top-level bundle signatures.

Planned artifacts:

- `chio.web3-settlement-proof-bundle.v1`
- `chio.anchor-proof-bundle.v1`
- `chio.oracle-conversion-evidence.v1`
- `chio.public-settlement-verifier-report.v1`

Durable home: existing `crates/economy/chio-web3` and settlement fixtures.

## Risk, Comptroller, And Insurance

Existing assets:

- `chio-underwriting`, `chio-appraisal`, `chio-reputation`, governance, settlement, facility, bond, reserve, claim, and slashing concepts appear across repo assets.

Launch gap:

- Remaining gaps are standalone risk schema fold documentation and a few
  premium or capital invariant refinements. The comptroller report, facility
  lifecycle replay, reserve lanes, appeals, sanction reserve ledger, actuarial
  evidence, insurance copy bounds, and capital adequacy checks are implemented
  in the launch verifier path.

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

Durable home: `crates/platform/chio-risk-comptroller`, composed with credit,
underwriting, appraisal, settlement, and trust-market evidence.

## Proof Room And Developer Experience

Existing assets:

- CLI, examples, evidence review pages, docs, and demos exist.

Launch gap:

- Remaining gaps are product-overlay negatives and some layout polish. The
  launch reviewer path has `chio proof` commands, Proof Room rendering, doctor,
  release-truth linting, Docker quickstart support, and aggregate launch
  acceptance packaging.

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

Durable homes: `crates/products/chio-cli` for proof commands and
`crates/products/chio-proof-room` for product serving and static bundle checks.

## External Standards

Existing assets:

- Adapters and edges exist for MCP, A2A, ACP-Client, AG-UI, OpenAPI, and commerce/payment surfaces.
- The project can align with VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE as projection and envelope standards.

Launch gap:

- Remaining gaps are per-protocol fixture breadth. The proof envelope,
  projection manifest, interop verifier report, copy lint, source-log refresh,
  standards sign-off, and external protocol exit gate are implemented without
  treating external protocols as Chio authority.

Planned artifacts:

- `chio.agent-web-proof-envelope.v1`
- `chio.agent-web.external-projection-manifest.v1`
- `chio.agent-web.interop-verifier-report.v1`
- copy lint banning ambiguous external-standard claims.

Durable home: `crates/platform/chio-agent-web-interop`, composed with existing
protocol adapters and bounded sidecar evidence.
