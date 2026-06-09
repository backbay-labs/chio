# Chio Launch Research Index

Status: research package for launch planning
Branch: `research/chio-launch-trust-network`
Confidence: high that the package captures the current launch architecture gaps from the agent campaign; moderate that individual implementation estimates survive engineering review.

## Thesis

The homepage promise is not a narrow runtime attestation story. It says Chio is the trust network for autonomous commerce and the proof layer for the emerging agent web. That means the launch proof must join five hard things:

1. Verifiable authority for every action.
2. Recursive delegation across multi-agent and multi-protocol execution.
3. Lineage and selective disclosure across trust boundaries.
4. Commerce, settlement, risk, and insurance context.
5. A public proof room that a skeptical developer, buyer, or partner can verify without internal knowledge.

If any of those stay as isolated demos, the copy overclaims. If they are joined by a signed Transaction Passport and a public verifier, the copy becomes defensible.

## Campaign Outputs

| Area | Raw agent research | Architecture outline | Build plan | Launch role |
| --- | --- | --- | --- | --- |
| Transaction Passport and evidence graph | `agent-drafts/01-transaction-passport-evidence-graph.md` | `architecture/01-transaction-passport-system.md` | `plans/01-transaction-passport-implementation.md` | Root artifact that makes a transaction independently reviewable. |
| Commerce order and settlement context | `agent-drafts/02-commerce-order-settlement-context.md` | `architecture/02-commerce-order-system.md` | `plans/02-commerce-order-implementation.md` | Turns "autonomous commerce" into a governed order state machine. |
| Swarm authority and recursive delegation | `agent-drafts/03-swarm-authority-recursive-delegation.md` | `architecture/03-swarm-authority-system.md` | `plans/03-swarm-authority-implementation.md` | Makes multi-hop and multi-swarm coordination verifiable instead of narrative. |
| Lineage, selective disclosure, and privacy | `agent-drafts/04-lineage-disclosure-privacy.md` | `architecture/04-lineage-disclosure-system.md` | `plans/04-lineage-disclosure-implementation.md` | Makes "lineage" and "selective disclosure" real verifier behavior. |
| Public runtime and web3 settlement proof | `agent-drafts/05-public-runtime-settlement-passport-web3.md` | `architecture/05-public-settlement-passport-system.md` | `plans/05-public-settlement-passport-implementation.md` | Makes the public runtime proof strong enough to carry web3 settlement claims. |
| Risk comptroller, facility, and insurance | `agent-drafts/06-risk-comptroller-facility-insurance.md` | `architecture/06-risk-comptroller-system.md` | `plans/06-risk-comptroller-implementation.md` | Makes underwriting, reserves, claims, slashing, and coverage auditable. |
| Proof Room and developer experience | `agent-drafts/07-proof-room-developer-experience.md` | `architecture/07-proof-room-system.md` | `plans/07-proof-room-implementation.md` | Converts the architecture into a launchable demo and review surface. |
| External proof envelope and standards alignment | `agent-drafts/08-external-standards-proof-envelope.md` | `architecture/08-agent-web-proof-envelope-system.md` | `plans/08-agent-web-proof-envelope-implementation.md` | Projects Chio proof into MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE without claiming to replace them. |

## Cross-Cutting Files

- `architecture/00-system-map.md` maps the final proof system and dependency order.
- `architecture/09-integration-contracts.md` defines the cross-artifact join rules that keep the proof system from fragmenting.
- `indices/source-map.md` maps existing repo assets, gaps, and planned artifacts.
- `indices/verification-gates.md` translates launch copy into concrete verifier gates.
- `indices/artifact-registry.md` is the canonical schema-ID registry for this research package.
- `indices/external-standards-source-log.md` records official standards sources checked on 2026-06-09.
- `indices/launch-risk-register.md` ranks the launch risks that must shape execution order.
- `indices/proof-room-fixture-catalog.md` defines the staged public fixture catalog and negative-control floor.
- `indices/build-priority-matrix.md` ranks the build sequence by launch proof dependency.
- `indices/decision-ledger.md` records second-pass architectural decisions and unresolved owner choices.
- `indices/execution-slice-contract.md` defines shared-file ownership, default crate homes, and agent-ready slice boundaries.
- `indices/debate-synthesis.md` integrates the third-wave feature debate into accepted priorities, candidate artifacts, and deferrals.
- `plans/00-roadmap.md` orders the work into a launch sequence and defines stop rules.
- `plans/09-first-implementation-sprint.md` turns the first build slice into an agentic worker handoff.
- `agent-debate/15-*.md` through `agent-debate/22-*.md` preserve the third-wave debate memos.

## Non-Negotiable Launch Requirements

1. A Transaction Passport must be a signed root artifact, not a markdown report.
2. The passport must bind a typed evidence graph, not a directory of unrelated JSON files.
3. Every signed artifact schema ID must use the canonical names in `indices/artifact-registry.md`.
4. Commerce must be represented as a monotonic order context and replay ledger.
5. Settlement evidence must be subordinate to Chio authority unless it is independently verified and bound to a chain or payment system.
6. Recursive delegation must carry per-hop attenuation witnesses and continuation tokens.
7. A multi-parent swarm join must have a signed join receipt.
8. Selective disclosure must reject excess disclosure under privacy profiles.
9. Lineage must be exported as a signed, redacted subgraph with a leakage ledger.
10. Risk and insurance claims must resolve through a risk comptroller report that reconciles exposure, reserve, bond, claim, payout, settlement, reputation, and governance state.
11. Public proof must be runnable through a single CLI verifier and visible in the Proof Room.
12. External standards integration must be an envelope and projection layer. Chio should not claim to replace MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, or DSSE.
13. Bare `ACP` copy is banned. Use `ACP-Client` for Agent Client Protocol, `ACP-Commerce` for Agentic Commerce Protocol, and `AGNTCY-ACP` only for historical Agent Connect Protocol references.
14. Runtime-enforced authority must include online execution evidence, not only after-the-fact proof assembly.
15. Product launch must include first-run evidence and `chio proof doctor`, or the proof layer remains insider-only.

## Strongest Missing Feature

The missing launch feature is the signed Transaction Passport with verifier-grade sub-artifacts. It is the only single product surface that can honestly connect action authority, swarm delegation, lineage, selective disclosure, settlement, and risk. Without it, Chio has many strong primitives but no public proof object that matches the homepage claim.

## Strongest Code Risk

The repo appears to contain many valuable demos and domain crates, but the evidence is still too fragmented. A launch reviewer should not have to know which receipts, ledgers, fixtures, registry snapshots, payment proofs, disclosure proofs, and risk state files matter. The code needs a canonical proof assembly and verification path, or the project will look broad but not decisive.

## Completion Standard For This Research Package

This package is complete when it has:

- eight raw agent research drafts;
- eight architecture outlines;
- eight implementation plans;
- cross-cutting architecture contracts;
- a canonical artifact registry;
- a source map;
- launch claim verification gates;
- a standards source log with access dates;
- a fixture catalog with negative controls;
- a build priority matrix and decision ledger;
- a phase-ordered roadmap;
- a first implementation sprint handoff;
- second-wave agent reviews preserved as evidence;
- third-wave debate memos and synthesis preserved as evidence;
- no unresolved placeholder markers;
- no Unicode punctuation that violates the repo documentation convention.
