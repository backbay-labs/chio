# Build Priority Matrix

Status: second-pass launch sequencing matrix
Confidence: high for priority order, moderate for effort sizing.

## Priority Principle

Launch should not start by widening the product surface. It should make the homepage claim provable through a small number of canonical artifacts.

The build order is:

1. root proof;
2. proof verifier;
3. runtime enforcement evidence;
4. first-run product evidence;
5. public fixtures;
6. commerce payments and settlement subgraphs;
7. recursive delegation and preflight;
8. disclosure, lineage, and crypto context;
9. risk, insurance, and enterprise evidence context;
10. external standards envelope and operational interop;
11. Proof Room polish and release truth.

## Priority Table

| Rank | Build priority | Why it matters | Current assets | Missing launch artifact | First useful slice |
| --- | --- | --- | --- | --- | --- |
| P0 | Transaction Passport | Without a signed root, the proof story fragments. | Receipts, evidence export, passport verifier primitives, canonical JSON, signed artifact registry. | `chio.transaction-passport.v1` and evidence graph verifier. | Minimal passport over one governed tool call. |
| P0 | `chio proof verify` | A proof layer must have a public verifier. | CLI, attest buyer verifier, replay verifier, runtime verifier, evidence export. | Unified proof command and normalized report. | `chio proof verify <transaction-passport.json>`. |
| P0 | Artifact registry discipline | Unknown signed-artifact schemas fail closed. | `spec/schemas/registry.json`, `KNOWN_SIGNED_ARTIFACT_SCHEMAS`. | Canonical schema IDs for launch artifacts. | Add Transaction Passport schemas and unknown-schema negative fixture. |
| P0 | Stage 0 Proof Room fixture | Public proof needs a clean starter. | Hello receipt/trust examples and Docker examples. | Single-call authority bundle. | Valid allow and invalid policy-hash fixture. |
| P0 | Runtime execution enforcement | After-the-fact proof is weaker than online prevention. | Kernel receipts, runtime admission, nonce concepts, tool-server isolation work. | Execution lease, nonce, revocation freshness proof, sandbox attestation, tool-server ack, and receipt totality claim. | Side-effecting call fails without execution lease. |
| P0 | First-run proof doctor | A proof layer that needs insider setup is not launchable. | CLI, fixtures, Docker examples, release truth scripts. | `chio proof doctor` and first-run evidence with allow plus denial. | Doctor rejects quickstart evidence without denial receipt. |
| P1 | Commerce order context | "Autonomous commerce" needs replayable state. | IOA web3 example, market, credit, settle, payment proof material. | `chio.commerce.order-context.v1`. | Replay order event log from IOA fixture. |
| P1 | Merchant payment lifecycle | Commerce proof needs capture, refund, dispute, chargeback, fraud, currency, PSP, and recurring mandate state. | AP2, x402, ACP-Commerce, settlement, credit, market examples. | Payment lifecycle, mandate allowance, dispute recovery, fraud assessment, currency liquidity ledgers. | Offline PSP-shaped fixture with AP2 and ACP-Commerce refs. |
| P1 | Settlement proof bundle | Settlement context must be independently bound. | `chio-web3`, `chio-settle`, anchor/link materials. | `chio.web3-settlement-proof-bundle.v1`. | Verify order id, chain id, tx/block/finality, and dispute posture in one fixture. |
| P1 | Recursive swarm authority | "Multi-swarm coordination" cannot be metadata-only. | runtime harness, federation continuation, routing, A2A/MCP/ACP-Client edges. | Swarm graph, continuation token, route-plan receipt, join receipt. | Runtime-spine fixture rejects stale continuation token. |
| P1 | Workflow preflight | Autonomous plans should fail before tokens, tools, budgets, or approvals are spent. | Runtime and replay surfaces, swarm authority plan. | Preflight plan and preflight report. | Reject broader child scope before execution. |
| P1 | Selective disclosure and lineage | "Selective disclosure" must be policy-enforced. | `chio-selective-disclosure`, BBS support, lineage crate, evidence export. | Disclosure capsule, privacy profile, signed lineage subgraph, leakage ledger. | Reject excess disclosure in one profile fixture. |
| P1 | Crypto verification context | BBS, SD-JWT, VC, and external proof are unsafe without key state, revocation, nonce, audience, and algorithm policy. | Core signing, disclosure, credentials, lineage. | Crypto verification context, key state, revocation snapshot, transparency inclusion state. | Disclosure capsule rejects replayed nonce or stale key state. |
| P1 | Risk comptroller report | Insurance and risk need reconciled state. | underwriting, appraisal, credit, market, reputation, governance, settlement. | `chio.risk.comptroller-report.v1`. | Facility state report with double-consumption negative fixture. |
| P1 | Enterprise evidence export | Buyers need evidence that is exportable, retainable, classifiable, approvable, and mappable to controls. | SIEM, metering, lineage, disclosure, control-plane and risk surfaces. | Enterprise data governance report, evidence export bundle, telemetry projection, approval case, control map. | Redacted export bundle binds back to Transaction Passport. |
| P1 | Trust-market context | A trust network needs provider discovery, local scorecards, SLAs, collateral, guarantee, and adjudication proof. | Market, reputation, credit, underwriting, settlement. | Discovery snapshot, selection report, scorecard, SLA, collateral, guarantee, jurisdiction receipt. | Marketplace-mode fixture rejects stale discovery and unsupported global score claim. |
| P2 | Agent Web Proof Envelope | External standards need digest-bound projection. | MCP, A2A, ACP-Client, AG-UI, OpenAPI bridges; AP2/x402 docs; passport projection work. | `chio.agent-web-proof-envelope.v1`. | Envelope for one MCP or A2A object plus unsupported-claim report. |
| P2 | Webhook and event interop | Real agents mutate systems through webhooks and event streams outside MCP/A2A. | Agent Web envelope, OpenAPI, HTTP, connector surfaces. | Standard Webhooks and CloudEvents projection values. | Webhook body digest mismatch fails. |
| P2 | Copy lint | Launch copy must not outrun proof. | scripts and docs gates exist in repo patterns. | launch-claim lint profile. | Ban bare `ACP`, universal protocol claims, and unsupported insurance/pricing claims. |
| P2 | Full Proof Room UI | UI should explain verifier output. | Evidence console ideas, CLI, docs. | Static bundle viewer. | Render Stage 0 report and failed claim path. |

## Do Not Start Here

These ideas are valuable but should not be first:

- adding more payment rails before order context exists;
- adding payment rails before payment lifecycle replay exists;
- adding more external protocol projections before the envelope manifest exists;
- building a polished UI before CLI verifier parity exists;
- expanding insurer pricing before comptroller report and capital adequacy evidence exist;
- adding more examples before the four-stage fixture catalog is generated and verified.
- launching marketplace, liquidity-pool, certification, compliance-platform, or hosted-plugin surfaces before the signed verifier contracts exist.

## Fastest Honest Launch Story

The shortest credible launch story is:

1. Stage 0 proves one governed action.
2. Stage 1 proves one autonomous commerce transaction.
3. Stage 2 proves one recursive delegation path.
4. Stage 3 proves one disclosure and external-envelope path.
5. Proof Room renders the same verifier reports.
6. Homepage copy links only to claims proven by those stages.
