# Launch Verification Gates

Status: launch claim gate index
Confidence: high for gate logic, moderate for current implementation status.

## Gate Classes

| Class | Meaning | Failure mode |
| --- | --- | --- |
| Authority gate | Proves the actor had bounded authority for the action. | Deny or mark the proof unverifiable. |
| Delegation gate | Proves each child action was authorized by its parent context. | Deny the child action and flag the continuation chain. |
| Lineage gate | Proves the action belongs to the claimed transaction graph. | Reject the passport root. |
| Disclosure gate | Proves the verifier saw exactly the allowed facts and no forbidden facts. | Reject the disclosure capsule. |
| Commerce gate | Proves order, quote, budget, mandate, payment, fulfillment, and settlement were coherent. | Reject order advancement or downgrade launch claim. |
| Risk gate | Proves exposure, reserve, bond, coverage, claim, payout, and slash state reconcile. | Block facility transition or mark insurance claim unsupported. |
| External envelope gate | Proves Chio facts are bound to external protocol objects by digest or signature. | Mark interop proof detached or advisory only. |
| Runtime enforcement gate | Proves online execution had a kernel allow receipt, execution lease, nonce, fresh revocation view, policy digest, sandbox attestation, and tool-server acknowledgement. | Reject runtime authority claim or mark evidence advisory. |
| Workflow preflight gate | Proves an autonomous plan was checked before live authority, budget, tool calls, or approvals were spent. | Reject plan execution or require fresh approval/reminting. |
| Enterprise export gate | Proves evidence export obeyed classification, residency, retention, legal hold, approval, and redaction rules. | Reject export or mark it noncompliant with policy. |
| Public proof gate | Proves a third party can run the verifier and reproduce the verdict. | Block launch proof publication. |

## Homepage Copy To Required Proof

| Copy claim | Required proof | Minimum launch artifact |
| --- | --- | --- |
| "The trust network for autonomous commerce" | A governed order context that joins authority, quote, budget, payment, settlement, risk, and review. | Transaction Passport with commerce order context and risk comptroller refs. |
| "Proof layer" | A signed proof root, typed evidence graph, deterministic verifier, and replayable verifier report. | `chio.transaction-passport.v1` plus `chio proof verify`. |
| "Emerging agent web" | Projections into MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE without replacing them. | Agent Web Proof Envelope. |
| "Every action" | Kernel-mediated receipt for each governed action or explicit unsupported-action exclusion. | Receipt coverage report. |
| "Single agent call" | Standalone call receipt with capability, policy, guard, decision, request/response digests, and signature. | Minimal passport fixture. |
| "Multi-swarm coordination" | Swarm graph, continuation tokens, per-hop witnesses, route-plan receipts, join receipts, revocation epoch, and budget pool. | Swarm passport fixture. |
| "Verifiable authority" | Capability validation and issuer/key/trust-root verification. | Authority section in verifier report. |
| "Recursive delegation" | Parent-to-child witness chain, attenuation proof, and continuation token freshness. | Delegation witness chain. |
| "Lineage" | Signed graph from intent to action to receipt to outcome. | Signed lineage subgraph. |
| "Selective disclosure" | BBS or equivalent disclosure capsule with verifier policy, hidden predicates, and leakage ledger. | Disclosure Capsule. |
| "Settlement context" | Bound order, mandate, payment proof, escrow/settlement state, dispute posture, and finality. | Commerce order passport plus public settlement proof bundle. |
| "Across trust boundaries" | External projection envelope with source protocol object digest, Chio receipt refs, and verifier report. | Agent Web Proof Envelope. |
| "Autonomous commerce" | Order replay plus merchant payment lifecycle, mandate allowance, currency liquidity, dispute posture, and risk reconciliation. | Commerce order context plus payment lifecycle ledger. |

## Hard Stop Rules

1. Do not ship the homepage claim if the proof room only shows isolated demos.
2. Do not claim "every action" without a receipt coverage matrix and known exclusions.
3. Do not claim "multi-swarm coordination" until nested child execution rejects stale continuation tokens, revoked epochs, and route-plan mismatches.
4. Do not claim "selective disclosure" until verifier profiles reject excess disclosure.
5. Do not claim "settlement context" until settlement evidence is bound to order context and public verifier inputs.
6. Do not claim "insurance" as autonomous pricing until actuarial backtests, reserve adequacy, and capital-charge rules exist.
7. Do not use bare `ACP` in launch docs.
8. Do not present x402, AP2, ACP-Commerce, or web3 settlement as ambient Chio authority. They are subordinate evidence unless Chio validates and binds them.
9. Do not claim runtime-enforced authority for side-effecting tools without execution leases, nonce defaults, revocation freshness, sandbox attestation, and tool-server acknowledgements.
10. Do not claim first-run launch readiness without `chio proof doctor` and both allow and denial evidence.
11. Do not claim AI-native autonomous planning without preflight or replay evidence that is clearly separate from live execution proof.

## Proof Room Acceptance

The launch proof room should contain at least four fixtures:

1. Minimal single-agent governed call:
   - valid capability;
   - guard allow/deny pair;
   - signed receipt;
   - deterministic verifier report.
2. Autonomous commerce transaction:
   - order context;
   - provider selection;
   - quote;
   - mandate or approval;
   - budget reservation;
   - payment or settlement proof;
   - risk comptroller report when coverage, reserve, bond, claim, payout, slash, or facility state is claimed;
   - Transaction Passport.
3. Recursive swarm transaction:
   - task graph;
   - continuation tokens;
   - route-plan receipts;
   - multi-parent join receipt;
   - delegated receipts.
4. Disclosure and external envelope:
   - selective disclosure capsule;
   - signed lineage subgraph;
   - leakage ledger;
   - Agent Web Proof Envelope;
   - external projection verifier report.

Each fixture must include negative cases that fail for a real reason:

- stale capability;
- mismatched policy hash;
- stale continuation token;
- wrong route-plan receipt;
- over-disclosed proof;
- settlement proof that does not bind the order;
- risk report with unreconciled reserves.
- double reserve consumption;
- open claim appeal blocking closure;
- external projection digest mismatch.
- missing execution lease;
- advisory evidence used as authorization;
- first-run evidence without denial receipt;
- broader child scope accepted in preflight;
- enterprise export over-discloses PII;
- webhook signature accepted as Chio authorization.
