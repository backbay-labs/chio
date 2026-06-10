# Launch Risk Register

Status: second-pass risk index
Confidence: high for risk categories, moderate for severity until implementation owners size the work.

## P0 Risks

| Risk | Why it matters | Evidence to retire it |
| --- | --- | --- |
| Proof fragmentation | The homepage claim fails if receipts, order context, settlement, disclosure, and risk remain separate demos. | `chio.transaction-passport.v1` verifies one complete fixture with all required subgraphs. |
| Schema-ID drift | The repo rejects unknown signed-artifact schemas, so informal names will create verifier gaps. | Every launch artifact in `artifact-registry.md` has schema, registry entry, fixture, and verifier constant. |
| "Every action" overclaim | Some actions may remain outside receipt coverage. | Receipt coverage matrix with explicit exclusions and proof room fixture coverage. |
| Swarm authority overclaim | Recursive execution without continuation tokens and per-hop witnesses is not verifiable delegation. | Negative fixture rejects stale continuation, broadened child scope, route mismatch, and bad join parent set. |
| Selective disclosure overclaim | Cryptographic proof alone is insufficient if verifier policy allows excess disclosure. | Privacy profile rejects forbidden fields and leakage ledger covers every disclosed fact. |
| Settlement overclaim | Demo settlement transcript is not public finality evidence. | Public settlement verifier recomputes chain/payment state from proof bundle. |
| Insurance overclaim | Autonomous pricing claims need actuarial and capital evidence. | Capital adequacy and actuarial backtest artifacts exist, or public copy limits insurance to auditable risk context. |
| Risk root missing | The repo has many risk-finance artifacts but no signed comptroller projection joining them. | `chio.risk.comptroller-report.v1` verifies underwriting, facility, reserve, claim, payout, settlement, reputation, governance, and slashing refs. |
| External standards drift | MCP, A2A, AP2, x402, SLSA, and commerce protocol names move quickly. | External source log is refreshed immediately before launch and copy lint enforces taxonomy. |
| Online enforcement gap | A passport can prove assembled evidence without proving the tool server enforced a live execution grant. | Side-effecting call requires execution lease, nonce, revocation freshness proof, policy digest, sandbox attestation, tool-server ack, and totality receipt. |
| First-run opacity | A proof system that requires insider evidence assembly will not survive launch review. | `chio proof doctor` validates valid and invalid fixtures, allow and denial receipts, docs command log, and release truth. |

## P1 Risks

| Risk | Why it matters | Evidence to retire it |
| --- | --- | --- |
| CLI sprawl | Users cannot verify the proof if commands are scattered. | `chio proof verify` is canonical and all lower-level commands produce compatible report JSON. |
| Proof Room as renderer only | A UI without verifier parity weakens credibility. | Proof Room displays the same verifier report emitted by CLI. |
| Provider trust ambiguity | Provider passport, reputation, and federation evidence can be mistaken for global scores. | Commerce admission report treats them as local-policy inputs with freshness and trust-root checks. |
| Risk ledger double consumption | Claim payout, reserve release, reserve slash, and market slash can spend the same reserve if not separated. | Ledger reconciliation negative fixture proves double consumption fails. |
| Claim appeal gap | Claim disputes exist, but appeal semantics can fail to block payout, release, slash, write-off, or closure. | `chio.risk.claim-appeal.v1` gates future projection without rewriting original signed artifacts. |
| Cross-currency netting | Facility, exposure, premium, reserve, capital, payout, settlement, and slash state can be misrepresented if currencies net together. | Currency invariant negative fixture rejects cross-currency netting. |
| Supply-chain proof confusion | Sigstore, SLSA, in-toto, and DSSE can be mistaken for runtime authority. | Agent Web verifier report labels supply-chain claims separately from runtime claims. |
| Merchant lifecycle flattening | Payment success can hide capture, refund, chargeback, fraud, transfer, recurrence, and currency failures. | Payment lifecycle and mandate allowance ledgers replay PSP-shaped state and reject unresolved disputes or mismatched currency. |
| Crypto context gap | Valid signatures and disclosure proofs can be replayed or accepted under stale keys, wrong audiences, or weak algorithms. | Crypto verification context binds key state, revocation snapshot, nonce, audience, holder binding, algorithm policy, and transparency state. |
| Preflight blind spot | Autonomous plans can be invalid before execution, but current proof is mostly post-execution. | Preflight report rejects broader child scope, missing approval, impossible budget, and route-plan gaps before token minting. |
| Enterprise export gap | Enterprise buyers need digest-bound export, retention, legal hold, PII, data residency, and control evidence. | Enterprise evidence export bundle, data governance report, approval case, telemetry projection, and control map verify against one passport. |

## P2 Risks

| Risk | Why it matters | Evidence to retire it |
| --- | --- | --- |
| Plan granularity | Existing plans are architecture-grade but not yet task-by-task implementation handoffs. | First sprint plan has file-level steps, failing tests, commands, and expected outputs. |
| Fixture maintenance | Launch fixtures can drift after code changes. | Fixture regeneration command and snapshot verifier run in CI. |
| Documentation copy drift | Homepage and docs can reintroduce banned claims. | Copy lint checks public docs for banned terms and overclaims. |
| Operational interop gap | Webhooks, GraphQL, events, browser/RPA, SaaS connectors, identity, Kubernetes, and OCI refs are outside the current Agent Web source list. | Interop source log and projection manifest add those subjects while preserving Chio-sidecar versus native-external proof labels. |
| Trust-market overclaim | Provider discovery, scorecards, SLAs, collateral, guarantees, and adjudication can be mistaken for a live marketplace. | Trust-market artifacts prove bounded selection context and block global score, liquidity pool, underwriter market, and slashing court claims. |
