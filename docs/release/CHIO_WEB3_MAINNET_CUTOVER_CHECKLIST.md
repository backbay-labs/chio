# Chio Web3 Mainnet Cutover Checklist

## Status

Mainnet is blocked until external assurance passes: independent external audit
with zero unresolved critical/high findings, four-week testnet soak, artifact
digest gate, deployed runtime codehash gate, minimum-bar checklist, and
security-owner sign-off. Base Sepolia smoke and operator manifest approval
are necessary after that gate, but they are not permission to deploy by
themselves.

## Pre-Cutover Gates

- Local runtime qualification is green: `./scripts/qualify-web3-runtime.sh`.
- Local end-to-end qualification is green: `./scripts/qualify-web3-e2e.sh`.
- Local ops qualification is green: `./scripts/qualify-web3-ops-controls.sh`.
- Promotion qualification is green: `./scripts/qualify-web3-promotion.sh`.
- Chio-mediated web3 example qualification is green:
  `./scripts/qualify-web3-examples.sh`.
- Base Sepolia promotion has a passing smoke report at
  `target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json`.
- The smoke report includes transaction hashes for operator/entity setup, USDC
  approval, escrow create, partial release, final release, timeout refund, root
  publication, and oracle price readback.
- The staged hosted artifact bundle includes runtime, promotion, e2e, ops,
  Base Sepolia smoke evidence, contract artifact JSON, contract release
  record, contract package, chain configuration, and schema manifest.
- The old `contracts/reports/local-devnet-qualification.json` and
  `contracts/reports/CHIO_WEB3_CONTRACT_SECURITY_REVIEW.md` are historical
  fixtures only.
- `contracts/reports/CHIO_WEB3_CONTRACT_GAS_AND_STORAGE.md` is historical
  budget evidence only. It is not promotion evidence without fresh artifact
  digest and deployed runtime codehash gates.
- External audit, testnet soak, artifact digest, runtime codehash,
  minimum-bar checklist, and security-owner sign-off are complete.
- The reviewed mainnet approval has a matching approved `--assurance-unlock`
  artifact.
- The staged hosted artifact bundle includes
  `examples/internet-of-agents-web3-network/summary.json`,
  `review-result.json`, `chio/topology.json`, Chio receipt and budget
  summaries, passport presentation verdict, federation admission verdict,
  reputation verdict, behavioral baseline status, RFQ selection, subcontractor
  lineage, signed approval, x402 payment proof, rail-selection rationale,
  dispute recovery, runtime degradation, observability, and all guardrail
  and adversarial denial receipts.

## Chio-Mediated Rehearsal Gate

Before any mainnet approval is prepared, run the local-realism agent-commerce
web3 rehearsal:

```bash
cargo build --bin chio
./scripts/qualify-web3-local.sh
./scripts/qualify-web3-examples.sh
```

If public testnet evidence exists and is required for the release gate, run:

```bash
examples/internet-of-agents-web3-network/smoke.sh \
  --artifact-dir target/web3-example-qualification/internet-of-agents-web3-network \
  --require-base-sepolia-smoke
```

The `review-result.json` verdict must be `ok: true`. The `summary.json` must
report `chio_mediated: true`, `mediation_status: pass`,
`budget_exposure: authorized`, `budget_reconciliation: reconciled`, passing
passport/federation/reputation/behavioral verdicts, `rfq_selection_status:
pass`, `subcontract_lineage_depth: 2`, `dispute_status: resolved`,
`approval_status: signed`, `x402_payment_status: satisfied`,
`rail_selection_status: pass`, `runtime_degradation_status:
quarantined_then_reattested`, `observability_status: correlated`,
`historical_reputation_status: pass`, denied invalid SPIFFE, overspend, and
velocity guardrails, and denied prompt injection, invoice tampering, quote
replay, expired capability reuse, unauthorized settlement route, and forged
passport controls. This gate proves local Chio mediation and evidence handling
only. It does not authorize mainnet transactions.

## Mainnet Inputs

- Mainnet deployer address funded with enough ETH for deployment plus a retry
  budget.
- Registry admin, price admin, operator, and delegate addresses split unless a
  written pilot exception approves a temporary one-wallet setup.
- Mainnet USDC token address reviewed against the intended settlement policy.
- Mainnet Chainlink feed addresses and heartbeat seconds reviewed from current
  Chainlink inventory.
- Mainnet sequencer uptime feed reviewed for the target network.
- CREATE2 factory address predeployed and recorded in the approval artifact.
- Base Builder Code configured for Base factory calls when the operator wants
  attribution.
- Private keys and CDP or RPC credentials supplied only through local secret
  material or deployment environment variables, never committed.

## Manifest And Approval

1. Materialize the reviewed mainnet manifest from
   `contracts/deployments/base-mainnet.template.json`.
2. Verify the manifest has no placeholders, no mock feed addresses, and no
   testnet dependency references.
3. Review and record the exact manifest SHA-256.
4. Complete the matching approval artifact with `status: approved`.
5. Confirm the approval binds the release id, policy id, environment, manifest
   hash, CREATE2 factory address, salt namespace, approvers, and rollback
   policy.
6. Dry-run manifest hashing and approval validation locally before any live
   transaction is sent.

## Cutover Execution

Do not execute this section before external assurance and an approved
`--assurance-unlock` artifact.

1. Export the mainnet RPC URL and signer keys in the operator shell.
2. Run the promotion runner with the reviewed Base mainnet manifest and
   approved artifact.
3. Watch each CREATE2 deployment transaction until confirmed.
4. Verify every deployed address matches the planned address in the deployment
   record.
5. Verify post-config transactions registered the operator, delegate, and live
   Chainlink feeds.
6. Run readback checks for registry status, delegate authorization, and price
   resolver freshness.
7. Archive the deployment record, promotion report, and rollback plan under the
   release qualification bundle.

## Abort Conditions

- Any manifest hash mismatch.
- Any unresolved placeholder in the reviewed manifest.
- Any mock Chainlink feed address in a mainnet manifest.
- Any CREATE2 planned address drift.
- Any failed or reverted deployment or post-config transaction.
- Any price readback failure, stale feed, or sequencer-down result.
- Any signer role mismatch against the reviewed approval.
- Any missing rollback plan after a failed promotion.
- Any missing, mismatched, or unapproved assurance artifact.

## Post-Cutover

- Attach BaseScan links for all deployment and post-config transactions.
- Record final contract addresses in the deployment inventory.
- Re-run runtime settlement readback against mainnet addresses with zero or
  dust-value settlement only if explicitly approved.
- Keep production settlement volume blocked until operations, monitoring, and
  incident response owners sign off.
- Open a separate release gate before enabling Solana, Chainlink CCIP, or x402
  production traffic.
