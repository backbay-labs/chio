# Chio Web3 Readiness Audit

## Purpose

This audit covers Chio's bounded web3 runtime stack.

It is intentionally narrower than the repository-wide release audit. The goal
here is to answer one question only: is the shipped web3 stack ready for
promotion from local qualification to operator-reviewed deployment templates?

## Decision

**Decision:** external assurance required. Local web3-runtime and
reviewed-promotion evidence is historical rehearsal coverage only. External
deployment, mainnet custody, and all non-testnet promotion are blocked until
the external assurance gate passes.

Meaning:

- the repo has one reproducible web3 qualification entrypoint:
  `./scripts/qualify-web3-runtime.sh`
- the repo has one reproducible ops-control drill lane:
  `./scripts/qualify-web3-ops-controls.sh`
- the repo has one reproducible partner-facing settlement lane:
  `./scripts/qualify-web3-e2e.sh`
- the repo has one reproducible reviewed-manifest promotion lane:
  `./scripts/qualify-web3-promotion.sh`
- the contract family, oracle runtime, anchor runtime, settlement runtime,
  and interop overlays all have explicit qualification artifacts
- runtime qualification now emits generated runtime reports, persisted
  control-state snapshots, append-only control traces, and one incident audit
  under `target/web3-ops-qualification/` and stages the same family into the
  hosted web3 bundle
- runtime qualification now also emits one generated end-to-end settlement
  proof bundle under `target/web3-e2e-qualification/` and stages the same
  family into `target/release-qualification/web3-runtime/e2e/`
- gas and latency budgets are frozen in
  `docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json`
- reviewed-manifest promotion now emits explicit approval, deployment-report,
  and rollback-plan artifacts
- mainnet publication remains blocked on external audit, testnet soak,
  artifact digest, runtime codehash, minimum-bar checklist, and
  security-owner sign-off. Hosted workflow observation and operator-owned
  target-chain approval material are still required after that gate.

## Security And Invariant Review

| Area | State | Disposition |
| --- | --- | --- |
| Contract proof, signature, delegate, stale-feed, and timeout invariants | historical | old review and local-devnet qualification are historical only; remediation is not promotion-closed until external re-review validates the current contract family |
| Runtime observability, replay, and pause controls | reviewed | closed through `docs/standards/CHIO_WEB3_OPERATIONS_PROFILE.md` and `docs/release/CHIO_WEB3_OPERATIONS_RUNBOOK.md` |
| On-chain Ed25519 verification | absent | accepted non-goal; identity binding remains registry-backed and explicit |
| Sanctions or blacklist screening | absent | operator obligation outside the shipped local runtime lane |
| Live CREATE2 deployment runner | present | closed through `contracts/scripts/promote-deployment.mjs`, `./scripts/qualify-web3-promotion.sh`, and explicit approval/rollback artifacts |
| Base Sepolia dependency bootstrap | present | closed for public testnet rehearsal through `contracts/scripts/deploy-base-sepolia-dependencies.mjs`, `contracts/scripts/refresh-base-sepolia-mock-feeds.mjs`, and `contracts/scripts/smoke-base-sepolia.mjs`; mainnet still requires reviewed live Chainlink feed addresses |
| Proxy upgrade path | absent | accepted by design; replacement deployments remain the fix path |

## Measured Budgets

Measured local-devnet gas came from the historical
`contracts/reports/local-devnet-qualification.json`. It remains budget context
only, not promotion evidence.

| Operation | Measured | Budget | Status |
| --- | ---: | ---: | --- |
| `registerOperator` | 97,958 | 110,000 | context |
| `registerDelegate` | 140,272 | 150,000 | context |
| `publishRoot` (operator) | 222,215 | 230,000 | context |
| `publishRoot` (delegate) | 196,015 | 230,000 | context |
| `registerFeed` | 123,638 | 140,000 | context |
| `getPrice` | 60,926 | 70,000 | context |
| `createEscrow` | 300,731 | 330,000 | context |
| `partialReleaseWithProofDetailed` | 169,790 | 180,000 | context |
| `releaseWithSignature` | 131,025 | 140,000 | context |
| `lockBond` | 322,524 | 330,000 | context |
| `releaseBondDetailed` | 151,768 | 160,000 | context |

Operational latency and drift budgets are also explicit:

- oracle refresh interval: `60s`
- bounded oracle max age: `600s`
- off-chain oracle sequencer recovery grace: `300s`
- on-chain price resolver sequencer recovery grace: `3600s`
- anchor indexer drift threshold: `3` checkpoints
- settlement indexer drift threshold: `12` blocks
- CCIP validity windows must remain at least `2x` the expected delivery latency

## Promotion Gate

Promotion from local devnet to operator-reviewed templates remains rehearsal
only and is allowed only when:

1. `./scripts/qualify-web3-runtime.sh` is green.
2. `./scripts/qualify-web3-e2e.sh` is green.
3. `./scripts/qualify-web3-promotion.sh` is green.
4. The reviewed manifest and approval artifact bind the same manifest hash,
   release id, deployment policy id, and CREATE2 salt namespace.
5. Replayed promotion over fresh local devnets yields identical CREATE2-planned
   and deployed addresses.
6. Failed promotion emits an explicit rollback plan, and local rehearsal proves
   snapshot rollback can execute fail closed.
7. The operator has reviewed `contracts/deployments/base-sepolia.template.json`
   and filled the placeholder addresses intentionally through the repo-shipped
   review-prep helper or an equivalent manifest-generation path. Mainnet and
   Arbitrum templates remain external-assurance only.
   Base Sepolia may use the dependency bootstrap helper's mock feed report only
   as public testnet evidence; mainnet approvals must use live Chainlink feeds.
   Public testnet mock feeds must be refreshed before delayed readback.
8. Base Sepolia promotion has a passing smoke report at
   `target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json` before any
   mainnet approval is prepared.
9. Web3-enabled runtime policy uses local durable receipt persistence with
   checkpoint issuance enabled; append-only remote receipt mirrors do not
   satisfy the promotion gate for Merkle or Solana evidence lanes.
10. The web3 operations and settlement/anchor/oracle runbooks are updated
   together with the candidate docs.
11. Same-candidate gas evidence is generated with artifact digest and runtime
    codehash binding, and it stays within the deployment policy budgets. Any
    overage blocks promotion until the contracts are optimized or the policy
    budgets are deliberately revised.

Promotion from template review to actual non-testnet deployment is blocked
until:

1. external audit reports zero unresolved critical/high findings,
2. the testnet soak, artifact digest, and minimum-bar checklist are signed off
   by the security owner,
3. `contracts/scripts/promote-deployment.mjs` receives an approved
   `--assurance-unlock` artifact for the exact approval, release, policy, and
   chain,
4. post-deployment runtime codehash verification passes before configuration or
   custody movement,
5. hosted `Release Qualification` results are observed on the candidate
   revision, including the staged artifact bundle under
   `target/release-qualification/web3-runtime/` and the generated ops-control
   evidence under `target/release-qualification/web3-runtime/ops/` plus the
   staged end-to-end settlement package under
   `target/release-qualification/web3-runtime/e2e/`,
6. the operator produces one environment-specific reviewed manifest and
   approval artifact with a predeployed CREATE2 factory address, and
7. operator RPC and deployer key material are supplied outside the repo for
   the target chain.

## Evidence

- `./scripts/qualify-web3-runtime.sh`
- `./scripts/qualify-web3-e2e.sh`
- `./scripts/qualify-web3-ops-controls.sh`
- `./scripts/qualify-web3-promotion.sh`
- `contracts/scripts/prepare-reviewed-manifest.mjs`
- `contracts/scripts/deploy-base-sepolia-dependencies.mjs`
- `contracts/scripts/refresh-base-sepolia-mock-feeds.mjs`
- `contracts/scripts/smoke-base-sepolia.mjs`
- `examples/internet-of-agents-web3-network/smoke.sh`
- `scripts/qualify-web3-examples.sh`
- `.github/workflows/release-qualification.yml`
- `./scripts/stage-web3-release-artifacts.sh`
- `target/web3-e2e-qualification/partner-qualification.json`
- `target/web3-e2e-qualification/scenarios/fx-dual-sign-settlement.json`
- `target/web3-e2e-qualification/scenarios/reorg-recovery.json`
- `target/web3-ops-qualification/incident-audit.json`
- `target/web3-ops-qualification/runtime-reports/chio-link-runtime-report.json`
- `target/web3-ops-qualification/runtime-reports/chio-anchor-runtime-report.json`
- `target/web3-ops-qualification/runtime-reports/chio-settle-runtime-report.json`
- `contracts/deployments/local-devnet.reviewed.json`
- `contracts/deployments/base-sepolia.template.json`
- `contracts/reports/local-devnet-qualification.json` (historical local evidence)
- `contracts/reports/CHIO_WEB3_CONTRACT_SECURITY_REVIEW.md` (historical review)
- `contracts/reports/CHIO_WEB3_CONTRACT_GAS_AND_STORAGE.md`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_OPERATOR_ENVIRONMENT.example`
- `docs/standards/CHIO_WEB3_OPERATIONS_PROFILE.md`
- `docs/release/CHIO_WEB3_OPERATIONS_RUNBOOK.md`
- `target/web3-promotion-qualification/review-prep/qualification.json`
