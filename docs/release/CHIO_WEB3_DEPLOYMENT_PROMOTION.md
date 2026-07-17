# Chio Web3 Deployment Promotion

## Purpose

This document defines how the shipped bounded web3 stack moves from local
qualification to reviewed-manifest rollout without implying unattended
public-chain deployment.

## Non-Testnet Guard

Mainnet deployment, non-testnet custody, and non-testnet promotion are blocked
until external audit, testnet soak, artifact digest, runtime codehash, and
minimum-bar checks pass with security-owner sign-off. Local and Base Sepolia
lanes are rehearsal only. The local-devnet qualification JSON and prior
contract security review are historical evidence, not promotion signals.

## Promotion Inputs

The bounded runner takes three explicit inputs:

- one reviewed deployment manifest
- one approval artifact that binds the exact manifest hash and shipped package
- one output directory that persists the promotion report, deployment record,
  and rollback plan

For local rehearsal those inputs are:

- `contracts/deployments/local-devnet.reviewed.json`
- a generated approval artifact under `target/web3-promotion-qualification/`
- `--local-devnet --rollback-on-failure`

For non-testnet operator rollout the reviewed manifest is derived from one
shipped template:

- `contracts/deployments/base-mainnet.template.json`
- `contracts/deployments/base-sepolia.template.json`
- `contracts/deployments/arbitrum-one.template.json`

The approval artifact must bind:

- `candidate_release_id`
- `deployment_policy_id`
- `reviewed_manifest_path`
- `reviewed_manifest_sha256`
- `environment`
- `create2.factory_mode`
- `create2.factory_address` for non-local rollout
- `create2.salt_namespace`
- explicit approver identities and timestamps
- explicit failure policy

## Promotion Stages

### 1. Runtime Qualification

Run:

```bash
./scripts/qualify-web3-runtime.sh
```

Required evidence:

- `contracts/reports/local-devnet-qualification.json` (historical local evidence)
- `target/web3-runtime-qualification/qualification.log`
- `docs/release/CHIO_WEB3_READINESS_AUDIT.md`

### 2. Promotion Qualification

Run:

```bash
./scripts/qualify-web3-promotion.sh
```

Required evidence:

- `target/web3-promotion-qualification/review-prep/qualification.json`
- `target/web3-promotion-qualification/promotion-qualification.json`
- `target/web3-promotion-qualification/run-a/promotion-report.json`
- `target/web3-promotion-qualification/run-a/rollback-plan.json`
- `target/web3-promotion-qualification/run-b/promotion-report.json`
- `target/web3-promotion-qualification/negative-approval/promotion-report.json`
- `target/web3-promotion-qualification/negative-rollback/rollback-plan.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json`

This lane proves three invariants:

- every shipped public-chain template can be materialized into a reviewed
  manifest plus pending-review approval scaffold with no unresolved
  operator-supplied placeholders
- the same reviewed manifest produces identical CREATE2-planned and deployed
  addresses across fresh local devnets
- tampered approval artifacts fail closed before deployment begins
- failed local promotion emits an explicit rollback plan and executes snapshot
  rollback when the runner is asked to do so

### 3. Runtime Devnet Rehearsal

Use the runtime devnet harness when the operator wants end-to-end rehearsal
over the settlement runtime rather than contract-only smoke coverage.

Required evidence:

- `contracts/deployments/runtime-devnet.json`
- `cargo test -p chio-settle --test runtime_devnet -- --nocapture`

### 4. Reviewed Manifest Rollout

Local rehearsal command:

```bash
node contracts/scripts/promote-deployment.mjs \
  --manifest contracts/deployments/local-devnet.reviewed.json \
  --approval target/web3-promotion-qualification/run-a/approval.json \
  --output-dir target/web3-promotion-qualification/manual-run \
  --local-devnet \
  --rollback-on-failure
```

Non-testnet rollout command shape:

```bash
node contracts/scripts/promote-deployment.mjs \
  --manifest contracts/deployments/base-mainnet.reviewed.json \
  --approval approvals/base-mainnet.approval.json \
  --output-dir target/web3-live-rollout/base-mainnet \
  --rpc-url "$CHIO_BASE_RPC_URL" \
  --deployer-key "$CHIO_BASE_DEPLOYER_KEY" \
  --registry-admin-key "$CHIO_BASE_REGISTRY_ADMIN_KEY" \
  --operator-key "$CHIO_BASE_OPERATOR_KEY" \
  --price-admin-key "$CHIO_BASE_PRICE_ADMIN_KEY" \
  --assurance-unlock approvals/base-mainnet.assurance.json
```

Public testnet rehearsal command shape:

```bash
pnpm --dir contracts deploy:base-sepolia-deps \
  --rpc-url "$CHIO_BASE_SEPOLIA_RPC_URL" \
  --deployer-key "$CHIO_BASE_SEPOLIA_DEPLOYER_KEY" \
  --role-address "$CHIO_BASE_SEPOLIA_WALLET" \
  --operator-key-hash "$CHIO_BASE_SEPOLIA_OPERATOR_KEY_HASH" \
  --base-builder-code "$CHIO_BASE_BUILDER_CODE" \
  --output-dir target/web3-live-rollout/base-sepolia/dependencies

node contracts/scripts/prepare-reviewed-manifest.mjs \
  --template contracts/deployments/base-sepolia.template.json \
  --values-file target/web3-live-rollout/base-sepolia/dependencies/base-sepolia.review-inputs.json \
  --environment base-sepolia \
  --output contracts/deployments/base-sepolia.reviewed.json \
  --approval-output approvals/base-sepolia.approval.json

pnpm --dir contracts refresh:base-sepolia-feeds \
  --dependencies target/web3-live-rollout/base-sepolia/dependencies/dependencies.json \
  --output target/web3-live-rollout/base-sepolia/dependencies/feed-refresh.json

node contracts/scripts/promote-deployment.mjs \
  --manifest contracts/deployments/base-sepolia.reviewed.json \
  --approval approvals/base-sepolia.approval.json \
  --output-dir target/web3-live-rollout/base-sepolia \
  --rpc-url "$CHIO_BASE_SEPOLIA_RPC_URL" \
  --deployer-key "$CHIO_BASE_SEPOLIA_DEPLOYER_KEY" \
  --registry-admin-key "$CHIO_BASE_SEPOLIA_REGISTRY_ADMIN_KEY" \
  --operator-key "$CHIO_BASE_SEPOLIA_OPERATOR_KEY" \
  --price-admin-key "$CHIO_BASE_SEPOLIA_PRICE_ADMIN_KEY" \
  --base-builder-code "$CHIO_BASE_BUILDER_CODE"

pnpm --dir contracts smoke:base-sepolia \
  --deployment target/web3-live-rollout/base-sepolia/promotion/deployment.json \
  --dependencies target/web3-live-rollout/base-sepolia/dependencies/dependencies.json \
  --output target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json
```

The dependency step is for public testnet rehearsal only. It deploys a Base
Sepolia CREATE2 factory plus mock Chainlink-compatible aggregators and emits
`base-sepolia.review-inputs.json`. The `CHIO_BASE_SEPOLIA_OPERATOR_KEY_HASH`
value is the runtime Ed25519 public-key hash that promotion registers on chain.
Mainnet promotion must replace those mock feed placeholders with reviewed live
Chainlink feed addresses. Refresh the testnet mock feed timestamps before
delayed readback or any rehearsal that waits longer than the configured
heartbeat windows.

The Base Sepolia smoke reads the promoted deployment record, then executes the
minimum public-chain transaction path: operator/entity setup, mock feed refresh,
price readback, USDC approval, proof-root publication, escrow create, partial
proof release, final proof release, and timeout refund. It must finish with
`status: pass` and preserve transaction hashes under
`target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json`.

For a one-wallet pilot, the review-inputs file can set `role_address` plus
`operator_key_hash`; `prepare-reviewed-manifest.mjs` will use the role address
as registry admin, price admin, operator, and delegate. Production promotion
should split those roles before mainnet approval.

Prepare one reviewed chain manifest from one shipped template:

- `contracts/deployments/base-mainnet.template.json`
- `contracts/deployments/base-sepolia.template.json`
- `contracts/deployments/arbitrum-one.template.json`

Review-prep helper:

```bash
node contracts/scripts/prepare-reviewed-manifest.mjs \
  --template contracts/deployments/base-sepolia.template.json \
  --values-file approvals/base-sepolia.review-inputs.json \
  --environment base-sepolia \
  --output contracts/deployments/base-sepolia.reviewed.json \
  --approval-output approvals/base-sepolia.approval.json
```

The generated approval scaffold is not rollout-ready by itself. It is emitted
with `status: pending-review`, binds the exact reviewed manifest hash, and
gives the operator one file to complete after review instead of hand-assembling
the shape from examples.

Coinbase/CDP local setup:

```bash
npm install -g @coinbase/cdp-cli
codex mcp add cdp -- cdp mcp
codex mcp add payments-mcp -- node "$HOME/.payments-mcp/bundle.js"

cdp env live --key-file /private/path/cdp-api-key.json
cdp env live --wallet-secret-file /private/path/cdp_wallet_secret.txt
cdp env
```

`CHIO_COINBASE_CLIENT_API_KEY` is a Base Node/RPC client key. It can form
`CHIO_BASE_SEPOLIA_RPC_URL` as
`https://api.developer.coinbase.com/rpc/v1/base-sepolia/${CHIO_COINBASE_CLIENT_API_KEY}`.
CDP server-wallet writes still require a Secret API Key JSON plus Wallet Secret
configured through `cdp env`.

Required review points:

- registry-admin, price-admin, and operator addresses are filled explicitly
- non-testnet promotion has an approved assurance artifact with matching
  approval id, release id, policy id, chain id, and security-owner sign-off
- testnet and mainnet feed addresses plus heartbeat_seconds are reviewed
  intentionally against current Chainlink inventory before approval
- Base Sepolia smoke evidence is attached for the promoted deployment before
  any mainnet approval proceeds
- Base Builder Code attribution is present on CREATE2 factory calls when
  `--base-builder-code` is set; strict ABI registry and oracle configuration
  calls remain unsuffixed
- settlement token address matches the intended jurisdiction and custody model
- CREATE2 salts remain unchanged from the shipped package unless a new version
  is cut intentionally
- the reviewed manifest hash recorded in the approval artifact matches the file
  sent to the runner exactly
- non-local rollout uses one predeployed CREATE2 factory address recorded in
  the approval artifact
- if deployer, registry admin, operator, and price admin are distinct, the
  runner must receive signer keys for those reviewed roles explicitly
- deferred capabilities in
  `docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json` remain deferred unless a
  separate reviewed package version reopens them

### 5. Hosted Publication Gate

Public deployment remains held outside the repo-local gate until:

- external audit, testnet soak, artifact digest, runtime codehash, and
  minimum-bar gates pass with zero unresolved critical/high findings
- hosted workflow observation is attached to the candidate revision
- the staged hosted artifact bundle under `target/release-qualification/web3-runtime/`
  includes both runtime and promotion qualification evidence
- the operator approves the exact reviewed manifest and target-chain rollout
  explicitly

## Rollback Rule

If any promotion stage fails, return to the last qualified stage and keep the
later stage blocked.

Examples:

- over-budget gas on a new contract build: return to local qualification
- approval artifact mismatch: stop before any deployment transaction is sent
- reviewed-manifest CREATE2 drift: stop and recut the manifest or package
- runtime-devnet replay or reorg mismatch: return to local qualification and
  re-run the rehearsal only after recovery
- missing live-chain RPC, deployer key, or predeployed CREATE2 factory:
  stop before any live chain work

Local rollback semantics:

- the local runner captures an EVM snapshot after dependency and factory setup
- failed local promotion can execute `evm_revert` and mark
  `rollback_executed: true`

Operator rollback semantics:

- live rollback is replacement-oriented, not proxy-upgrade-oriented
- stop broader promotion immediately
- retain the reviewed manifest, approval, report, and rollback plan
- recut a replacement reviewed manifest if a fix is required

## Non-Claims

- This document does not claim that Chio performs unattended testnet or mainnet
  deployment.
- This document does not claim that local-devnet qualification, ABI parity, or
  the prior security review authorizes non-testnet promotion.
- This document does not replace custody, sanctions, or legal review required
  by the operator.
- This document does not override the repository-wide release rule that hosted
  workflow results must still be observed before external publication.
- This document does not claim that operator RPC credentials, deployer keys, or
  predeployed CREATE2 factories belong in the repo.
