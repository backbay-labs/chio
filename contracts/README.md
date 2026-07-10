# Chio Web3 Contracts

This package is the Solidity settlement and anchoring adapter package for
Chio's official web3 contract family:

- `ChioRootRegistry`
- `ChioEscrow`
- `ChioBondVault`
- `ChioIdentityRegistry`
- `ChioPriceResolver`

The implementation tightens three contract-shape gaps deliberately:

1. RFC6962 proof verification needs `leafIndex` and `treeSize`. The reference
   and prototype interface examples omitted those fields in the public methods,
   so the contracts add `*Detailed` overloads and make the under-specified
   methods revert fail closed.
2. Signature-based escrow release must bind `escrowId`, `settledAmount`, and
   chain context into the signed payload. Verifying a bare `receiptHash` would
   leave the amount under-specified.
3. Root publication supports explicit delegate publishers so Chio can authorize
   automation or HA anchoring infrastructure without widening operator trust.

The compiled interface artifacts under `contracts/artifacts/interfaces/` are
also the canonical binding input for `crates/economy/chio-web3-bindings/`. Chio now
derives the Rust Alloy surface from those compiled interface artifacts instead
of maintaining a second handwritten contract interface inventory.

The money-handling boundary is intentionally narrow:

- `ChioBondVault` locks collateral on-chain and preserves reserve requirement
  metadata from the signed Chio bond artifact for parity checks; it does not
  create a second on-chain reserve ledger.
- `ChioPriceResolver` is an auxiliary on-chain feed reader for bounded contract
  parity and review. The canonical runtime FX authority remains the off-chain
  `chio-link` receipt-evidence path.

## Deployment Guard

Mainnet deployment, non-testnet custody, and non-testnet promotion are blocked
until external audit, testnet soak, artifact digest, runtime codehash, and
minimum-bar gates pass with security-owner sign-off. The prior
`contracts/reports/CHIO_WEB3_CONTRACT_SECURITY_REVIEW.md` and both
`local-devnet-qualification.json` copies are historical fixtures,
not promotion signals. The local smoke and promotion lanes remain useful for
rehearsal only.

Compile locally with:

```bash
pnpm --dir contracts install
pnpm --dir contracts compile
```

Run the local qualification harness with:

```bash
pnpm --dir contracts devnet:smoke
```

That deploys the full contract family plus mocks to an ephemeral Ganache
devnet, exercises the core fail-closed paths, and writes deployment and
qualification reports under `contracts/deployments/` and `contracts/reports/`.

Run the full local dress rehearsal with:

```bash
./scripts/qualify-web3-local.sh
```

That installs the locked JavaScript dependencies, reruns the runtime, end-to-
end, ops, and reviewed-manifest promotion qualification lanes, and leaves the
generated evidence under `target/web3-*/`. This evidence does not authorize
mainnet deployment or non-testnet custody before external assurance.

Run the reviewed-manifest promotion qualification with:

```bash
./scripts/qualify-web3-promotion.sh
```

That compiles the contract package, verifies that every shipped public-chain
template can be turned into a reviewed manifest plus pending-review approval
scaffold, uses `contracts/deployments/local-devnet.reviewed.json`, generates a
local approval artifact, proves CREATE2 address reproducibility across fresh
local devnets, and verifies that bad approvals and failed promotions emit
explicit rollback artifacts.

Prepare a reviewed public-chain manifest with:

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
```

The dependency step deploys a public Base Sepolia CREATE2 factory plus mock
Chainlink-compatible aggregators for the testnet dress rehearsal, then writes
the review-inputs JSON consumed by the manifest helper. The review-inputs JSON
supplies the one-wallet role address, runtime operator key hash, CREATE2 factory
details, and template placeholders such as testnet feed addresses. The generated
approval scaffold is intentionally emitted with `status: pending-review` so the
operator must still
complete approval explicitly before rollout. Mainnet manifests must use
reviewed live Chainlink feed addresses instead of the testnet mock feeds.
Refresh testnet mock feed timestamps before readback or any delayed rehearsal:

```bash
pnpm --dir contracts refresh:base-sepolia-feeds \
  --dependencies target/web3-live-rollout/base-sepolia/dependencies/dependencies.json \
  --output target/web3-live-rollout/base-sepolia/dependencies/feed-refresh.json
```

Run the public Base Sepolia smoke after promotion:

```bash
pnpm --dir contracts smoke:base-sepolia \
  --deployment target/web3-live-rollout/base-sepolia/promotion/deployment.json \
  --dependencies target/web3-live-rollout/base-sepolia/dependencies/dependencies.json \
  --output target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json
```

The smoke reads the promoted deployment record, refreshes testnet mock feed
timestamps, verifies price readback, registers a fresh entity, publishes proof
roots, approves Base Sepolia USDC, exercises create, partial release, final
release, and timeout refund escrow paths, then writes transaction hashes and
pass/fail checks to `target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json`.

The bounded promotion runner itself is:

```bash
node contracts/scripts/promote-deployment.mjs \
  --manifest contracts/deployments/local-devnet.reviewed.json \
  --approval target/web3-promotion-qualification/run-a/approval.json \
  --output-dir target/web3-promotion-qualification/manual-run \
  --local-devnet \
  --rollback-on-failure
```

For non-local rollout the same runner requires operator-owned `--rpc-url`,
`--deployer-key`, a reviewed manifest derived from the shipped `*.template.json`
files, and an approval artifact that binds the exact manifest hash, release id,
deployment policy id, predeployed CREATE2 factory, and salt namespace.
For any non-testnet chain it also requires `--assurance-unlock <reviewed-json>` with
detached, digest-bound external audit, testnet soak, artifact digest,
minimum-bar, zero critical/high finding, and a recoverable security-owner
signature before deployment. The runner then verifies deployed runtime codehashes
after CREATE2 deployment and before post-deployment configuration.
Set `CHIO_BASE_BUILDER_CODE` or pass `--base-builder-code` to append a Base
ERC-8021 attribution suffix to CREATE2 factory calls. Strict ABI registry and
oracle configuration calls are not suffixed because some public RPC paths reject
trailing calldata on those static-argument functions. Contract-creation
dependency transactions are not suffixed because appending bytes to init code
changes the created bytecode.
