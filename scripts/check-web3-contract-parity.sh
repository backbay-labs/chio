#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "web3 contract parity requires jq on PATH" >&2
  exit 1
fi

if ! command -v pnpm >/dev/null 2>&1; then
  echo "web3 contract parity requires pnpm on PATH" >&2
  exit 1
fi

pnpm --dir contracts compile

env CARGO_TARGET_DIR=target/chio-web3-parity CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-web3 -- --test-threads=1
env CARGO_TARGET_DIR=target/chio-settle-web3-parity CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-settle web3 -- --test-threads=1
env CARGO_TARGET_DIR=target/chio-web3-bindings-parity CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-web3-bindings -- --test-threads=1
scripts/check-chio-schema-registry.sh
diff -qr contracts/artifacts crates/economy/chio-web3-bindings/artifacts
diff -u contracts/deployments/local-devnet.json \
  crates/economy/chio-web3-bindings/deployments/local-devnet.json
diff -u contracts/reports/local-devnet-qualification.json \
  crates/economy/chio-web3-bindings/reports/local-devnet-qualification.json
jq -e '
  .bytecode != "" and
  .deployedBytecode != "" and
  (.creationBytecodeHash | test("^0x[0-9a-fA-F]{64}$")) and
  (.deployedRuntimeCodehash | test("^0x[0-9a-fA-F]{64}$"))
' \
  contracts/artifacts/ChioRootRegistry.json \
  contracts/artifacts/ChioEscrow.json \
  contracts/artifacts/ChioBondVault.json \
  contracts/artifacts/ChioIdentityRegistry.json \
  contracts/artifacts/ChioPriceResolver.json >/dev/null
node --input-type=module <<'NODE'
import fs from "node:fs";

const packageJson = JSON.parse(fs.readFileSync("docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json", "utf8"));
const artifactByKind = {
  root_registry: "contracts/artifacts/ChioRootRegistry.json",
  escrow: "contracts/artifacts/ChioEscrow.json",
  bond_vault: "contracts/artifacts/ChioBondVault.json",
  identity_registry: "contracts/artifacts/ChioIdentityRegistry.json",
  price_resolver: "contracts/artifacts/ChioPriceResolver.json",
};

for (const contract of packageJson.contracts ?? []) {
  const artifactPath = artifactByKind[contract.kind];
  if (!artifactPath) {
    throw new Error(`unknown contract package kind ${contract.kind}`);
  }
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  if (contract.creation_bytecode_hash?.toLowerCase() !== artifact.creationBytecodeHash?.toLowerCase()) {
    throw new Error(`${contract.contract_id} creation_bytecode_hash does not match ${artifactPath}`);
  }
  if (contract.deployed_runtime_codehash?.toLowerCase() !== artifact.deployedRuntimeCodehash?.toLowerCase()) {
    throw new Error(`${contract.contract_id} deployed_runtime_codehash does not match ${artifactPath}`);
  }
}

const policy = JSON.parse(fs.readFileSync("docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json", "utf8"));
const qualification = JSON.parse(fs.readFileSync("contracts/reports/local-devnet-qualification.json", "utf8"));
const qualificationRuntime = qualification.deployed_runtime_codehashes ?? {};
for (const contract of packageJson.contracts ?? []) {
  const record = qualificationRuntime[contract.kind] ?? qualificationRuntime[contract.contract_id];
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(`local-devnet qualification is missing runtime codehash record for ${contract.contract_id}`);
  }
  if (record.immutable_normalized_runtime_codehash?.toLowerCase() !== contract.deployed_runtime_codehash?.toLowerCase()) {
    throw new Error(`local-devnet qualification runtime codehash for ${contract.contract_id} is stale`);
  }
  if (record.package_runtime_codehash?.toLowerCase() !== contract.deployed_runtime_codehash?.toLowerCase()) {
    throw new Error(`local-devnet qualification package codehash for ${contract.contract_id} is stale`);
  }
}
const gasBudgets = policy.gasBudgets ?? {};
const gasEstimates = qualification.gas_estimates ?? {};
const gasChecks = {
  register_operator: "registerOperator",
  register_delegate: "registerDelegate",
  publish_root_operator: "publishRoot",
  publish_root_delegate: "publishRoot",
  register_feed: "registerFeed",
  price_read: "getPrice",
  create_escrow: "createEscrow",
  merkle_partial_release: "merklePartialRelease",
  dual_sign_release: "dualSignRelease",
  lock_bond: "lockBond",
  bond_release: "releaseBond",
};

for (const [estimateKey, budgetKey] of Object.entries(gasChecks)) {
  const rawEstimate = gasEstimates[estimateKey];
  const budget = gasBudgets[budgetKey];
  const estimate = typeof rawEstimate === "string" ? Number(rawEstimate) : rawEstimate;
  if (!Number.isSafeInteger(estimate) || estimate <= 0) {
    throw new Error(`local-devnet gas_estimates.${estimateKey} is missing or invalid`);
  }
  if (!Number.isSafeInteger(budget) || budget <= 0) {
    throw new Error(`deployment policy gasBudgets.${budgetKey} is missing or invalid`);
  }
  if (estimate > budget) {
    throw new Error(`gas budget exceeded for ${estimateKey}: ${estimate} > ${budgetKey} ${budget}`);
  }
}
NODE
jq empty \
  docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json \
  docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json \
  docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json \
  docs/standards/CHIO_WEB3_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json

echo "web3 contract parity verified"
