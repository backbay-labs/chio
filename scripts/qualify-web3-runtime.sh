#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "web3 runtime qualification requires jq on PATH" >&2
  exit 1
fi

if command -v corepack >/dev/null 2>&1; then
  pnpm_cmd=(corepack pnpm)
elif command -v pnpm >/dev/null 2>&1; then
  pnpm_cmd=(pnpm)
else
  echo "web3 runtime qualification requires pnpm on PATH" >&2
  exit 1
fi

output_root="target/web3-runtime-qualification"
cargo_target_dir="${output_root}/cargo-target"
log_path="${output_root}/qualification.log"
public_settlement_passport="fixtures/proof-room/public-settlement/valid-offline-finality/transaction-passport.json"
public_settlement_report="${output_root}/public-settlement-verifier-report.json"
proof_room_bundle_signer_keys="${CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS:-66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a}"
transaction_trusted_root_keys="${CHIO_TRANSACTION_TRUSTED_ROOT_KEYS:-ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,68f4b6017d0f876a55c80a82b8388a54aad264d367269e2de8be079c935b5f96,66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a}"
public_settlement_capital_keys="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS:-fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618}"
public_settlement_bundle_signer_keys="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS:-fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618}"
public_settlement_anchor_keys="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS:-ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c}"
public_settlement_beneficiary_keys="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS:-91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a}"
public_settlement_oracle_keys="${CHIO_PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS:-d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c}"
public_settlement_allowed_chain_ids="${CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS:-eip155:8453,eip155:42161}"
public_settlement_minimum_confirmations="${CHIO_PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS:-1}"
public_settlement_independent_chain_head="${CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON:-{\"chain_id\":\"eip155:8453\",\"observed_block_number\":12345678,\"observed_block_hash\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"latest_block_number\":12345701}}"
public_settlement_verifier_now="${CHIO_PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS:-1743293560}"
mkdir -p "${output_root}"
: >"${log_path}"

run() {
  printf '==> %s\n' "$*" | tee -a "${log_path}"
  "$@" 2>&1 | tee -a "${log_path}"
}

run "${pnpm_cmd[@]}" --dir contracts install --frozen-lockfile
run "${pnpm_cmd[@]}" --dir contracts compile
run ./scripts/check-web3-contract-parity.sh
run cargo fmt --all --check
run env CARGO_TARGET_DIR="${cargo_target_dir}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-cli web3_evidence -- --test-threads=1
run env CARGO_TARGET_DIR="${cargo_target_dir}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-control-plane web3_evidence -- --test-threads=1
run env CARGO_TARGET_DIR="${cargo_target_dir}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-link -- --test-threads=1
run env CARGO_TARGET_DIR="${cargo_target_dir}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-kernel web3_evidence -- --test-threads=1
run env CARGO_TARGET_DIR="${cargo_target_dir}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-kernel cross_currency -- --test-threads=1
run env CARGO_TARGET_DIR="${cargo_target_dir}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-anchor evidence_bundle -- --test-threads=1
run env CARGO_TARGET_DIR="${cargo_target_dir}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-anchor -- --test-threads=1
run env CARGO_TARGET_DIR="${cargo_target_dir}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-settle evidence_substrate -- --test-threads=1
run env CARGO_TARGET_DIR="${cargo_target_dir}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-settle --lib -- --test-threads=1
run env CARGO_TARGET_DIR="${cargo_target_dir}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-settle --test runtime_devnet -- --nocapture
run "${pnpm_cmd[@]}" --dir contracts devnet:smoke
run git diff --exit-code -- \
  contracts/artifacts \
  crates/economy/chio-web3-bindings/artifacts \
  contracts/deployments/local-devnet.json \
  crates/economy/chio-web3-bindings/deployments/local-devnet.json \
  contracts/reports/local-devnet-qualification.json \
  crates/economy/chio-web3-bindings/reports/local-devnet-qualification.json
run env CARGO_TARGET_DIR="${cargo_target_dir}" ./scripts/qualify-web3-e2e.sh
run ./scripts/qualify-web3-ops-controls.sh
run env CARGO_TARGET_DIR="${cargo_target_dir}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS="${proof_room_bundle_signer_keys}" \
  CHIO_TRANSACTION_TRUSTED_ROOT_KEYS="${transaction_trusted_root_keys}" \
  CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS="${public_settlement_capital_keys}" \
  CHIO_PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS="${public_settlement_bundle_signer_keys}" \
  CHIO_PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS="${public_settlement_anchor_keys}" \
  CHIO_PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS="${public_settlement_beneficiary_keys}" \
  CHIO_PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS="${public_settlement_oracle_keys}" \
  CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS="${public_settlement_allowed_chain_ids}" \
  CHIO_PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS="${public_settlement_minimum_confirmations}" \
  CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON="${public_settlement_independent_chain_head}" \
  CHIO_PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS="${public_settlement_verifier_now}" \
  cargo run -p chio-cli --bin chio -- proof verify "${public_settlement_passport}" \
  --require settlement \
  --out "${public_settlement_report}"
run test -s "${public_settlement_report}"
run jq empty \
  docs/standards/CHIO_LINK_BASE_MAINNET_CONFIG.json \
  docs/standards/CHIO_LINK_MONITOR_REPORT_EXAMPLE.json \
  docs/standards/CHIO_LINK_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_ANCHOR_DISCOVERY_EXAMPLE.json \
  docs/standards/CHIO_ANCHOR_OTS_SUBMISSION_EXAMPLE.json \
  docs/standards/CHIO_ANCHOR_SOLANA_MEMO_EXAMPLE.json \
  docs/standards/CHIO_ANCHOR_PROOF_BUNDLE_EXAMPLE.json \
  docs/standards/CHIO_ANCHOR_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_ANCHOR_RUNTIME_REPORT_EXAMPLE.json \
  docs/standards/CHIO_SETTLE_FINALITY_REPORT_EXAMPLE.json \
  docs/standards/CHIO_SETTLE_SOLANA_RELEASE_EXAMPLE.json \
  docs/standards/CHIO_SETTLE_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_SETTLE_RUNTIME_REPORT_EXAMPLE.json \
  docs/standards/CHIO_FUNCTIONS_REQUEST_EXAMPLE.json \
  docs/standards/CHIO_FUNCTIONS_RESPONSE_EXAMPLE.json \
  docs/standards/CHIO_ANCHOR_AUTOMATION_JOB_EXAMPLE.json \
  docs/standards/CHIO_SETTLEMENT_WATCHDOG_JOB_EXAMPLE.json \
  docs/standards/CHIO_CCIP_MESSAGE_EXAMPLE.json \
  docs/standards/CHIO_CCIP_RECONCILIATION_EXAMPLE.json \
  docs/standards/CHIO_X402_REQUIREMENTS_EXAMPLE.json \
  docs/standards/CHIO_EIP3009_TRANSFER_WITH_AUTHORIZATION_EXAMPLE.json \
  docs/standards/CHIO_CIRCLE_NANOPAYMENT_EXAMPLE.json \
  docs/standards/CHIO_4337_PAYMASTER_COMPAT_EXAMPLE.json \
  docs/standards/CHIO_WEB3_AUTOMATION_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json
run git diff --check

printf 'web3 runtime qualification complete; log written to %s\n' "${log_path}" | tee -a "${log_path}"
