#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "staging hosted web3 artifacts requires python3 on PATH" >&2
  exit 1
fi

require_cutover_evidence=false
runtime_rpc_url="${CHIO_STAGE_WEB3_RUNTIME_RPC_URL:-}"
base_sepolia_runtime_rpc_url="${CHIO_STAGE_WEB3_BASE_SEPOLIA_RPC_URL:-}"
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --require-cutover-evidence)
      require_cutover_evidence=true
      ;;
    --runtime-rpc-url)
      shift
      runtime_rpc_url="${1:-}"
      if [[ -z "${runtime_rpc_url}" ]]; then
        echo "--runtime-rpc-url requires a value" >&2
        exit 2
      fi
      ;;
    --base-sepolia-runtime-rpc-url)
      shift
      base_sepolia_runtime_rpc_url="${1:-}"
      if [[ -z "${base_sepolia_runtime_rpc_url}" ]]; then
        echo "--base-sepolia-runtime-rpc-url requires a value" >&2
        exit 2
      fi
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

./scripts/check-web3-contract-parity.sh
./scripts/check-chio-schema-registry.sh

dest_root="target/release-qualification/web3-runtime"
rm -rf "${dest_root}"
mkdir -p "${dest_root}"

present_list="$(mktemp "${TMPDIR:-/tmp}/chio-web3-present.XXXXXX")"
missing_list="$(mktemp "${TMPDIR:-/tmp}/chio-web3-missing.XXXXXX")"
required_missing_list="$(mktemp "${TMPDIR:-/tmp}/chio-web3-required-missing.XXXXXX")"

cleanup() {
  rm -f "${present_list}" "${missing_list}" "${required_missing_list}"
}
trap cleanup EXIT

copy_if_exists() {
  local src="$1"
  local dest="$2"
  if [[ -e "${src}" ]]; then
    mkdir -p "$(dirname "${dest}")"
    cp "${src}" "${dest}"
    printf '%s\n' "${dest}" >>"${present_list}"
  else
    printf '%s\n' "${src}" >>"${missing_list}"
  fi
}

copy_required() {
  local src="$1"
  local dest="$2"
  if [[ -e "${src}" ]]; then
    mkdir -p "$(dirname "${dest}")"
    cp "${src}" "${dest}"
    printf '%s\n' "${dest}" >>"${present_list}"
  else
    printf '%s\n' "${src}" >>"${missing_list}"
    printf '%s\n' "${src}" >>"${required_missing_list}"
  fi
}

copy_cutover() {
  local src="$1"
  local dest="$2"
  if [[ "${require_cutover_evidence}" == "true" ]]; then
    copy_required "${src}" "${dest}"
  else
    copy_if_exists "${src}" "${dest}"
  fi
}

copy_external_assurance() {
  local src="$1"
  local dest="$2"
  if [[ "${require_cutover_evidence}" == "true" ]]; then
    copy_required "${src}" "${dest}"
  else
    copy_if_exists "${src}" "${dest}"
  fi
}

copy_required \
  "target/web3-runtime-qualification/qualification.log" \
  "${dest_root}/logs/qualification.log"
copy_required \
  "target/web3-ops-qualification/qualification.log" \
  "${dest_root}/logs/ops-qualification.log"
copy_required \
  "target/web3-e2e-qualification/qualification.log" \
  "${dest_root}/logs/e2e-qualification.log"
copy_required \
  "target/web3-promotion-qualification/qualification.log" \
  "${dest_root}/logs/promotion-qualification.log"
copy_cutover \
  "target/web3-example-qualification/qualification.log" \
  "${dest_root}/logs/example-qualification.log"
copy_if_exists \
  "contracts/deployments/local-devnet.json" \
  "${dest_root}/historical/contracts/deployments/local-devnet.json"
copy_if_exists \
  "contracts/deployments/local-devnet.reviewed.json" \
  "${dest_root}/historical/contracts/deployments/local-devnet.reviewed.json"
copy_required \
  "contracts/deployments/base-mainnet.template.json" \
  "${dest_root}/contracts/deployments/base-mainnet.template.json"
copy_required \
  "contracts/deployments/base-sepolia.template.json" \
  "${dest_root}/contracts/deployments/base-sepolia.template.json"
copy_required \
  "contracts/deployments/arbitrum-one.template.json" \
  "${dest_root}/contracts/deployments/arbitrum-one.template.json"
copy_if_exists \
  "contracts/reports/local-devnet-qualification.json" \
  "${dest_root}/historical/contracts/reports/local-devnet-qualification.json"
copy_if_exists \
  "contracts/reports/CHIO_WEB3_CONTRACT_SECURITY_REVIEW.md" \
  "${dest_root}/historical/contracts/reports/CHIO_WEB3_CONTRACT_SECURITY_REVIEW.md"
copy_if_exists \
  "contracts/reports/CHIO_WEB3_CONTRACT_GAS_AND_STORAGE.md" \
  "${dest_root}/historical/contracts/reports/CHIO_WEB3_CONTRACT_GAS_AND_STORAGE.md"
copy_required \
  "contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json" \
  "${dest_root}/contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json"
copy_required \
  "contracts/artifacts/ChioRootRegistry.json" \
  "${dest_root}/contracts/artifacts/ChioRootRegistry.json"
copy_required \
  "contracts/artifacts/ChioIdentityRegistry.json" \
  "${dest_root}/contracts/artifacts/ChioIdentityRegistry.json"
copy_required \
  "contracts/artifacts/ChioEscrow.json" \
  "${dest_root}/contracts/artifacts/ChioEscrow.json"
copy_required \
  "contracts/artifacts/ChioBondVault.json" \
  "${dest_root}/contracts/artifacts/ChioBondVault.json"
copy_required \
  "contracts/artifacts/ChioPriceResolver.json" \
  "${dest_root}/contracts/artifacts/ChioPriceResolver.json"
copy_required \
  "contracts/artifacts/interfaces/IChioRootRegistry.json" \
  "${dest_root}/contracts/artifacts/interfaces/IChioRootRegistry.json"
copy_required \
  "contracts/artifacts/interfaces/IChioIdentityRegistry.json" \
  "${dest_root}/contracts/artifacts/interfaces/IChioIdentityRegistry.json"
copy_required \
  "contracts/artifacts/interfaces/IChioEscrow.json" \
  "${dest_root}/contracts/artifacts/interfaces/IChioEscrow.json"
copy_required \
  "contracts/artifacts/interfaces/IChioBondVault.json" \
  "${dest_root}/contracts/artifacts/interfaces/IChioBondVault.json"
copy_required \
  "contracts/artifacts/interfaces/IChioPriceResolver.json" \
  "${dest_root}/contracts/artifacts/interfaces/IChioPriceResolver.json"
copy_required \
  "scripts/qualify-web3-runtime.sh" \
  "${dest_root}/scripts/qualify-web3-runtime.sh"
copy_required \
  "scripts/qualify-web3-e2e.sh" \
  "${dest_root}/scripts/qualify-web3-e2e.sh"
copy_required \
  "scripts/qualify-web3-ops-controls.sh" \
  "${dest_root}/scripts/qualify-web3-ops-controls.sh"
copy_required \
  "scripts/qualify-web3-promotion.sh" \
  "${dest_root}/scripts/qualify-web3-promotion.sh"
copy_required \
  "contracts/scripts/promote-deployment.mjs" \
  "${dest_root}/contracts/scripts/promote-deployment.mjs"
copy_required \
  "scripts/stage-web3-release-artifacts.sh" \
  "${dest_root}/scripts/stage-web3-release-artifacts.sh"
copy_required \
  "docs/release/CHIO_WEB3_READINESS_AUDIT.md" \
  "${dest_root}/docs/release/CHIO_WEB3_READINESS_AUDIT.md"
copy_required \
  "docs/release/CHIO_WEB3_DEPLOYMENT_PROMOTION.md" \
  "${dest_root}/docs/release/CHIO_WEB3_DEPLOYMENT_PROMOTION.md"
copy_required \
  "docs/release/CHIO_WEB3_MAINNET_CUTOVER_CHECKLIST.md" \
  "${dest_root}/docs/release/CHIO_WEB3_MAINNET_CUTOVER_CHECKLIST.md"
copy_required \
  "docs/release/CHIO_WEB3_OPERATIONS_RUNBOOK.md" \
  "${dest_root}/docs/release/CHIO_WEB3_OPERATIONS_RUNBOOK.md"
copy_required \
  "docs/release/CHIO_WEB3_PARTNER_PROOF.md" \
  "${dest_root}/docs/release/CHIO_WEB3_PARTNER_PROOF.md"
copy_required \
  "docs/standards/CHIO_WEB3_OPERATIONS_PROFILE.md" \
  "${dest_root}/docs/standards/CHIO_WEB3_OPERATIONS_PROFILE.md"
copy_required \
  "docs/standards/CHIO_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json"
copy_required \
  "docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json"
copy_required \
  "docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json"
copy_required \
  "docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json"
copy_required \
  "docs/standards/CHIO_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json"
copy_required \
  "docs/standards/CHIO_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json"
copy_required \
  "docs/standards/CHIO_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json"
copy_required \
  "docs/standards/CHIO_WEB3_OPERATOR_ENVIRONMENT.example" \
  "${dest_root}/docs/standards/CHIO_WEB3_OPERATOR_ENVIRONMENT.example"
copy_required \
  "docs/standards/CHIO_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json" \
  "${dest_root}/docs/standards/CHIO_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json"
copy_required \
  "spec/schemas/MANIFEST.sha256" \
  "${dest_root}/spec/schemas/MANIFEST.sha256"
copy_required \
  "spec/schemas/chio-web3/v1/settlement-proof-bundle.schema.json" \
  "${dest_root}/spec/schemas/chio-web3/v1/settlement-proof-bundle.schema.json"
copy_required \
  "target/web3-promotion-qualification/review-prep/qualification.json" \
  "${dest_root}/promotion/review-prep/qualification.json"
copy_required \
  "target/web3-promotion-qualification/promotion-qualification.json" \
  "${dest_root}/promotion/promotion-qualification.json"
copy_required \
  "target/web3-e2e-qualification/partner-qualification.json" \
  "${dest_root}/e2e/partner-qualification.json"
copy_required \
  "target/web3-e2e-qualification/scenarios/fx-dual-sign-settlement.json" \
  "${dest_root}/e2e/scenarios/fx-dual-sign-settlement.json"
copy_required \
  "target/web3-e2e-qualification/scenarios/timeout-refund-recovery.json" \
  "${dest_root}/e2e/scenarios/timeout-refund-recovery.json"
copy_required \
  "target/web3-e2e-qualification/scenarios/reorg-recovery.json" \
  "${dest_root}/e2e/scenarios/reorg-recovery.json"
copy_required \
  "target/web3-e2e-qualification/scenarios/bond-impair-recovery.json" \
  "${dest_root}/e2e/scenarios/bond-impair-recovery.json"
copy_required \
  "target/web3-e2e-qualification/scenarios/bond-expiry-recovery.json" \
  "${dest_root}/e2e/scenarios/bond-expiry-recovery.json"
copy_required \
  "target/web3-ops-qualification/runtime-reports/chio-link-runtime-report.json" \
  "${dest_root}/ops/runtime-reports/chio-link-runtime-report.json"
copy_required \
  "target/web3-ops-qualification/runtime-reports/chio-anchor-runtime-report.json" \
  "${dest_root}/ops/runtime-reports/chio-anchor-runtime-report.json"
copy_required \
  "target/web3-ops-qualification/runtime-reports/chio-settle-runtime-report.json" \
  "${dest_root}/ops/runtime-reports/chio-settle-runtime-report.json"
copy_required \
  "target/web3-ops-qualification/control-state/chio-link-control-state.json" \
  "${dest_root}/ops/control-state/chio-link-control-state.json"
copy_required \
  "target/web3-ops-qualification/control-state/chio-anchor-control-state.json" \
  "${dest_root}/ops/control-state/chio-anchor-control-state.json"
copy_required \
  "target/web3-ops-qualification/control-state/chio-settle-control-state.json" \
  "${dest_root}/ops/control-state/chio-settle-control-state.json"
copy_required \
  "target/web3-ops-qualification/control-traces/chio-link-control-trace.json" \
  "${dest_root}/ops/control-traces/chio-link-control-trace.json"
copy_required \
  "target/web3-ops-qualification/control-traces/chio-anchor-control-trace.json" \
  "${dest_root}/ops/control-traces/chio-anchor-control-trace.json"
copy_required \
  "target/web3-ops-qualification/control-traces/chio-settle-control-trace.json" \
  "${dest_root}/ops/control-traces/chio-settle-control-trace.json"
copy_required \
  "target/web3-ops-qualification/incident-audit.json" \
  "${dest_root}/ops/incident-audit.json"
copy_required \
  "target/web3-promotion-qualification/run-a/approval.json" \
  "${dest_root}/promotion/run-a/approval.json"
copy_required \
  "target/web3-promotion-qualification/run-a/promotion-report.json" \
  "${dest_root}/promotion/run-a/promotion-report.json"
copy_required \
  "target/web3-promotion-qualification/run-a/rollback-plan.json" \
  "${dest_root}/promotion/run-a/rollback-plan.json"
copy_required \
  "target/web3-promotion-qualification/run-a/deployment.json" \
  "${dest_root}/promotion/run-a/deployment.json"
copy_required \
  "target/web3-promotion-qualification/run-b/promotion-report.json" \
  "${dest_root}/promotion/run-b/promotion-report.json"
copy_required \
  "target/web3-promotion-qualification/run-b/deployment.json" \
  "${dest_root}/promotion/run-b/deployment.json"
copy_required \
  "target/web3-promotion-qualification/resume-existing/promotion-report.json" \
  "${dest_root}/promotion/resume-existing/promotion-report.json"
copy_required \
  "target/web3-promotion-qualification/resume-existing/deployment.json" \
  "${dest_root}/promotion/resume-existing/deployment.json"
copy_required \
  "target/web3-promotion-qualification/negative-approval/promotion-report.json" \
  "${dest_root}/promotion/negative-approval/promotion-report.json"
copy_required \
  "target/web3-promotion-qualification/negative-rollback/promotion-report.json" \
  "${dest_root}/promotion/negative-rollback/promotion-report.json"
copy_required \
  "target/web3-promotion-qualification/negative-rollback/rollback-plan.json" \
  "${dest_root}/promotion/negative-rollback/rollback-plan.json"
copy_required \
  "target/web3-promotion-qualification/negative-assurance-security-owner/top-level-only/promotion-report.json" \
  "${dest_root}/promotion/negative-assurance-security-owner/top-level-only/promotion-report.json"
copy_required \
  "target/web3-promotion-qualification/negative-assurance-security-owner/pending-owner/promotion-report.json" \
  "${dest_root}/promotion/negative-assurance-security-owner/pending-owner/promotion-report.json"
copy_required \
  "target/web3-promotion-qualification/negative-assurance-security-owner/missing-owner-approved-at/promotion-report.json" \
  "${dest_root}/promotion/negative-assurance-security-owner/missing-owner-approved-at/promotion-report.json"
copy_required \
  "target/web3-promotion-qualification/negative-assurance-security-owner/conflicting-owner/promotion-report.json" \
  "${dest_root}/promotion/negative-assurance-security-owner/conflicting-owner/promotion-report.json"
copy_required \
  "target/web3-promotion-qualification/negative-assurance-security-owner/conflicting-approved-owners/promotion-report.json" \
  "${dest_root}/promotion/negative-assurance-security-owner/conflicting-approved-owners/promotion-report.json"
copy_cutover \
  "target/web3-live-rollout/base-sepolia/promotion/deployment.json" \
  "${dest_root}/live/base-sepolia/promotion/deployment.json"
copy_cutover \
  "target/web3-live-rollout/base-sepolia/promotion/promotion-report.json" \
  "${dest_root}/live/base-sepolia/promotion/promotion-report.json"
copy_cutover \
  "target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json" \
  "${dest_root}/live/base-sepolia/base-sepolia-smoke.json"
copy_cutover \
  "target/web3-live-rollout/base-sepolia/dependencies/dependencies.json" \
  "${dest_root}/live/base-sepolia/dependencies/dependencies.json"
copy_cutover \
  "target/web3-live-rollout/base-sepolia/dependencies/base-sepolia.review-inputs.json" \
  "${dest_root}/live/base-sepolia/dependencies/base-sepolia.review-inputs.json"
copy_cutover \
  "target/web3-example-qualification/internet-of-agents-web3-network/review-result.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/review-result.json"
copy_cutover \
  "target/web3-example-qualification/internet-of-agents-web3-network/summary.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/summary.json"
copy_cutover \
  "target/web3-example-qualification/internet-of-agents-web3-network/web3/validation-index.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/web3/validation-index.json"
copy_cutover \
  "target/web3-example-qualification/internet-of-agents-web3-network/evidence/cutover-readiness.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/evidence/cutover-readiness.json"
copy_cutover \
  "target/web3-example-qualification/internet-of-agents-web3-network/contracts/settlement-packet.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/contracts/settlement-packet.json"
copy_cutover \
  "target/web3-example-qualification/internet-of-agents-web3-network/contracts/web3-settlement-dispatch.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/contracts/web3-settlement-dispatch.json"
copy_cutover \
  "target/web3-example-qualification/internet-of-agents-web3-network/contracts/web3-settlement-receipt.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/contracts/web3-settlement-receipt.json"
copy_cutover \
  "target/web3-example-qualification/internet-of-agents-web3-network/bundle-manifest.json" \
  "${dest_root}/examples/internet-of-agents-web3-network/bundle-manifest.json"

copy_external_assurance \
  "target/web3-external-assurance/external-audit-report.json" \
  "${dest_root}/external-assurance/external-audit-report.json"
copy_external_assurance \
  "target/web3-external-assurance/testnet-soak-report.json" \
  "${dest_root}/external-assurance/testnet-soak-report.json"
copy_external_assurance \
  "target/web3-external-assurance/artifact-digest-gate.json" \
  "${dest_root}/external-assurance/artifact-digest-gate.json"
copy_external_assurance \
  "target/web3-external-assurance/deployed-runtime-codehash-gate.json" \
  "${dest_root}/external-assurance/deployed-runtime-codehash-gate.json"
copy_external_assurance \
  "target/web3-external-assurance/minimum-bar-checklist.json" \
  "${dest_root}/external-assurance/minimum-bar-checklist.json"
copy_external_assurance \
  "target/web3-external-assurance/security-owner-assurance-unlock.json" \
  "${dest_root}/external-assurance/security-owner-assurance-unlock.json"
copy_external_assurance \
  "target/web3-external-assurance/hosted-workflow-observation.json" \
  "${dest_root}/external-assurance/hosted-workflow-observation.json"
copy_external_assurance \
  "target/web3-external-assurance/target-chain-manifest.json" \
  "${dest_root}/external-assurance/target-chain-manifest.json"
copy_external_assurance \
  "target/web3-external-assurance/target-chain-approval.json" \
  "${dest_root}/external-assurance/target-chain-approval.json"
copy_external_assurance \
  "target/web3-external-assurance/operator-approval.json" \
  "${dest_root}/external-assurance/operator-approval.json"

example_root="target/web3-example-qualification/internet-of-agents-web3-network"
example_dest="${dest_root}/examples/internet-of-agents-web3-network"
for artifact in \
  "chio/topology.json" \
  "chio/receipts/receipt-summary.json" \
  "chio/receipts/trust-control.json" \
  "chio/receipts/market-api-sidecar.json" \
  "chio/receipts/settlement-api-sidecar.json" \
  "chio/receipts/provider-review-mcp.json" \
  "chio/receipts/subcontractor-review-mcp.json" \
  "chio/receipts/web3-evidence-mcp.json" \
  "chio/receipts/budget.json" \
  "chio/receipts/approval.json" \
  "chio/receipts/rail-selection.json" \
  "chio/budgets/budget-summary.json" \
  "chio/budgets/quote-exposure-authorization.json" \
  "chio/budgets/settlement-spend-reconciliation.json" \
  "identity/passports/proofworks-provider-passport.json" \
  "identity/passports/proofworks-provider-passport-provenance.json" \
  "identity/passports/proofworks-provider-passport-verdict.json" \
  "identity/passports/provider-passport-verdicts.json" \
  "identity/passports/cipherworks-subcontractor-passport.json" \
  "identity/presentations/provider-challenge.json" \
  "identity/presentations/provider-presentation.json" \
  "identity/presentations/provider-presentation-verdict.json" \
  "identity/presentations/subcontractor-challenge.json" \
  "identity/presentations/subcontractor-presentation.json" \
  "identity/runtime-appraisals/treasury-agent.json" \
  "identity/runtime-appraisals/procurement-agent.json" \
  "identity/runtime-appraisals/provider-agent.json" \
  "identity/runtime-appraisals/subcontractor-agent.json" \
  "identity/runtime-appraisals/settlement-agent.json" \
  "identity/runtime-appraisals/auditor-agent.json" \
  "identity/runtime-degradation/capability-denial.json" \
  "identity/runtime-degradation/provider-quarantine.json" \
  "identity/runtime-degradation/reattestation.json" \
  "identity/runtime-degradation/readmission.json" \
  "identity/runtime-degradation/summary.json" \
  "federation/bilateral-evidence-policy.json" \
  "federation/evidence-export.json" \
  "federation/evidence-export-package/manifest.json" \
  "federation/evidence-import.json" \
  "federation/federated-delegation-policy.json" \
  "federation/open-admission-evaluation.json" \
  "federation/federated-provider-capability.json" \
  "federation/provider-admission-verdicts.json" \
  "federation/subcontractor-admission.json" \
  "reputation/history-ledger.json" \
  "reputation/provider-scorecards.json" \
  "reputation/passport-drift-report.json" \
  "reputation/provider-local-report.json" \
  "reputation/provider-passport-comparison.json" \
  "reputation/provider-reputation-verdict.json" \
  "behavior/behavioral-feed.json" \
  "behavior/baseline.json" \
  "behavior/behavioral-status.json" \
  "guardrails/invalid-spiffe-denial.json" \
  "guardrails/overspend-denial.json" \
  "guardrails/velocity-burst-denial.json" \
  "adversarial/prompt_injection-denial.json" \
  "adversarial/invoice_tampering-denial.json" \
  "adversarial/quote_replay-denial.json" \
  "adversarial/expired_capability-denial.json" \
  "adversarial/unauthorized_settlement_route-denial.json" \
  "adversarial/forged_passport-denial.json" \
  "adversarial/summary.json" \
  "approvals/high-risk-release-challenge.json" \
  "approvals/high-risk-release-decision.json" \
  "approvals/high-risk-release-receipt.json" \
  "approvals/high-risk-release-audit.json" \
  "payments/x402-payment-required.json" \
  "payments/chio-payment-proof.json" \
  "payments/x402-payment-satisfaction.json" \
  "subcontracting/delegated-capability.json" \
  "subcontracting/inherited-obligations.json" \
  "subcontracting/review-request.json" \
  "subcontracting/review-attestation.json" \
  "settlement/rail-selection.json" \
  "disputes/weak-deliverable.json" \
  "disputes/partial-payment.json" \
  "disputes/refund.json" \
  "disputes/reputation-downgrade.json" \
  "disputes/passport-claim-drift.json" \
  "disputes/remediation-packet.json" \
  "disputes/dispute-packet.json" \
  "disputes/dispute-audit.json" \
  "disputes/dispute-summary.json" \
  "operations/trace-map.json" \
  "operations/siem-events.json" \
  "operations/observability-status.json" \
  "operations/operations-timeline.json" \
  "market/rfq-request.json" \
  "market/provider-bids.json" \
  "market/provider-selection.json" \
  "provider/review-result.json" \
  "provider/review-attestation.json" \
  "provider/reputation-evaluation.json"; do
  copy_cutover "${example_root}/${artifact}" "${example_dest}/${artifact}"
done

python3 - <<'PY' "${dest_root}" "${require_cutover_evidence}"
from __future__ import annotations

import json
import hashlib
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

dest_root = Path(sys.argv[1])
require_cutover_evidence = sys.argv[2] == "true"
errors: list[str] = []

def load_json(relative_path: str) -> dict:
    path = dest_root / relative_path
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        errors.append(f"{relative_path} is missing")
    except json.JSONDecodeError as error:
        errors.append(f"{relative_path} is not valid JSON: {error}")
    return {}

def sha256_file(relative_path: str) -> str | None:
    path = dest_root / relative_path
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        errors.append(f"{relative_path} is missing")
    return None

def parse_generated_at(relative_path: str, value: str | None) -> datetime | None:
    if not value:
        errors.append(f"{relative_path} has no generated_at")
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{relative_path} has invalid generated_at: {value}")
        return None

def require_checks_pass(relative_path: str, report: dict) -> None:
    checks = report.get("checks")
    if not isinstance(checks, list) or not checks:
        errors.append(f"{relative_path} has no checks")
        return
    for check in checks:
        if check.get("outcome") != "pass":
            errors.append(f"{relative_path} check {check.get('id', '<unknown>')} is not pass")

def find_field(value: object, names: set[str]) -> object | None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in names:
                return item
        for item in value.values():
            found = find_field(item, names)
            if found is not None:
                return found
    if isinstance(value, list):
        for item in value:
            found = find_field(item, names)
            if found is not None:
                return found
    return None

def is_non_empty(value: object | None) -> bool:
    return value is not None and value != "" and value != [] and value != {}

def number_field(report: dict, *names: str) -> float | None:
    value = find_field(report, set(names))
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None

def bool_field(report: dict, *names: str) -> bool:
    value = find_field(report, set(names))
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"true", "yes", "pass", "passed", "approved", "complete"}
    return False

def non_empty_field(report: dict, *names: str) -> bool:
    return is_non_empty(find_field(report, set(names)))

def text_field(report: dict, *names: str) -> str | None:
    value = find_field(report, set(names))
    if isinstance(value, str) and value:
        return value
    return None

def top_text_field(report: dict, *names: str) -> str | None:
    for name in names:
        value = report.get(name)
        if isinstance(value, str) and value:
            return value
    return None

def nested_value(report: dict, path: tuple[str, ...]) -> object | None:
    value: object = report
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value

def require_top_field_equals(
    relative_path: str,
    report: dict,
    names: tuple[str, ...],
    expected: str | None,
    label: str,
) -> None:
    if not expected:
        errors.append(f"{relative_path} cannot validate {label}; expected value is unavailable")
        return
    actual = top_text_field(report, *names)
    if actual != expected:
        errors.append(f"{relative_path} {label} {actual} does not match {expected}")

def require_nested_equals(
    relative_path: str,
    report: dict,
    path: tuple[str, ...],
    expected: object,
) -> None:
    actual = nested_value(report, path)
    if actual != expected:
        dotted = ".".join(path)
        errors.append(f"{relative_path} {dotted} {actual!r} does not match {expected!r}")

def staged_relative_path(declared_path: object) -> str | None:
    if not isinstance(declared_path, str) or not declared_path:
        return None
    log_paths = {
        "target/web3-runtime-qualification/qualification.log": "logs/qualification.log",
        "target/web3-ops-qualification/qualification.log": "logs/ops-qualification.log",
        "target/web3-e2e-qualification/qualification.log": "logs/e2e-qualification.log",
        "target/web3-promotion-qualification/qualification.log": "logs/promotion-qualification.log",
        "target/web3-example-qualification/qualification.log": "logs/example-qualification.log",
    }
    if declared_path in log_paths:
        return log_paths[declared_path]
    release_prefix = "target/release-qualification/web3-runtime/"
    promotion_prefix = "target/web3-promotion-qualification/"
    e2e_prefix = "target/web3-e2e-qualification/"
    ops_prefix = "target/web3-ops-qualification/"
    external_prefix = "target/web3-external-assurance/"
    live_prefix = "target/web3-live-rollout/base-sepolia/"
    example_prefix = "target/web3-example-qualification/internet-of-agents-web3-network/"
    if declared_path.startswith(release_prefix):
        return declared_path[len(release_prefix):]
    if declared_path.startswith(promotion_prefix):
        return f"promotion/{declared_path[len(promotion_prefix):]}"
    if declared_path.startswith(e2e_prefix):
        return f"e2e/{declared_path[len(e2e_prefix):]}"
    if declared_path.startswith(ops_prefix):
        return f"ops/{declared_path[len(ops_prefix):]}"
    if declared_path.startswith(external_prefix):
        return f"external-assurance/{declared_path[len(external_prefix):]}"
    if declared_path.startswith(live_prefix):
        return f"live/base-sepolia/{declared_path[len(live_prefix):]}"
    if declared_path.startswith(example_prefix):
        return f"examples/internet-of-agents-web3-network/{declared_path[len(example_prefix):]}"
    return declared_path

def require_staged_digest(reference_path: str, declared_path: object, expected_sha256: object, label: str) -> None:
    staged_path = staged_relative_path(declared_path)
    if staged_path is None:
        errors.append(f"{reference_path} {label}.path is missing")
        return
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        errors.append(f"{reference_path} {label}.sha256 is not a SHA-256 digest")
        return
    actual_sha256 = sha256_file(staged_path)
    if actual_sha256 and actual_sha256.lower() != expected_sha256.lower():
        errors.append(f"{reference_path} {label}.sha256 does not match staged {staged_path}")

def require_artifact_digests(relative_path: str, report: dict) -> None:
    digests = report.get("digests")
    if not isinstance(digests, dict):
        errors.append(f"{relative_path} has no structured digests object")
        return
    for artifact_path in required_digest_paths:
        staged_path = staged_relative_path(artifact_path)
        if staged_path is None:
            errors.append(f"{relative_path} cannot resolve staged path for {artifact_path}")
            continue
        expected = sha256_file(staged_path)
        value = digests.get(artifact_path)
        if not isinstance(value, str):
            errors.append(f"{relative_path} missing digest for {artifact_path}")
            continue
        normalized = value.removeprefix("sha256:")
        if expected is None or normalized.lower() != expected.lower():
            errors.append(f"{relative_path} digest for {artifact_path} does not match staged artifact")

def field_value(report: dict, *names: str) -> object | None:
    for name in names:
        value = report.get(name)
        if value not in (None, "", [], {}):
            return value
    return None

def require_manifest_hash_scope(relative_path: str, report: dict, expected: str | None) -> None:
    if not expected:
        errors.append(f"{relative_path} cannot validate reviewed manifest sha256; expected value is unavailable")
        return
    actual = field_value(report, "reviewed_manifest_sha256", "manifest_sha256")
    if actual != expected:
        errors.append(f"{relative_path} reviewed manifest sha256 {actual} does not match {expected}")

def require_report_digest_and_signature(relative_path: str, report: dict) -> None:
    digest = field_value(report, "report_sha256", "report_digest", "sha256", "digest")
    if not isinstance(digest, str) or not re.fullmatch(r"(sha256:)?[0-9a-fA-F]{64}", digest):
        errors.append(f"{relative_path} has no report SHA-256 digest")
    candidate = field_value(report, "candidate_revision", "candidate_sha", "workflow_sha", "git_sha")
    if not isinstance(candidate, str) or not candidate.strip():
        errors.append(f"{relative_path} does not bind a candidate revision")
    issued_at = field_value(report, "issued_at", "generated_at", "observed_at", "completed_at", "approved_at")
    if not isinstance(issued_at, str) or not issued_at.strip():
        errors.append(f"{relative_path} has no report freshness timestamp")
    signer = field_value(report, "signed_by", "approver", "approved_by", "actor")
    signature = field_value(report, "signature", "signature_hex", "approval_signature", "attestation_signature")
    if not signer or not signature:
        errors.append(f"{relative_path} has no signer plus signature")

def normalized_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))

def require_embedded_gate_matches(relative_path: str, report: dict, field: str, component_path: str) -> None:
    embedded = report.get(field)
    component = load_json(component_path)
    if not isinstance(embedded, dict):
        errors.append(f"{relative_path} has no embedded {field}")
        return
    if not isinstance(component, dict):
        errors.append(f"{component_path} is not a JSON object")
        return
    if normalized_json(embedded) != normalized_json(component):
        errors.append(f"{relative_path} embedded {field} does not match staged {component_path}")

def require_component_ref_matches(relative_path: str, report: dict, field: str, component_path: str) -> None:
    components = report.get("components") or report.get("component_digests") or {}
    ref = None
    if isinstance(components, dict):
        ref = components.get(field)
    if ref is None:
        ref = report.get(f"{field}_component") or report.get(f"{field}_ref")
    if isinstance(ref, str):
        declared_path = component_path
        declared_digest = ref
    elif isinstance(ref, dict):
        declared_path = ref.get("path") or ref.get("report_path") or ref.get("file") or component_path
        declared_digest = ref.get("sha256") or ref.get("digest") or ref.get("report_sha256")
    else:
        errors.append(f"{relative_path} has no detached component reference for {field}")
        return
    if staged_relative_path(declared_path) != component_path:
        errors.append(f"{relative_path} {field} path {declared_path} does not resolve to {component_path}")
        return
    if not isinstance(declared_digest, str) or not re.fullmatch(r"(sha256:)?[0-9a-fA-F]{64}", declared_digest):
        errors.append(f"{relative_path} {field} digest is not a SHA-256 digest")
        return
    expected = sha256_file(component_path)
    normalized = declared_digest.removeprefix("sha256:")
    if expected is None or normalized.lower() != expected.lower():
        errors.append(f"{relative_path} {field} digest does not match staged {component_path}")

def strings_in(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        result: list[str] = []
        for item in value.values():
            result.extend(strings_in(item))
        return result
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(strings_in(item))
        return result
    return []

def status_passes(report: dict) -> bool:
    status = str(report.get("status") or report.get("outcome") or "").lower()
    return status in {"pass", "passed", "approved"} or report.get("approved") is True

def require_status(relative_path: str, report: dict) -> None:
    if not status_passes(report):
        errors.append(f"{relative_path} does not report pass or approval")

def require_status_or_promoted(relative_path: str, report: dict) -> None:
    status = str(report.get("status") or report.get("outcome") or "").lower()
    if status not in {"pass", "passed", "approved", "promoted"} and report.get("approved") is not True:
        errors.append(f"{relative_path} does not report pass, approval, or promotion")

def require_field_equals(
    relative_path: str,
    report: dict,
    names: tuple[str, ...],
    expected: str | None,
    label: str,
    required: bool,
) -> None:
    if not expected:
        errors.append(f"{relative_path} cannot validate {label}; expected value is unavailable")
        return
    actual = text_field(report, *names)
    if actual is None:
        if required:
            errors.append(f"{relative_path} has no {label}")
        return
    if actual != expected:
        errors.append(f"{relative_path} {label} {actual} does not match {expected}")

def require_tx_hash(relative_path: str, report: dict) -> None:
    for value in strings_in(report):
        if re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
            return
    errors.append(f"{relative_path} has no transaction hash")

def require_deployment_transactions(relative_path: str, report: dict) -> None:
    transactions = report.get("deployment_transactions")
    if not isinstance(transactions, dict) or not transactions:
        errors.append(f"{relative_path} has no deployment_transactions object")
        return
    for contract in expected_runtime_contracts:
        contract_id = contract["contract_id"]
        kind = contract["kind"]
        tx = transactions.get(contract_id)
        if tx is None:
            tx = transactions.get(kind)
        if not isinstance(tx, dict):
            errors.append(f"{relative_path} missing deployment transaction for {contract_id}")
            continue
        status = str(tx.get("status") or "").lower()
        tx_hash = tx.get("tx_hash")
        if status == "already_deployed":
            if tx_hash is not None:
                require_tx_hash_value(relative_path, tx_hash, f"{contract_id}.tx_hash")
        else:
            if status not in {"deployed", "submitted", "confirmed"}:
                errors.append(f"{relative_path} {contract_id} deployment status {status or '<missing>'} is not deploy evidence")
            require_tx_hash_value(relative_path, tx_hash, f"{contract_id}.tx_hash")
        require_tx_hash_value(relative_path, tx.get("init_code_hash"), f"{contract_id}.init_code_hash")

def require_transaction_ids(relative_path: str, report: dict, required_ids: set[str]) -> None:
    transactions = report.get("transactions")
    if not isinstance(transactions, list) or not transactions:
        errors.append(f"{relative_path} has no transaction list")
        return
    found: dict[str, dict] = {}
    for tx in transactions:
        if isinstance(tx, dict) and isinstance(tx.get("id"), str):
            found[tx["id"]] = tx
    for tx_id in sorted(required_ids):
        tx = found.get(tx_id)
        if not tx:
            errors.append(f"{relative_path} missing transaction id {tx_id}")
            continue
        tx_hash = tx.get("tx_hash")
        if not isinstance(tx_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
            errors.append(f"{relative_path} transaction {tx_id} has no valid tx_hash")

def require_runtime_codehashes(relative_path: str, report: dict) -> None:
    records = report.get("deployed_runtime_codehashes") or report.get("runtime_codehashes")
    if not isinstance(records, dict) or not records:
        errors.append(f"{relative_path} has no deployed_runtime_codehashes object")
        return
    chain_id = report.get("chain_id")
    if chain_id is not None and chain_id != expected_base_sepolia_chain_id and not str(chain_id).startswith("eip155:"):
        errors.append(f"{relative_path} chain_id is not an EIP-155 chain id")

    address_sources = (
        report.get("deployed_contract_addresses"),
        report.get("contract_addresses"),
        report.get("contracts"),
    )
    planned_address_sources = (
        report.get("planned_contract_addresses"),
        report.get("reviewed_planned_contract_addresses"),
    )
    for contract in expected_runtime_contracts:
        contract_id = contract["contract_id"]
        kind = contract["kind"]
        expected_codehash = contract["deployed_runtime_codehash"].lower()
        record = records.get(contract_id)
        if record is None:
            record = records.get(kind)
        if not isinstance(record, dict):
            errors.append(f"{relative_path} has no structured runtime codehash record for {contract_id}")
            continue

        actual_codehash = record.get("actual_runtime_codehash")
        normalized_codehash = record.get("immutable_normalized_runtime_codehash")
        package_codehash = record.get("package_runtime_codehash")
        if not isinstance(actual_codehash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", actual_codehash):
            errors.append(f"{relative_path} {contract_id} actual_runtime_codehash is not a bytes32 hash")
        if not isinstance(normalized_codehash, str) or normalized_codehash.lower() != expected_codehash:
            errors.append(f"{relative_path} {contract_id} immutable_normalized_runtime_codehash does not match package")
        if not isinstance(package_codehash, str) or package_codehash.lower() != expected_codehash:
            errors.append(f"{relative_path} {contract_id} package_runtime_codehash does not match package")
        observed_block_number = record.get("observed_block_number")
        if not isinstance(observed_block_number, int) or observed_block_number < 0:
            errors.append(f"{relative_path} {contract_id} observed_block_number is not a non-negative integer")
        observed_block_hash = record.get("observed_block_hash")
        if not isinstance(observed_block_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", observed_block_hash):
            errors.append(f"{relative_path} {contract_id} observed_block_hash is not a bytes32 hash")
        if record.get("observation_source") not in {"eth_getCode", "eth_getCode:latest-local-fallback"}:
            errors.append(f"{relative_path} {contract_id} observation_source is not eth_getCode")

        address = None
        for source in address_sources:
            if isinstance(source, dict):
                address = source.get(contract_id)
                if address is None:
                    address = source.get(kind)
                if address is not None:
                    break
        require_evm_address(relative_path, address, f"{contract_id} deployed address")
        planned_address = None
        for source in planned_address_sources:
            if isinstance(source, dict):
                planned_address = source.get(contract_id)
                if planned_address is None:
                    planned_address = source.get(kind)
                if planned_address is not None:
                    break
        require_evm_address(relative_path, planned_address, f"{contract_id} planned address")
        if isinstance(address, str) and isinstance(planned_address, str) and address.lower() != planned_address.lower():
            errors.append(f"{relative_path} {contract_id} deployed address does not match planned CREATE2 address")

def require_evm_address(relative_path: str, value: object, label: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        errors.append(f"{relative_path} {label} is not an EVM address")

def require_tx_hash_value(relative_path: str, value: object, label: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        errors.append(f"{relative_path} {label} is not a transaction hash")

def require_all_items_pass(relative_path: str, report: dict) -> None:
    items = report.get("items") or report.get("checks")
    if not isinstance(items, list) or not items:
        errors.append(f"{relative_path} has no checklist items")
        return
    for item in items:
        if not isinstance(item, dict):
            errors.append(f"{relative_path} has a malformed checklist item")
            continue
        status = str(item.get("status") or item.get("outcome") or "").lower()
        if status not in {"pass", "passed", "checked", "complete"} and item.get("checked") is not True:
            errors.append(f"{relative_path} checklist item {item.get('id', '<unknown>')} is not pass")

def require_external_assurance(relative_path: str, report: dict) -> None:
    require_status(relative_path, report)
    target_approval = load_json("external-assurance/target-chain-approval.json")
    expected_manifest_sha256 = target_approval.get("reviewed_manifest_sha256") or target_approval.get("manifest_sha256")
    if relative_path not in {
        "external-assurance/target-chain-approval.json",
        "external-assurance/operator-approval.json",
    }:
        require_manifest_hash_scope(relative_path, report, expected_manifest_sha256)
        require_field_equals(
            relative_path,
            report,
            ("chain_id", "chainId"),
            expected_primary_chain_id,
            "chain id",
            required=True,
        )
    require_field_equals(
        relative_path,
        report,
        ("deployment_policy_id", "policy_id", "policyId"),
        expected_policy_id,
        "deployment policy id",
        required=True,
    )
    require_field_equals(
        relative_path,
        report,
        ("candidate_release_id", "release_id", "candidateReleaseId"),
        expected_release_id,
        "candidate release id",
        required=True,
    )
    if relative_path.endswith("external-audit-report.json"):
        require_report_digest_and_signature(relative_path, report)
        zero_flag = bool_field(
            report,
            "zero_unresolved_critical_high_findings",
            "no_unresolved_critical_high_findings",
        )
        critical = number_field(
            report,
            "unresolved_critical_findings",
            "critical_findings_unresolved",
        )
        high = number_field(
            report,
            "unresolved_high_findings",
            "high_findings_unresolved",
        )
        if not zero_flag and (critical != 0 or high != 0):
            errors.append(f"{relative_path} does not prove zero unresolved critical/high findings")
    elif relative_path.endswith("testnet-soak-report.json"):
        require_report_digest_and_signature(relative_path, report)
        days = number_field(report, "soak_days", "duration_days", "observed_days")
        if days is None or days < 28:
            errors.append(f"{relative_path} does not prove at least 28 soak days")
    elif relative_path.endswith("artifact-digest-gate.json"):
        require_field_equals(
            relative_path,
            report,
            ("contract_package_id", "package_id", "packageId"),
            expected_package_id,
            "contract package id",
            required=True,
        )
        require_artifact_digests(relative_path, report)
    elif relative_path.endswith("deployed-runtime-codehash-gate.json"):
        require_runtime_codehashes(relative_path, report)
    elif relative_path.endswith("minimum-bar-checklist.json"):
        require_report_digest_and_signature(relative_path, report)
        if not bool_field(report, "minimum_bar_complete", "all_required_items_passed"):
            require_all_items_pass(relative_path, report)
    elif relative_path.endswith("security-owner-assurance-unlock.json"):
        require_top_field_equals(
            relative_path,
            report,
            ("status",),
            "approved",
            "status",
        )
        require_top_field_equals(
            relative_path,
            report,
            ("gate",),
            "EXTERNAL_ASSURANCE",
            "gate",
        )
        require_top_field_equals(
            relative_path,
            report,
            ("chain_id", "chainId"),
            expected_primary_chain_id,
            "chain id",
        )
        require_top_field_equals(
            relative_path,
            report,
            ("candidate_release_id", "release_id", "candidateReleaseId"),
            expected_release_id,
            "candidate release id",
        )
        require_top_field_equals(
            relative_path,
            report,
            ("deployment_policy_id", "policy_id", "policyId"),
            expected_policy_id,
            "deployment policy id",
        )
        expected_approval_id = target_approval.get("approval_id")
        require_top_field_equals(
            relative_path,
            report,
            ("approval_id",),
            expected_approval_id,
            "approval id",
        )
        owner = report.get("security_owner_approval")
        if not isinstance(owner, dict) or owner.get("status") != "approved" or not owner.get("actor") or not owner.get("approved_at"):
            errors.append(f"{relative_path} requires security_owner_approval with status approved, actor, and approved_at")
        signature = None if not isinstance(owner, dict) else field_value(
            owner,
            "signature",
            "signature_hex",
            "approval_signature",
            "attestation_signature",
        )
        if not isinstance(signature, str) or not re.fullmatch(r"0x[0-9a-fA-F]{130}", signature):
            errors.append(f"{relative_path} requires a recoverable security-owner signature")
        unresolved = report.get("unresolved_critical_high_findings")
        if not isinstance(unresolved, list) or unresolved:
            errors.append(f"{relative_path} must declare zero unresolved critical/high findings")
        require_component_ref_matches(
            relative_path,
            report,
            "artifact_digest_gate",
            "external-assurance/artifact-digest-gate.json",
        )
        require_component_ref_matches(
            relative_path,
            report,
            "runtime_codehash_gate",
            "external-assurance/deployed-runtime-codehash-gate.json",
        )
        require_component_ref_matches(
            relative_path,
            report,
            "external_audit",
            "external-assurance/external-audit-report.json",
        )
        require_component_ref_matches(
            relative_path,
            report,
            "testnet_soak",
            "external-assurance/testnet-soak-report.json",
        )
        require_component_ref_matches(
            relative_path,
            report,
            "minimum_bar_checklist",
            "external-assurance/minimum-bar-checklist.json",
        )
    elif relative_path.endswith("hosted-workflow-observation.json"):
        if not non_empty_field(report, "workflow_run_id", "hosted_workflow_url", "observation_id"):
            errors.append(f"{relative_path} has no hosted workflow observation id")
        if not non_empty_field(report, "candidate_sha", "candidateSha", "workflow_sha", "git_sha"):
            errors.append(f"{relative_path} has no candidate SHA binding")
        if not non_empty_field(report, "artifact_manifest_sha256", "artifactManifestSha256"):
            errors.append(f"{relative_path} has no artifact manifest SHA-256 binding")
        runtime_gate_digest = field_value(
            report,
            "runtime_codehash_gate_sha256",
            "runtimeCodehashGateSha256",
            "runtime_gate_sha256",
        )
        if not isinstance(runtime_gate_digest, str):
            errors.append(f"{relative_path} has no runtime gate SHA-256 binding")
        else:
            require_staged_digest(
                relative_path,
                "external-assurance/deployed-runtime-codehash-gate.json",
                runtime_gate_digest,
                "runtime_codehash_gate",
            )
    elif relative_path.endswith("target-chain-manifest.json"):
        require_field_equals(
            relative_path,
            report,
            ("chain_id", "chainId"),
            expected_primary_chain_id,
            "chain id",
            required=True,
        )
        require_field_equals(
            relative_path,
            report,
            ("deployment_policy_id", "policy_id", "policyId"),
            expected_policy_id,
            "deployment policy id",
            required=True,
        )
        require_field_equals(
            relative_path,
            report,
            ("candidate_release_id", "release_id", "candidateReleaseId"),
            expected_release_id,
            "candidate release id",
            required=True,
        )
        if not non_empty_field(report, "manifest_sha256", "reviewed_manifest_hash"):
            errors.append(f"{relative_path} has no reviewed manifest hash")
    elif relative_path.endswith("target-chain-approval.json"):
        require_field_equals(
            relative_path,
            report,
            ("chain_id", "chainId"),
            expected_primary_chain_id,
            "chain id",
            required=True,
        )
        if not non_empty_field(report, "approval_id"):
            errors.append(f"{relative_path} has no approval_id")
        if not non_empty_field(report, "approved_by", "approver"):
            errors.append(f"{relative_path} has no approver")
    elif relative_path.endswith("operator-approval.json"):
        if not non_empty_field(report, "operator_address"):
            errors.append(f"{relative_path} has no operator_address")
        if not non_empty_field(report, "approved_by", "operator_approval_id"):
            errors.append(f"{relative_path} has no operator approver or approval id")

def require_base_sepolia_cutover() -> None:
    deployment_path = "live/base-sepolia/promotion/deployment.json"
    promotion_path = "live/base-sepolia/promotion/promotion-report.json"
    smoke_path = "live/base-sepolia/base-sepolia-smoke.json"
    dependency_path = "live/base-sepolia/dependencies/dependencies.json"
    review_inputs_path = "live/base-sepolia/dependencies/base-sepolia.review-inputs.json"

    deployment = load_json(deployment_path)
    require_top_field_equals(
        deployment_path,
        deployment,
        ("environment",),
        "base-sepolia",
        "environment",
    )
    require_top_field_equals(
        deployment_path,
        deployment,
        ("chain_id", "chainId"),
        expected_base_sepolia_chain_id,
        "chain id",
    )
    require_top_field_equals(
        deployment_path,
        deployment,
        ("manifest_id", "manifestId"),
        expected_base_sepolia_reviewed_manifest_id,
        "manifest id",
    )
    require_top_field_equals(
        deployment_path,
        deployment,
        ("deployment_id", "deploymentId"),
        expected_base_sepolia_deployment_id,
        "deployment id",
    )
    require_deployment_transactions(deployment_path, deployment)
    require_runtime_codehashes(deployment_path, deployment)

    promotion = load_json(promotion_path)
    if promotion.get("status") != "promoted":
        errors.append(f"{promotion_path} status is not promoted")
    require_top_field_equals(
        promotion_path,
        promotion,
        ("environment",),
        "base-sepolia",
        "environment",
    )
    require_top_field_equals(
        promotion_path,
        promotion,
        ("chain_id", "chainId"),
        expected_base_sepolia_chain_id,
        "chain id",
    )
    require_top_field_equals(
        promotion_path,
        promotion,
        ("manifest_id", "manifestId"),
        expected_base_sepolia_reviewed_manifest_id,
        "manifest id",
    )
    require_top_field_equals(
        promotion_path,
        promotion,
        ("deployment_path", "deploymentPath"),
        "target/web3-live-rollout/base-sepolia/promotion/deployment.json",
        "deployment path",
    )
    require_checks_pass(promotion_path, promotion)
    require_runtime_codehashes(promotion_path, promotion)
    require_field_equals(
        promotion_path,
        promotion,
        ("deployment_policy_id", "policy_id", "policyId"),
        expected_policy_id,
        "deployment policy id",
        required=True,
    )
    require_field_equals(
        promotion_path,
        promotion,
        ("candidate_release_id", "release_id", "candidateReleaseId"),
        expected_release_id,
        "candidate release id",
        required=True,
    )

    smoke = load_json(smoke_path)
    require_status(smoke_path, smoke)
    require_top_field_equals(
        smoke_path,
        smoke,
        ("chain_id", "chainId"),
        expected_base_sepolia_chain_id,
        "chain id",
    )
    require_top_field_equals(
        smoke_path,
        smoke,
        ("deployment_id", "deploymentId"),
        expected_base_sepolia_deployment_id,
        "deployment id",
    )
    require_top_field_equals(
        smoke_path,
        smoke,
        ("deployment_path", "deploymentPath"),
        "target/web3-live-rollout/base-sepolia/promotion/deployment.json",
        "deployment path",
    )
    require_transaction_ids(
        smoke_path,
        smoke,
        {
            "identity.operator_registration",
            "identity.entity_registration",
            "anchor.partial_root_publish",
            "anchor.final_root_publish",
            "settlement.usdc_approval",
            "settlement.primary_escrow_create",
            "settlement.partial_release",
            "settlement.final_release",
            "settlement.refund_escrow_create",
            "settlement.timeout_refund",
        },
    )
    require_checks_pass(smoke_path, smoke)

    dependencies = load_json(dependency_path)
    require_top_field_equals(
        dependency_path,
        dependencies,
        ("report_id", "reportId"),
        "chio.web3-base-sepolia-dependencies.v1",
        "report id",
    )
    require_top_field_equals(
        dependency_path,
        dependencies,
        ("chain_id", "chainId"),
        expected_base_sepolia_chain_id,
        "chain id",
    )
    create2_factory = dependencies.get("create2_factory")
    if not isinstance(create2_factory, dict):
        errors.append(f"{dependency_path} has no create2_factory object")
    else:
        require_evm_address(dependency_path, create2_factory.get("address"), "create2_factory.address")
        require_tx_hash_value(dependency_path, create2_factory.get("tx_hash"), "create2_factory.tx_hash")
    mock_feeds = dependencies.get("mock_chainlink_feeds")
    if not isinstance(mock_feeds, dict) or not mock_feeds:
        errors.append(f"{dependency_path} has no mock_chainlink_feeds")
    else:
        for feed_name, feed in sorted(mock_feeds.items()):
            if not isinstance(feed, dict):
                errors.append(f"{dependency_path} mock_chainlink_feeds.{feed_name} is not an object")
                continue
            require_evm_address(dependency_path, feed.get("address"), f"mock_chainlink_feeds.{feed_name}.address")
            require_tx_hash_value(dependency_path, feed.get("tx_hash"), f"mock_chainlink_feeds.{feed_name}.tx_hash")

    review_inputs = load_json(review_inputs_path)
    require_nested_equals(
        review_inputs_path,
        review_inputs,
        ("testnet_dependency_source", "kind"),
        "mock-chainlink-feeds",
    )
    require_nested_equals(
        review_inputs_path,
        review_inputs,
        ("testnet_dependency_source", "report_path"),
        "target/web3-live-rollout/base-sepolia/dependencies/dependencies.json",
    )

def require_example_cutover() -> None:
    review_path = "examples/internet-of-agents-web3-network/review-result.json"
    summary_path = "examples/internet-of-agents-web3-network/summary.json"
    index_path = "examples/internet-of-agents-web3-network/web3/validation-index.json"
    readiness_path = "examples/internet-of-agents-web3-network/evidence/cutover-readiness.json"

    review = load_json(review_path)
    if review.get("ok") is not True:
        errors.append(f"{review_path} ok is not true")
    if review.get("errors") not in (None, []):
        errors.append(f"{review_path} contains errors")
    for path, expected in [
        (("chio", "rfq"), "pass"),
        (("chio", "runtime_degradation"), "quarantined_then_reattested"),
        (("chio", "observability"), "correlated"),
        (("chio", "adversarial", "prompt_injection"), "denied"),
        (("chio", "adversarial", "invoice_tampering"), "denied"),
        (("chio", "adversarial", "quote_replay"), "denied"),
        (("chio", "adversarial", "expired_capability"), "denied"),
        (("chio", "adversarial", "unauthorized_settlement_route"), "denied"),
        (("chio", "adversarial", "forged_passport"), "denied"),
        (("web3", "rfq_selection_status"), "pass"),
        (("web3", "dispute_status"), "resolved"),
        (("web3", "approval_status"), "signed"),
        (("web3", "x402_payment_status"), "satisfied"),
        (("web3", "rail_selection_status"), "pass"),
    ]:
        require_nested_equals(review_path, review, path, expected)
    require_nested_equals(review_path, review, ("chio", "subcontractor_lineage_depth"), 2)

    summary = load_json(summary_path)
    for path, expected in [
        (("chio_mediated",), True),
        (("mediation_status",), "pass"),
        (("budget_exposure",), "authorized"),
        (("budget_reconciliation",), "reconciled"),
        (("passport_verdict",), "pass"),
        (("federation_verdict",), "pass"),
        (("reputation_verdict",), "pass"),
        (("behavioral_baseline_status",), "pass"),
        (("rfq_selection_status",), "pass"),
        (("subcontract_lineage_depth",), 2),
        (("dispute_status",), "resolved"),
        (("approval_status",), "signed"),
        (("x402_payment_status",), "satisfied"),
        (("rail_selection_status",), "pass"),
        (("runtime_degradation_status",), "quarantined_then_reattested"),
        (("observability_status",), "correlated"),
        (("historical_reputation_status",), "pass"),
        (("guardrail_denial_status", "invalid_spiffe"), "denied"),
        (("guardrail_denial_status", "overspend"), "denied"),
        (("guardrail_denial_status", "velocity"), "denied"),
        (("adversarial_denial_status", "prompt_injection"), "denied"),
        (("adversarial_denial_status", "invoice_tampering"), "denied"),
        (("adversarial_denial_status", "quote_replay"), "denied"),
        (("adversarial_denial_status", "expired_capability"), "denied"),
        (("adversarial_denial_status", "unauthorized_settlement_route"), "denied"),
        (("adversarial_denial_status", "forged_passport"), "denied"),
        (("base_sepolia_live_smoke_included",), True),
        (("base_sepolia_smoke_status",), "pass"),
    ]:
        require_nested_equals(summary_path, summary, path, expected)

    index = load_json(index_path)
    require_top_field_equals(
        index_path,
        index,
        ("schema",),
        "chio.example.ioa-web3.validation-index.v1",
        "schema",
    )
    require_nested_equals(index_path, index, ("required_local_validations", "e2e", "status"), "pass")
    if not nested_value(index, ("required_local_validations", "promotion", "checks")):
        errors.append(f"{index_path} has no promotion checks")
    if not nested_value(index, ("required_local_validations", "ops", "assertions")):
        errors.append(f"{index_path} has no ops assertions")
    require_nested_equals(index_path, index, ("base_sepolia_live_smoke", "included"), True)
    require_nested_equals(index_path, index, ("base_sepolia_live_smoke", "status"), "pass")
    require_nested_equals(index_path, index, ("base_sepolia_live_smoke", "chain_id"), expected_base_sepolia_chain_id)
    require_nested_equals(index_path, index, ("base_sepolia_live_smoke", "path"), "target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json")
    require_nested_equals(index_path, index, ("base_sepolia_live_smoke", "deployment_id"), expected_base_sepolia_deployment_id)
    if not nested_value(index, ("base_sepolia_live_smoke", "sha256")):
        errors.append(f"{index_path} has no base_sepolia_live_smoke.sha256")
    else:
        require_staged_digest(
            index_path,
            nested_value(index, ("base_sepolia_live_smoke", "path")),
            nested_value(index, ("base_sepolia_live_smoke", "sha256")),
            "base_sepolia_live_smoke",
        )

    live_smoke_path = "live/base-sepolia/base-sepolia-smoke.json"
    live_smoke = load_json(live_smoke_path)
    require_status(live_smoke_path, live_smoke)
    require_top_field_equals(
        live_smoke_path,
        live_smoke,
        ("chain_id", "chainId"),
        expected_base_sepolia_chain_id,
        "chain id",
    )
    require_top_field_equals(
        live_smoke_path,
        live_smoke,
        ("deployment_id", "deploymentId"),
        expected_base_sepolia_deployment_id,
        "deployment id",
    )

    live_deployment_path = "live/base-sepolia/promotion/deployment.json"
    live_deployment = load_json(live_deployment_path)
    require_deployment_transactions(live_deployment_path, live_deployment)
    require_runtime_codehashes(live_deployment_path, live_deployment)

    ops_status_path = "examples/internet-of-agents-web3-network/operations/observability-status.json"
    ops_status = load_json(ops_status_path)
    require_status(ops_status_path, ops_status)
    status_strings = {value.lower() for value in strings_in(ops_status)}
    if "correlated" not in status_strings:
        errors.append(f"{ops_status_path} does not prove correlated operations evidence")

    readiness = load_json(readiness_path)
    require_nested_equals(readiness_path, readiness, ("mainnet_blocked",), True)
    require_nested_equals(readiness_path, readiness, ("local_evidence_present",), True)
    require_nested_equals(readiness_path, readiness, ("base_sepolia_smoke_passed",), True)
    require_nested_equals(readiness_path, readiness, ("base_sepolia_chain_id",), expected_base_sepolia_chain_id)
    require_nested_equals(readiness_path, readiness, ("base_sepolia_smoke_path",), "target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json")

policy_doc = load_json("docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json")
release_doc = load_json("contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json")
chain_config = load_json("docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json")
contract_package = load_json("docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json")
base_sepolia_template = load_json("contracts/deployments/base-sepolia.template.json")
expected_policy_id = policy_doc.get("policyId")
expected_release_id = release_doc.get("release_id")
expected_primary_chain_id = chain_config.get("primary_chain_id")
expected_package_id = contract_package.get("package_id")
expected_contract_package_sha256 = sha256_file("docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json")
expected_base_sepolia_chain_id = base_sepolia_template.get("chain_id")
expected_base_sepolia_reviewed_manifest_id = "chio.web3-deployment.base-sepolia.reviewed.v1"
expected_base_sepolia_deployment_id = "chio.web3-reviewed-rollout.base-sepolia.v1"
expected_runtime_contracts = [
    {
        "contract_id": contract.get("contract_id"),
        "kind": contract.get("kind"),
        "deployed_runtime_codehash": contract.get("deployed_runtime_codehash"),
    }
    for contract in contract_package.get("contracts", [])
    if isinstance(contract, dict)
    and contract.get("contract_id")
    and contract.get("kind")
    and contract.get("deployed_runtime_codehash")
]
if not expected_runtime_contracts:
    errors.append("docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json has no runtime contract entries")
required_digest_path_set = set()
artifact_digest_excluded_paths = {
    "target/web3-external-assurance/artifact-digest-gate.json",
    "target/web3-external-assurance/security-owner-assurance-unlock.json",
    "target/release-qualification/web3-runtime/artifact-manifest.json",
}
for source in (
    [
        "docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json",
        "contracts/artifacts/ChioRootRegistry.json",
        "contracts/artifacts/ChioEscrow.json",
        "contracts/artifacts/ChioBondVault.json",
        "contracts/artifacts/ChioIdentityRegistry.json",
        "contracts/artifacts/ChioPriceResolver.json",
    ],
    policy_doc.get("requiredEvidence", []),
    policy_doc.get("stagedBundleRequiredEvidence", []),
    policy_doc.get("stagedBundleCutoverRequiredEvidence", []),
    policy_doc.get("externalAssuranceRequiredEvidence", []),
):
    for raw_path in source:
        if isinstance(raw_path, str):
            normalized_path = raw_path.removeprefix("./")
            if normalized_path not in artifact_digest_excluded_paths and not normalized_path.startswith("target/web3-external-assurance/"):
                required_digest_path_set.add(normalized_path)
required_digest_paths = sorted(required_digest_path_set)

promotion_root = "promotion"
promotion_summary = load_json(f"{promotion_root}/promotion-qualification.json")
require_checks_pass(f"{promotion_root}/promotion-qualification.json", promotion_summary)
parse_generated_at(
    f"{promotion_root}/promotion-qualification.json",
    promotion_summary.get("generated_at"),
)

for promotion_run in ["run-a", "run-b", "resume-existing"]:
    relative_path = f"{promotion_root}/{promotion_run}/promotion-report.json"
    deployment_path = f"{promotion_root}/{promotion_run}/deployment.json"
    report = load_json(relative_path)
    deployment = load_json(deployment_path)
    if report.get("status") != "promoted":
        errors.append(f"{relative_path} status is not promoted")
    require_checks_pass(relative_path, report)
    require_runtime_codehashes(relative_path, report)
    require_deployment_transactions(deployment_path, deployment)
    require_runtime_codehashes(deployment_path, deployment)

expected_negative_errors = {
    f"{promotion_root}/negative-assurance-security-owner/top-level-only/promotion-report.json": "non-testnet approval must declare an approved security-owner EVM address",
    f"{promotion_root}/negative-assurance-security-owner/pending-owner/promotion-report.json": "non-testnet approval must declare an approved security-owner EVM address",
    f"{promotion_root}/negative-assurance-security-owner/missing-owner-approved-at/promotion-report.json": "non-testnet approval must declare an approved security-owner EVM address",
    f"{promotion_root}/negative-assurance-security-owner/conflicting-owner/promotion-report.json": "non-testnet approval security-owner address does not match approved role entry",
    f"{promotion_root}/negative-assurance-security-owner/conflicting-approved-owners/promotion-report.json": "non-testnet approval has conflicting approved security-owner addresses",
}
for relative_path in [
    f"{promotion_root}/negative-approval/promotion-report.json",
    f"{promotion_root}/negative-rollback/promotion-report.json",
    *expected_negative_errors.keys(),
]:
    report = load_json(relative_path)
    if report.get("status") in {"promoted", "pass"}:
        errors.append(f"{relative_path} unexpectedly reports promotion success")
    if relative_path in expected_negative_errors:
        if str(report.get("status") or "").lower() != "failed":
            errors.append(f"{relative_path} status is not failed")
        expected_error = expected_negative_errors[relative_path]
        if expected_error not in " ".join(strings_in(report)):
            errors.append(f"{relative_path} does not prove expected security-owner rejection")

if require_cutover_evidence:
    require_base_sepolia_cutover()
    require_example_cutover()
    for relative_path in [
        "external-assurance/external-audit-report.json",
        "external-assurance/testnet-soak-report.json",
        "external-assurance/artifact-digest-gate.json",
        "external-assurance/deployed-runtime-codehash-gate.json",
        "external-assurance/minimum-bar-checklist.json",
        "external-assurance/security-owner-assurance-unlock.json",
        "external-assurance/hosted-workflow-observation.json",
        "external-assurance/target-chain-manifest.json",
        "external-assurance/target-chain-approval.json",
        "external-assurance/operator-approval.json",
    ]:
        report = load_json(relative_path)
        require_external_assurance(relative_path, report)

if errors:
    print("staged web3 release evidence failed validation:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    raise SystemExit(1)
PY

if [[ "${require_cutover_evidence}" == "true" ]]; then
  (
    cd contracts
    CHIO_STAGE_WEB3_DEST_ROOT="../${dest_root}" \
    CHIO_STAGE_WEB3_RUNTIME_RPC_URL="${runtime_rpc_url}" \
    CHIO_STAGE_WEB3_BASE_SEPOLIA_RPC_URL="${base_sepolia_runtime_rpc_url}" \
    node --input-type=module <<'NODE'
import fs from "node:fs";
import path from "node:path";

import { ethers } from "ethers";

const destRoot = path.resolve(process.cwd(), process.env.CHIO_STAGE_WEB3_DEST_ROOT);
const contractPackage = readJson("docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json");
const chainConfig = readJson("docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json");
const contractRelease = readJson("contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json");
const deploymentPolicy = readJson("docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json");
const artifactByContractId = {
  "chio.root-registry": "contracts/artifacts/ChioRootRegistry.json",
  "chio.escrow": "contracts/artifacts/ChioEscrow.json",
  "chio.bond-vault": "contracts/artifacts/ChioBondVault.json",
  "chio.identity-registry": "contracts/artifacts/ChioIdentityRegistry.json",
  "chio.price-resolver": "contracts/artifacts/ChioPriceResolver.json",
};
const providers = new Map();

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(destRoot, relativePath), "utf8"));
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256CanonicalObject(value) {
  return ethers.sha256(ethers.toUtf8Bytes(canonicalJson(value))).slice(2);
}

function sha256PrettyJsonObject(value) {
  return ethers.sha256(ethers.toUtf8Bytes(`${JSON.stringify(value, null, 2)}\n`)).slice(2);
}

function normalizeReviewedManifestId(templateId) {
  if (templateId.includes(".template.")) {
    return templateId.replace(".template.", ".reviewed.");
  }
  if (templateId.endsWith(".template")) {
    return `${templateId.slice(0, -".template".length)}.reviewed`;
  }
  return `${templateId}.reviewed`;
}

function replaceExactPlaceholders(value, replacements) {
  if (typeof value === "string") {
    const match = /^<([^>]+)>$/.exec(value);
    if (!match) {
      return value;
    }
    const replacement = replacements[match[1]];
    return replacement === undefined ? value : replacement;
  }
  if (Array.isArray(value)) {
    return value.map((item) => replaceExactPlaceholders(item, replacements));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, replaceExactPlaceholders(nested, replacements)])
    );
  }
  return value;
}

function expectedSecurityOwnerAddress(approval) {
  const declaredValues = [
    approval.security_owner_address,
    approval.securityOwnerAddress,
    approval.security_owner?.address,
    approval.securityOwner?.address
  ].filter((value) => value !== undefined && value !== null && value !== "");
  for (const value of declaredValues) {
    if (typeof value !== "string" || !ethers.isAddress(value)) {
      throw new Error("target-chain approval security-owner address is invalid");
    }
  }
  const declaredAddress = declaredValues.length > 0 ? ethers.getAddress(declaredValues[0]) : null;
  for (const value of declaredValues.slice(1)) {
    if (ethers.getAddress(value) !== declaredAddress) {
      throw new Error("target-chain approval has conflicting security-owner addresses");
    }
  }

  const approvedAddresses = [];
  for (const entry of approval.approvals ?? []) {
    const role = String(entry.role ?? "").toLowerCase().replaceAll("_", "-");
    if (role === "security-owner" && entry.status === "approved" && entry.approved_at) {
      for (const value of [entry.address, entry.evm_address, entry.signer_address]) {
        if (typeof value === "string" && ethers.isAddress(value)) {
          approvedAddresses.push(ethers.getAddress(value));
        }
      }
    }
  }
  const uniqueApprovedAddresses = [...new Set(approvedAddresses)];
  if (uniqueApprovedAddresses.length > 1) {
    throw new Error("target-chain approval has conflicting approved security-owner addresses");
  }
  const approvedAddress = uniqueApprovedAddresses[0] ?? null;
  if (declaredAddress && approvedAddress && declaredAddress !== approvedAddress) {
    throw new Error("target-chain approval security-owner address does not match approved role entry");
  }
  if (approvedAddress) {
    return approvedAddress;
  }
  throw new Error("target-chain approval must declare an approved security-owner EVM address");
}

function assuranceUnlockSignaturePayload(unlock) {
  const copy = structuredClone(unlock);
  const ownerApproval = structuredClone(copy.security_owner_approval ?? {});
  delete ownerApproval.signature;
  delete ownerApproval.signature_hex;
  delete ownerApproval.approval_signature;
  delete ownerApproval.attestation_signature;
  copy.security_owner_approval = ownerApproval;
  delete copy.security_owner_signature;
  delete copy.signature;
  delete copy.signature_hex;
  return `chio.web3.assurance-unlock.v1:${sha256CanonicalObject(copy)}`;
}

function verifySecurityOwnerUnlock() {
  const unlock = readJson("external-assurance/security-owner-assurance-unlock.json");
  const approval = readJson("external-assurance/target-chain-approval.json");
  const owner = unlock.security_owner_approval ?? {};
  const signature =
    owner.signature ??
    owner.signature_hex ??
    owner.approval_signature ??
    owner.attestation_signature ??
    unlock.security_owner_signature;
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    throw new Error("security-owner assurance unlock has no recoverable signature");
  }
  const recovered = ethers.verifyMessage(assuranceUnlockSignaturePayload(unlock), signature);
  const expected = expectedSecurityOwnerAddress(approval);
  if (ethers.getAddress(recovered) !== expected) {
    throw new Error("security-owner assurance unlock signature does not match target-chain approval");
  }
}

function runtimeRpcUrl(chainId) {
  const normalizedKey = `CHIO_STAGE_WEB3_RPC_${chainId.replace(/[^A-Za-z0-9]/g, "_").toUpperCase()}`;
  if (process.env[normalizedKey]) {
    return process.env[normalizedKey];
  }
  if (chainId === "eip155:84532" && process.env.CHIO_STAGE_WEB3_BASE_SEPOLIA_RPC_URL) {
    return process.env.CHIO_STAGE_WEB3_BASE_SEPOLIA_RPC_URL;
  }
  if (chainId === "eip155:8453" && process.env.CHIO_STAGE_WEB3_MAINNET_RPC_URL) {
    return process.env.CHIO_STAGE_WEB3_MAINNET_RPC_URL;
  }
  if (chainId === "eip155:42161" && process.env.CHIO_STAGE_WEB3_ARBITRUM_RPC_URL) {
    return process.env.CHIO_STAGE_WEB3_ARBITRUM_RPC_URL;
  }
  return process.env.CHIO_STAGE_WEB3_RUNTIME_RPC_URL;
}

async function providerForChain(chainId) {
  const match = /^eip155:(\d+)$/.exec(chainId);
  if (!match) {
    throw new Error(`${chainId} is not an EIP-155 chain id`);
  }
  const rpcUrl = runtimeRpcUrl(chainId);
  if (!rpcUrl) {
    throw new Error(
      `cutover runtime verification requires an RPC URL for ${chainId}; set CHIO_STAGE_WEB3_RPC_${chainId.replace(/[^A-Za-z0-9]/g, "_").toUpperCase()}`
    );
  }
  if (!providers.has(rpcUrl)) {
    providers.set(rpcUrl, new ethers.JsonRpcProvider(rpcUrl));
  }
  const provider = providers.get(rpcUrl);
  const network = await provider.getNetwork();
  if (network.chainId !== BigInt(match[1])) {
    throw new Error(`runtime RPC chain ${network.chainId} does not match ${chainId}`);
  }
  return provider;
}

function normalizeDeployedCodeForImmutableReferences(label, artifact, deployedCode) {
  const deployedHex = deployedCode.toLowerCase().replace(/^0x/, "");
  const templateHex = (artifact.deployedBytecode ?? "").toLowerCase().replace(/^0x/, "");
  if (!templateHex) {
    throw new Error(`${label} artifact has no deployedBytecode`);
  }
  if (deployedHex.length !== templateHex.length) {
    throw new Error(`${label} deployed runtime bytecode length does not match staged artifact`);
  }
  let normalized = deployedHex;
  for (const references of Object.values(artifact.immutableReferences ?? {})) {
    for (const reference of references) {
      const start = reference.start * 2;
      const end = start + reference.length * 2;
      normalized = `${normalized.slice(0, start)}${templateHex.slice(start, end)}${normalized.slice(end)}`;
    }
  }
  return `0x${normalized}`;
}

function addressFromSource(source, contract) {
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    return null;
  }
  const kindAddressKey = `${contract.kind}_address`;
  return source[contract.contract_id] ?? source[contract.kind] ?? source[kindAddressKey] ?? null;
}

function requiredBaseSepoliaRoleAddress(reviewInputs, fieldName) {
  const value = reviewInputs[fieldName] ?? reviewInputs.role_address;
  if (typeof value !== "string" || !ethers.isAddress(value)) {
    throw new Error(`Base Sepolia review inputs missing ${fieldName}`);
  }
  return ethers.getAddress(value);
}

function baseSepoliaReviewedManifestAndInputs() {
  const template = readJson("contracts/deployments/base-sepolia.template.json");
  const reviewInputs = readJson("live/base-sepolia/dependencies/base-sepolia.review-inputs.json");
  const replacements = {
    ...(reviewInputs.placeholders ?? {}),
    registry_admin_address: requiredBaseSepoliaRoleAddress(reviewInputs, "registry_admin_address"),
    price_admin_address: requiredBaseSepoliaRoleAddress(reviewInputs, "price_admin_address"),
    operator_address: requiredBaseSepoliaRoleAddress(reviewInputs, "operator_address"),
    delegate_address: requiredBaseSepoliaRoleAddress(reviewInputs, "delegate_address")
  };
  let manifest = structuredClone(template);
  manifest.manifest_id = normalizeReviewedManifestId(template.manifest_id);
  manifest.deployment_mode = "reviewed-manifest";
  manifest.review_context = {
    candidate_release_id: contractRelease.release_id,
    deployment_policy_id: deploymentPolicy.policyId
  };
  manifest.operator_configuration = {
    registry_admin_address: replacements.registry_admin_address,
    price_admin_address: replacements.price_admin_address,
    operator_address: replacements.operator_address,
    operator_ed_key_label: reviewInputs.operator_ed_key_label ?? "chio-operator-ed25519-key",
    delegate_address: replacements.delegate_address,
    delegate_expiry_seconds: Number(reviewInputs.delegate_expiry_seconds ?? 3600)
  };
  manifest = replaceExactPlaceholders(manifest, replacements);
  return { manifest, reviewInputs };
}

function resolveReviewedConstructorValue(value, state) {
  if (typeof value !== "string") {
    return value;
  }
  const match = /^<([^>]+)>$/.exec(value);
  if (!match) {
    return value;
  }
  const resolved = state.contractAddresses[match[1]];
  if (!resolved) {
    throw new Error(`Base Sepolia reviewed manifest has unresolved constructor placeholder ${value}`);
  }
  return resolved;
}

function packageContractById(contractId) {
  return (contractPackage.contracts ?? []).find((contract) => contract.contract_id === contractId);
}

function saltForReviewedContract(namespace, localSalt) {
  return ethers.keccak256(ethers.toUtf8Bytes(`${namespace}:${localSalt}`));
}

function baseSepoliaReviewedPlannedAddresses(report) {
  const { manifest, reviewInputs } = baseSepoliaReviewedManifestAndInputs();
  const manifestHash = sha256PrettyJsonObject(manifest);
  if (report.manifest_id !== manifest.manifest_id) {
    throw new Error("live Base Sepolia deployment manifest id does not match reconstructed reviewed manifest");
  }
  if (String(report.manifest_sha256 ?? "").toLowerCase() !== manifestHash) {
    throw new Error("live Base Sepolia deployment manifest sha256 does not match reconstructed reviewed manifest");
  }
  const dependencies = readJson("live/base-sepolia/dependencies/dependencies.json");
  const trustedFactory =
    reviewInputs.create2_factory_address ??
    reviewInputs.create2?.factory_address ??
    dependencies.create2_factory?.address;
  if (typeof trustedFactory !== "string" || !ethers.isAddress(trustedFactory)) {
    throw new Error("Base Sepolia review inputs have no trusted CREATE2 factory address");
  }
  if (dependencies.create2_factory?.address && ethers.getAddress(dependencies.create2_factory.address) !== ethers.getAddress(trustedFactory)) {
    throw new Error("Base Sepolia review inputs CREATE2 factory does not match dependency report");
  }
  if (report.create2_factory_address && ethers.getAddress(report.create2_factory_address) !== ethers.getAddress(trustedFactory)) {
    throw new Error("live Base Sepolia deployment CREATE2 factory does not match review inputs");
  }

  const state = { contractAddresses: {} };
  const addresses = {};
  for (const contract of manifest.contracts ?? []) {
    const artifact = readJson(contract.artifact);
    const constructorArgs = (contract.constructor_args ?? []).map((arg) =>
      resolveReviewedConstructorValue(arg, state)
    );
    const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode);
    const initCode = ethers.concat([artifact.bytecode, factory.interface.encodeDeploy(constructorArgs)]);
    const plannedAddress = ethers.getCreate2Address(
      trustedFactory,
      saltForReviewedContract(manifest.salt_namespace, contract.create2_salt),
      ethers.keccak256(initCode)
    );
    const packageEntry = packageContractById(contract.contract_id);
    if (!packageEntry?.kind) {
      throw new Error(`contract package missing kind for ${contract.contract_id}`);
    }
    addresses[contract.contract_id] = plannedAddress;
    addresses[`${packageEntry.kind}_address`] = plannedAddress;
    state.contractAddresses[contract.contract_id] = plannedAddress;
    const placeholderKey = contract.contract_id.replace("chio.", "").replaceAll("-", "_");
    state.contractAddresses[`${placeholderKey}_address`] = plannedAddress;
    state.contractAddresses[placeholderKey] = plannedAddress;
  }
  return addresses;
}

function trustedAddressesForRuntimeReport(relativePath, report) {
  if (relativePath === "external-assurance/deployed-runtime-codehash-gate.json") {
    const targetManifest = readJson("external-assurance/target-chain-manifest.json");
    const targetApproval = readJson("external-assurance/target-chain-approval.json");
    const chainId = report.chain_id ?? report.chainId;
    const chainDeployment = (chainConfig.deployments ?? []).find((deployment) => deployment.chain_id === chainId) ?? {};
    return [
      targetManifest.deployed_contract_addresses,
      targetManifest.planned_contract_addresses,
      targetManifest.reviewed_planned_contract_addresses,
      targetManifest.contract_addresses,
      targetManifest.contracts,
      targetApproval.deployed_contract_addresses,
      targetApproval.planned_contract_addresses,
      targetApproval.reviewed_planned_contract_addresses,
      targetApproval.contract_addresses,
      targetApproval.contracts,
      chainDeployment.deployed_contract_addresses,
      chainDeployment.planned_contract_addresses,
    ].filter(Boolean);
  }
  if (relativePath === "live/base-sepolia/promotion/deployment.json") {
    return [baseSepoliaReviewedPlannedAddresses(report)];
  }
  if (relativePath === "live/base-sepolia/promotion/promotion-report.json") {
    const deployment = readJson("live/base-sepolia/promotion/deployment.json");
    return [
      deployment.deployed_contract_addresses,
      deployment.planned_contract_addresses,
    ].filter(Boolean);
  }
  return [];
}

function runtimeAddress(relativePath, report, contract) {
  const trustedSources = trustedAddressesForRuntimeReport(relativePath, report);
  let trustedAddress = null;
  for (const source of trustedSources) {
    trustedAddress = addressFromSource(source, contract);
    if (trustedAddress) {
      break;
    }
  }
  if (!trustedAddress) {
    throw new Error(`runtime report has no trusted address for ${contract.contract_id}`);
  }
  for (const source of [report.deployed_contract_addresses, report.contract_addresses, report.contracts]) {
    const selfDeclared = addressFromSource(source, contract);
    if (selfDeclared && ethers.isAddress(selfDeclared) && ethers.isAddress(trustedAddress)) {
      if (ethers.getAddress(selfDeclared) !== ethers.getAddress(trustedAddress)) {
        throw new Error(`${contract.contract_id} deployed address does not match trusted target-chain plan`);
      }
    }
  }
  return trustedAddress;
}

async function verifyRuntimeReport(relativePath) {
  const report = readJson(relativePath);
  const chainId = report.chain_id ?? report.chainId;
  if (typeof chainId !== "string") {
    throw new Error(`${relativePath} has no chain_id`);
  }
  const provider = await providerForChain(chainId);
  const records = report.deployed_runtime_codehashes ?? report.runtime_codehashes;
  if (!records || typeof records !== "object" || Array.isArray(records)) {
    throw new Error(`${relativePath} has no deployed_runtime_codehashes object`);
  }
  for (const contract of contractPackage.contracts ?? []) {
    const record = records[contract.contract_id] ?? records[contract.kind];
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw new Error(`${relativePath} has no runtime record for ${contract.contract_id}`);
    }
    if (record.observation_source !== "eth_getCode") {
      throw new Error(`${relativePath} ${contract.contract_id} observation_source must be eth_getCode`);
    }
    const blockNumber = record.observed_block_number;
    if (!Number.isSafeInteger(blockNumber) || blockNumber < 0) {
      throw new Error(`${relativePath} ${contract.contract_id} observed_block_number is invalid`);
    }
    const block = await provider.getBlock(blockNumber);
    if (!block?.hash || block.hash.toLowerCase() !== String(record.observed_block_hash).toLowerCase()) {
      throw new Error(`${relativePath} ${contract.contract_id} observed block hash does not match live chain`);
    }
    const address = runtimeAddress(relativePath, report, contract);
    if (!ethers.isAddress(address)) {
      throw new Error(`${relativePath} ${contract.contract_id} address is invalid`);
    }
    const deployedCode = await provider.getCode(address, blockNumber);
    if (!deployedCode || deployedCode === "0x") {
      throw new Error(`${relativePath} ${contract.contract_id} has no live bytecode at observed block`);
    }
    const actualRuntimeCodehash = ethers.keccak256(deployedCode);
    if (actualRuntimeCodehash.toLowerCase() !== String(record.actual_runtime_codehash).toLowerCase()) {
      throw new Error(`${relativePath} ${contract.contract_id} actual runtime codehash does not match live eth_getCode`);
    }
    const artifactPath = artifactByContractId[contract.contract_id];
    if (!artifactPath) {
      throw new Error(`${relativePath} ${contract.contract_id} has no staged artifact mapping`);
    }
    const artifact = readJson(artifactPath);
    const normalizedRuntimeCodehash = ethers.keccak256(
      normalizeDeployedCodeForImmutableReferences(contract.contract_id, artifact, deployedCode)
    );
    if (normalizedRuntimeCodehash.toLowerCase() !== contract.deployed_runtime_codehash.toLowerCase()) {
      throw new Error(`${relativePath} ${contract.contract_id} live normalized codehash does not match contract package`);
    }
  }
}

verifySecurityOwnerUnlock();
for (const reportPath of [
  "external-assurance/deployed-runtime-codehash-gate.json",
  "live/base-sepolia/promotion/deployment.json",
  "live/base-sepolia/promotion/promotion-report.json",
]) {
  await verifyRuntimeReport(reportPath);
}
NODE
  )
fi

python3 - <<'PY' "${dest_root}/artifact-manifest.json" "${present_list}" "${missing_list}" "${required_missing_list}" "${require_cutover_evidence}" "${dest_root}"
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

manifest_path = Path(sys.argv[1])
present_path = Path(sys.argv[2])
missing_path = Path(sys.argv[3])
required_missing_path = Path(sys.argv[4])
require_cutover_evidence = sys.argv[5] == "true"
dest_root = Path(sys.argv[6])

def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]

present_artifacts = sorted(set(read_lines(present_path) + [str(manifest_path)]))

manifest = {
    "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "source": "github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "local",
    "candidateSha": os.environ.get("GITHUB_SHA", "local"),
    "workflowRunId": os.environ.get("GITHUB_RUN_ID"),
    "workflowRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    "cutoverEvidenceRequired": require_cutover_evidence,
    "externalAssuranceRequired": require_cutover_evidence,
    "bundleMode": "cutover" if require_cutover_evidence else "rehearsal",
    "cutoverReady": require_cutover_evidence and not read_lines(required_missing_path),
    "presentArtifacts": present_artifacts,
    "missingArtifacts": read_lines(missing_path),
    "requiredMissingArtifacts": read_lines(required_missing_path),
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

actual_artifacts = sorted(
    str(path) for path in dest_root.rglob("*") if path.is_file()
)
unlisted_artifacts = [path for path in actual_artifacts if path not in present_artifacts]
if unlisted_artifacts:
    manifest["unlistedArtifacts"] = unlisted_artifacts
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("staged web3 bundle contains unlisted artifacts:", file=sys.stderr)
    for artifact in unlisted_artifacts:
        print(f"  - {artifact}", file=sys.stderr)
    raise SystemExit(1)
PY

if [[ -s "${required_missing_list}" ]]; then
  echo "missing required web3 release artifacts:" >&2
  sed 's/^/  - /' "${required_missing_list}" >&2
  exit 1
fi
