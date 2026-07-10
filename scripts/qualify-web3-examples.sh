#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

output_root="target/web3-example-qualification"
log_path="${output_root}/qualification.log"
e2e_report="target/web3-e2e-qualification/partner-qualification.json"
promotion_report="target/web3-promotion-qualification/promotion-qualification.json"
ops_audit="target/web3-ops-qualification/incident-audit.json"
mkdir -p "${output_root}"
: >"${log_path}"

run() {
  printf '==> %s\n' "$*" | tee -a "${log_path}"
  "$@" 2>&1 | tee -a "${log_path}"
}

ensure_report() {
  local report_path="$1"
  shift
  if [[ -s "${report_path}" ]]; then
    return 0
  fi
  run "$@"
}

ensure_report "${e2e_report}" ./scripts/qualify-web3-e2e.sh
ensure_report "${promotion_report}" ./scripts/qualify-web3-promotion.sh
ensure_report "${ops_audit}" ./scripts/qualify-web3-ops-controls.sh

run bash examples/internet-of-agents-web3-network/smoke.sh \
  --artifact-dir "${output_root}/internet-of-agents-web3-network" \
  --e2e-report "${e2e_report}" \
  --promotion-report "${promotion_report}" \
  --ops-audit "${ops_audit}"

run jq empty \
  "${output_root}/internet-of-agents-web3-network/review-result.json" \
  "${output_root}/internet-of-agents-web3-network/summary.json" \
  "${output_root}/internet-of-agents-web3-network/chio/topology.json" \
  "${output_root}/internet-of-agents-web3-network/chio/receipts/receipt-summary.json" \
  "${output_root}/internet-of-agents-web3-network/chio/budgets/budget-summary.json" \
  "${output_root}/internet-of-agents-web3-network/identity/passports/proofworks-provider-passport-provenance.json" \
  "${output_root}/internet-of-agents-web3-network/identity/passports/proofworks-provider-passport-verdict.json" \
  "${output_root}/internet-of-agents-web3-network/identity/passports/provider-passport-verdicts.json" \
  "${output_root}/internet-of-agents-web3-network/identity/presentations/provider-presentation-verdict.json" \
  "${output_root}/internet-of-agents-web3-network/federation/evidence-export-package/manifest.json" \
  "${output_root}/internet-of-agents-web3-network/federation/federated-delegation-policy.json" \
  "${output_root}/internet-of-agents-web3-network/federation/open-admission-evaluation.json" \
  "${output_root}/internet-of-agents-web3-network/federation/provider-admission-verdicts.json" \
  "${output_root}/internet-of-agents-web3-network/federation/subcontractor-admission.json" \
  "${output_root}/internet-of-agents-web3-network/reputation/history-ledger.json" \
  "${output_root}/internet-of-agents-web3-network/reputation/provider-scorecards.json" \
  "${output_root}/internet-of-agents-web3-network/reputation/passport-drift-report.json" \
  "${output_root}/internet-of-agents-web3-network/reputation/provider-reputation-verdict.json" \
  "${output_root}/internet-of-agents-web3-network/behavior/behavioral-status.json" \
  "${output_root}/internet-of-agents-web3-network/guardrails/invalid-spiffe-denial.json" \
  "${output_root}/internet-of-agents-web3-network/guardrails/overspend-denial.json" \
  "${output_root}/internet-of-agents-web3-network/guardrails/velocity-burst-denial.json" \
  "${output_root}/internet-of-agents-web3-network/adversarial/summary.json" \
  "${output_root}/internet-of-agents-web3-network/approvals/high-risk-release-audit.json" \
  "${output_root}/internet-of-agents-web3-network/payments/x402-payment-satisfaction.json" \
  "${output_root}/internet-of-agents-web3-network/subcontracting/delegated-capability.json" \
  "${output_root}/internet-of-agents-web3-network/subcontracting/review-attestation.json" \
  "${output_root}/internet-of-agents-web3-network/settlement/rail-selection.json" \
  "${output_root}/internet-of-agents-web3-network/disputes/dispute-summary.json" \
  "${output_root}/internet-of-agents-web3-network/operations/observability-status.json" \
  "${output_root}/internet-of-agents-web3-network/identity/runtime-degradation/summary.json" \
  "${output_root}/internet-of-agents-web3-network/market/rfq-request.json" \
  "${output_root}/internet-of-agents-web3-network/market/provider-bids.json" \
  "${output_root}/internet-of-agents-web3-network/market/provider-selection.json" \
  "${output_root}/internet-of-agents-web3-network/provider/review-result.json" \
  "${output_root}/internet-of-agents-web3-network/web3/validation-index.json" \
  "${output_root}/internet-of-agents-web3-network/evidence/cutover-readiness.json" \
  "${output_root}/internet-of-agents-web3-network/contracts/settlement-packet.json" \
  "${output_root}/internet-of-agents-web3-network/contracts/web3-settlement-dispatch.json" \
  "${output_root}/internet-of-agents-web3-network/contracts/web3-settlement-receipt.json" \
  "${output_root}/internet-of-agents-web3-network/transaction-passport/transaction-passport.json" \
  "${output_root}/internet-of-agents-web3-network/transaction-passport/verifier-report.json"

run jq -e '
  .ok == true
  and (.chio.provenance_sources.passport == "chio-cli")
  and (.chio.provenance_sources.evidence_export == "chio-cli")
  and (.chio.provenance_sources.evidence_import == "chio-trust-control")
  and (.chio.provenance_sources.federated_issue == "chio-trust-control")
  and (.chio.rfq == "pass")
  and (.chio.subcontractor_lineage_depth == 2)
  and (.chio.runtime_degradation == "quarantined_then_reattested")
  and (.chio.observability == "correlated")
  and (.chio.adversarial.prompt_injection == "denied")
  and (.chio.adversarial.invoice_tampering == "denied")
  and (.chio.adversarial.quote_replay == "denied")
  and (.chio.adversarial.expired_capability == "denied")
  and (.chio.adversarial.unauthorized_settlement_route == "denied")
  and (.chio.adversarial.forged_passport == "denied")
  and (.web3.rfq_selection_status == "pass")
  and (.web3.dispute_status == "resolved")
  and (.web3.approval_status == "signed")
  and (.web3.x402_payment_status == "satisfied")
  and (.web3.rail_selection_status == "pass")
' "${output_root}/internet-of-agents-web3-network/review-result.json" >/dev/null

run jq -e '.organizations | length == 4' \
  "${output_root}/internet-of-agents-web3-network/chio/topology.json" >/dev/null

run jq -e '
  .rfq_selection_status == "pass"
  and .subcontract_lineage_depth == 2
  and .dispute_status == "resolved"
  and .approval_status == "signed"
  and .x402_payment_status == "satisfied"
  and .rail_selection_status == "pass"
  and .runtime_degradation_status == "quarantined_then_reattested"
  and .observability_status == "correlated"
  and .historical_reputation_status == "pass"
  and .selected_provider_id == "proofworks-agent-auditors"
  and (.rejected_provider_count == 2)
  and (.selected_rail | type == "string")
  and .adversarial_denial_status.prompt_injection == "denied"
  and .adversarial_denial_status.invoice_tampering == "denied"
  and .adversarial_denial_status.quote_replay == "denied"
  and .adversarial_denial_status.expired_capability == "denied"
  and .adversarial_denial_status.unauthorized_settlement_route == "denied"
  and .adversarial_denial_status.forged_passport == "denied"
' "${output_root}/internet-of-agents-web3-network/summary.json" >/dev/null

run jq -e '
  .schema == "chio.transaction.verifier-report.v1"
  and .passport_id == "passport-ioa-web3-service-order"
  and .verdict == "verified"
' "${output_root}/internet-of-agents-web3-network/transaction-passport/verifier-report.json" >/dev/null

printf 'web3 example qualification complete; log written to %s\n' "${log_path}" | tee -a "${log_path}"
