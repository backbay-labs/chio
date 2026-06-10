#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! cargo kani --version >/dev/null 2>&1; then
  echo "Kani public core check requires cargo-kani" >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path

source = Path("crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs")
text = source.read_text(encoding="utf-8")
expected = [
    "public_verify_capability_rejects_untrusted_issuer_before_signature",
    "public_normalized_scope_subset_rejects_widened_child",
    "public_normalized_scope_subset_rejects_value_widened_child",
    "public_normalized_scope_subset_rejects_identity_mismatch",
    "public_resolve_matching_grants_rejects_out_of_scope_request",
    "public_resolve_matching_grants_preserves_wildcard_matching",
    "public_evaluate_rejects_untrusted_issuer_before_dispatch",
    "public_sign_receipt_rejects_kernel_key_mismatch_before_signing",
    "public_sign_receipt_accepts_matching_kernel_key",
    # Recursive-delegation, receipt, revocation-view, and
    # oracle-inclusion harnesses (public-core sweep totals 13).
    "verify_delegate_no_widen",
    "verify_delegation_receipt_canonical",
    "verify_revocation_view_freshness",
    "verify_oracle_inclusion_soundness",
]
missing = [name for name in expected if f"fn {name}" not in text]
if missing:
    raise SystemExit(f"missing public Kani harnesses: {missing}")
PY

PUBLIC_HARNESSES=(
  public_verify_capability_rejects_untrusted_issuer_before_signature
  public_normalized_scope_subset_rejects_widened_child
  public_normalized_scope_subset_rejects_value_widened_child
  public_normalized_scope_subset_rejects_identity_mismatch
  public_resolve_matching_grants_rejects_out_of_scope_request
  public_resolve_matching_grants_preserves_wildcard_matching
  public_evaluate_rejects_untrusted_issuer_before_dispatch
  public_sign_receipt_rejects_kernel_key_mismatch_before_signing
  public_sign_receipt_accepts_matching_kernel_key
  verify_delegate_no_widen
  verify_delegation_receipt_canonical
  verify_revocation_view_freshness
  verify_oracle_inclusion_soundness
)

for harness in "${PUBLIC_HARNESSES[@]}"; do
  cargo kani -p chio-kernel-core --lib --harness "$harness" --default-unwind 8 --no-unwinding-checks
done

echo "Kani public core harnesses passed"
