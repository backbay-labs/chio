# Trajectory 5.1 Kani Manifest Evidence

Date: 2026-05-09

Integrated main: `2afeb07a1febacd1323f6903fc96d7f764254420`

## Local Toolchain

`cargo kani --version` failed locally:

```text
error: no such command: `kani`
```

This means no local Kani proof result is claimed by Trajectory 5.1.
The manifest enrollment and runner shape were checked, and the proof
execution remains a hosted or toolchain-prepared follow-up.

## Manifest List

`bash scripts/run-kani-manifest.sh --list` exited 0 and listed 30 PR-lane
harnesses:

```text
chio-kernel-core::public_verify_capability_rejects_untrusted_issuer_before_signature
chio-kernel-core::public_normalized_scope_subset_rejects_widened_child
chio-kernel-core::public_normalized_scope_subset_rejects_value_widened_child
chio-kernel-core::public_normalized_scope_subset_rejects_identity_mismatch
chio-kernel-core::public_resolve_matching_grants_rejects_out_of_scope_request
chio-kernel-core::public_resolve_matching_grants_preserves_wildcard_matching
chio-kernel-core::public_evaluate_rejects_untrusted_issuer_before_dispatch
chio-kernel-core::public_sign_receipt_rejects_kernel_key_mismatch_before_signing
chio-kernel-core::public_sign_receipt_accepts_matching_kernel_key
chio-kernel-core::verify_scope_intersection_associative
chio-kernel-core::verify_revocation_predicate_idempotent
chio-kernel-core::verify_delegation_chain_step
chio-kernel-core::verify_receipt_roundtrip
chio-kernel-core::verify_budget_checked_add_no_overflow
chio-kernel-core::verify_delegate_no_widen
chio-kernel-core::verify_delegation_receipt_canonical
chio-kernel-core::verify_revocation_view_freshness
chio-kernel-core::verify_oracle_inclusion_soundness
chio-attest-verify::public_expect_report_data_determinism_under_input_change
chio-attest-verify::public_nitro_verify_quote_rejects_report_data_mismatch
chio-attest-verify::public_sev_snp_verify_quote_rejects_unacceptable_tcb
chio-attest-verify::public_tdx_verify_quote_rejects_algorithm_mismatch
chio-anchor::public_anchor_emergency_controls_allows_truth_table
chio-anchor::public_classify_anchor_lane_invariants
chio-anchor::public_anchor_indexer_cursor_lag_classification
chio-anchor::public_evaluate_witness_policy_advisory_fail_closed_model
chio-weights::public_weights_hash_of_determinism_and_tampering
chio-weights::public_model_card_require_live_fail_closed
chio-weights::public_weights_error_urn_is_stable
chio-weights::public_model_card_new_pins_schema_version
```

## Dry Run

`bash scripts/run-kani-manifest.sh --dry-run` exited 0 and emitted one
`cargo kani -p <crate> --lib --harness <name>` command for each manifest
entry. On macOS in this workspace, `timeout(1)` was not on `PATH`, so
the dry-run lines annotated each command with the configured timeout
rather than wrapping it.

## 5.1 Disposition

The 5.1 Kani claim is limited to manifest integrity and command
enumeration. It does not claim local proof completion until `cargo-kani`
is installed and the manifest lane exits 0.
