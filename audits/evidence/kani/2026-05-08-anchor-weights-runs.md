# Kani live-run evidence: chio-anchor + chio-weights (Kani harness evidence/A3.3)

Evidence cross-reference: Kani enrolled-harness coverage for
`chio-anchor` and `chio-weights`.

This file records the live `cargo kani` outputs for every enrolled harness in
`.kani/harnesses.toml`. Without this evidence the harnesses would be
enrolled-but-never-run.

## Scope boundary

These are bounded harness results, not an implementation-complete proof
of `chio-anchor` or `chio-weights`. Each successful row proves only the
named harness under the listed Kani unwind and lane constraints.
MODEL-ONLY harnesses prove their local surrogate algebra, not the full
production implementation. The nightly-lane row remains unproven at the
short-run tier until its dedicated lane completes.

**Environment**

| Field          | Value                                |
| -------------- | ------------------------------------ |
| Date           | 2026-05-08                           |
| Host           | macOS aarch64 (Apple silicon)        |
| cargo-kani     | 0.67.0                               |
| Rust toolchain | nightly-2025-11-21 (kani-pinned)     |
| Evidence scope | local evidence run |
| HEAD at run    | (filled in below per-harness)        |

Each block records the command, `VERIFICATION:` line, total checks,
and verification time. Full Kani transcripts are not committed (they
are several MB each); rerun locally for the full check list.

760de8d3f7037c96afc1961aee20906a2639d4d2

=== chio-anchor :: public_anchor_emergency_controls_allows_truth_table ===


SUMMARY:
 ** 0 of 96 failed (2 unreachable)

VERIFICATION:- SUCCESSFUL
Verification Time: 0.088100374s

Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.

=== chio-anchor :: public_ensure_anchor_operation_allowed_fail_closed ===
Unwinding loop _RNvNtNtCs2fBbJ0VEDWe_4core3str5count14do_count_chars.0 iteration 6 file <rust-src>/core/src/str/count.rs line 82 column 13 function core::str::count::do_count_chars thread 0
aborting path on assume(false) at file <kani>src/lib.rs line 57 column 1 function kani::mem::cbmc::same_allocation thread 0
Unwinding loop _RNvNtNtCs2fBbJ0VEDWe_4core3str5count14do_count_chars.0 iteration 7 file <rust-src>/core/src/str/count.rs line 82 column 13 function core::str::count::do_count_chars thread 0
aborting path on assume(false) at file <kani>src/lib.rs line 57 column 1 function kani::mem::cbmc::same_allocation thread 0
Not unwinding loop _RNvNtNtCs2fBbJ0VEDWe_4core3str5count14do_count_chars.0 iteration 8 file <rust-src>/core/src/str/count.rs line 82 column 13 function core::str::count::do_count_chars thread 0
Not unwinding loop _RNvNtNtCs2fBbJ0VEDWe_4core3str5count14do_count_chars.1 iteration 8 file <rust-src>/core/src/str/count.rs line 81 column 9 function core::str::count::do_count_chars thread 0
Not unwinding loop _RNvNtNtCs2fBbJ0VEDWe_4core3str5count14do_count_chars.2 iteration 8 file <rust-src>/core/src/str/count.rs line 75 column 5 function core::str::count::do_count_chars thread 0
aborting path on assume(false) at file <kani-core>src/models.rs line 176 column 17 function <usize as kani::rustc_intrinsics::ToISize>::to_isize thread 0
aborting path on assume(false) at file <kani>src/lib.rs line 57 column 1 function <usize as kani::rustc_intrinsics::ToISize>::to_isize thread 0
aborting path on assume(false) at file <kani>src/lib.rs line 57 column 1 function <usize as kani::rustc_intrinsics::ToISize>::to_isize thread 0

=== chio-anchor :: public_classify_anchor_lane_invariants ===


SUMMARY:
 ** 0 of 128 failed (2 unreachable)

VERIFICATION:- SUCCESSFUL
Verification Time: 0.1376853s

Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.

=== chio-anchor :: public_anchor_indexer_cursor_lag_classification ===


SUMMARY:
 ** 0 of 106 failed (2 unreachable)

VERIFICATION:- SUCCESSFUL
Verification Time: 0.1827967s

Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.

=== chio-anchor :: public_evaluate_witness_policy_advisory_fail_closed_model ===


SUMMARY:
 ** 0 of 20 failed

VERIFICATION:- SUCCESSFUL
Verification Time: 0.05808679s

Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.

=== chio-weights :: public_weights_hash_of_determinism_and_tampering ===


SUMMARY:
 ** 0 of 1664 failed (166 unreachable)

VERIFICATION:- SUCCESSFUL
Verification Time: 1.8581622s

Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.

=== chio-weights :: public_model_card_require_live_fail_closed ===


SUMMARY:
 ** 0 of 3650 failed (308 unreachable)

VERIFICATION:- SUCCESSFUL
Verification Time: 1.6812204s

Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.

=== chio-weights :: public_weights_error_urn_is_stable ===


SUMMARY:
 ** 0 of 335 failed (16 unreachable)

VERIFICATION:- SUCCESSFUL
Verification Time: 1.0562179s

Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.

=== chio-weights :: public_model_card_new_pins_schema_version ===


SUMMARY:
 ** 0 of 3637 failed (309 unreachable)

VERIFICATION:- SUCCESSFUL
Verification Time: 1.7159969s

Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.


---

## Per-harness summary

| # | Crate         | Harness                                                       | Lane    | Result                  | Time    |
|---|---------------|---------------------------------------------------------------|---------|-------------------------|---------|
| 1 | chio-anchor   | public_anchor_emergency_controls_allows_truth_table           | pr      | VERIFICATION: SUCCESSFUL | 0.088s  |
| 2 | chio-anchor   | public_ensure_anchor_operation_allowed_fail_closed            | nightly | See note below          | -       |
| 3 | chio-anchor   | public_classify_anchor_lane_invariants                        | pr      | VERIFICATION: SUCCESSFUL | 0.137s  |
| 4 | chio-anchor   | public_anchor_indexer_cursor_lag_classification               | pr      | VERIFICATION: SUCCESSFUL | 0.182s  |
| 5 | chio-anchor   | public_evaluate_witness_policy_advisory_fail_closed_model     | pr      | VERIFICATION: SUCCESSFUL | 0.058s  |
| 6 | chio-weights  | public_weights_hash_of_determinism_and_tampering              | pr      | VERIFICATION: SUCCESSFUL | 1.858s  |
| 7 | chio-weights  | public_model_card_require_live_fail_closed                    | pr      | VERIFICATION: SUCCESSFUL | 1.681s  |
| 8 | chio-weights  | public_weights_error_urn_is_stable                            | pr      | VERIFICATION: SUCCESSFUL | 1.056s  |
| 9 | chio-weights  | public_model_card_new_pins_schema_version                     | pr      | VERIFICATION: SUCCESSFUL | 1.715s  |

## Honesty note: harness #2 (public_ensure_anchor_operation_allowed_fail_closed)

This harness calls the production `chio_anchor::ops::ensure_anchor_operation_allowed`,
whose fail-closed arm constructs an `AnchorError::InvalidInput` payload via
`format!()`. The `format!()` macro paths into
`core::str::count::do_count_chars` for UTF-8 length accounting, which
inflates cbmc's symex into hundreds of thousands of steps even at unwind=4
(local run: ~147s symex completed, then minutes of SAT solving still
ahead when the run was interrupted at ~5GB RSS). At the workspace-default
unwind=8 the same harness exceeds 21 minutes / 2.7GB before any answer.

**Lane decision**: this harness is enrolled in the **nightly** lane at
unwind=4 with `timeout_secs = 3600`. PR-tier CI cannot afford the
wall-clock; the truth-table harness #1 covers the same `controls.allows()`
predicate at PR-tier without traversing the `format!()` path, and the
runtime negative tests under `crates/chio-anchor/tests/` exercise the
full error path including the `String` payload.

**Future hardening follow-up** (option (a) per model-scope notes): extract a
`pub(crate) fn classify_operation_admission(controls:
AnchorEmergencyControls, operation: AnchorOperationKind) -> Result<(),
AnchorOperationAdmissionError>` whose error type is a small enum carrying
only a variant tag (no `String` payload). The runtime fail-closed branch
wraps that into the existing `AnchorError::InvalidInput` for
backwards-compatibility. The Kani harness then targets
`classify_operation_admission` directly and skips the format-string path,
letting the tightened harness migrate back to the PR lane.

This nightly-lane lane move is the honest interim posture; merging this
PR enrolls the harness in nightly CI (which has the wall-clock budget)
rather than letting it stay un-enforced. A green PR-tier run does NOT
prove this fail-closed property; the runtime negative tests do.
