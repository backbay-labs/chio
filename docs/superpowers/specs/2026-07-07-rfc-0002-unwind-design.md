# SP-1 Design: Unconditional post-admission unwind (RFC-0002)

- Date: 2026-07-07
- Source spec: `docs/architecture/reliability/RFC-0002-unconditional-post-admission-unwind.md` (the technical source of truth; this document records the implementation-cycle decisions only)
- Program: reliability criticals, track A (parallel; no dependencies)
- Closes: F02 (critical), F08 (medium)
- Branch: `chio/rfc-0002-unwind` off `main`, one PR

## Goal

A tool-call evaluation future dropped after budget admission must always leave
exactly one signed terminal receipt and an explicit, fail-closed reservation
disposition. Today `PostAdmissionDropGuard::drop` early-returns for every
non-monetary call (no receipt at all) and never releases or marks
runtime-admission reservations on any unwind arm.

## In scope

1. `dispatch_started` flag on `PostAdmissionDropGuard` plus
   `mark_dispatch_started()` wiring at BOTH arm sites:
   `async_evaluation_core.rs` and the nested-flow site in
   `nested_flow_evaluation.rs` (verify pass 2026-07-07 found the second
   site). At the nested-flow site the tool-server lookup is hoisted above
   guard construction so its armed `?` early return cannot fire while armed.
2. Restructured `Drop`: always-run section (cancellation receipt whenever
   dispatch was in flight) plus charge-gated section
   (`unwind_charge_from_drop`, monetary hold reversal only).
3. Pre-dispatch drop branch: safe-release reservations, no receipt.
4. Post-dispatch drop branch: retain reservations, mark them via the new
   `mark_runtime_admission_reservations_retained_fail_closed` helper, record a
   `Decision::Cancelled` receipt through the synchronous signing path.
5. Parity on the non-drop unwind arms (`RequestCancelled`,
   `RequestIncomplete`, generic error not preceding a side effect): wrap
   receipt metadata in the retained marker, in `async_evaluation_core.rs`
   AND the mirrored nested-flow arms in `nested_flow_evaluation.rs`.
6. Widen `POST_ADMISSION_DROP_REASON` to "tool evaluation future dropped after
   admission".
7. Tests (PR gate): the unit tests named in the RFC's test plan (reusing the
   `ReleaseTrackingRuntimeAdmissionHook` / `FailingReleaseRuntimeAdmissionHook`
   fixtures), plus `nested_flow_drop_post_dispatch_records_cancellation_receipt`
   (second arm site) and `drop_pre_dispatch_monetary_unwinds_without_receipt`
   (the flag-drop behavioral delta below), the `build_layered` integration
   test against a real kernel, the proptest over {monetary} x {dispatch
   phase} x {lease presence}, and the two loom models.

## Out of scope (explicit cuts)

- The `post_admission_unwind_v2` feature flag is dropped (program decision,
  2026-07-07): pre-launch, single deployment, no receipt dashboards to
  recalibrate. The new behavior ships as the only behavior. NOTE: the
  verify-updated RFC grounds this flag as a `pub post_admission_unwind_v2:
  bool` on `KernelConfig` and gates both new drop branches on it; this cycle
  implements the RFC's flag-ON semantics unconditionally and adds no config
  field. One behavioral delta therefore ships unconditionally: a MONETARY
  pre-dispatch drop changes from today's cancellation receipt to a
  receipt-free full unwind (hold reversed, reservations released); it gets
  its own test.
- The "cancellation storm" soak scenario (belongs to
  `PLAN-load-soak-chaos-program.md`).
- The receipt-completeness formal lemma (belongs to
  `PLAN-formal-methods-program.md`).
- RFC-0003's dispatch-intent journal (separate RFC; composes later via
  `request_id`).

## Interfaces produced

- `PostAdmissionDropGuard::mark_dispatch_started(&mut self)`
- `PostAdmissionDropGuard::unwind_charge_from_drop(&self) -> Option<serde_json::Value>` (private helper)
- `ChioKernel::mark_runtime_admission_reservations_retained_fail_closed(&self, Option<serde_json::Value>) -> Option<serde_json::Value>` (`pub(crate)`)
- New receipt-metadata keys under `chio_runtime`:
  `reservations_retained_fail_closed`, `retained_destructive_lease_id`,
  `retained_treaty_continuation_id`, `retained_swarm_continuation_id`.

No wire, schema, or receipt-kind changes. No new `KernelError` variants.

## Commit split (conventional commits)

1. `feat(kernel): add dispatch_started to PostAdmissionDropGuard and split the drop unwind`
2. `feat(kernel): mark retained runtime-admission reservations on aborted unwind paths`
3. `test(chio-tower): prove build_layered timeout records a cancellation receipt`

## Acceptance criteria

RFC-0002 acceptance criteria 1-6 verbatim, minus the feature flag. Headline
proof: `drop_non_monetary_post_dispatch_records_cancellation_receipt`.
Workspace gate: `cargo build --workspace && cargo test --workspace && cargo
clippy --workspace -- -D warnings && cargo fmt --all -- --check`.

## Risks carried from the RFC

- Synchronous sign inside `Drop` briefly blocks the dropping thread
  (pre-existing monetary behavior, accepted).
- A failed synchronous record inside `Drop` cannot propagate; the
  `audit_fault = "post_admission_drop_receipt_unrecorded"` structured log is
  the residual signal (strictly better than today's silence).
