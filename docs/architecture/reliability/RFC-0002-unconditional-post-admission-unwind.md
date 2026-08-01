# RFC-0002: Unconditional post-admission unwind: a receipt and reservation release on every drop path

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0006 (monetary budget semantics), ADR-0003 (nested flow model)
- Depends on: none
- Closes findings: F02 (critical), F08 (medium) (see ./README.md and the readiness review)

> **Security correction (2026-07-14):** This draft is retained as design
> history. The implemented contract does not reverse monetary state after
> dispatch. Every error returned after polling `invoke_stream`, `invoke`, or
> `invoke_with_cost` is outcome-unknown, including URL elicitation. The kernel
> preserves credentials, runtime admission, child budget, budget exposure, and
> payment authorization, then signs their identifiers into a terminal receipt.
> Only kernel-owned failures before polling are reversible.

## Summary

`PostAdmissionDropGuard` is the kernel's last-resort unwind for a tool-call
evaluation whose future is dropped after budget admission while a tool dispatch
is in flight. Today the guard early-returns for every non-monetary call
(`let Some(charge) = self.charge_result else { return; }`), so a dropped
non-monetary post-admission future records no receipt at all, silently
violating the core "exactly one signed receipt per call" invariant (F02). The
same guard never releases the runtime-admission reservations (destructive
leases and treaty/swarm continuations) consumed at admission, and neither do
the `RequestCancelled` / `RequestIncomplete` / generic-error unwind arms, so an
aborted attempt burns a single-use lease with no audit trail (F08). This RFC
restructures the guard into an always-run section (record a cancellation
receipt whenever dispatch was in flight, gated on a new `dispatch_started`
flag) and a charge-gated section (monetary hold reversal only), and makes the
reservation disposition explicit and fail-closed: safe-release when no side
effect was possible, retain-and-mark (auditable, operator-recoverable) when a
side effect may have executed. The receipt is built and persisted from the
synchronous signing path because a `Drop` impl cannot await.

## Motivation

The article lens (Ubicloud, "PostgreSQL and the OOM Killer") demands that when
a component dies mid-operation the blast radius is known and the internal
accounting stays trustworthy or is loudly broken. Two findings show the drop
path fails both tests today.

F02 (critical, CONFIRMED). Trigger: a host drops the `evaluate` future after
admission while a non-monetary dispatch is in flight. This is not exotic. The
blessed embedder stack (`chio-tower::build_layered`) installs a mandatory
`TimeoutLayer` that drops the response future on elapse, and any external async
embedder that awaits `evaluate_tool_call` inside a hyper/axum handler inherits
future cancellation on client disconnect (no timeout required). Effect: the
tool server (remote HTTP or stdio MCP) has already received the request and may
execute the side effect, but `PostAdmissionDropGuard::drop` returns before
writing the cancellation receipt, so the append-only log contains nothing for
the call. Impact: a silent violation of the product's central guarantee, and it
is attacker-inducible - an agent can issue an authorized side-effectful call
and drop its connection before completion to execute a tool off the audit
record. Nothing marks the gap for later verification.

Note on reachability (severity is the review's corrected severity). No in-repo
production surface drops the evaluate future mid-flight today: every shipped
mediation path enters via the blocking bridge or a dedicated thread and cannot
be cancelled mid-poll. The defect is latent-but-adjacent - unreachable through
any shipped binary, reachable by default through the exported `build_layered`
stack and by any external async embedder. Calling this "embedder misuse" is
wrong: the documented integration path is the drop-capable configuration, so
the invariant must hold on the drop path before that path carries traffic.

F08 (medium, CONFIRMED). Trigger: a governed request that consumed a single-use
destructive lease (or treaty/swarm continuation) at admission is cancelled
mid-dispatch, returns `RequestIncomplete`, hits a generic tool-server error, or
has its evaluate future dropped. Effect: the lease stays consumed; a retry with
the same lease is rejected with `destructive_lease_replay`; the destructive
workflow wedges until an operator re-issues the lease. In the dropped-future
non-monetary case there is additionally no receipt at all, so the audit log
cannot even show why the lease is burned. Blast radius is scoped to deployments
running the runtime-admission hook with destructive leases or continuations,
where routine cancellations become a recurring operational tax.

## Current behavior (verified 2026-07-04)

The guard lives in `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs`.
Its fields and drop body (lines 19-28, 57-107):

```rust
pub(crate) struct PostAdmissionDropGuard<'a> {
    kernel: &'a ChioKernel,
    request: &'a ToolCallRequest,
    cap: &'a CapabilityToken,
    matched_grant_index: Option<usize>,
    charge_result: Option<&'a BudgetChargeResult>,
    payment_authorization: Option<&'a PaymentAuthorization>,
    receipt_context: PostAdmissionReceiptContext,
    armed: bool,
}

impl Drop for PostAdmissionDropGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let Some(charge) = self.charge_result else {
            return;                          // F02: non-monetary drops exit here
        };
        // ... monetary unwind, then build_cancelled_response_with_metadata ...
    }
}
```

The early return at lines 63-65 is the F02 defect: for a non-monetary grant
`charge_result` is `None`, so the whole body (monetary unwind and the
cancellation receipt at lines 93-105) is skipped. The guard never calls
`release_runtime_admission_reservations`, so every drop-cancellation leaks the
reservation regardless of monetary status (F08). The reason string is also
narrowed to the monetary case (line 12):

```rust
const POST_ADMISSION_DROP_REASON: &str = "tool evaluation future dropped after monetary admission";
```

The guard is armed at two sites. The primary site wraps the single dispatch
await in
`crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs`
(lines 512-529):

```rust
let has_monetary = budget_mutation.charge_result().is_some();
let mut post_admission_drop_guard = PostAdmissionDropGuard::new(
    self, request, cap, Some(matched_grant_index),
    budget_mutation.charge_result(), payment_authorization.as_ref(),
    PostAdmissionReceiptContext { /* extra_metadata, pre_invocation_guard_evidence */ },
);
let dispatch_result = self
    .dispatch_tool_call_with_cost_after_nonce_check(request, has_monetary)
    .await;                                  // the only await in the guarded window
post_admission_drop_guard.disarm();
drop(post_admission_drop_guard);
```

The second arm site is the nested-flow evaluation path
(`crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs`,
lines 437-489): the guard is constructed at 437-448, and the guarded block
performs the tool-server lookup inline (its `ToolNotRegistered` failure
early-returns via `?` at line 455 while the guard is still armed) before
awaiting `invoke_stream` / `invoke` with the nested-flow bridge; `disarm()`
runs at line 488. The non-drop unwind arms are mirrored in that file
(`RequestCancelled` at 508, `RequestIncomplete` at 549, the generic-error
release gate at 592). Any restructure of the guard must cover both sites.

The dispatch await on the primary site routes to
`dispatch_tool_call_with_cost_after_nonce_check` (dispatch.rs:448-479), which
awaits the tool-server `invoke_stream` / `invoke_with_cost` / `invoke` inline
(not spawned). The non-drop unwind arms in async_evaluation_core.rs confirm
the F08 asymmetry:

- `UrlElicitationsRequired` (lines 532-546): unwinds monetary, then calls
  `self.release_runtime_admission_reservations(extra_metadata.as_ref())?`.
- `RequestCancelled` (lines 547-581): monetary unwind only, no reservation
  release, records a cancellation receipt.
- `RequestIncomplete` (lines 582-617): monetary unwind only, no reservation
  release, records an incomplete receipt.
- generic error (lines 618-652): reservation release is gated on
  `dispatch_error_precedes_tool_side_effect(&e)` (lines 625-627).

That gate is defined narrowly (kernel_drop_guard.rs:109-114):

```rust
pub(crate) fn dispatch_error_precedes_tool_side_effect(error: &KernelError) -> bool {
    matches!(
        error,
        KernelError::ToolNotRegistered(_) | KernelError::UrlElicitationsRequired { .. }
    )
}
```

The release primitive and its metadata contract are (dispatch.rs:393-404 and
`crates/kernel/chio-runtime-core/src/admission_hook.rs:355-393`):

```rust
pub(crate) fn release_runtime_admission_reservations(
    &self,
    metadata: Option<&serde_json::Value>,
) -> Result<(), KernelError> {
    let Some(metadata) = metadata else { return Ok(()); };
    let Some(hook) = self.runtime_admission_hook.as_ref() else { return Ok(()); };
    hook.release_reserved(metadata)
}
```

`release_reserved` reads the admission ids straight out of the receipt
metadata: `chio_runtime.admission_id`, `chio_runtime.reserved_destructive_lease_id`,
`chio_runtime.reserved_treaty_continuation_id`, and
`chio_runtime.reserved_swarm_continuation_id`. The in-memory store makes the
lease single-use (`crates/kernel/chio-runtime-core/src/store/memory.rs:136-163`):
`consume_destructive_lease` inserts into `consumed_leases` and returns
`ChioRuntimeError::Rejected { code: "destructive_lease_replay", .. }` on reuse;
`release_destructive_lease` removes the id, restoring reusability.

The monetary unwind primitive is charge-gated already
(dispatch.rs:125-131):

```rust
pub(crate) fn unwind_aborted_monetary_invocation(
    &self,
    request: &ToolCallRequest,
    cap: &CapabilityToken,
    charge_result: Option<&BudgetChargeResult>,
    payment_authorization: Option<&PaymentAuthorization>,
) -> Result<Option<BudgetReverseHoldDecision>, KernelError> {
    let Some(charge) = charge_result else { return Ok(None); };
    // ... reverse the pre-execution hold ...
}
```

The receipt builder the guard already uses is fully synchronous
(`crates/kernel/chio-kernel/src/kernel/responses/terminal_responses.rs:4-61`):

```rust
pub(crate) fn build_cancelled_response_with_metadata(
    &self,
    request: &ToolCallRequest,
    reason: &str,
    timestamp: u64,
    matched_grant_index: Option<usize>,
    extra_metadata: Option<serde_json::Value>,
) -> Result<ToolCallResponse, KernelError> { /* ... */ }
```

It builds `Decision::Cancelled { reason }`, signs via `build_and_sign_receipt`
(receipt_persistence.rs:5-98, delegating to
`chio_kernel_core::sign_receipt_with_handle` under WYSIWYS), and persists via
`record_chio_receipt_with_federation` -> `record_chio_receipt`
(receipt_persistence.rs:164-187), which takes the `receipt_store_write_lock`
`std::sync::Mutex` and appends. None of this awaits. This is the load-bearing
fact for the drop-context mechanism below.

Finally, the kernel already self-acknowledges the gap
(`crates/kernel/chio-kernel/src/kernel/evaluator.rs:10-11`): "The synchronous
bridge path is not cancellation-safe for futures dropped after budget admission
or tool dispatch; that gap is a known open item." And the concrete drop trigger
is the exported stack (`crates/protocol/chio-tower/src/kernel_service.rs`:
`call` awaits `kernel.evaluate_tool_call(&req.call).await` at line 97;
`build_layered` at lines 355-365 wraps it in `TimeoutLayer::new(request_timeout)`
at line 362).

## Design

The restructure has four parts, all inside `chio-kernel`, no new crate.

### 1. A `dispatch_started` flag on the guard

Add one field and one setter to `PostAdmissionDropGuard`. `new()` initializes
it `false`; the async core flips it to `true` immediately before entering the
dispatch await.

```rust
pub(crate) struct PostAdmissionDropGuard<'a> {
    // ... existing fields ...
    armed: bool,
    dispatch_started: bool,   // NEW: false until the tool-server invoke is entered
}

impl<'a> PostAdmissionDropGuard<'a> {
    // new() sets `dispatch_started: false` alongside `armed: true`.

    /// Mark that the tool-server dispatch await has been entered. After this
    /// point a dropped future may correspond to an executed side effect, so
    /// the drop path must record a cancellation receipt and fail closed on
    /// reservations.
    pub(crate) fn mark_dispatch_started(&mut self) {
        self.dispatch_started = true;
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}
```

Wiring in async_evaluation_core.rs, unchanged arming site, one added call
before the await:

```rust
let mut post_admission_drop_guard = PostAdmissionDropGuard::new(/* ... */);
post_admission_drop_guard.mark_dispatch_started();
let dispatch_result = self
    .dispatch_tool_call_with_cost_after_nonce_check(request, has_monetary)
    .await;
post_admission_drop_guard.disarm();
```

The nested-flow arm site (nested_flow_evaluation.rs:437-489) gets the same
one-line wiring, with one preparatory move: hoist the tool-server lookup
(lines 450-455) above the guard construction so its `ToolNotRegistered` `?`
can no longer early-return while the guard is armed, then call
`mark_dispatch_started()` immediately before the `invoke_stream` await. After
the hoist, both guarded windows contain only dispatch awaits (the single
dispatch await in the async core; the `invoke_stream` / `invoke` pair in the
nested path), so a future dropped in either window is always parked at a
dispatch await and `dispatch_started` is `true` at drop time. The flag is
still load-bearing: it encodes the invariant
explicitly, so a future refactor that inserts an await between guard
construction and dispatch (an async nonce spend, an async pre-dispatch hook)
cannot silently reintroduce the "receipt for a call that never dispatched"
hole, and a panic unwinding through the synchronous gap between construction
and `mark_dispatch_started` correctly takes the pre-dispatch branch.

### 2. Restructured `Drop`: always-run section plus charge-gated section

```rust
impl Drop for PostAdmissionDropGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        // Charge-gated section: reverse the pre-execution monetary hold, if
        // any. Best-effort from a Drop context; a non-monetary grant
        // (charge_result == None) returns the base metadata unchanged.
        let reversed_metadata = self.unwind_charge_from_drop();

        if !self.dispatch_started {
            // Pre-dispatch drop (or panic unwind before dispatch). Nothing was
            // written to the tool server, so no side effect is possible.
            // Safe-release the runtime-admission reservations and record NO
            // cancellation receipt: there is no executed action to audit, and
            // the monetary hold is already reversed above.
            if let Err(error) = self
                .kernel
                .release_runtime_admission_reservations(
                    self.receipt_context.extra_metadata.as_ref(),
                )
            {
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(&error),
                    "failed to release runtime-admission reservations on pre-dispatch drop"
                );
            }
            return;
        }

        // Post-dispatch drop. The tool-server invoke was in flight; a side
        // effect MAY have executed. Fail closed:
        //   (1) RETAIN the runtime-admission reservations - never release a
        //       single-use destructive lease when the destructive action may
        //       already have run, because releasing it licenses a replay.
        //   (2) ALWAYS record a cancellation receipt so the executed-or-not
        //       side effect is on the append-only log (closes F02), annotated
        //       with an operator-visible reservations-retained marker so the
        //       burned lease is auditable and recoverable (closes F08 audit gap).
        let receipt_metadata = self
            .kernel
            .mark_runtime_admission_reservations_retained_fail_closed(reversed_metadata);

        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            self.receipt_context.pre_invocation_guard_evidence.clone(),
        );
        if let Err(error) = self.kernel.build_cancelled_response_with_metadata(
            self.request,
            POST_ADMISSION_DROP_REASON,
            current_unix_timestamp(),
            self.matched_grant_index,
            receipt_metadata,
        ) {
            warn!(
                request_id = %self.request.request_id,
                reason = %redacted!(&error),
                audit_fault = "post_admission_drop_receipt_unrecorded",
                "failed to record cancellation receipt for dropped post-admission invocation"
            );
        }
    }
}
```

The charge-gated section is factored into a private helper so the Drop body
reads as two clean branches. It preserves today's monetary metadata shaping
byte-for-byte:

```rust
impl PostAdmissionDropGuard<'_> {
    /// Reverse the pre-execution monetary hold, if any, and fold the reversal
    /// into the receipt metadata. Charge-gated: `None` charge_result (every
    /// non-monetary grant) returns the base metadata unchanged. Errors are
    /// logged; a Drop impl cannot surface them.
    fn unwind_charge_from_drop(&self) -> Option<serde_json::Value> {
        let base = self.receipt_context.extra_metadata.clone();
        let Some(charge) = self.charge_result else {
            return base;
        };
        match self.kernel.unwind_aborted_monetary_invocation(
            self.request,
            self.cap,
            self.charge_result,
            self.payment_authorization,
        ) {
            Ok(Some(reverse)) => self.kernel.merge_budget_receipt_metadata(
                base,
                self.kernel
                    .budget_execution_receipt_metadata(charge, Some(("reversed", &reverse))),
            ),
            Ok(None) => base,
            Err(error) => {
                warn!(
                    request_id = %self.request.request_id,
                    reason = %redacted!(&error),
                    "failed to unwind dropped post-admission monetary invocation"
                );
                base
            }
        }
    }
}
```

Also widen the reason constant so it is accurate for non-monetary drops:

```rust
const POST_ADMISSION_DROP_REASON: &str = "tool evaluation future dropped after admission";
```

Both new behaviors (the pre-dispatch safe-release branch and the non-monetary
post-dispatch receipt) are gated on the `post_admission_unwind_v2` kernel
config flag: a new `pub post_admission_unwind_v2: bool` field on
`KernelConfig` (`crates/kernel/chio-kernel/src/kernel/kernel_struct.rs:10`),
read as `self.kernel.config.post_admission_unwind_v2` inside `drop`. With the
flag off, the guard behaves exactly as today (monetary-only receipt, no
reservation handling). See Migration for the rollout sequence and the one
behavioral delta.

### 3. Drop-context signing: synchronous, not the async channel

A `Drop` impl cannot be `async` and cannot `await`. The kernel has two signing
paths: the async `sign_receipt_via_channel` (construction.rs:365-371, the
mpsc-backed signing task used on the normal await path) and the synchronous
`build_and_sign_receipt` (receipt_persistence.rs:5-98). The drop guard must use
the synchronous path, which is exactly what `build_cancelled_response_with_metadata`
already calls. Both paths delegate to `chio_kernel_core::sign_receipt_with_handle`
and are equally fail-closed (WYSIWYS: the signer recomputes
`sha256_hex(canonical_content)` and refuses to sign on mismatch), so the drop
receipt is byte-identical in signing semantics to a normal one; only the
executor requirement differs.

Mechanism, precisely:

- The synchronous `build_and_sign_receipt` -> `record_chio_receipt` path
  acquires the `receipt_store_write_lock` `std::sync::Mutex`, appends the
  signed receipt, runs the checkpoint check, releases the lock, then runs the
  settlement observer. It does not await. From `Drop` this runs to completion
  on the thread that is dropping the future (which may be a tokio worker when
  `TimeoutLayer` elapses). The critical section is small and bounded; this is
  the pre-existing behavior of the monetary drop path, now extended to
  non-monetary drops.
- Enqueue-to-async-channel was considered and rejected (see Risks): Drop cannot
  await the channel round-trip, and a fire-and-forget send would break the
  durable-before-return posture (ADR-0013) and could be lost during runtime
  shutdown. The synchronous path is the only one that guarantees the receipt is
  durable by the time `drop` returns.
- If the synchronous record fails (poisoned lock, store error), Drop cannot
  propagate. It emits a structured `audit_fault = "post_admission_drop_receipt_unrecorded"`
  warning that SIEM ingests as an audit fault (ADR-0013 audit-fault wording).
  This is a strictly smaller hole than today, where non-monetary drops write
  nothing and log nothing about the missing receipt.

### 4. The retained-reservation marker, and parity on the non-drop unwind arms

New charge-free kernel helper that copies the reserved ids out of the admission
metadata into an operator-visible marker. Fail-closed: if there is no
`chio_runtime` block, the metadata is returned unchanged.

```rust
impl ChioKernel {
    /// Record, in receipt metadata, that runtime-admission reservations
    /// consumed at admission were deliberately NOT released because a tool
    /// side effect may have executed. The reserved ids are copied so an
    /// operator can locate and re-issue the burned lease/continuation from the
    /// signed receipt alone.
    pub(crate) fn mark_runtime_admission_reservations_retained_fail_closed(
        &self,
        metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let mut retained = serde_json::Map::new();
        {
            let Some(runtime) = metadata
                .as_ref()
                .and_then(|value| value.get("chio_runtime"))
                .and_then(serde_json::Value::as_object)
            else {
                return metadata;
            };
            retained.insert(
                "reservations_retained_fail_closed".to_string(),
                serde_json::Value::Bool(true),
            );
            for (source, target) in [
                ("reserved_destructive_lease_id", "retained_destructive_lease_id"),
                ("reserved_treaty_continuation_id", "retained_treaty_continuation_id"),
                ("reserved_swarm_continuation_id", "retained_swarm_continuation_id"),
            ] {
                if let Some(id) = runtime.get(source).and_then(serde_json::Value::as_str) {
                    retained.insert(target.to_string(), serde_json::json!(id));
                }
            }
        }
        merge_metadata_objects(
            metadata,
            Some(serde_json::json!({ "chio_runtime": retained })),
        )
    }
}
```

(`merge_metadata_objects` is `pub(crate)` in
`crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs:86`. The
inner block scopes the `runtime` borrow so it ends before `metadata` is moved
into the merge, keeping the borrow checker satisfied without a clone. The
helper lives in dispatch.rs next to `release_runtime_admission_reservations`
so the reservation-disposition primitives stay in one file.)

Apply the same marker on the non-drop unwind arms in async_evaluation_core.rs
that today retain silently, so F08 auditability is uniform across every path
where a side effect may have occurred:

- `RequestCancelled` (547-581): wrap the metadata passed to
  `build_cancelled_response_with_metadata` in
  `mark_runtime_admission_reservations_retained_fail_closed(..)`.
- `RequestIncomplete` (582-617): same, for
  `build_incomplete_response_with_output_and_metadata`.
- generic error (618-652): when `dispatch_error_precedes_tool_side_effect(&e)`
  is true the code already releases (line 626) and must NOT add the marker;
  otherwise wrap the metadata in the retained marker.

The mirrored arms in nested_flow_evaluation.rs (`RequestCancelled` at 508,
`RequestIncomplete` at 549, the generic-error release gate at 592) get the
identical treatment.

Reservation disposition, made explicit and fail-closed:

| Path | Side effect possible | Reservations | Receipt |
|------|----------------------|--------------|---------|
| Pre-dispatch denial (evaluation_helpers.rs:29,82) | no | release | deny receipt |
| `ToolNotRegistered` (generic-error arm) | no | release | deny receipt |
| `UrlElicitationsRequired` | no | release | none from this arm (error returned to the embedder) |
| Pre-dispatch drop (`!dispatch_started`) | no | release | none |
| `RequestCancelled` / `RequestIncomplete` | yes | retain + mark | cancelled/incomplete receipt |
| Generic tool-server error (not pre-side-effect) | yes | retain + mark | deny receipt |
| Post-dispatch drop (`dispatch_started`) | yes | retain + mark | cancellation receipt |

This is the fail-closed reading of the finding's "reservations leak" framing.
A blind release on the drop path would be fail-open: it would let an agent
replay a single-use destructive lease after the destructive action already
executed. The leak is resolved two ways instead - by actually releasing in the
provably-safe pre-dispatch subclass, and by converting the ambiguous case from
a silent burn into an auditable, operator-recoverable retained reservation. The
finding's "no side effect occurred" signal from the connection (error before
request write) is the future widening of the safe-release subclass; when it
lands it simply moves rows from retain to release.

### Error taxonomy

No new `KernelError` variants. The drop path consumes existing typed errors:
`unwind_aborted_monetary_invocation` and `release_runtime_admission_reservations`
return `Result<_, KernelError>`, and `build_cancelled_response_with_metadata`
returns `Result<ToolCallResponse, KernelError>`. Because `Drop` cannot return,
every fallible call is an explicit `match` / `if let Err(..)` that logs and
continues (no `?`, no `.unwrap()`, no `.expect()`), consistent with the
workspace `unwrap_used`/`expect_used = "deny"` lint. The only new observable is
the `audit_fault = "post_admission_drop_receipt_unrecorded"` log field.

## Wire, schema, and receipt impact

- Receipt kind: unchanged. Drop still produces `ReceiptKind::MediatedDecision`
  with `Decision::Cancelled { reason }`; the reason string is widened to "tool
  evaluation future dropped after admission". No new receipt kind, no schema
  version bump.
- New metadata keys under the existing free-form `chio_runtime` object in
  receipt metadata: `reservations_retained_fail_closed` (bool),
  `retained_destructive_lease_id`, `retained_treaty_continuation_id`,
  `retained_swarm_continuation_id` (strings, present only when the matching
  reserved id was present). These flow through the same
  `build_and_sign_receipt` -> `sign_receipt_with_handle` path and are
  serialized under canonical JSON (RFC 8785), so signing determinism is
  preserved. Existing verifiers ignore unknown metadata keys.
- The only configuration change is the new `post_admission_unwind_v2` boolean
  on `KernelConfig` (see Migration). No changes to signed capability tokens or
  DPoP payloads.

## Migration and compatibility

- Backward compatible, with one narrow flag-gated delta. The change otherwise
  only adds receipts and metadata that were previously absent; no receipt that
  exists today changes shape. A downstream auditor that keyed on "monetary
  drops only" now also sees non-monetary drop receipts - a strict superset,
  which is the point. The delta: a monetary future dropped BEFORE dispatch
  (after the nested lookup hoist, only a panic unwinding between guard
  construction and `mark_dispatch_started`) today records a drop-cancellation
  receipt; under v2 it takes the pre-dispatch branch instead - hold reversed,
  reservations released, no receipt - because no dispatch was ever entered.
  The staged rollout exists to absorb exactly this.
- No data migration. The reservation store (`consumed_leases`) is unchanged;
  the marker is a read-only projection of admission metadata.
- Staged rollout via one feature flag `post_admission_unwind_v2` (new
  `pub post_admission_unwind_v2: bool` on `KernelConfig` in kernel_struct.rs,
  default off for one release, then default on) so the widened
  drop-receipt behavior can be dark-launched and receipt-count dashboards
  recalibrated before it becomes the default. The flag gates only the new
  branches; when off, the guard behaves as today. Fail-closed default once
  promoted: on.
- Ordering with respect to a pre-existing `receipt_store_write_lock` is
  unchanged; the drop path takes the same lock the normal path does.

## Test and verification plan

Unit (PR gate), in `crates/kernel/chio-kernel/src/kernel/tests/chio_runtime.rs`,
reusing the existing `ReleaseTrackingRuntimeAdmissionHook` and
`FailingReleaseRuntimeAdmissionHook` fixtures (structs at lines 22 and 31,
`release_reserved` impls at 200 and 238) plus a blocking/side-effecting tool
server:

- `drop_non_monetary_post_dispatch_records_cancellation_receipt` - non-monetary
  grant, tool server that parks; drop the evaluate future mid-dispatch by
  racing it under `tokio::time::timeout`; assert exactly one receipt exists for
  the request and its decision is `Cancelled`. Direct F02 proof.
- `drop_post_dispatch_retains_and_marks_reservations` - a reserved destructive
  lease; drop mid-dispatch; assert the lease is still consumed (a retry is
  rejected with `destructive_lease_replay`) and the cancellation receipt carries
  `chio_runtime.reservations_retained_fail_closed = true` and
  `retained_destructive_lease_id`. F08 audit proof.
- `drop_pre_dispatch_releases_reservations_no_receipt` - construct the
  `pub(crate)` guard directly, do not call `mark_dispatch_started`, drop it;
  assert `release_reserved` was invoked and no receipt was appended.
- `request_cancelled_marks_reservations_retained` and
  `request_incomplete_marks_reservations_retained` - drive a tool server that
  returns `RequestCancelled` / `RequestIncomplete`; assert the receipt carries
  the retained marker.
- `generic_error_pre_side_effect_releases_without_marker` - assert
  `ToolNotRegistered` still releases and carries no retained marker.
- `nested_flow_drop_post_dispatch_records_cancellation_receipt` - same shape
  as the first test but driven through the nested-flow evaluation path,
  proving the second arm site is wired.

Integration (PR gate), in `crates/protocol/chio-tower/src/kernel_service.rs`
tests. The existing `timeout_layer_maps_elapsed_error` (line 501) drives a bare
`service_fn`, not a real kernel, so it does not exercise the guard. Add
`build_layered_timeout_drop_records_cancellation_receipt` - `build_layered`
around a real `ChioKernel` with a parking tool server and a 1 ms
`request_timeout`; call the service; assert the `Timeout` error and that the
kernel receipt store now contains a `Cancelled` receipt for the request. This
proves the concrete exported-API drop path end to end.

Property (PR gate) - a proptest over {monetary, non-monetary} x {pre-dispatch,
post-dispatch} x {lease present, absent} asserting: post-dispatch always yields
exactly one terminal receipt; reservations are retained iff (post-dispatch and
present); pre-dispatch always releases and never emits a receipt.

Loom (PR gate) - model two concurrent evaluations whose guards fire and race on
`receipt_store_write_lock`, asserting no lost receipt and no double-release
under interleaving; and model the `disarm()`-then-`drop` happy path to prove the
disarmed guard is a no-op.

Chaos / soak (nightly, load-chaos program) - the "cancellation storm" scenario:
under sustained load, inject client disconnects and timeout elapses at a fixed
rate and assert the receipt-completeness invariant (terminal receipts ==
dispatched calls; no dispatched call without a terminal receipt) and that no
reservation is lost outside the retained-and-marked set. Extended weekly soak
watches for receipt-store growth anomalies from the added drop receipts.

Formal (formal-methods plan) - register the receipt-completeness obligation
"every call whose dispatch was entered produces exactly one terminal receipt
on every exit path including drop, and every pre-dispatch exit fully unwinds
admission and produces none" as a lemma to extend; this RFC makes the drop
path satisfy it, but the lemma itself is owned by that plan.

The single test that proves the headline change is
`drop_non_monetary_post_dispatch_records_cancellation_receipt`.

## Acceptance criteria

1. A dropped non-monetary post-admission future produces exactly one
   `Decision::Cancelled` receipt (F02 closed).
2. No admitted call whose dispatch was entered, monetary or not, exits any
   drop / cancel / incomplete / error path without a terminal receipt. The
   only receipt-free exit is the pre-dispatch drop, which fully unwinds
   admission (hold reversed, reservations released).
3. A post-dispatch cancellation or drop with a reserved destructive lease
   leaves the lease consumed and emits `chio_runtime.reservations_retained_fail_closed`
   with the retained id, on the cancel, incomplete, generic-error, and drop
   paths (F08 audit closed).
4. A pre-dispatch drop releases the reservation and emits no receipt.
5. The `build_layered` timeout path, exercised against a real kernel, records a
   cancellation receipt.
6. No `.unwrap()` / `.expect()` introduced; `cargo clippy --workspace -- -D
   warnings` and `cargo fmt --all -- --check` pass; no em dashes.

## Risks and alternatives

- Synchronous sign plus `std::sync::Mutex` acquisition inside `Drop` runs on
  the dropping thread, possibly a tokio worker, briefly blocking it. Mitigation:
  the critical section is small (append plus checkpoint check); the settlement
  observer runs after the lock is released; this is the pre-existing monetary
  drop behavior, now also covering non-monetary drops. Accepted.
- Enqueue-the-receipt-to-the-async-signing-channel-from-Drop was considered and
  rejected: `Drop` cannot await the channel round-trip; a fire-and-forget send
  breaks durable-before-return (ADR-0013) and can be lost during runtime
  shutdown. The synchronous path is the only one that guarantees durability by
  the time `drop` returns.
- Blind release on the drop path was rejected as fail-open: it would license a
  destructive-lease replay after the action may already have executed. Retain-
  and-mark is the fail-closed choice; the operational tax of a burned lease is
  bounded and made recoverable by the audit marker.
- Residual: if the synchronous record fails inside `Drop`, the receipt is not
  written and the error cannot propagate. Mitigation: the `audit_fault` log is
  SIEM-visible, strictly better than today's silent miss. Accepted with the
  formal receipt-completeness lemma as the backstop signal.
- Out of scope: this RFC makes the drop path correct; it does not add a
  serving-side deadline, so a hung tool server can still pin a tokio worker
  (via `block_in_place`) or a per-session OS thread with no inbound timeout
  (the L1/L4 predictability concern). That belongs to a separate deadline /
  budget RFC and is not a dependency of this one.
- Latency / throughput: negligible on the happy path (the guard is disarmed and
  `Drop` is a single no-op branch). The added work is entirely on drop / cancel
  paths, which are off the hot path by definition.

## Rollout and sequencing

- Lands independently. Depends on nothing.
- Composes with RFC-0003's intent journal but does not require it. RFC-0003
  provides a durable pre-dispatch record of intent-to-dispatch for the process-
  death case, where the future is never dropped in-process because the whole
  process dies and `Drop` never runs. This RFC covers the in-process case where
  `Drop` does run. The two are keyed on `request_id` for a clean handoff: when
  the guard records a cancellation receipt it closes the matching journal entry
  (idempotently), so the journal's orphan-sweep does not emit a second terminal
  receipt for the same `request_id`; conversely, if the process dies before
  `Drop` runs, the sweep produces the cancellation receipt. Invariant: at most
  one terminal receipt per `request_id` regardless of which mechanism fires.
  When RFC-0003 is absent, this guard is fully self-sufficient for the in-
  process drop / cancel / panic cases; the only uncovered case is hard process
  death mid-dispatch, which is precisely RFC-0003's charter.
- Extends ADR-0006: the monetary unwind stays charge-gated and is a reversal of
  the pre-execution hold (`BudgetReverseHoldDecision`), not a refund of a
  committed charge, so ADR-0006's monotonic no-refund model for settled charges
  is untouched.
- Extends ADR-0003: it supplies the cancellation-receipt and reservation
  semantics that ADR-0003 called out as required follow-up ("define
  cancellation behavior for parent and child requests").
- Must land before the load-chaos "cancellation storm" scenario can assert the
  receipt-completeness invariant, and before the exported `build_layered` stack
  is documented as production-ready for external embedders.
- Suggested commit split, conventional-commit friendly:
  1. `feat(kernel): add dispatch_started to PostAdmissionDropGuard and split the
     drop unwind` (guard restructure, nested-flow lookup hoist, both arm sites
     wired, pre-dispatch release, unit tests).
  2. `feat(kernel): mark retained runtime-admission reservations on aborted
     unwind paths` (new helper, wired into cancel / incomplete / error arms).
  3. `test(chio-tower): prove build_layered timeout records a cancellation
     receipt` (integration test).
