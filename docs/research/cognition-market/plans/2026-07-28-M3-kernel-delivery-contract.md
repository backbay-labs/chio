# Kernel Delivery Contract (M3) Implementation Plan

Bite-sized implementation plan for milestone M3 of the cognition-market
program ([../PLAN.md](../PLAN.md) section "M3 Kernel delivery contract"),
authored from the decisions in
[ADR-0018](../../../adr/ADR-0018-kernel-delivery-contract.md) with the
target files open. The M0/M1 plan
([2026-07-20-M0-M1-finding-artifact-family.md](2026-07-20-M0-M1-finding-artifact-family.md))
is the format precedent. Every ADR-0018 decision it cites was verified by
direct read of the post-#974 kernel; the milestone-text corrections in
ADR-0018 supersede the original PLAN wording where they conflict.

## Goal and boundary

M3 makes an Allow for a grant carrying `Constraint::OutputDigestSha256`
valid only if the delivered output hashes to the frozen expected digest,
and otherwise produces a persisted, replay-stable signed Deny with a
zero-charge financial terminal, before any irreversible money movement.
The result is GENERIC delivery evidence, attached as the
`chio.delivery-contract.v1` receipt block.

Out of scope (M4 and later): finding-specific binding, the
`chio.finding.delivery.v1` overlay, media-type policy,
`RequireFindingPurchase`, the `BidMintContext` constraint extension, DPoP
flags, and any stream-payload representation. M3 admits any durable
`ReversibleHold` (or non-payment) operation; M4 narrows to
`HoldCapture` + `ReversibleHold`.

Baseline: branch `codex/cognition-market-m3`, stacked on
`codex/cognition-market-m2` (PR #1033). The kernel source is identical to
main, so the ADR reasoning holds. The qualified `umask 022`
full-workspace gate discipline carries over.

## Two decisions to confirm before the owning task lands

ADR-0018 flags two points a human kernel owner would still weigh. Each is
resolved here with a default and an explicit fallback; the default is
taken unless review overturns it before the task that depends on it.

- CONF-1 (Task 5, freezing): fold the expected digest into
  `immutable_tool_admission_request_hash`
  (`admission_operation/identity.rs:289-325`), which reuses the existing
  recovery re-derivation and comparison
  (`terminal.rs:481-487`). Default: DO fold, and gate the
  persisted-format change behind an operation-record version bump plus a
  migration that treats a pre-M3 record's absent digest as "no
  constraint". Fallback if the version bump proves too invasive: a new
  `AdmissionAttachment` slot (`admission_operation.rs:372-390`, cap 13 at
  `:422-434`) with a phase rule in `validate_state_attachments`
  (`state.rs:160-205`), which does not change `operation_id`.
- CONF-2 (Task 4, read-only classification): the self-declared
  `tool_is_read_only` manifest flag (`runtime.rs:399-406`, default false)
  is treated as an admission INPUT, not authenticated evidence, and M3
  does NOT ship the generic no-capture read-only mismatch profile.
  Default: M3 enforces digest constraints only on the durable
  `ReversibleHold`/non-payment path (where the zero-charge terminal
  exists) and rejects everything else predispatch. The read-only
  no-capture profile is deferred to a later milestone that can
  authenticate side-effect class. This keeps M3's claim narrow and true.

## Program constraints that bind every task

- Fail-closed everywhere; an unaware binary must DENY a token carrying the
  new variant (adjacent serde tag gives this for free); every kernel
  `Constraint` match is exhaustive so a new variant is a compile error;
  every no-output surface rejects before nonce minting or budget/payment
  mutation; `Stream` and `None` outputs deny.
- No em dashes; clippy `unwrap_used`/`expect_used` deny; conventional
  commits; Chio naming.
- Schema discipline: the new receipt-metadata block registers as a block
  (schema file under `spec/schemas/chio-wire/v1/receipt/`, `registry.json`
  + `MANIFEST.sha256` rows, PROTOCOL 6.4 text, enclosing-receipt
  round-trip test), NOT in `SIGNED_ARTIFACT_SCHEMA_SPECS`. The
  `admission-metadata.schema.json` `projected_state` enum gains the new
  terminal, forcing a registry + manifest digest bump.
- Wire codegen: the `Constraint` variant lands in
  `spec/schemas/chio-wire/v1/**` and is regenerated
  (`cargo xtask codegen rust`) so `_generated/chio_wire_v1.rs` stays in
  sync and the generated-check test stays green.
- Verification gate per change: full workspace build/test/clippy/fmt plus
  `scripts/check-chio-schema-registry.sh`,
  `scripts/check-chio-owned-v1-only.sh`, and the verdict-matrix corpus
  check.

## Files

New:
- `spec/schemas/chio-wire/v1/receipt/delivery-contract.schema.json`.
- `crates/core/chio-core-types/src/receipt/metadata.rs` additions (the
  `DeliveryContract` typed block, the reserved-key registry consts).
- `crates/kernel/chio-kernel-core/src/formal_core.rs`
  (`delivery_contract_admits`) plus its Kani harness registration.
- `chio-conformance` verdict-matrix corpus directory
  `delivery_contract/` with twelve scenarios.
- Kernel exit test `output_digest_delivery_contract` (siting in Task 7).

Extended: `crates/core/chio-core-types/src/capability/scope.rs`
(`Constraint` variant + attenuation arm); the five compile-forced
`Constraint` match sites and the wildcard replacements per ADR-0018
item 6; `crates/kernel/chio-kernel/src/admission_operation.rs` and
`admission_operation/{state,projection,identity}.rs` (18th state +
projection + qualify + reason enum + freeze); `kernel/admission_coordinator/terminal.rs`
(compare + verdict input to disposition + recovery/reconcile arms);
`kernel/evaluation/{async_evaluation_core,nested_flow_evaluation}.rs`
(legacy + prepay predispatch rejection); `receipt/body.rs`,
`receipt/signing.rs`, `receipt_persistence.rs` (block accessor + key
registry + reserved-key/object assertions); `spec/errors/registry.yaml`
(deny-reason URNs); `spec/PROTOCOL.md` 6.4; the verdict-matrix manifest,
drivers, and docs; the ADR-referenced FV registries.

## Non-negotiable invariants (repeated at every enforcement point)

1. An Allow for a digest-constrained grant implies the signed receipt's
   `content_hash` equals the frozen expected digest. Every admitted lane
   either proves this at an atomic output-aware terminal or rejects the
   request before dispatch.
2. No money moves on a mismatch. The durable terminal releases the open
   hold, captures zero, and reconciles realized spend to zero; the Deny
   receipt reports `cost_charged` zero and one consumed invocation.
3. The frozen `(grant_index, expected_digest)` is restart-stable: recovery
   re-derives and compares it, so a restart cannot select a different
   grant or digest.
4. `sha256("null")` is never a legal expected digest, and the comparison
   is never invoked from a surface whose output is `None`.
5. The `delivery_contract` block is present only on a digest-constrained
   request, is merged last by the kernel, and rejects a pre-existing key
   from caller or hook metadata.
6. Every `Constraint` match in `chio-kernel`, `chio-kernel-core`, and
   `chio-control-plane` is exhaustive; wildcard arms over `Constraint` are
   forbidden and tested.

## Task 1: The carrier and exhaustive fail-closed handling

Files: `crates/core/chio-core-types/src/capability/scope.rs`; the wire
schema under `spec/schemas/chio-wire/v1/**` + regeneration; the five
compile-forced match sites; the wildcard replacements.

- Add `Constraint::OutputDigestSha256(String)` (`scope.rs:331-410`), wire
  `output_digest_sha256`. Add an explicit attenuation arm at `:455-484`
  (structural equality) rather than the `_ => self == child` catch-all.
- Land the variant in the wire schema and run `cargo xtask codegen rust`;
  confirm `_generated/chio_wire_v1.rs:7705` and `:21795` regenerate and
  the generated-check test is green.
- Production request matcher (`request_matching.rs:405-458`): explicit arm
  returning `Ok(true)` (carrier admission only, enforcement at the durable
  terminal), plus an explicit reject of
  `Custom("output_digest_sha256", _)` so the carrier cannot be downgrade
  re-expressed.
- Governed validation (`governed_validation.rs:166-227`): explicit no-op
  arm per the crate convention.
- Portable matcher and namers (`chio-kernel-core/src/scope.rs:193-255`,
  `:338-365`; `normalized.rs:627-654`): add the variant; add the name.
- Replace the `unsupported =>` wildcard at `normalized.rs:560-562` with an
  explicit variant list.
- Fix the `_ => true` fail-open in
  `chio-ag-ui-proxy/src/proxy/helpers.rs:117-121` (enumerate or
  fail-closed); this is a live fail-open for every non-`Custom` constraint
  today, independent of M3.
- Add the variant to the control-plane economic-sensitivity list
  (`chio-control-plane/src/issuance/scope.rs:94-106`).
- Add a test asserting no wildcard `Constraint` match exists in the three
  crates (there is no such tripwire today).

Red/green: a round-trip serde test for the variant; a test that an unknown
`type` denies (adjacent tag); rejection tests for `Custom` downgrade and
for a non-canonical digest value.

Commits: `feat(chio-core-types): output-digest capability constraint`,
`feat(chio-kernel): fail-closed handling for the output-digest constraint`.

## Task 2: The delivery-contract receipt block and the key registry

Files: `spec/schemas/chio-wire/v1/receipt/delivery-contract.schema.json`;
`crates/core/chio-core-types/src/receipt/metadata.rs`;
`receipt/body.rs`; `receipt_persistence.rs`; `spec/schemas/registry.json`;
`spec/schemas/MANIFEST.sha256`; `spec/PROTOCOL.md` 6.4; COVERAGE.

- Typed `DeliveryContract` block in `receipt/metadata.rs` (not
  `chio-kernel`, so M4/M5 and portable verifiers can read it):
  `{schema, expected_digest, observed_digest, result}`, `result` in
  `{matched, mismatched}`, `deny_unknown_fields`, all required. Public
  accessor beside `body.rs:579-599`.
- Reserved-key registry: named consts in `receipt/metadata.rs`; convert
  the scattered key literals (`body.rs:580,585,590,598`;
  `admission_operation.rs:29`) to reference them; a normative key table in
  PROTOCOL 6.4 replacing the prose at `:1062-1072`.
- Reserved-key collision assertion and a metadata-is-object assertion
  before body construction (`receipt_persistence.rs:40`), so a
  last-write-wins merge (`receipt_metadata.rs:87-112`) cannot let a hook
  forge or displace the block, and a non-object metadata value cannot hide
  it under `original_metadata` (`signing.rs:106-107`).
- Register the block: schema file, registry row (artifactKind
  `delivery_contract`, introducedBy `delivery-contract-v1`), manifest,
  subtree README, COVERAGE, PROTOCOL 6.4 paragraph after `:1080`.
- Add the instance-conformance test the admission precedent lacks
  (serialize the struct, validate against the registered schema), and a
  test that mutating `metadata` breaks `verify_signature` (ARCHITECTURE
  1980-1981 requires this and no test provides it).

Red/green: schema conformance + rejection; the two authenticity tests
above; a merge test that a caller-supplied `delivery_contract` key is
rejected.

Commits: `feat(chio-core-types): delivery-contract receipt block`,
`feat(chio-core-types): reserved receipt-metadata key registry`.

## Task 3: The 18th terminal state and its financial terminal

Files: `crates/kernel/chio-kernel/src/admission_operation.rs`;
`admission_operation/{state,projection}.rs`;
`admission-metadata.schema.json` + registry + manifest.

- Add `AdmissionOperationState::DeniedAfterDelivery` to the enum and
  `ALL` (`admission_operation.rs:163-202`; `ALL` becomes `[Self; 18]`).
- Legal transition only from `Finalizing` (`state.rs:519-618`); confirmed
  the only current exits from `Finalizing` are `Completed` and
  `OutcomeUnknownAfterDispatch`, neither of which can carry a
  post-delivery Deny.
- New `AdmissionTerminalProjection` variant carrying the signed Deny
  receipt (`projection.rs:1190-1216`); `qualify` arm admitting
  `Decision::Deny` for and only for this state (`projection.rs:187-191`);
  a payment-presence rule analogue of
  `validate_completed_participant_presence` (`projection.rs:1157-1179`);
  compensation status `NotCompensated` (the hold was released, not
  compensated).
- Closed reason enum with exactly one M3 member `DigestMismatch`,
  extensible additively for M4.
- `admission-metadata.schema.json` `projected_state` gains the state;
  regenerate registry + manifest digests.
- Financial terminal: reuse `SettlementDispositionV1::ContractualZeroCharge`
  (`tool_outcome.rs:711-715`), which releases the open hold, captures
  zero, and reconciles realized spend to zero on `ReversibleHold`
  (`terminal.rs:1114-1123,1198-1210`), authorized by
  `VerifiedContractualZeroCharge` from persisted records
  (`tool_outcome/release.rs:1649-1715`). No new disposition variant.

Red/green: state-machine tests (legal from `Finalizing`, illegal from
every other state, terminal, `qualify` admits Deny only here); a
projection round-trip; a `ContractualZeroCharge` financial test proving
hold released + zero captured + zero realized spend.

Commits: `feat(chio-kernel): DeniedAfterDelivery terminal state`,
`feat(chio-kernel): zero-charge financial terminal for delivery denial`.

## Task 4: Pre-dispatch rejection on legacy, prepayment, and no-output surfaces

Files: `kernel/evaluation/async_evaluation_core.rs`,
`nested_flow_evaluation.rs`; `chio-kernel-core/src/scope.rs`,
`evaluate.rs`; `crates/platform/chio-http-core/src/authority.rs`;
reserve/reconcile paths.

- Gate A: in the `async_evaluation_core.rs:347`-`:378` window (after
  `begin_durable_tool_admission` at `:328` establishes
  `durable_admission`, before any budget/payment mutation and before the
  `InvocationHold` capture at `:952-953`) and the
  `nested_flow_evaluation.rs` mirror. Reject when any candidate carries
  the constraint and any request-knowable condition holds: legacy lane
  (`durable_admission.is_none()`), governed `MustPrepay`, or nonce
  preflight required. A gate above `:328` cannot read `durable_admission`.
- Gate B: after grant selection at `:633` and before the `InvocationHold`
  capture at `:952` and `authorize_payment_if_needed` at `:1002`. Reject
  when the selected grant carries the constraint and
  `adapter.rail_mode()` is not `ReversibleHold` (`validation.rs:2522`, a
  pure property read, no money move). This is the money-safe placement
  for the `PrepaidFinal` rejection: `authorize_payment_if_needed` settles
  a `PrepaidFinal` prepayment inside the call (`validation.rs:2656`,
  `:2680-2693`; x402 settles at `payment.rs:896-905`), and a settled
  prepayment cannot be released and has no `ContractualZeroCharge`
  terminal, so a check after `:1002` would deny after money loss. Gate B
  runs before the authorize call.
- Portable core: add the variant to the "cannot safely evaluate" group in
  `chio-kernel-core/src/scope.rs:250`, firing before `admit_delegated_budget`
  (`evaluate.rs:448`); covers browser, mobile, and C++ FFI.
- HTTP authority: gate in `validate_capability_token`
  (`authority.rs:1250`) before the kernel call, surfacing as an invalid
  reason.
- Declare `/v1/reconcile` (`reconcile_reserved_authorization_by_nonce`)
  out of the M3 qualified profile; record that this is sound only because
  reserve-for-caller is rejected upstream so no digest-constrained nonce
  can exist. Declare `api-protect build_manual_receipt` outside the
  contract as a standing hazard.
- Reject `sha256("null")` as an expected digest at the admission gate; do
  not invoke the comparison from any `None`-output surface (CONF-2 keeps
  those reject-only anyway).

Red/green: per-surface rejection tests proving no budget/payment mutation
occurred (assert the hold/journal is untouched); a `PrepaidFinal`
rejection test; a `sha256("null")` rejection test.

Commits: `feat(chio-kernel): reject the output-digest constraint on
no-output and legacy lanes predispatch`.

## Task 5: Durable enforcement, freezing, and recovery

Files: `kernel/admission_coordinator/terminal.rs`;
`admission_operation/identity.rs`; `kernel/admission_coordinator.rs`.

- Freeze (CONF-1 default): fold the expected digest into
  `immutable_tool_admission_request_hash` (`identity.rs:289-325`), gated
  by an operation-record version bump treating a pre-M3 absent digest as
  no constraint. Confirm recovery re-derives and compares it
  (`terminal.rs:481-487`) alongside the `matched_grant_index` check.
- Selection ambiguity: reject at Gate B (after grant selection at
  `async_evaluation_core.rs:633`) unless the selected grant carries
  exactly one `OutputDigestSha256`, canonical lowercase 64-hex, not
  `sha256("null")`, and no other candidate in `matching_grants` carries
  one. Closes the budget-fallthrough case (`:584-593`).
- Compare: in `finalize_durable_tool_return`, between the post-transform
  hash at `terminal.rs:1289` and `post_guard_decision_digest` at `:1365`,
  compare `receipt_content.content_hash` against the frozen expected
  digest; on mismatch set `terminal_decision = Decision::Deny` before
  `:1365` so the verdict is covered by the existing frozen replay contract
  (`:1491-1509`).
- Disposition: give `durable_payment_disposition` (`:890-968`) the
  delivery verdict as an input and force `ContractualZeroCharge` on
  mismatch (`:955-966`); it does not read the decision today.
- Populate the `delivery_contract` block on both branches: `matched` on
  Allow, `mismatched` on the Deny; merge it last and reject a pre-existing
  key.
- Recovery/reconcile arms: `recover_durable_tool_admission`
  (`terminal.rs:326-342`) returns the persisted Deny for the new state
  instead of redispatching; `reconcile_recoverable_admissions`
  (`admission_coordinator.rs:364-502`) gains an arm; the replay lane
  `completed_durable_tool_response` (`:509-684`) reproduces the block
  byte-for-byte (`:828-832,856`).

Red/green: durable reversible-hold mismatch produces a signed Deny with no
capture, zero realized spend, one consumed invocation, and a `mismatched`
block; a matched Allow carries a `matched` block and the frozen expected
digest; a transformed-output (redaction) mismatch; restart between compare
and settle recovers to the persisted Deny (not a redispatch); exact-digest
cardinality and alternate-grant negatives.

Commits: `feat(chio-kernel): freeze and enforce the output digest at the
durable terminal`.

## Task 6: Verdict matrix and the Kani hook

Files: `chio-conformance/verdict_matrix/**`; `spec/errors/registry.yaml`;
`chio-kernel-core/src/formal_core.rs` + Kani registries; docs.

- Factor the comparison into a pure
  `chio_kernel_core::formal_core::delivery_contract_admits(expected,
  observed) -> DeliveryVerdict` and call it from the durable terminal.
- Kani harness proving `verdict == Allow implies expected == observed`,
  modelled on `kani_public_harnesses.rs:396-422`; register in
  `.kani/harnesses.toml`, `kani-public-harnesses.toml [lanes.pr]`, and
  both hard-coded lists in `scripts/check-kani-public-core.sh`.
- Sixth `ScenarioCategory::DeliveryContract`
  (`verdict_matrix/src/lib.rs:45-118`; do not reuse `Receipt`); twelve
  scenarios authored so the required Python and Go mock drivers produce a
  real tuple from carrier admission alone (deny-on-unsupported-constraint).
- Full rotation: enum + `as_str`/`FromStr` + stability test; the corpus
  directory; `manifest.toml` counts and recomputed hashes; the hard-coded
  `48` in `verdict_matrix_rust_driver.rs:72` and
  `test_verdict_matrix.py:41-45`; the Go driver; docs including the stale
  hash at `docs/conformance/verdict-matrix.md:26`; the workflow count
  step; new deny-reason URNs in `spec/errors/registry.yaml`;
  `[drivers.wasm-browser] supported_categories` in `manifest.toml:70`.
- Defer the bounded Lean entry with a named follow-up (the Lean model has
  no output or content hash). State the enforcement asymmetry: only the
  verdict-matrix rotation is a required PR gate; the Kani lane is nightly.

Sequence the rotation as its own commit (it can red the required
python-go and deployment-shape jobs in ways unrelated to the kernel
change).

Commits: `feat(chio-kernel-core): delivery-contract soundness core + Kani
harness`, `test(chio-conformance): delivery_contract verdict scenario
class`.

## Task 7: Exit test and gate

- `output_digest_delivery_contract` integration test proving: every
  admitted lane either enforces "Allow implies content_hash equals
  expected digest" or rejects the constrained request before dispatch;
  durable reversible-hold mismatch produces a signed Deny with no capture;
  transformed-output and stream cases are covered; the chosen
  `PrepaidFinal` behavior (rejection) is proved; legacy financial dispatch
  is rejected; browser/mobile/portable pre-dispatch surfaces reject; a
  matched Allow carries a signed `delivery_contract` block with the frozen
  expected digest and `matched`, with the selected grant identified by the
  existing authorization/payment metadata; exact-digest cardinality and
  alternate-grant negatives pass. Siting: an in-kernel integration test
  under `crates/kernel/chio-kernel/tests/`, following the durable-admission
  test precedent (`durable_admission_sqlite.rs`).
- Full `umask 022` workspace gate, schema and v1-only scripts, verdict
  matrix check, the Kani lane locally, then an adversarial review pass over
  the branch diff. Record exact results here under "Recorded results".
- Update the PLAN ladder row for M3 and the ignored spec test's seam list.

## M3 exit criteria

1. The named `output_digest_delivery_contract` test is green and proves
   every clause of the exit definition, including both fault-injection
   legs (mismatch-no-capture and restart-recovers-to-persisted-Deny).
2. Every kernel `Constraint` match is exhaustive; the wildcard-forbidden
   test passes; the ag-ui fail-open is closed.
3. The `chio.delivery-contract.v1` block and the `DeniedAfterDelivery`
   `projected_state` are registered with schema/registry/manifest/PROTOCOL
   parity, and the metadata-authenticity tests pass.
4. The verdict matrix rotation is green (required PR gate); the Kani
   harness is registered and green in its lane; the Lean entry is deferred
   with a named follow-up.
5. The full qualified workspace gate passes at the branch HEAD.
6. CONF-1 and CONF-2 are resolved (default or overturned by review) and
   recorded.
