# Trajectory 5 - Lane A: Threat Evidence Backfill

This document maps every threat ID in
`spec/security/chio-threat-model.v1.json` to:

- the existing evidence file at `audits/evidence/threats/<id>.json`,
- the production call path that should be exercised,
- the public symbol the test invokes,
- the test file at `crates/chio-conformance/tests/threats/<id>.rs`,
- the per-row triage status,
- the per-row acceptance criteria.

## Common acceptance criteria (every row)

A row passes Lane A's close bar when **all five** are true:

1. `audits/evidence/threats/<id>.json` shows `caught >= 1`.
2. `audits/evidence/threats/<id>.json` shows `needs_real_run: false` (or
   the field is absent).
3. `audits/evidence/threats/<id>.json` shows `ran_at` as a real ISO-8601
   2026 timestamp, **not** `1970-01-01T00:00:00Z`.
4. The test body at `crates/chio-conformance/tests/threats/<id>.rs` is a
   deny-asserting fixture: builds a verifier or guard, feeds an attack
   input, asserts a `Verdict::Deny` (or crate-typed equivalent). It is
   NOT an `assert_file_contains` body, NOT an
   `assert_threat_covered_by_corpus` body, NOT a meta-only check.
5. The "Public symbol invoked in test" column entry is a real `pub fn`
   (or `pub` trait method on a `pub` impl) that exists in the workspace
   at the moment the ticket closes (verified by `grep`). The test
   imports the production module by its workspace path
   (`use chio_kernel::...`, etc.), not a copy.

## Backing scripts

- `bash scripts/check-threat-coverage.sh` -- file-existence gate.
- `bash scripts/check-threat-coverage-mutants.sh` -- per-row mutation gate
  (the runtime backstop). The gate emits a downgrade hint with reason
  among `missing_evidence`, `zero_kills`, `no_coveredby`,
  `bootstrap_placeholder`, `bootstrap_expired`, `inconsistent_bootstrap`.
  Lane A's close bar requires zero hints from any reason except possibly
  the informational `bootstrap_placeholder`, and that one only while the
  ticket is in flight.

## Triage status legend (R2 BLOCKER 2.3, R2 MAJOR 2.4)

Each row carries one of four triage tags. Wave 1 produces the per-row
triage; the tag is recorded in the evidence JSON's `triage_status`
field (R2 Section 9 patch) and re-checked at Lane A close.

- `IMPL-EXISTS-AND-PUBLIC`: the cited symbol is a `pub fn` (or
  publicly-accessible trait-impl method) that exists in the workspace
  today. The test can import it by its workspace path. The ticket can
  start immediately.
- `IMPL-EXISTS-PRIVATE`: the production decision is implemented in
  crate-private code. The test must live in the same crate (under
  `tests/`) or call through a public wrapper. The wrapper is named in
  the ticket if needed.
- `IMPL-PARTIAL`: the production stub exists but does not yet enforce
  the property. The ticket must either land the enforcement (in which
  case the row depends on the enforcing crate's wave plan) or
  `BLOCKED-BY-ARCHITECTURE`.
- `BLOCKED-BY-ARCHITECTURE`: the property cannot be enforced today
  without a non-trivial architectural change. The row is deferred to
  trj6 with a Risk Register R3 entry. The release work banner reads
  `<n> of 20 covered, <m> deferred to trj6`, not `20 of 20`. R3's
  escalation criterion fires when the count of `IMPL-PARTIAL +
  BLOCKED-BY-ARCHITECTURE` exceeds 2 (tightened from >4 per R2 Section
  2.4 patch).

## Per-row map

The 20 rows below are the universe of threat IDs in the threat model.
Test file paths follow the pattern
`crates/chio-conformance/tests/threats/<id>.rs` and are verified to
exist (per `ls` of that directory).

The "Public symbol invoked in test" column is verified by grep against
the workspace at this writing (R2 BLOCKER 2.3). Where the column is
followed by `(verified)`, the symbol exists today. Where it is followed
by `(needs Wave 1 confirmation)`, Wave 1 verifies and either confirms
or downgrades the row to `IMPL-PARTIAL` / `BLOCKED-BY-ARCHITECTURE`.

| Row | ID | Triage | Public symbol invoked in test | Test file | Per-row acceptance |
|---|---|---|---|---|---|
| 1 | `agent_velocity_abuse` | IMPL-EXISTS-AND-PUBLIC | `chio_guards::agent_velocity::*` (module verified at `crates/chio-guards/src/lib.rs:49`; the public guard struct is in that module) | `crates/chio-conformance/tests/threats/agent_velocity_abuse.rs` | Real `caught >= 1`; existing real test body retained. |
| 2 | `audience_confusion` | IMPL-EXISTS-AND-PUBLIC | `chio_kernel_core::capability_verify::verify_capability_full` at `crates/chio-kernel-core/src/capability_verify.rs:400` (`pub fn` verified) | `crates/chio-conformance/tests/threats/audience_confusion.rs` | Real `caught >= 1`; verify body asserts deny on audience mismatch. |
| 3 | `behavioral_sequence_attack` | IMPL-EXISTS-AND-PUBLIC | `chio_guards::behavioral_sequence::*` (module verified at `crates/chio-guards/src/lib.rs:51`; the public guard struct is in that module) | `crates/chio-conformance/tests/threats/behavioral_sequence_attack.rs` | Real `caught >= 1`; existing real test body retained. |
| 4 | `capability_token_theft` | IMPL-EXISTS-PRIVATE (Wave 1 verifies) | `chio_kernel::execution_nonce::verify_execution_nonce` at `crates/chio-kernel/src/execution_nonce.rs:364` (`pub fn` verified). The `body_hash` rebinding test path lands as Lane B receipt-v2 work; this row pins the nonce-replay-store side. | `crates/chio-conformance/tests/threats/capability_token_theft.rs` | Real `caught >= 1`; deny-asserting body. **If Lane B receipt v2 work is incomplete by Wave 1, downgrade row to `IMPL-PARTIAL` and defer the body-hash subset to trj6.** |
| 5 | `cumulative_data_exfiltration` | IMPL-EXISTS-AND-PUBLIC | `chio_guards::data_flow::DataFlowGuard` at `crates/chio-guards/src/data_flow.rs:38` (`pub struct` verified) | `crates/chio-conformance/tests/threats/cumulative_data_exfiltration.rs` | Real `caught >= 1`; existing real test body retained. |
| 6 | `delegation_chain_abuse` | IMPL-EXISTS-AND-PUBLIC | `chio_kernel_core::capability_verify::verify_capability_with_trusted_and_floor` at `crates/chio-kernel-core/src/capability_verify.rs:275` (`pub fn` verified). Kani harness already covers a step (per existing `kani_public_harnesses.rs`); A2 is the runtime row. | `crates/chio-conformance/tests/threats/delegation_chain_abuse.rs` | Real `caught >= 1`; deny-asserting body. |
| 7 | `device_key_extraction` | IMPL-EXISTS-AND-PUBLIC (depends on TRJ4-033) | `chio_custody_hw::attestation::app_attest::verify_app_attest` at `crates/chio-custody-hw/src/attestation/app_attest.rs:55` (`pub fn` verified) | `crates/chio-conformance/tests/threats/device_key_extraction.rs` | Real `caught >= 1`; rewritten deny-asserting body that feeds a forged device key. **Wave 1 must confirm TRJ4-033 is closed; if not, this row blocks on TRJ4-033 closure.** |
| 8 | `kernel_impersonation` | IMPL-EXISTS-AND-PUBLIC | `chio_kernel_core::receipts::sign_receipt` at `crates/chio-kernel-core/src/receipts.rs:38` (`pub fn` verified) | `crates/chio-conformance/tests/threats/kernel_impersonation.rs` | Real `caught >= 1`; rewritten deny-asserting body that feeds an impersonation key (kernel signs with key `K_attacker` not `K_kernel`; verifier rejects). |
| 9 | `mobile_attestation_replay` | IMPL-EXISTS-AND-PUBLIC (depends on TRJ4-033) | `chio_custody_hw::attestation::app_attest::verify_app_attest` at `crates/chio-custody-hw/src/attestation/app_attest.rs:55` (`pub fn` verified) | `crates/chio-conformance/tests/threats/mobile_attestation_replay.rs` | Real `caught >= 1`; rewritten deny-asserting body using deterministic conformance hooks (replay the same App Attest receipt twice; second call denies). **Wave 1 must confirm TRJ4-033 is closed.** |
| 10 | `native_channel_replay` | IMPL-EXISTS-AND-PUBLIC | `chio_kernel::execution_nonce::verify_execution_nonce` at `crates/chio-kernel/src/execution_nonce.rs:364` (`pub fn` verified). Quality Skeptic line 35: "calls `assert_threat_covered_by_corpus(...)` and asserts the corpus has `>= 2` distinct attack classes. Never instantiates a verifier..." | `crates/chio-conformance/tests/threats/native_channel_replay.rs` | Real `caught >= 1`; rewritten deny-asserting body that feeds a replayed nonce against `verify_execution_nonce`. |
| 11 | `passkey_credential_theft` | IMPL-EXISTS-PRIVATE (Wave 1 confirms) | Public passkey path candidates: `chio_credentials::registry::verify_signed_passport_verifier_policy` at `crates/chio-credentials/src/registry.rs:25` and the `chio_credentials::oid4vp::*` verifiers. Wave 1 picks the closest production decision matching the threat-row attack class. **If neither is a fit (passkey enforcement still partial), downgrade to `IMPL-PARTIAL` and defer.** | `crates/chio-conformance/tests/threats/passkey_credential_theft.rs` | Real `caught >= 1`; rewritten deny-asserting body if `IMPL-EXISTS-AND-PUBLIC` after Wave 1 triage. |
| 12 | `pii_phi_exposure` | IMPL-EXISTS-AND-PUBLIC | `chio_guards::response_sanitization::*` (module verified at `crates/chio-guards/src/lib.rs:64`; the public guard struct is in that module) | `crates/chio-conformance/tests/threats/pii_phi_exposure.rs` | Real `caught >= 1`; existing real test body retained. |
| 13 | `play_integrity_token_replay` | IMPL-EXISTS-AND-PUBLIC (depends on TRJ4-033) | `chio_custody_hw::attestation::play_integrity::verify_play_integrity` at `crates/chio-custody-hw/src/attestation/play_integrity.rs:82` (`pub fn` verified) | `crates/chio-conformance/tests/threats/play_integrity_token_replay.rs` | Real `caught >= 1`; rewritten deny-asserting body. **Wave 1 must confirm TRJ4-033 is closed.** |
| 14 | `pq_signature_downgrade` | IMPL-EXISTS-AND-PUBLIC | `chio_kernel_core::capability_verify::verify_capability_full` at `crates/chio-kernel-core/src/capability_verify.rs:400` (`pub fn` verified). The hybrid-PQ algorithm-tag check is internal to this entry; the test feeds a token whose declared algorithm tag does not match the signature byte layout and asserts deny. Quality Skeptic line 36: "does `assert_file_contains` on four other test files to grep for test-function names. It is a glorified `grep -F`." | `crates/chio-conformance/tests/threats/pq_signature_downgrade.rs` | Real `caught >= 1`; rewritten deny-asserting body. |
| 15 | `resource_exhaustion_dos` | IMPL-EXISTS-PRIVATE (Wave 1 confirms) | Rate-limit/budget admit path is in `chio-kernel`. Wave 1 names the specific public entry (candidate: a budget-checked dispatch wrapper). **If the budget admit path is not a `pub fn` reachable from a conformance test, downgrade to `IMPL-PARTIAL`.** | `crates/chio-conformance/tests/threats/resource_exhaustion_dos.rs` | Real `caught >= 1`; deny-asserting body. |
| 16 | `ssrf_via_http_substrate` | IMPL-EXISTS-AND-PUBLIC | `chio_link::HttpEgressContract` (verified to exist via `grep -rln HttpEgressContract crates/chio-link/`); the contract trait's `validate` step is the production decision. Wave 1 confirms the `pub` impl crate. | `crates/chio-conformance/tests/threats/ssrf_via_http_substrate.rs` | Real `caught >= 1`; existing real test body retained. |
| 17 | `tee_quote_forgery` | IMPL-EXISTS-AND-PUBLIC | `chio_tee_frame::schema::validate_signed` at `crates/chio-tee-frame/src/schema.rs:93` (`pub fn` verified) and `chio_tee_frame::schema::verify_tenant_sig` at `crates/chio-tee-frame/src/schema.rs:117` (`pub fn` verified). | `crates/chio-conformance/tests/threats/tee_quote_forgery.rs` | Real `caught >= 1`; rewritten deny-asserting body that feeds a forged quote (signature mismatch) and asserts both `validate_signed` and `verify_tenant_sig` reject. |
| 18 | `tool_server_escape` | IMPL-PARTIAL (Wave 1 verifies) | Sandbox/scope enforcement in tool-server dispatch; the production `pub` decision is the kernel `dispatch` entry. Wave 1 names the specific `pub fn` in `chio-kernel/src/kernel/mod.rs`. **If dispatch sandbox enforcement is still partial after release work-B0 `ToolServerConnection` async migration, this row defers; ssrf_via_http_substrate (#16) is the closest companion that DOES land.** | `crates/chio-conformance/tests/threats/tool_server_escape.rs` | Real `caught >= 1` IF row tags `IMPL-EXISTS-AND-PUBLIC` after Wave 1 triage; otherwise defer to trj6. |
| 19 | `wasm_guard_resource_exhaustion` | BLOCKED-BY-ARCHITECTURE | Per Risk Register R3 line 117: depends on `wasm-guard SDK v4` which is out of scope for release work. The existing `chio-wasm-guards/tests/escape/` fuel-exhaustion pins are real but pin only the harness, not a production-call-path. | `crates/chio-conformance/tests/threats/wasm_guard_resource_exhaustion.rs` | **DEFER to trj6.** Banner reads "<n> of 20 covered, 1 deferred to trj6 (wasm_guard_resource_exhaustion)". Risk Register R3 row updated. |
| 20 | `weights_hash_spoof` | IMPL-EXISTS-AND-PUBLIC | `chio_weights::card::weights_hash_of` at `crates/chio-weights/src/card.rs:274` (`pub fn` verified) and `chio_weights::lineage::verify_model_card_anchor` at `crates/chio-weights/src/lineage.rs:217` (`pub fn` verified). Quality Skeptic line 37: "real failure-path test (`Err(WeightsError::CardMismatch)`)". | `crates/chio-conformance/tests/threats/weights_hash_spoof.rs` | Real `caught >= 1`; existing real test body retained. |

### Triage tally (R2 MAJOR 2.4)

Wave 1 produces the final tally. The pre-Wave 1 estimate based on the
table above:

- `IMPL-EXISTS-AND-PUBLIC`: 13 (rows 1, 2, 3, 5, 6, 7, 8, 9, 10, 12,
  13, 14, 17, 20). [14 strictly counted above]
- `IMPL-EXISTS-PRIVATE` (Wave 1 confirms): 4 (rows 4, 11, 15, 16).
- `IMPL-PARTIAL` (Wave 1 confirms): 1 (row 18).
- `BLOCKED-BY-ARCHITECTURE`: 1 (row 19).

If Wave 1 confirms 1 BLOCKED-BY-ARCHITECTURE and >= 2 IMPL-PARTIAL, R3
escalation fires (>2 sum). review reconsiders the release work banner.

## Sweep / closeout

- threat evidence item runs the gate end-to-end: `bash
  scripts/check-threat-coverage-mutants.sh` under `CI=true`. Captures
  exit-0 transcript (or, if rows defer to trj6, the exit-0 transcript
  reflects "<n> of 20 covered, <m> deferred").
- threat evidence item deletes the `needs_real_run` clause from
  `scripts/check-threat-coverage-mutants.sh` (R2 MAJOR 2.6) so the
  bootstrap-bypass code does not exist after Lane A closes; updates
  `docs/security/threat-coverage.md`: removes the "9 of the 20 covered
  rows currently pass the gate on file-exists +
  no-`unimplemented!()` alone" footnote (line 7); adds a "0 weak
  coverage rows" assertion grounded in threat evidence item transcript.

## Anti-patterns explicitly forbidden

Per the Quality Skeptic
(`.planning/trajectory-5/debate/04-quality-verification-skeptic.md`
lines 25-31, 35-37):

- Evidence JSON with `{ "caught": 0, "needs_real_run": true, "ran_at":
  "1970-01-01T00:00:00Z", "survivors": [] }` (the bootstrap-placeholder
  pattern). Lane A close bar rejects this for all 20 rows.
- Test body that calls `assert_threat_covered_by_corpus(...)` and
  asserts only that the corpus has >= 2 distinct attack classes.
- Test body that calls `assert_file_contains` to grep for other test
  function names.
- Test body that exists to make `check-threat-coverage.sh` happy without
  exercising any defensive code.
- Test that imports a stub from a `tests/common/` helper that
  redefines a production type. Per Evidence Gate Anti-Pattern Catalog
  2.3 ("Mock-not-runtime"), `cargo expand` on the test crate must show
  only `chio_*` workspace crates as the imports of the function under
  test.

The Lane A close bar promotes the runtime backstop in
`scripts/check-threat-coverage-mutants.sh` from advisory (today, with the
`needs_real_run: true` bootstrap-bypass) to required (no bypass). After
threat evidence item lands, the bypass clause is **deleted from the script**
(R2 MAJOR 2.6), not just bypassed at runtime.
