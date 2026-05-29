# Chio-CLI Trust-Control Test-Suite Remediation

## Resolution (completed)

The chio-cli trust-control suite is fully green (all 44 test binaries). Several
hypotheses below were corrected during the work: almost every failure was a
test-only defect, not the deep trust-control, terms, or replication bugs feared.

- Cluster A (rows) and F (residual): tests matched report rows by the
  caller-supplied receipt id, but ChioReceipt::sign replaces body.id with a
  content-addressed hash. Match on the real id.
- Cluster B (terms): seed receipts were signed with throwaway random keys, so the
  reputation integrity filter dropped them, collapsing credit scoring to
  probationary and forcing terms=None. Sign with a trusted test key and seed it
  into the service. The fail-closed filter is correct and unchanged.
- Cluster C (reputation): same trusted-key seeding for local_reputation and the
  evidence import roundtrip.
- Cluster D (mcp_serve): the fixtures omitted allow_ephemeral_receipt_log, so the
  fail-closed receipt-persistence gate denied every tool call (the "cancellation
  race" was that gate, not a race). Enable the flag; make the serial test lock
  poison-tolerant.
- Cluster E: federated_issue exposed a real product bug (serde_json parsed some
  17-digit floats to a neighboring ULP, breaking canonical-signature verification
  on persisted credentials; fixed by enabling the serde_json float_roundtrip
  feature) plus a stale read-boundary flag. trust_cluster, conformance_cli, init,
  code_agent_preset, and receipt_explain_bilateral were test-only (content-id,
  receipt-gate, read-boundary, or stale-string). The forward_compat
  receipt_with_unknown_fields case was also the content-id pattern (it was
  misfiled below as a golden).

The one genuine product fix was serde_json float_roundtrip. Everything else in
the plan was test-only.

## Out-of-plan failures found by the workspace regression sweep

Running the full workspace (to confirm the float fix regressed nothing) surfaced
pre-existing failures in crates outside this plan. None were caused by the float
fix (confirmed: all are string-id, structural, golden, or environmental, never a
float-value mismatch). The two that were the same content-id pattern were fixed
(chio-credit, chio-kernel-core). The rest are a separate remediation:

- chio-e2e full_flow (2): untrusted_issuer is a stale denial-reason string (the
  verdict is correctly Deny; the reason wording changed to "capability issuer is
  not a trusted CA"). revocation_cascade is a setup gap: the test issuer is not
  registered as a trusted CA, so a valid capability is denied before revocation.
- chio-external-guards bedrock (1): stale test, not fail-open. The guard enforces
  hostname DNS pinning at connect via its egress contract, not at construction;
  the test expects construction-time rejection (the same enforce-at-connect
  relocation handled earlier for chio-anchor/chio-link). The test should assert
  the connect-time failure.
- chio-pheromone-runtime runtime_receiver (5): structural (report admission
  rejected); needs investigation, likely a trusted-key or admission-setup gap.
- Blessed-vector goldens (2): capability/v1.json (a cross-language signature
  vector) and rust_canonical_receipt_body_matches_blessed_vector_bytes. Stale;
  need a deliberate, owner-aware re-bless. The vectors are consumed by the go, py,
  and ts SDKs, so regenerating only to make Rust pass could mask cross-language
  canonical divergence, which is what the vectors exist to catch.
- Environmental: py_guard_integration (needs a built .wasm guard component) and
  the SIEM datadog/ocsf/sumo exporters (post to external endpoints).

## Context (read first)

A full `cargo test --workspace --no-fail-fast` sweep surfaced a large cohort of
failing tests. The local build + clippy + fmt gate does not run tests, so these
failures lurked unobserved. The largest cohort is the chio-cli trust-control
integration suite, which was unbuildable on `main` (a stale
`chio-runtime-harness/src/treaty.rs` against the `Option<Decision>`
`ChioReceiptBody`). Repairing that build revived the suite and exposed
pre-existing failures that had never executed. These are pre-existing debt, not
a regression introduced by the cleanup.

## Governing principles

Because these tests never ran, some encode expectations that may themselves be
wrong, not just code that regressed. Therefore:

- Validate each assertion against intended trust-control behavior before
  satisfying it. Where intended behavior is ambiguous, surface to the owner
  before changing code.
- Never weaken a security assertion to make a test pass. (Example: a tamper test
  kept its core `!verify.success()` assertion; only the matched error string was
  corrected to the behavior actually emitted.)
- Run per-binary (`cargo test -p <crate> --test <bin>`), not the parallel
  workspace sweep. The chio-cli suites share serial `Mutex` locks that
  poison-cascade under parallelism (one panic masks roughly twenty siblings) and
  bind fixed ports. Track progress with explicit per-binary runs.
- After each change: gate (build + clippy + fmt) and run the affected binaries
  to confirm progress and no regression.

## Completed: checkpoint signer-key-mismatch cluster

15 tests; 12 green, 3 cleared the checkpoint panic and now block only on the
rows/reputation clusters below. Root cause: a kernel checkpoint must be signed by
the same kernel key that signed the receipts it covers
(`validate_checkpoint_claim_log_signer_range`); the affected paths used a
different key.

- chio-wall (4): a real library bug in `create_chio_wall_receipt_db`
  (`build_checkpoint` used the capability issuer key, not the kernel/receipt
  signer key) - fixed.
- receipt_query (3): added `_signed_by(&Keypair, ..)` helper variants and
  threaded the checkpoint keypair into the in-range receipts.
- evidence_export (5) + passport (3): in-range receipts switched to
  `receipt_with_keypair(.., &issuer)`.

## Remaining clusters

### Cluster A - report rows missing or empty (tractable; likely shared root)

- Signatures: `operator attribution row`, `budget authority feed row`,
  `authorization receipt row`, `asserted authorization receipt row`,
  `review-pack record for first governed receipt`.
- Tests: receipt_query (`test_operator_report_endpoint`,
  `test_behavioral_feed_export_surfaces`,
  `test_authorization_context_report_and_cli`,
  `authorization_context_report_does_not_mark_asserted_call_chain_as_sender_bound`,
  `test_authorization_metadata_and_review_pack_surfaces`), plus others surfaced
  once upstream panics clear.
- Hypothesis: the report projections
  (`chio-store-sqlite/src/receipt_store/reports/*.rs`) return no row for the
  seeded receipts - either a seeding/metadata gap (the test receipts lack the
  attribution/budget-authority metadata the report filters on) or a projection
  regression from the support.rs split.
- Approach: trace one (for example operator attribution) from the report
  SQL/projection back to the receipt metadata it requires, versus what
  `make_*_receipt` stamps. Determine seed-gap versus query-bug; expect a shared
  root across the rows tests.

### Cluster B - trust-control economic terms (deepest; domain-heavy)

- Signatures: `CreditFacilityReport.terms: None`, `capital book requires one
  active granted facility with terms`, `credit bond ... is missing terms
  required for loss lifecycle accounting`.
- Tests: receipt_query `test_capital_*`, `test_credit_*`, `test_underwriting_*`,
  `test_liability_*`, and the `run_large_stack_test` inner tests (the
  "join large-stack thread" panics are these - business-logic assertion
  failures, not checkpoint cascades).
- Hypothesis: facilities/bonds/capital are created without `terms` - either the
  test setup omits a grant-terms step, or
  `trust_control/{capital_and_liability,credit_and_loss}.rs` does not
  attach/persist `terms` after the module split.
- Approach: map the `terms` lifecycle - where terms are set on a facility/bond
  (grant/issue handlers) versus read (report/accounting). Decide setup-omission
  versus behavior-gap. Likely needs owner confirmation of intended terms
  semantics. Do this after Cluster A (rows infrastructure understood).

### Cluster C - reputation seed (receipts filtered out) (tractable)

- Symptom: scorecard `history_depth.receipt_count` is 0 versus an expected 2.
- Root: `compute_local_scorecard` -> `receipt_integrity_valid`
  (chio-reputation/src/lib.rs) drops receipts whose `kernel_key` is not in
  `trusted_kernel_keys`; bare-DB fixtures wire no authority seed, so all are
  filtered (documented at chio-control-plane/src/reputation.rs).
- Tests: evidence_export `evidence_import_roundtrip_surfaces_imported_trust...`,
  local_reputation (5).
- Approach: seed `trusted_kernel_keys` with the receipts' signer key (now
  feasible since the checkpoint fix made receipts use a known key), or confirm
  the intended local path. Verify the positive-count expectation matches the
  trust-service path (which gets a nonzero count only via a configured trust
  service).

### Cluster D - mcp_serve (1 root plus poison-cascade) (tractable; high payoff)

- Symptom:
  `mcp_serve_parent_cancellation_during_tasks_result_marks_task_cancelled`
  (a cancellation-count race, 0 versus 1) panics while holding a shared serial
  `Mutex`, poisoning it, so roughly twenty siblings then fail with
  `mcp_serve test lock poisoned`.
- Fix (two parts): (1) make the shared mcp_serve test lock poison-tolerant
  (recover from `PoisonError` via `into_inner()`, or use `parking_lot::Mutex`)
  so one panic stops masking the rest - this alone reveals the true residual
  count; (2) root-cause the cancellation race (likely an ordering/timing issue
  in nested-task cancellation propagation).

### Cluster E - other binaries (per-binary triage)

- federated_issue, local_reputation (overlaps C), trust_cluster,
  conformance_cli, init, code_agent_preset, receipt_explain_bilateral, and the
  `chio` binary.
- Approach: run each in isolation, extract distinct root causes (expect overlap
  with A/B/C plus a few own setup bugs).

### Cluster F - residual generic assertion mismatches

- A set of `assertion left == right` failures in receipt_query not yet
  attributed; re-triage after A/B/C.

## Out of scope (document as known; do not chase as code bugs)

- py_guard_integration: needs a built `.wasm` guard component
  (`sdks/guard/*/scripts/build-guard.sh`) - a build-artifact/environment
  prerequisite, not a code bug.
- `*_live` harness tests: need live JS and Python peers - environmental.
- SIEM exporters (datadog/ocsf/sumo): post to external endpoints -
  environmental.
- Stale blessed-vector goldens
  (`capability_fixture_cases_round_trip_through_public_api`,
  `rust_canonical_receipt_body_matches_blessed_vector_bytes`,
  `forward_compat receipt_with_unknown_fields`): need a deliberate re-bless/regen
  (verify the new bytes are intentionally correct first), not a logic fix.

## Suggested sequencing

1. Cluster A (rows) + Cluster C (reputation seed) + Cluster D (mcp_serve). Most
   tractable / shared-root / mechanical; D's poison fix de-noises the whole
   mcp_serve count.
2. Cluster B (terms). Deepest; map the lifecycle first; likely owner input on
   intended semantics before fixing.
3. Cluster E (other binaries) + Cluster F (residual assertions).
4. Owner decisions: environmental enablement (build the guard `.wasm`; decide CI
   wiring once Actions billing is restored) plus the golden re-bless.

After each pass, re-run the full `cargo test --workspace --no-fail-fast` to
confirm the total failing count drops monotonically and nothing regressed.
