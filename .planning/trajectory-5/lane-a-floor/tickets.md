# Trajectory 5 - Lane A: Tickets

Format follows the trj4 EXECUTION-BOARD pattern (`Ticket | Title | Lane |
Effort | Depends-on`). Ticket IDs are namespaced `release work-A<sub-lane>.<n>`.

Effort scale (from trj4 EXECUTION-BOARD): XS / S / M / L / XL.

## Ticket-ID convention (R1 MAJOR section 2.1)

- Sub-lane work tickets: `release work-A<sub-lane>.<n>` (e.g. `mutation evidence item`,
  `threat evidence item`). The `<n>` is single-digit or two-digit; trj4
  EXECUTION-BOARD uses single-digit form which Lane A inherits.
- Sub-lane Evidence Gate ticket: `release work-A<sub-lane>.E` (capital `E`,
  no number), per `templates/TICKET-TEMPLATE.md` section 1.1
  ("Evidence Gate tickets use the `.E` suffix"). One `.E` ticket per
  sub-lane: `mutation evidence item`, `threat evidence item`, `release work-A3.E`, `release work-A4.E`,
  `release work-A5.E`. Each is the close-bar ticket for its sub-lane and runs
  the four-artifact gate over every preceding work ticket in the
  sub-lane.

The `.E` suffix is the canonical Evidence Gate marker across the release work
plan; Lane B and Lane C apply the same convention.

## Evidence Gate close bar

Every ticket closes under the Lane A Evidence Gate trio (PLAN.md
"Evidence Gate close bar"): enforced call site + spec/audit citation +
signed evidence artifact (real evidence JSON, harness pass, or theorem
proof; never a placeholder).

For Lane A2 tickets, the **Artifact A: Enforced call site** entry must
name a literal `pub fn` import path of the form
`crate::module::function_name` (R2 BLOCKER 6.2; see
`threat-evidence-backfill.md` per-row "Public symbol invoked in test"
column). The test invokes that symbol directly; if the production
decision is a trait method, the test instantiates the named concrete
impl. Tickets that cannot satisfy this enter R3-defer at Wave 1, not at
Wave 2.

For Lane A1 / A3 / A4 / A5 tickets, the **Artifact A** entry names the
file:line where the production check executes and the public symbol
the test or harness invokes.

For every ticket, the **Artifact D: Production-call-path exercise**
includes a one-line revert-and-rerun procedure (or a CI run URL where
the test failed when the change was reverted) so the test's failure
mode is recorded.

## Threat-evidence count footnote

The synthesis (`debate/00-SYNTHESIS.md` line 79) names "21" threat
evidence files. The on-disk count under `audits/evidence/threats/` is
**20** (verified by `ls audits/evidence/threats/ | wc -l` returning 20
on 2026-05-07; one file per threat-model row in
`spec/security/chio-threat-model.v1.json` whose `grep -c '"id":'`
returns 20). Lane A targets the on-disk count of **20** as the
authoritative number. The synthesis "21" is treated as a minor
arithmetic drift; it does not require re-opening the synthesis.

---

## Sub-lane A1 - Mutation uplift

| Ticket | Title | Lane | Effort | Depends-on |
|---|---|---|---|---|
| mutation exclusion audit | **Audit `.cargo/mutants.toml` `exclude_globs`** (R2 OBSERVATION 1.2 / MAJOR 7.4). Confirm each exclusion is either (a) test/build/fuzz scaffolding, (b) covered by a Kani harness, or (c) accompanied by a production-call-path conformance test. Output: per-line audit report under `audits/evidence/mutation exclusion audit/exclude-audit.md` with each exclusion marked `OK` or `FOR-REMOVAL`. Without this, the >=65% target is held against a pre-existing exclusion list whose justification has not been re-checked. | A | S | - |
| mutation evidence item | Unblock hosted nightly cargo-mutants on `mutants.yml` so the full sweep completes (no fuzz-budget skip). Carry-forward of TRJ4-010. **R2 MINOR 1.4 addition**: verify `status_at_capture` of the last 7 nightly runs and document any flake. If the workflow has been red, this ticket owns un-flaking before per-crate measurement starts. | A | M | mutation exclusion audit |
| mutation evidence item | **Run baseline measurement** (R2 MAJOR 1.1 split). For each of the six trust-boundary crates (`chio-policy`, `chio-credentials`, `chio-attest-verify`, `chio-kernel-core`, `chio-guards`, `chio-anchor`), run `cargo mutants -p <crate> --in-place --output audits/evidence/mutants/<crate>/<date>.json --json`. Capture per-mutant results. Do NOT publish per-crate kill rates yet. Use trust-boundary line targeting via `--in-place` and the (audited) exclusion globs. | A | M | mutation evidence item |
| mutation evidence item | **Publish per-crate kill rates** to `releases.toml [per_crate_kill_rate_percent]` (replacing the six "pending..." strings). After A1.2a measures, this ticket re-baselines the per-crate targets. **If the `chio-attest-verify` baseline is below 50%, escalate to Wave 2 IMMEDIATELY rather than after two waves of test-surface expansion** (R2 MAJOR 1.1 patch; tighter than R2's "two waves" criterion). | A | S | mutation evidence item |
| mutation evidence item | Drive `chio-policy` kill rate to >= 65%. Author tests for survivors; document residuals with `# unreachable:` justifications. Mutation runs target trust-boundary lines specifically (per A1.0 audit output): `cargo mutants -p chio-policy --in-place --json --output audits/evidence/mutants/chio-policy/<date>.json`. | A | L | mutation evidence item |
| mutation evidence item | Drive `chio-credentials` kill rate to >= 65%. Run pattern matches A1.3. | A | L | mutation evidence item |
| mutation evidence item | Drive `chio-kernel-core` kill rate to >= 65%. Run pattern matches A1.3. | A | L | mutation evidence item |
| mutation evidence item | Drive `chio-guards` kill rate to >= 65%. Run pattern matches A1.3. Note: `chio-guards/src/external/**` is excluded today (per A1.0 audit); if the audit re-adds external paths, the kill-rate target re-baselines. | A | L | mutation evidence item |
| mutation evidence item | Drive `chio-anchor` kill rate to >= 65%. Run pattern matches A1.3. **Lane B coordination**: Lane B may modify `chio-anchor/src/batch.rs` during release work-B3; this ticket is updated within the same PR or one wave behind, never more than one wave behind. | A | L | mutation evidence item |
| mutation evidence item | Drive `chio-attest-verify` kill rate to >= 80%. Annotate every residual survivor with `# unreachable: <justification>` per audit `T0.B-substrate-hardening.md` line 16. Run pattern matches A1.3. | A | XL | mutation evidence item |
| mutation evidence item | Two consecutive green hosted nightly mutant runs with `status_at_capture: success`. Capture run URLs to `audits/evidence/mutants/two-night-history.md`. The two-night clock starts from the first green nightly after A1.1 lands; if `mutants.yml` was red in the prior 7 days the clock starts after un-flaking. | A | S | mutation evidence item |
| mutation evidence item | Update `mutants-banner.yml` to render the **lowest observed** per-crate kill rate (not target). Re-render `README.md` mutation banner. Verify the banner update is reproducible: re-running the workflow on the same data produces an identical line. Banner shape per `mutation-budget.md` "Banner regeneration" section. | A | S | mutation evidence item |
| mutation evidence item | **Sub-lane A1 Evidence Gate**: every release work-A1.<n> ticket above is EVIDENCE-COMPLETE. The four-artifact rule (per `templates/EVIDENCE-GATE.md` section 1) is satisfied for each: enforced call site, audit-JSON citation, real evidence file, production-call-path exercise. Banner update from A1.10 reflects observed values. | A | S | mutation exclusion audit..A1.10 |

**A1 close-bar artifact**: `releases.toml` per-crate table with two-night
history; `audits/evidence/mutants/<crate>/<date>.json` for each of six
crates; updated README banner.

**A1 anti-pattern guard**: README banner that names a target rate fails
the close bar. The banner script reads from
`audits/evidence/mutants/*.json`, not from a hard-coded value. Mutation
runs target trust-boundary lines (per A1.0 audit), not test or build
scaffolding (R2 MAJOR 7.4).

---

## Sub-lane A2 - Threat-evidence backfill

Each ticket in this sub-lane closes only when **all four** runtime-check
exclusions in `scripts/check-threat-coverage-mutants.sh` pass for the
target threat ID:

- `caught >= 1` (rule out `zero_kills`).
- `needs_real_run: false` or absent (rule out `bootstrap_placeholder` and
  `bootstrap_expired`).
- `ran_at` is a real ISO-8601 2026 timestamp (rule out
  `inconsistent_bootstrap`).
- The Artifact A "Public symbol invoked in test" line names a literal
  `pub fn` (verified by grep at close) and the test imports that symbol
  by its workspace path (R2 BLOCKER 6.2).

Tickets `threat evidence item` map 1:1 to the 20 threat IDs in
`spec/security/chio-threat-model.v1.json`. The `assert_file_contains` and
`assert_threat_covered_by_corpus` test bodies on the nine weak rows are
rewritten as deny-asserting fixtures (per
`04-quality-verification-skeptic.md` line 86).

Each ticket below carries an "Artifact A" line naming the public symbol
the test invokes, drawn from `threat-evidence-backfill.md`.

| Ticket | Title | Lane | Effort | Depends-on | Artifact A (public symbol) |
|---|---|---|---|---|---|
| threat row triage | **Per-row triage** (R2 MAJOR 2.4 / R3 mitigation): tag each of the 20 rows in `audits/evidence/threats/<id>.json` with a top-level `triage_status` field in {`provable-in-release work`, `provable-only-in-trj6`, `architecture-blocked`, `IMPL-EXISTS-AND-PUBLIC`, `IMPL-EXISTS-PRIVATE`, `IMPL-PARTIAL`, `BLOCKED-BY-ARCHITECTURE`}. Wave 1 critical-path deliverable. R3 escalation fires when `IMPL-MISSING + IMPL-PARTIAL + BLOCKED-BY-ARCHITECTURE` exceeds 2. | A | S | - | n/a (sweep ticket) |
| threat evidence item | `agent_velocity_abuse`: refresh `audits/evidence/threats/agent_velocity_abuse.json` from a real cargo-mutants run against `tests/threats/agent_velocity_abuse.rs` (already real-body per audit T0.D line 45). | A | S | mutation evidence item, threat row triage | `chio_guards::agent_velocity::*` |
| threat evidence item | `audience_confusion`: refresh evidence file from real run against `tests/threats/audience_confusion.rs`. | A | S | mutation evidence item, threat row triage | `chio_kernel_core::capability_verify::verify_capability_full` (`crates/chio-kernel-core/src/capability_verify.rs:400`) |
| threat evidence item | `behavioral_sequence_attack`: refresh evidence file. Test body already exercises `chio_guards::behavioral_sequence::*` (audit T0.D line 46). | A | S | mutation evidence item, threat row triage | `chio_guards::behavioral_sequence::*` |
| threat evidence item | `capability_token_theft`: refresh evidence file. Body-hash check is Lane B receipt-v2; this row pins the nonce-replay store. | A | S | mutation evidence item, threat row triage | `chio_kernel::execution_nonce::verify_execution_nonce` (`crates/chio-kernel/src/execution_nonce.rs:364`) |
| threat evidence item | `cumulative_data_exfiltration`: refresh evidence file. Real-body per audit T0.D line 47. | A | S | mutation evidence item, threat row triage | `chio_guards::data_flow::DataFlowGuard` (`crates/chio-guards/src/data_flow.rs:38`) |
| threat evidence item | `delegation_chain_abuse`: refresh evidence file. | A | S | mutation evidence item, threat row triage | `chio_kernel_core::capability_verify::verify_capability_with_trusted_and_floor` (`crates/chio-kernel-core/src/capability_verify.rs:275`) |
| threat evidence item | `device_key_extraction` (mobile): rewrite test body from `assert_file_contains` to a deny-asserting fixture using TRJ4-033 mobile-attestation hooks; refresh evidence file. **A2.7 fails closed if `TRJ4-033` is not in its `closed` bucket** (R2 MINOR 2.7 patch). | A | M | mutation evidence item, threat row triage, TRJ4-033 | `chio_custody_hw::attestation::app_attest::verify_app_attest` (`crates/chio-custody-hw/src/attestation/app_attest.rs:55`) |
| threat evidence item | `kernel_impersonation`: rewrite test body to feed an impersonation key (kernel signs with `K_attacker`), call the verifier, assert deny. | A | M | mutation evidence item, threat row triage | `chio_kernel_core::receipts::sign_receipt` (`crates/chio-kernel-core/src/receipts.rs:38`) |
| threat evidence item | `mobile_attestation_replay` (mobile): rewrite test body to replay the same App Attest receipt twice; second call denies. **Fails closed if TRJ4-033 not closed.** | A | M | mutation evidence item, threat row triage, TRJ4-033 | `chio_custody_hw::attestation::app_attest::verify_app_attest` |
| threat evidence item | `native_channel_replay`: rewrite the 41-line meta-only body (per Quality Skeptic line 35) to instantiate a verifier, feed a replayed nonce, observe deny. | A | M | mutation evidence item, threat row triage | `chio_kernel::execution_nonce::verify_execution_nonce` (`crates/chio-kernel/src/execution_nonce.rs:364`) |
| threat evidence item | `passkey_credential_theft`: rewrite test body to instantiate the production passkey-decision verifier (Wave 1 names the exact `pub fn`) and assert deny. **If Wave 1 cannot identify a `pub fn` for this row, downgrade to `IMPL-PARTIAL` and defer to trj6.** | A | M | mutation evidence item, threat row triage | (Wave 1 confirms; candidates: `chio_credentials::registry::verify_signed_passport_verifier_policy` or `chio_credentials::oid4vp::*`) |
| threat evidence item | `pii_phi_exposure`: refresh evidence file. Real-body per audit T0.D line 48. | A | S | mutation evidence item, threat row triage | `chio_guards::response_sanitization::*` |
| threat evidence item | `play_integrity_token_replay` (mobile): rewrite test body. **Fails closed if TRJ4-033 not closed.** | A | M | mutation evidence item, threat row triage, TRJ4-033 | `chio_custody_hw::attestation::play_integrity::verify_play_integrity` (`crates/chio-custody-hw/src/attestation/play_integrity.rs:82`) |
| threat evidence item | `pq_signature_downgrade`: rewrite the 52-line `assert_file_contains` body (per Quality Skeptic line 36) to feed a downgrade-attempt token, assert deny. | A | M | mutation evidence item, threat row triage | `chio_kernel_core::capability_verify::verify_capability_full` (`crates/chio-kernel-core/src/capability_verify.rs:400`) |
| threat evidence item | `resource_exhaustion_dos`: refresh evidence file. **If Wave 1 cannot identify a `pub fn` reachable from a conformance test, downgrade to `IMPL-PARTIAL` and defer.** | A | S | mutation evidence item, threat row triage | (Wave 1 confirms; candidate: a budget-checked dispatch wrapper in `chio-kernel`) |
| threat evidence item | `ssrf_via_http_substrate`: refresh evidence file. Real-body per audit T0.D Lane-A slice line 70. | A | S | mutation evidence item, threat row triage | `chio_link::HttpEgressContract` (Wave 1 names the exact validate impl) |
| threat evidence item | `tee_quote_forgery`: rewrite test body to feed a forged quote against `validate_signed` and `verify_tenant_sig`, assert both reject. | A | M | mutation evidence item, threat row triage | `chio_tee_frame::schema::validate_signed` (`crates/chio-tee-frame/src/schema.rs:93`) and `chio_tee_frame::schema::verify_tenant_sig` (`crates/chio-tee-frame/src/schema.rs:117`) |
| threat evidence item | `tool_server_escape`: rewrite test body. **If Wave 1 confirms `IMPL-PARTIAL` post-release work-B0 `ToolServerConnection` migration, this row defers; row 16 (ssrf_via_http_substrate) is the closest companion that DOES land.** | A | M | mutation evidence item, threat row triage | (Wave 1 confirms; candidate: kernel `dispatch` entry in `chio-kernel/src/kernel/mod.rs`) |
| threat evidence item | `wasm_guard_resource_exhaustion`: **DEFER to trj6.** Per Risk Register R3 (depends on `wasm-guard SDK v4` which is out of scope for release work). The release work banner reads "<n> of 20 covered, 1 deferred to trj6 (wasm_guard_resource_exhaustion)". | A | XS (defer-only) | - | (deferred) |
| threat evidence item | `weights_hash_spoof`: refresh evidence file. Test is already real (Quality Skeptic line 37); this ticket only fixes the placeholder JSON. | A | S | mutation evidence item, threat row triage | `chio_weights::card::weights_hash_of` and `chio_weights::lineage::verify_model_card_anchor` |
| threat evidence item | Run `bash scripts/check-threat-coverage-mutants.sh` (default mode, `CI=true`) and capture exit-0 transcript to `audits/evidence/release work-A2/check-threat-coverage-mutants.log`. The transcript reflects the per-row triage (e.g. "19 of 20 covered, 1 deferred to trj6"). | A | S | threat evidence item | n/a |
| threat evidence item | **Delete the `needs_real_run` clause** from `scripts/check-threat-coverage-mutants.sh` (R2 MAJOR 2.6); not just the doc footnote. After Lane A closes, the bypass code does not exist. Update `docs/security/threat-coverage.md` line 7 footnote: remove the "9 of the 20 covered rows currently pass the gate on file-exists + no-`unimplemented!()` alone" sentence; add a "0 weak coverage rows" assertion grounded in threat evidence item transcript. | A | S | threat evidence item | n/a |
| threat evidence item | **Sub-lane A2 Evidence Gate**: every release work-A2.<n> ticket above (excluding A2.19 which is deferred to trj6) is EVIDENCE-COMPLETE. The runtime gate transcript from A2.21 is the close-bar artifact; A2.22 has deleted the bypass clause from the script. | A | S | threat row triage..A2.22 | n/a |

**A2 close-bar artifact**: 19 (or 20 minus deferred count) refreshed
evidence JSON files; 9 rewritten test-body files; one exit-0
transcript of `check-threat-coverage-mutants.sh`; the bypass clause
deleted from the script.

**A2 anti-pattern guard**: any evidence JSON keeping `caught: 0`,
`needs_real_run: true`, or `ran_at: "1970-01-01T00:00:00Z"` fails the
close bar. Any ticket whose Artifact A line cites a non-existent
`pub fn` fails the close bar (R2 BLOCKER 2.3).

---

## Sub-lane A3 - Kani harness completion

| Ticket | Title | Lane | Effort | Depends-on |
|---|---|---|---|---|
| Kani harness evidence | **Kani feasibility spike** (R2 MAJOR 3.2). Run each proposed Kani invariant (per `kani-harness-design.md`) locally with the proposed bounds and `#[kani::unwind]` values. Capture per-harness wall-clock, peak memory, and exit status to `audits/evidence/Kani harness evidence/local-bound-validation.md`. **If any harness exceeds 30 minutes locally, escalate (open R-new in the Risk Register) before Kani harness evidence starts.** | A | S | - |
| Kani harness evidence | Author `crates/chio-attest-verify/src/kani_public_harnesses.rs` modeled on `crates/chio-kernel-core/src/kani_public_harnesses.rs`. >= 4 `#[kani::proof]` functions covering: `expect_report_data` binding determinism; `<NitroVerifier as QuoteVerifier>::verify_quote` fail-closed on report-data mismatch; `<SevSnpVerifier as QuoteVerifier>::verify_quote` fail-closed on TCB rejection; `<TdxDcapVerifier as QuoteVerifier>::verify_quote` fail-closed on algorithm-tag mismatch. Production entries verified to exist as `pub fn` (`expect_report_data` at `quote.rs:163`) or `pub` impl methods (`NitroVerifier`, `SevSnpVerifier`, `TdxDcapVerifier` impls of `QuoteVerifier`). See `kani-harness-design.md` Section (1) for full bounds and `#[kani::unwind(8)]` per harness. | A | M | Kani harness evidence |
| Kani harness evidence | Author `crates/chio-anchor/src/kani_public_harnesses.rs`. >= 4 `#[kani::proof]` functions covering: `verify_anchor_batch` correctness on small symbolic Merkle tree; `verify_anchor_batch` mis-ordered sibling rejection; `evaluate_witness_policy` fail-closed when `require_public_witness=true` with no witness; `batch_body_hash` determinism. Production entries: `chio_anchor::batch::verify_anchor_batch` (`batch.rs:208`), `chio_anchor::witness::evaluate_witness_policy` (`witness.rs:312`), `chio_anchor::witness::batch_body_hash` (`witness.rs:193`) -- all `pub fn` verified. `#[kani::unwind(4)]` for sibling-loop. **Lane B coordination**: if Lane B revises the `verify_anchor_batch` signature during release work-B3, this harness is updated within the same PR or one wave behind, never more than one wave behind. | A | L | Kani harness evidence |
| Kani harness evidence | Author `crates/chio-weights/src/kani_public_harnesses.rs`. >= 4 `#[kani::proof]` functions covering: `weights_hash_of` determinism; `anchor_projection_bytes` purity; `verify_model_card_anchor` fail-closed on lineage-mismatch; `verify_model_card_bundle` fail-closed on bundle-mismatch (with admit-only `AttestVerifier` stub so rejection comes from bundle comparison alone). Production entries: `chio_weights::card::weights_hash_of` (`card.rs:274`), `chio_weights::lineage::anchor_projection_bytes` (`lineage.rs:120`), `chio_weights::lineage::verify_model_card_anchor` (`lineage.rs:217`), `chio_weights::bundle::verify_model_card_bundle` (`bundle.rs:71`) -- all `pub fn` verified. | A | M | Kani harness evidence |
| Kani harness evidence | Update `formal/rust-verification/kani-public-harnesses.toml` (R2 MINOR 3.4 corrected file path; existence verified). Register the three new harness modules under the multi-crate schema established by Kani multi-crate manifesta. Mirror in `formal/proof-manifest.toml` IF that file references the relevant crate; otherwise the kani-public-harnesses entry is the source of truth. | A | S | Kani harness evidence, Kani harness evidence, Kani harness evidence, Kani multi-crate manifesta |
| Kani multi-crate manifesta | **Multi-crate Kani manifest schema change** (R2 BLOCKER 3.3). Extend `formal/rust-verification/kani-public-harnesses.toml` from single-crate to multi-crate. Default approach (B): change top-level `crate = "chio-kernel-core"` to `crates = [...]`; reshape `lanes.pr.harnesses` and `lanes.nightly_only.harnesses` as records of `{ crate = "<name>", harness = "<fn>" }`. Update the Python helper in `nightly.yml` lines 102-118 to emit `(crate, harness)` pairs. | A | M | Kani harness evidence, Kani harness evidence, Kani harness evidence |
| Kani multi-crate manifestb | **Workflow rewrite** (R2 BLOCKER 3.3). Update `.github/workflows/nightly.yml` lines 102-128 and `.github/workflows/ci.yml` `kani-public-pr` job (lines 478-590 per R2 review) so the shell loop iterates `(crate, harness)` pairs and runs `cargo kani -p "${crate}" --lib --harness "${harness}" --default-unwind 8 --no-unwinding-checks`. Capture two consecutive green multi-crate runs to `audits/evidence/release work-A3/nightly-runs.md`. | A | M | Kani multi-crate manifesta |
| Kani harness evidence | **Promote multi-crate Kani lane from advisory to required** (R2 MINOR 10.3). After two consecutive green nightly runs, remove `continue-on-error` (where present) and add the multi-crate Kani job to GitHub branch-protection required-checks for `main`. Capture branch-protection screenshot to `audits/evidence/Kani harness evidence/branch-protection.png`. Without this, a regression in `chio-attest-verify` Kani would not block a PR; this is banner-vs-reality drift in real time. | A | S | Kani multi-crate manifestb |
| release work-A3.E | **Sub-lane A3 Evidence Gate**: three `kani_public_harnesses.rs` files exist; all `#[kani::proof]` functions target real production entries (verified by grep at close); two green nightly runs; the multi-crate Kani lane is in the required-checks list for `main`. | A | S | Kani harness evidence..A3.6 |

**A3 close-bar artifact**: three `kani_public_harnesses.rs` files; two
green nightly multi-crate Kani runs; multi-crate manifest landed;
required-checks promotion landed.

**A3 anti-pattern guard**: a harness that imports `kani::` but contains
zero `#[kani::proof]` attributes, or whose proofs go through under
`kani::assume(false)`, fails the close bar. A harness whose
`#[kani::proof]` body calls a function name that does not exist as a
`pub fn` (or a `pub` trait-impl method on a publicly constructible
type) in the workspace fails the close bar (R2 BLOCKER 3.1).

---

## Sub-lane A4 - TLA+ rewrites

| Ticket | Title | Lane | Effort | Depends-on |
|---|---|---|---|---|
| release work-A4.1 | Split `Allow` action in `formal/tla/RevocationPropagation.tla` into `LogReceipt` and `PublishAllow`. Introduce `ReceiptBeforeAllow` invariant that requires a `LogReceipt` to precede a corresponding `PublishAllow` for any `(proc, cap, t)` tuple. (Carry-forward of TRJ4-016.) **R2 MINOR 6.5 addition**: acceptance includes "remove the `ReceiptBeforeAllow` invariant from the cfg and confirm apalache produces a counterexample trace within a length-6 budget; capture trace to `audits/evidence/release work-A4.1/counterexample-on-revert.tla`". | A | M | - |
| release work-A4.2 | Rewrite `RevocationCutCompleteness` as a bounded transitive-closure unrolling at depth >= 3 over the propagation graph; export the property name from `RevocationPropagation.tla`. (Carry-forward of TRJ4-015.) **R2 MAJOR 4.2 addition**: include a "feasibility spike" sub-task: write a 20-line TLA fragment expressing the bounded transitive-closure operator and run Apalache against it standalone. Capture exit status and link in `audits/evidence/release work-A4.2/feasibility-spike.md`. **If Apalache 0.50.x does not handle the encoding, escalate**; the only realistic fallback is to inline-unroll the closure into hand-written `Reachable_step1`, `Reachable_step2`, `Reachable_step3` chain. | A | M | - |
| release work-A4.3 | Bump `EpochMax`-equivalent (`DEPTH_MAX`) from 4 to 6 in `MCRevocationPropagation.cfg` and `MCRevocationPropagationTemporal.cfg`. (Carry-forward of TRJ4-017.) **R2 MINOR 4.3 addition**: record the apalache run wall-clock BEFORE and AFTER the bump in `audits/evidence/release work-A4.3/length-budget.md`. If post-bump exceeds 25 minutes (within 5 minutes of timeout), follow-up either sets `DEPTH_MAX=5` or extends the workflow timeout. | A | S | release work-A4.1, release work-A4.2 |
| release work-A4.4 | Fix the `RevocationEventuallySeen` apalache 0.50.1 temporal-encoding bug. Promote `apalache-temporal.yml` from advisory to required: remove `continue-on-error: true`; add the workflow to required-checks for `main`. (Carry-forward of TRJ4-018.) **R2 OBSERVATION 4.4 addition**: capture `audits/evidence/release work-A4.4/branch-protection.png` (screenshot of GitHub branch-protection settings showing `apalache-temporal` in the required list) so future reviewers can verify without PR archaeology. | A | M | release work-A4.3 |
| release work-A4.5 | Cascade theorem-inventory cross-reference: every theorem whose `mapsTo` lists a property whose name changed in release work-A4.1 or whose proof shape changed in release work-A4.2 is updated in `formal/theorem-inventory.json`. Risk per `audits/T0.B-substrate-hardening.md` line 18. **R2 OBSERVATION 4.5 addition**: review `theorem-inventory.json` AND the `PublishAllow` definition for evidence of unfolding shortcuts (a `PublishAllow(a,c,t) == LogReceipt(a,c,t) /\ ...` definition would re-tautologize `ReceiptBeforeAllow`). | A | S | release work-A4.1, release work-A4.2 |
| release work-A4.E | **Sub-lane A4 Evidence Gate**: rewritten `RevocationPropagation.tla` with `LogReceipt`, `PublishAllow`, `ReceiptBeforeAllow`, `RevocationCutCompleteness` exported; updated cfg files; `apalache-temporal.yml` in required-checks; two green temporal-lane run URLs; counterexample-on-revert trace captured; branch-protection screenshot captured. | A | S | release work-A4.1..A4.5 |

**A4 close-bar artifact**: rewritten `RevocationPropagation.tla`; updated
cfg files; `apalache-temporal.yml` in required-checks; two green
temporal-lane run URLs; counterexample-on-revert trace; branch-protection
screenshot.

**A4 anti-pattern guard**: an `apalache-temporal.yml` job that still
carries `continue-on-error: true` after release work-A4.4 lands fails the close
bar.

---

## Sub-lane A5 - Lean4 negotiation_safety against executable model

| Ticket | Title | Lane | Effort | Depends-on |
|---|---|---|---|---|
| release work-A5.1 | Add a `lean.yml` (or extend the existing chosen lane) so the Lean toolchain runs in CI. Resolves the disclaimer at `formal/lean4/Chio/Chio/Proofs/HandshakeNegotiation.lean:10-12`. **Re-scoped from M to L** (R2 MINOR 5.3): pin a specific Lean 4 toolchain version in `formal/lean4/lean-toolchain` (or equivalent); document elaboration time + CI cache strategy (cache key = toolchain-pin + source-tree hash). | A | L | - |
| release work-A5.2 | Define `verify_capability_with_negotiated_floor_model` (executable-model term) in `formal/lean4/Chio/Chio/Proofs/HandshakeNegotiation.lean`. Signature mirrors `crates/chio-kernel-core/src/capability_verify.rs:226-255` actual signature (R2 BLOCKER 5.1: `CapabilityCryptoFloor` not `CryptoFloor`; `&CapabilityNegotiation` not flat `Schema`; `Result<VerifiedCapability, CapabilityError>` not `Result<(), _>`). The Lean model abstracts `crypto_floor` and the three downstream sub-decisions to Boolean witnesses. See `lean4-fix.md` for the target signature. | A | M | - |
| release work-A5.3 | Re-state and re-prove **three theorems** (R2 MAJOR 5.2: not one): `negotiation_safety_admit_implies_le`, `negotiation_safety_reject_implies_not_le_or_other_failure`, and `negotiation_safety_schema_first` (the ordering theorem). The proof bodies must use `cases`, `induction`, `split_ifs`, or `intro`-with-case-work, not a one-line `rfl` or `decide` against the executable-model term's own definition (R2 MINOR 7.2). The proof must not be `rfl` against `schemaCeilingCheck`'s own definition. **R2 MAJOR 5.2 addition**: after merge, replace the executable-model term body with the schemaCeilingCheck-only one-liner and confirm Lean elaboration FAILS for at least theorem 2 and theorem 3; capture failing elaboration to `audits/evidence/release work-A5.3/elaboration-fails-on-revert.txt`. | A | M | release work-A5.1, release work-A5.2 |
| release work-A5.4 | Update `formal/theorem-inventory.json` rows for `handshake.negotiation_safety`, `handshake.negotiation_safety_reject_implies_not_le_or_other_failure`, and `handshake.negotiation_safety_schema_first` from `assumed` to `proven` (one row per theorem). Add `formal/MAPPING.md` cross-reference between the new Lean model term and the Rust function. The mapping notes `crypto_floor: CapabilityCryptoFloor` and `peer: &CapabilityNegotiation` are abstracted to Boolean witnesses (`floorOk`, `peerMax`) at the refinement level. | A | S | release work-A5.3 |
| release work-A5.E | **Sub-lane A5 Evidence Gate**: rewritten `HandshakeNegotiation.lean`; green Lean CI run; updated `theorem-inventory.json` and `MAPPING.md`; revert-and-rerun proof captured. | A | S | release work-A5.1..A5.4 |

**A5 close-bar artifact**: rewritten `HandshakeNegotiation.lean`;
green Lean CI run; updated `theorem-inventory.json` and
`MAPPING.md`; elaboration-fails-on-revert capture.

**A5 anti-pattern guard**: a proof body that is `rfl` against the same
function definition fails the close bar. A proof body without `cases`,
`induction`, `split_ifs`, or `intro`-with-case-work fails the close
bar.

---

## On the dropped TRJ4-019 (R1 MAJOR section A.4)

The trj4 wave-plan ticket TRJ4-019 (`chio-equivalence-tests` proptest
hosted-vs-portable equivalence: 10k cases per PR + 1M nightly, zero
divergence) was originally listed under master `EXECUTION-BOARD.md` as
absorbed by `release work-A5`. Lane A subsequently re-purposed `release work-A5` for
the Lean4 `negotiation_safety` re-proof, leaving TRJ4-019 without a
release work home.

**Decision** (Wave 3 fix): defer TRJ4-019 to **trj6**. Rationale:

- Lane A's 8-week horizon is already loaded with five sub-lanes
  (mutation uplift, threat backfill, Kani harnesses, TLA+ rewrites,
  Lean refinement) and 50+ tickets. Adding a sixth sub-lane for
  proptest equivalence-tests at 10k/PR + 1M/nightly is real
  engineering work (CI matrix, infrastructure spend, run-time budget)
  and risks plateau on the higher-priority Lane A work.
- The hosted-vs-portable equivalence claim is currently informational;
  no synthesis ship-bar depends on it. Deferral does not change any
  ship-bar.
- SCOPE-LOCK records the deferral with rationale; the trj6 lane plan
  picks up TRJ4-019 as a first-week ticket.

This decision is captured in:

- `SCOPE-LOCK.md` (TRJ4-019 row removed from Lane A; added to a new
  "Deferred to trj6 with rationale" subsection).
- `EXECUTION-BOARD.md` (TRJ4-019 absorption row removed from Lane A;
  the absorbed-by column reads `(trj6, deferred per Wave 3 review)`).
- `KICKOFF-CHECKLIST.md` (TRJ4-019 absorbed checkbox dropped; the
  deferral note replaces it).

---

## Ticket count summary

| Sub-lane | Count |
|---|---|
| A1 mutation uplift | 13 (incl. A1.0, A1.2a, A1.2b, A1.E) |
| A2 threat-evidence backfill | 24 (incl. A2.0, A2.E; A2.19 deferred) |
| A3 Kani harness completion | 9 (incl. A3.0, A3.5a, A3.5b, A3.6, A3.E) |
| A4 TLA+ rewrites | 6 (incl. A4.E) |
| A5 Lean4 negotiation_safety | 5 (incl. A5.E) |
| **Total** | **57** |

The total is heavier than the prior 46 because the Wave 3 review added
sub-tickets (R2 BLOCKER and MAJOR fixes: per-row triage, baseline-then-
publish split, Kani feasibility spike, multi-crate manifest, advisory-
to-required promotion, and `.E` Evidence Gate ticket per sub-lane).
The over-count is concentrated in A2 (one ticket per threat ID + a
sweep ticket + a script-deletion ticket + an `.E` ticket) and in A3
(workflow rewrite split into A3.5a / A3.5b / A3.6).

The trj4 EXECUTION-BOARD pattern follows the same per-row granularity
(see TRJ4-041..047, one ticket per stub).

If the parent agent prefers a tighter ticket count, A2 can be collapsed
to four tickets (refresh JSON for the rows already real; rewrite +
refresh the rows needing rewrites; sweep ticket; script-deletion
ticket); that lands at **34 total** including the per-sub-lane `.E`
tickets. The current granular form is preferred because it keeps the
per-row Artifact A check explicit (R2 BLOCKER 6.2).
