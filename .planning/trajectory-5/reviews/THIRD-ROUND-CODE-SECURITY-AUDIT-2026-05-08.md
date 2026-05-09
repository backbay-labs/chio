# Trajectory 5 Third-Round Code And Security Audit

Date: 2026-05-08
Repository: `bb-connor/arc`
Base: `main@708c7bb33df43594f5e76542b05fca7a56d9689e`
Scope: refreshed open PRs #601 through #626 after the R2 cleanup wave.

## Method

- Refreshed all PR refs with `git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*' --prune`.
- Launched seven read-only R3 reviewers covering security propagation, Lane B build/verifier behavior, Lane A evidence integrity, Lane C release/demo truth, GitHub graph/comments/CI, hygiene/slop, and targeted regression checks.
- Ran local spot checks on disputed findings before recording them here.
- No PR branch source was edited by this audit. This file is the only new artifact from the R3 review pass.

## Executive Verdict

R2 fixed several of the worst security-propagation defects. The stale async bridge, stale DSSE receipt-wrapper hash, #615 multi-subject verifier acceptance, and #611 post-dispatch freshness race appear fixed in the refreshed refs by source inspection. Some targeted commands also passed on archived PR refs.

The PR set is still not release-clean. The remaining blockers are mostly graph/evidence/release-truth failures:

- All 26 PRs are still `mergeStateStatus=UNSTABLE` with failed checks.
- All 26 PRs still have empty labels.
- The review graph still has unresolved Medium/actionable threads.
- Pairwise merge conflicts increased to 57 of 325.
- Aggregate truth ownership is still not actually consolidated.
- #619 still commits PII-bearing cargo-mutants artifacts.
- #618 still has stale planning docs contradicting its corrected release notes.

## R2 Claims That Now Validate

### Security Propagation

- #612 now carries the #606 current-thread Tokio fail-closed bridge in `crates/chio-kernel/src/kernel/mod.rs`, `crates/chio-a2a-edge/src/lib.rs`, and `crates/chio-acp-edge/src/lib.rs`.
- #611 now handles both post-dispatch freshness-drift sites:
  - `record_chio_receipt_with_federation` degrades post-dispatch drift instead of dropping the already-executed receipt.
  - `apply_federation_cosign` treats drift as logged cosign omission and allows bare receipt persistence.
- #614, #615, and #617 now hash `receipt.body()` for DSSE subjects.
- #615 enforces `subject.len() == 1` in both the DSSE verifier path and the higher bilateral verifier path.

### Lane B Build/Verifier

- #615 `cargo check -p bilateral-invocation` passed in an archived #615 checkout.
- #615 `cargo run -p bilateral-invocation` passed and printed `Partial local verifier accepted envelope`.
- #615 `cargo test -p chio-conformance --test c2_bilateral_invocation_partial_verifier` passed 18/18 in an archived #615 checkout.
- #606 `cargo check --manifest-path crates/chio-conformance/verdict_matrix/Cargo.toml` passed after adding `async-trait`.
- #612 `cargo test -p chio-conformance --test b1_capability_v2_single_entry_no_bypass` passed 2/2.
- #611 `cargo test -p chio-conformance --test b2_receipt_v2_failclosed_pre_dispatch` passed 3/3.

### Lane C Main Release Surface

- #618 `releases.toml` must use `[v0_1_0_bounded_chiodome].release_status`, not trajectory-scoped release status keys.
- #618 release notes now include a stale-packaging prerequisite block and list open PRs #601 through #626.
- #614 full-mode KB MCP assertion now queries the SQLite receipt DB with `chio --receipt-db ... receipt list`, not `${CHIO_RECEIPT_DIR}` globs.
- #620 `scripts/check-bounded-ship-bar.sh` is strict by default: PARTIAL rows count as release-gate failures unless `--diagnostic` is passed.

### Lane A Evidence

- The `target_met` posture is now correct in the inspected evidence: partial `chio-credentials`, `chio-policy`, `chio-kernel-core`, `chio-attest-verify`, `chio-guards`, and `chio-anchor` do not claim target met. `chio-weights` remains `target_met=true` on a full 66/66 run.
- #625 now adds a `PENDING-RERUN` artifact instead of presenting the 97.9 percent touched-line result as a crate-level mutation baseline.
- #603 `summary.sh` now uses a strict durable-annotation whitelist rather than preserving arbitrary release-truth keys.
- #603 `aggregate.sh` now propagates partial/subset/below-target labels from summary JSON state.

## Validated P0 Findings

### review item - The GitHub graph is still not release-clean

- PRs: #601 through #626
- Evidence:
  - All 26 PRs are `OPEN`, non-draft, and `mergeable=MERGEABLE`.
  - Every PR is still `mergeStateStatus=UNSTABLE`.
  - Every PR has failed checks. The graph reviewer counted 969 bad check contexts across the set.
  - Every PR has empty labels.
  - There are 185 unresolved review threads across the set.
  - Pairwise merge simulation found 57 conflicting pairs out of 325.
  - Ordered aggregate merge #601 through #626 now blocks at #607 on `.kani/harnesses.toml` after #605.
- Impact: the PR set cannot be treated as a clean merge train or release train.
- Required fix: sequence and rebase the train. Do not report "MERGEABLE" without also reporting `UNSTABLE`, failed checks, unresolved threads, and pairwise conflicts.

### review item - #619 still commits PII-bearing cargo-mutants artifacts

- PR: #619
- Files:
  - `audits/evidence/mutants/chio-credentials/mutants.out/lock.json`
  - `audits/evidence/mutants/chio-credentials/mutants.out/outcomes.json`
- Evidence:
  - `lock.json` contains `hostname = Connors-MacBook-Pro.local` and `username = connor`.
  - `outcomes.json` contains repeated user-local Rust toolchain paths.
- Impact: R2 claimed PII artifacts were removed, but #619 still leaks workstation identity and local absolute paths.
- Required fix: remove or sanitize committed `lock.json` and `outcomes.json` artifacts from #619. Do not rely only on `.gitignore` for future runs.

### review item - Mutation aggregate ownership is still not consolidated

- PRs: #603, #619, #621, #622, #623, #624, #626
- Files:
  - `audits/mutation/2026-05-08-per-crate-baseline.md`
  - `.planning/trajectory-5/baselines/BAR-1-MUTATION.md`
  - `audits/mutation/aggregate.sh`
  - `audits/mutation/summary.sh`
  - `releases.toml`
- Evidence:
  - #603 says it is the single aggregate owner.
  - Worker refs #619, #621, #622, #623, #624, and #626 still modify aggregate or planning truth files.
  - Several worker PRs still carry sibling crate evidence:
    - #619: `chio-attest-verify` plus stale `chio-credentials`.
    - #622: `chio-anchor`, `chio-attest-verify`, `chio-credentials`.
    - #623: `chio-policy`, `chio-attest-verify`, `chio-credentials`.
    - #626: `chio-kernel-core`, `chio-policy`, `chio-attest-verify`, `chio-credentials`.
- Impact: merge order can still overwrite release truth or aggregate rows with stale coordinated state.
- Required fix: make worker PRs own only their crate evidence. Keep aggregate docs/scripts in #603 or a final integrator PR generated from merged main.

### review item - #618 planning docs contradict the corrected release package

- PR: #618
- Files:
  - `.planning/trajectory-5/READINESS.md`
  - `.planning/trajectory-5/KICKOFF-CHECKLIST.md`
- Evidence:
  - `READINESS.md` still says C2 MET, C4+C5 MET, C6 `ready_for_tag`, Bar 2 MET, Bar 3 MET, and only seventeen open PRs #601 through #617.
  - `KICKOFF-CHECKLIST.md` still says Lane C2 "Section 7 17-step verifier landed", C4+C5 "zk feature landed", all seventeen PRs #601 through #617, and `ready_for_tag` tag flow.
- Impact: #618 release notes and `releases.toml` now say `pending_upstream_merges`, but adjacent planning docs still publish the old tag-ready story. This is release-truth contradiction.
- Required fix: update or remove stale planning docs from #618 so every release-facing artifact says pending upstream merges, #601 through #626, `bbs-stub`, C2 partial, C3 partial, and no ready-for-tag state.

## Validated P1 Findings

### review item - Four Cursor Medium threads remain unresolved

- PRs: #603, #607, #613
- Evidence examples:
  - #603 `audits/mutation/aggregate.sh:88`: summary JSON glob selects wrong file in direct layout.
  - #603 `audits/mutation/aggregate.sh:108`: PARTIAL case ignores `examine_scope` despite reading it.
  - #607 `scripts/tests/run-kani-manifest-empty-match.test.sh:93`: test expects wrong exit code for lane validation.
  - #613 `.kani/harnesses.toml:77`: chio-anchor manifest entries missing required features field.
- Impact: the cleanup claim that Cursor Medium threads were addressed is incomplete.
- Required fix: resolve or explicitly defer these in the PRs with concrete rationale.

### review item - #615 unit tests still route a positive verifier test through `DefaultRoutine`

- PR: #615
- File: `crates/chio-federation/src/bilateral_verifier.rs`
- Evidence:
  - The helper at lines around 1027 to 1052 constructs `VerifierConfig` with `UnknownActionClassPolicy::DefaultRoutine`.
  - `happy_path_passes_partial_local_verifier` uses that helper without registering the tool/action class.
  - The conformance test file is fixed and uses `Reject`, but the unit-test helper is not.
- Impact: part of the positive verifier test suite still does not prove the strict fail-closed default.
- Required fix: register the tool action class and run positive unit tests under `Reject`. Keep `DefaultRoutine` only in an explicitly named legacy fallback test.

### review item - #625 file evidence is honest, but PR metadata still overclaims

- PR: #625
- Evidence:
  - File artifact `2026-05-08-post-gap-closure.json` says `result_label = PENDING-RERUN` and `target_met = null`.
  - README says the 97.9 percent result is touched-line-only and not crate-level.
  - Live PR title remains "close mutation gap", and the first summary line says it closes the `chio-attest-verify` mutation gap.
- Impact: readers can still infer closure from GitHub metadata before seeing the caveats.
- Required fix: rename the PR and first summary line to "add gap-closure tests; full mutation rerun pending".

### review item - #614 README still documents the old KB receipt assertion target

- PR: #614
- File: `examples/chiodome-bilateral/README.md`
- Evidence: README says `--full` exits if `${CHIO_RECEIPT_DIR}` is empty, while the script now checks `CHIO_RECEIPT_DB` via `chio receipt list`.
- Impact: operator docs are stale even though the script was fixed.
- Required fix: update README to describe the SQLite receipt DB assertion.

### review item - #617 has a stale selective-disclosure filename comment

- PR: #617
- File: `crates/chio-conformance/Cargo.toml`
- Evidence: comment still says `c5_selective_disclosure_zk.rs`, while the file is now `c5_selective_disclosure_stub.rs`.
- Impact: minor but direct residue from the zk to bbs-stub rename.
- Required fix: update the comment.

### review item - #620 strict ship-bar mode lacks a dedicated behavioral regression test

- PR: #620
- File: `scripts/check-bounded-ship-bar.sh`
- Evidence: source inspection shows strict default behavior, and `bash -n` passes, but no dedicated `scripts/tests/*release work*` test exists for release mode versus `--diagnostic`.
- Impact: the exact paper-gate bug can regress without a focused shell test.
- Required fix: add a synthetic test that creates partial evidence, asserts default exit 1, then asserts `--diagnostic` exit 0.

### review item - #613 Kani manifest still lacks required feature annotation

- PR: #613
- File: `.kani/harnesses.toml`
- Evidence: unresolved Cursor Medium says chio-anchor manifest entries are missing the required features field. This matters because `kani = ["web3"]` was added, but the manifest must exercise the right feature set.
- Impact: cargo-kani can still run a configuration that does not match the intended crate body.
- Required fix: add required feature metadata to chio-anchor manifest entries and verify the Kani runner consumes it.

### review item - #605/#613 Kani evidence is still incomplete

- PRs: #605, #613
- Evidence:
  - #605 has source plus manifest entries but no committed Kani run transcript.
  - #613 marks `public_ensure_anchor_operation_allowed_fail_closed` as nightly-only, not PR-tier verified.
- Impact: atomicity improved, but proof evidence remains partial.
- Required fix: either commit run evidence for PR-tier harnesses or label the proof surface as partial/nightly-only in ship-bar truth.

### review item - TLA negative tests remain local-only and leak absolute paths

- PR: #602
- Files:
  - `formal/apalache/_negative_tests/README.md`
  - `.planning/trajectory-5/lane-a-floor/evidence/*.log`
- Evidence:
  - README says negative tests are not run by CI.
  - committed logs include local worktree paths.
- Impact: non-tautology evidence is manual and logs leak local machine paths.
- Required fix: add expected-failure CI or downgrade the gate; scrub absolute paths from committed logs.

### review item - Threat evidence remains partial and partial rows are not mutation-gated

- PR: #616
- Files:
  - `docs/security/threat-coverage.md`
  - `scripts/check-threat-coverage-mutants.sh`
- Evidence:
  - Coverage is 18 covered, 2 partial.
  - Partial rows `pq_signature_downgrade` and `tool_server_escape` are explicitly deferred.
  - mutation gate skips non-covered rows.
- Impact: honest but still partial. It should not be presented as full threat closure.
- Required fix: keep ship-bar and release language partial until trj6 deferred vectors are implemented or separately gated.

### review item - Runtime/user-facing output still contains audit provenance

- PR: #617
- File: `crates/chio-cli/src/cli/trust_commands.rs`
- Evidence: `honesty_note` JSON includes `P0-008 fix (audit 2026-05-08)`.
- Impact: user-facing CLI output encodes audit-ticket provenance instead of product rationale.
- Required fix: keep the warning content, remove audit IDs and date/provenance.

### review item - Product code and scripts still contain AI/process metadata

- PRs: #603, #606, #610, #611, #612, #617 and others
- Evidence examples:
  - `codex[bot]`, `cursor[bot]`, `Round-3 codex`, `PR #...`, `P0-004 fix`, and `audit 2026-05-08` appear in product code comments, scripts, and config.
  - `scripts/triage-threat-rows.sh` prints an "R3 escalation criterion" message.
  - `scripts/check-tool-server-async.sh` prints `release work/B0 gate violation`.
- Impact: this violates the stated P1 rule against AI slop and planning/ticket metadata.
- Required fix: replace provenance comments with stable product rationale and remove audit/PR/ticket strings from runtime/user-facing output.

## Notable False Positives Or Narrowed Findings

- #615 no longer has the old public example/package "Section 7 17-step verifier" overclaim in the refreshed ref. The remaining 17-step hits are historical/self-critical notes or research/spec wording, plus stale #618 planning docs.
- #618 `releases.toml` and release notes are materially improved. The remaining #618 issue is stale adjacent planning docs, not the main release notes block.
- #620 source implements strict default behavior. The remaining issue is missing behavioral test coverage.
- Base-checkout targeted tests that reported `bilateral-invocation` and `scripts/check-bounded-ship-bar.sh` absent were run against `main`, not the PR refs. They are not evidence that #615 or #620 lack those files.

## Required Next Actions

1. Fix #619 PII artifacts immediately.
2. Finish aggregate ownership cleanup. Worker PRs should not carry aggregate truth or sibling crate evidence.
3. Update #618 planning docs to match `pending_upstream_merges`.
4. Resolve remaining Cursor Medium threads.
5. Fix #615 unit-test helper to use `Reject` on positive tests.
6. Add #620 strict/diagnostic behavioral test.
7. Re-run graph merge simulation after rebasing #605/#607/#613 and mutation/release PRs.
8. Do not tag or present Trajectory 5 as closed until all 26 PRs are checks-clean or explicitly classified, review-clean, and merged through an actual conflict-free train.
