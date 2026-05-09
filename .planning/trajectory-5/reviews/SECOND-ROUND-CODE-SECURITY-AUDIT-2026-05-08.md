# Trajectory 5 Second-Round Code And Security Audit

Date: 2026-05-08
Repository: `bb-connor/arc`
Base: `main@708c7bb33df43594f5e76542b05fca7a56d9689e`
Scope: open PRs #601 through #626, executor closure claims, and cross-PR merge/release state.

## Severity Rubric

- P0: security bug, build blocker on a claimed ship surface, significant design or structure issue, bad Trajectory 5 idea that should be replaced, evidence design that can publish false release truth, or stacked-PR hazard that can undo a foundational fix.
- P1: missing or low verification coverage, stale or weak evidence, unresolved Medium/P1 review state, committed AI/process metadata, release-honesty drift that is not itself a direct build/security blocker, or hygiene issue that can mislead future reviewers.
- P2: local test weakness, naming drift, or cleanup issue that should be fixed but does not currently block the release train by itself.

## Review Method

- Wave 1: six read-only reviewers split by Lane A evidence/formal work, Lane B kernel/security work, Lane C demo/release work, cross-PR mergeability, adversarial crypto/security, and comment/hygiene state.
- Wave 2: four read-only validators cross-checked the high-severity findings for async/kernel behavior, DSSE/release behavior, Lane A evidence integrity, and GitHub graph state.
- Local commands used live `origin/pr/<number>` refs after fetching PR heads. GitHub state was queried with `/opt/homebrew/bin/gh` where needed.
- No PR branch code was edited by this audit pass.

## Executive Verdict

The executor summary is materially false as a ship statement.

All 26 PRs are individually content-mergeable against `main`, but every PR is `mergeStateStatus=UNSTABLE`, every PR has failing checks, every PR has an empty label set, the review graph has unresolved non-outdated threads, and the 26-PR set is not mergeable as a graph. More importantly, several dependent PRs still carry stale copies of security-sensitive files that undo earlier fixes when merged in the wrong order.

The immediate release posture should be: do not merge #618, do not tag, and do not treat Bar 1, Bar 2, or Bar 3 as closed. Land foundational fixes first (#606 async shape and #610 DSSE shape), then rebase dependent branches, then regenerate aggregate mutation evidence and release packaging from merged `main`.

## Validated P0 Findings

### review item - The 26-PR set is not a clean merge train

- PRs: #601 through #626
- Evidence: GitHub reports all 26 as `mergeable=MERGEABLE`, but all 26 as `mergeStateStatus=UNSTABLE`. All 26 have failing checks. Pairwise merge simulation found 53 conflicting pairs out of 325. Ordered virtual merge succeeds through #610 and fails at #611 on `crates/chio-kernel/src/kernel/mod.rs`.
- Review state: 160 unresolved review threads, 109 non-outdated unresolved threads, and 6 unresolved Cursor Medium comments across #603, #606, #611, #613, and #614. No unresolved Cursor High was found.
- Label state: all 26 PRs have empty labels, contradicting the "honest ship-bar labels" claim.
- Impact: "all MERGEABLE" is only text-conflict status against current `main`; it is not a safe merge or ship signal.
- Required fix: run a sequenced merge train. Merge foundational PRs first, rebase dependents, resolve all Medium/P1 actionable threads, and rerun checks.

### review item - #612 reintroduces the current-thread Tokio deadlock that #606 fixed

- PRs: #606, #612
- Files: `crates/chio-kernel/src/kernel/mod.rs`, `crates/chio-a2a-edge/src/lib.rs`, `crates/chio-acp-edge/src/lib.rs`
- Evidence: #606 fails closed on current-thread Tokio by returning `SyncBridgeIncompatibleWithCurrentThreadRuntime`. #612 still routes current-thread and no-runtime cases through `_ => futures::executor::block_on(future)` in the kernel helper and edge shims.
- Live paths: #612 calls the stale bridge from nested flow dispatch and `dispatch_tool_call_with_cost_blocking`.
- Impact: async tool-server futures that await Tokio timers or I/O can hang after #612 lands, even though #606 closed the issue.
- Required fix: merge #606 first, rebase #612, and remove stale B0 async bridge copies from #612. Current-thread Tokio must fail closed or use the async API directly.

### review item - #611 still has a post-dispatch receipt freshness TOCTOU

- PR: #611
- Files: `crates/chio-kernel/src/kernel/mod.rs`, `crates/chio-kernel/src/kernel/responses.rs`
- Evidence: #611 adds a useful pre-dispatch receipt negotiation gate, but `record_chio_receipt_with_federation` recomputes `current_unix_timestamp()` and calls `kernel_receipt_version_for_remote` again after tool execution and before persistence.
- Impact: a peer can be fresh at admission, expire while a long-running tool executes, then fail receipt persistence after side effects already happened. That can produce a state-changing tool call with no persisted receipt.
- Required fix: carry the admission-time negotiated version/freshness decision into receipt persistence, or make the post-dispatch path unable to fail the same request for freshness drift.

### review item - DSSE subject binding is fixed in #610 but stale in #614/#615/#617

- PRs: #610, #614, #615, #617
- File: `crates/chio-federation/src/bilateral_dsse.rs`
- Evidence: #610 hashes `receipt.body()` for the DSSE subject digest and has a regression test for body-not-wrapper binding. #614, #615, and #617 still hash `canonical_json_bytes(receipt)`, the full signed wrapper.
- Impact: dependent branches can undo the DSSE body-binding fix and break verifier/store interop.
- Required fix: land #610 first. Rebase #614/#615/#617 and keep the body digest contract in all dependent branches and fixtures.

### review item - #615 accepts extra DSSE subjects while validating only `subject[0]`

- PR: #615
- File: `crates/chio-federation/src/bilateral_verifier.rs`
- Evidence: verifier logic rejects an empty subject array, then validates `statement.subject[0]` without rejecting additional subjects.
- Impact: downstream consumers can treat a multi-subject Statement as fully verified when only the first subject was checked.
- Required fix: require `statement.subject.len() == 1` for the bilateral profile and add a negative two-subject test.

### review item - #615 workspace example is not buildable

- PR: #615
- Files: `examples/bilateral-invocation/src/main.rs`, `crates/chio-federation/src/bilateral_verifier.rs`, root `Cargo.toml`
- Evidence: `VerifierConfig` requires `unknown_action_class_policy`; the workspace example constructs `VerifierConfig` without that field. The example is a workspace member.
- Impact: the PR cannot honestly ship the bilateral invocation example or claim C2 as build-clean.
- Required fix: add the missing config field and run `cargo check -p bilateral-invocation`.

### review item - #615 still overclaims a partial verifier as a full 17-step verifier

- PR: #615
- Files: `crates/chio-federation/src/bilateral_verifier.rs`, `examples/bilateral-invocation/Cargo.toml`, `examples/bilateral-invocation/src/main.rs`, conformance test names
- Evidence: module docs honestly call the verifier partial, but example package text, runtime output, and test names still advertise the "Section 7 17-step verifier".
- Impact: release/demo truth overstates verifier conformance and can hide missing predicate-schema coverage.
- Required fix: either complete the schema/verifier or rename all public/example/test surfaces to partial local verifier.

### review item - Mutation aggregate truth is multiply owned and non-atomic

- PRs: #603, #619, #621, #622, #623, #624, #626
- Files: `audits/mutation/2026-05-08-per-crate-baseline.md`, `audits/mutation/aggregate.sh`, `audits/mutation/summary.sh`, `.planning/trajectory-5/baselines/BAR-1-MUTATION.md`, `audits/evidence/mutants/.gitignore`
- Evidence: multiple worker PRs edit the same aggregate truth artifacts while only owning their own crate evidence. #626 publishes rows for sibling crates whose evidence is not present in that PR; #624 seeds a weights-only aggregate while sibling PRs carry different aggregate tables.
- Impact: whichever PR lands last can overwrite release truth with stale, partial, or externally coordinated numbers.
- Required fix: remove aggregate truth from worker PRs, or make one post-merge integrator PR regenerate the aggregate from merged evidence.

### review item - Partial mutation runs can still be marked `target_met`

- PRs: #623, #626
- Files: `audits/evidence/mutants/chio-policy/2026-05-08.json`, `audits/mutation/2026-05-08-per-crate-baseline.md`
- Evidence: `chio-policy` is interrupted at 314/418 mutants but has `"target_met": true`. The aggregate docs elsewhere say partial runs cannot retire target status without a full run or a pre-registered sampling method.
- Impact: machine-readable evidence can claim release target success while human docs say the target is not retired.
- Required fix: set `target_met=false` or remove it for interrupted/partial/subset runs. Full target success requires complete execution or a documented sampling contract approved before the run.

### review item - `summary.sh` preserves stale release-truth keys across regeneration

- PR: #626
- File: `audits/mutation/summary.sh`
- Evidence: the script preserves unknown top-level keys from an existing summary JSON and only overwrites a limited emitted field set. Keys such as `run_status`, `evaluated`, `total_discovered`, `target_met`, and `result_label` can survive after counts change.
- Impact: regenerated summaries can carry stale partial/full/target status from earlier runs.
- Required fix: whitelist durable annotations only. Recompute or delete all run-shape and release-truth fields on every regeneration.

### review item - Kani source and manifest do not land atomically

- PRs: #605, #607, #613
- Files: `.kani/harnesses.toml`, `.github/workflows/ci.yml`, `crates/chio-attest-verify/src/*`, `crates/chio-anchor/src/kani_public_harnesses.rs`, `crates/chio-weights/src/kani_public_harnesses.rs`
- Evidence: #607 enrolls harnesses in `.kani/harnesses.toml` and CI, but source for attest-verify is in #605 and source for anchor/weights is in #613. #607 itself admits the split by referencing #613 in manifest comments.
- Impact: merge order can leave CI manifest entries without source, or source without enrollment. Proof state is not atomic.
- Required fix: consolidate manifest plus source in one PR per proof set, or stack/rebase so no intermediate main state is broken.

### review item - #618 release packaging is stale and must not be release-last yet

- PR: #618
- Files: `releases.toml`, `releases/v0.1.0-bounded-chiodome/RELEASE-NOTES.md`
- Evidence: #618 says `ready_for_tag`, lists open PRs only through #617, still calls C5 a `zk` feature, and marks C2/C5/Bar 3 as MET while C3 is explicitly partial. Later PRs #619 through #626 materially change Bar 1 mutation truth.
- Refuted subclaim: the pinned fixture hashes in #618 match #618's own blobs. The problem is not internal hash mismatch; the problem is stale release truth and prereq ordering.
- Impact: #618 can publish a tag-ready package before upstream code, fixtures, mutation evidence, and release wording are integrated.
- Required fix: keep #618 last. Regenerate release notes, `releases.toml`, fixtures, and ship-bar docs from merged `main` after all non-release PRs land.

### review item - #620 ship-bar gate passes with PARTIAL evidence

- PR: #620
- File: `scripts/check-bounded-ship-bar.sh`
- Evidence: `partial()` prints `OK`, increments checks, and does not increment failures. Final exit is 0 when only partial rows exist. The tracker says Trajectory 5 closes only when all bars are DONE.
- Impact: the close gate can report PASS with incomplete mutation, demo, or release-tag evidence.
- Required fix: make PARTIAL nonzero by default. If diagnostic behavior is needed, require an explicit non-release flag.

## Validated P1 Findings

### review item - GitHub checks are failing across every PR

- PRs: #601 through #626
- Evidence: common failing checks include `Build, lint, test`, `Coverage`, `cargo-deny`, `cargo-vet`, `formal-tla`, `kani-public-pr`, `MSRV`, `JVM build`, `freeze-guard`, replay/proptest/schema/vector gates, and more.
- Impact: no PR in the set is checks-clean.
- Required fix: treat this as a release blocker until each PR is either green or explicitly classified as blocked by a known global policy failure.

### review item - Unresolved review state contradicts the executor claim

- PRs: #603, #606, #611, #613, #614, plus other Codex threads
- Evidence: unresolved Cursor Medium comments remain on #603, #606, #611, #613, and #614. The review graph has 109 non-outdated unresolved threads.
- Impact: "no unaddressed Cursor High/Medium comments" is false for Medium comments.
- Required fix: resolve or explicitly defer each actionable Medium/P1 thread in the PR, not in chat.

### review item - `cargo-mutants` lock files leak local workstation identity

- PRs: #621, #623, #626
- Files: `audits/evidence/mutants/*/mutants.out/lock.json`
- Evidence: tracked lock files include `hostname: Connors-MacBook-Pro.local` and `username: connor`.
- Impact: unnecessary local identity leakage in audit artifacts.
- Required fix: remove or redact tracked lock files. Update ignore rules for future direct and nested cargo-mutants layouts.

### review item - `aggregate.sh` and `summary.sh` do not robustly reproduce evidence

- PRs: #603, #626
- Files: `audits/mutation/aggregate.sh`, `audits/mutation/summary.sh`
- Evidence: scripts accept `outcomes.json` as evidence but count only `.txt` files, can crash under `set -euo pipefail` when summary JSON is missing, and depend on lock/outcomes files that are either ignored or PII-bearing.
- Impact: fresh checkout reproduction can silently produce zero-mutant rows, unknown metadata, wrong scope, or a pipeline failure.
- Required fix: parse `outcomes.json` directly or require text files. Make missing optional metadata nonfatal and keep redacted committed metadata as the source of truth.

### review item - `aggregate.sh` loses partial/subset caveats

- PR: #626
- File: `audits/mutation/aggregate.sh`
- Evidence: partial detection compares evaluated text-file counts to `mutants.json` length only. It does not read `result_label`, `run_status`, `examine_scope`, or `target_met`.
- Impact: hand-picked subset results can render as ordinary crate percentages.
- Required fix: aggregate from summary JSON and propagate partial/subset labels into every table row.

### review item - #625 adds tests but no mutation evidence rerun

- PR: #625
- Files: `crates/chio-attest-verify/src/sigstore.rs`, `crates/chio-attest-verify/tests/tenant_policy_resolver.rs`
- Evidence: #625 changes only code and tests; no `audits/evidence/mutants/chio-attest-verify/*` artifact is updated. Comments identify intended mutants killed, but no committed cargo-mutants output proves the 97.9 percent claim.
- Impact: this is a test-addition PR, not an evidence closure PR.
- Required fix: rerun cargo-mutants and commit evidence, or downgrade the claim to "tests added, mutation evidence pending".

### review item - `chio-attest-verify` full-crate mutation target is still not closed

- PRs: #619, #625
- Evidence: #619 records 44.1 percent full-crate mutation for `chio-attest-verify`. #625 reports targeted touched-line closure, not a full crate rerun or aggregate JSON update.
- Impact: touched-line closure cannot replace the load-bearing full-crate Bar 1 target.
- Required fix: rerun full `chio-attest-verify` mutation after #625 and update aggregate evidence.

### review item - TLA negative specs are not CI-gated

- PR: #602
- Files: `formal/apalache/_negative_tests/README.md`, `.github/workflows/apalache-safety.yml`
- Evidence: README explicitly says negative specs are local-only and not run by CI. The workflow runs only production specs.
- Impact: non-tautology evidence is manual and can regress silently.
- Required fix: add an expected-failure CI wrapper that passes only when broken specs produce the expected counterexample.

### review item - Threat evidence still relies on prose or weak counts

- PRs: #604, #608, #616
- Files: `audits/evidence/threats/*.json`, `crates/chio-conformance/tests/threats/*.rs`, `scripts/check-threat-coverage-mutants.sh`
- Evidence: some JSON files claim test headers contain revert-to-fail recipes that are not actually present. #608 records `tee_quote_forgery` count 4 while its branch only demonstrates three branches. #616 improves partial handling but the shell test still greps for the old `coverage_state partial is not allowed` text and lacks a positive partial-with-deferred fixture.
- Impact: threat coverage can be overstated or not mechanically checked.
- Required fix: add concrete revert recipes, direct negative verifier calls, and tests for the updated partial semantics.

### review item - #608 TEE quote evidence is too weak

- PR: #608
- File: `crates/chio-conformance/tests/threats/tee_quote_forgery.rs`
- Evidence: the test checks file existence and weak strings instead of directly exercising quote rejection paths.
- Impact: evidence can pass without proving the intended verifier behavior.
- Required fix: replace needle/file pinning with direct negative verifier calls for each claimed deny arm.

### review item - #614 KB MCP full-mode receipt assertion checks the wrong store

- PR: #614
- File: `examples/chiodome-bilateral/scripts/run-with-kb-mcp.sh`
- Evidence: full-mode docs use `CHIO_RECEIPT_DB` for SQLite receipt persistence, but the optional assertion counts `${CHIO_RECEIPT_DIR}/*.json`.
- Impact: a full-mode receipt assertion can fail or pass against the wrong artifact location.
- Required fix: query the SQLite receipt DB with `chio receipt list --receipt-db`.

### review item - #614/#617 stale keyid tests remain in dependent branches

- PRs: #614, #617
- File: `crates/chio-federation/src/bilateral_dsse.rs`
- Evidence: implementations hash Ed25519 raw bytes, but module tests still expect `sha256(pk.to_hex().as_bytes())`.
- Impact: dependent branches are not self-verifying and can fail or invite reverting the runtime invariant.
- Required fix: update tests to assert raw public-key byte hashing.

### review item - #606 standalone verdict-matrix crate misses `async-trait`

- PR: #606
- Files: `crates/chio-conformance/verdict_matrix/src/driver.rs`, `crates/chio-conformance/verdict_matrix/Cargo.toml`
- Evidence: driver uses `#[async_trait::async_trait(?Send)]`, but the standalone crate does not declare `async-trait`.
- Impact: standalone verdict-matrix builds can fail even if parent workspace dependencies mask it elsewhere.
- Required fix: add `async-trait` to the nested crate manifest.

### review item - #613 Kani feature does not imply required `web3`

- PR: #613
- File: `crates/chio-anchor/Cargo.toml`
- Evidence: `kani = []` does not imply `web3`, while the crate body is gated by `#![cfg(feature = "web3")]`.
- Impact: cargo-kani can find zero harnesses unless `web3` is separately enabled.
- Required fix: make `kani = ["web3"]` or enforce the required feature set in the Kani runner.

### review item - #615 positive verifier tests opt into legacy `DefaultRoutine`

- PR: #615
- File: `crates/chio-conformance/tests/c2_bilateral_invocation_verifier_17_step.rs`
- Evidence: positive helpers explicitly configure `UnknownActionClassPolicy::DefaultRoutine`.
- Impact: main positive tests do not prove the fail-closed default posture.
- Required fix: make positive tests use `Reject` unless the test is specifically exercising legacy behavior.

### review item - #612 non-tool/planning paths skip budget admission

- PR: #612
- File: `crates/chio-kernel/src/kernel/mod.rs`
- Evidence: tool dispatch admits budget, but non-tool/planning paths use `verify_capability_full_pre_admit` with `NoopBudgetRegistry` and do not call `admit_capability_budget`.
- Confidence: moderate. Some paths appear intentionally stateless, and one helper may not have a live call site.
- Impact: if the B1 claim is "single-entry verifier for all capability-backed surfaces", this gap weakens sibling-sum budget enforcement.
- Required fix: either admit budget on live delegated non-tool surfaces or narrow the B1 claim and tests.

### review item - AI/process/planning metadata remains in code and scripts

- PRs: many, including #601, #602, #603, #606, #607, #609, #611, #615, #617, #620, #625
- Evidence examples: comments mention `release work`, PR numbers, Codex/Cursor review provenance, audit tickets, wave metadata, and "Kills: mutant ..." planning notes in runtime-adjacent code, CI scripts, and tests.
- Impact: this violates the user's explicit rule that AI slop comments and planning/ticket metadata are P1. It also makes source history read like a review transcript instead of product code.
- Required fix: keep protocol rationale, remove bot/PR/ticket/provenance comments from code, scripts, configs, and production-adjacent tests.

### review item - #607/#609 gates can be advisory while looking like release gates

- PRs: #607, #609
- Evidence: #607 can filter invalid Kani lane values rather than failing hard. #609 has an anchor async witness checker pattern that can be advisory via `|| true` or exit 0.
- Impact: a gate can go green while missing intended enforcement.
- Required fix: validate lane enum values, fail on invalid manifest entries, and do not count advisory scripts as release gates.

### review item - #624 still has unresolved boundary-polarity review state

- PR: #624
- File: `audits/evidence/mutants/chio-weights/README.md`
- Evidence: active review says the README boundary-polarity guidance remains wrong even after JSON correction.
- Impact: the human-readable evidence still misleads even if the machine JSON was corrected.
- Required fix: update README to match current `ModelCard::validate` semantics.

### review item - #618 release provenance SHA is stale

- PR: #618
- File: `releases.toml`
- Evidence: [v0_1_0_bounded_chiodome].integrated_merge_sha records an older branch head than current #618.
- Impact: provenance is not mechanically current.
- Required fix: update at final release packaging time only, after upstream merges.

## P2 / Cleanup Findings

- #615 B4 conformance keyid assertion is partly tautological because it compares production output to `Keyid::from_public_key`. Keep the independent raw-byte regression test and avoid calling the tautological assertion load-bearing.
- #613 has an unused import in a Kani harness file. Clean it when touching the harness.
- #618 fixture hashes were alleged stale by one reviewer, but Wave 2 validated that the hashes match #618's own committed blobs. Do not file that exact claim without regenerating against integrated `main`.

## Claims That Appear Closed Or Narrowed

- #609 anchor-batch async-only behavior appears closed for the reviewed surface: sync public-witness path rejects and async path performs witness verification.
- #611 does add useful pre-dispatch receipt-version admission for already-stale or never-pinned peers. The remaining P0 is the post-dispatch freshness recheck race.
- #617's selective-disclosure implementation is honestly renamed to `bbs-stub` in code and targeted tests pass according to the lane-C reviewer. The stale `zk` problem is primarily in #618 release packaging and any dependent wording.
- #616 improves threat-evidence honesty by marking some rows partial. Remaining issues are test/gate coverage, not the entire batch being fake.
- No unresolved Cursor High review comments were found. The executor claim fails because Cursor Medium comments remain unresolved.

## Required Merge Order

1. Fix active GitHub review threads and CI failure causes first. Do not use individual `MERGEABLE` as a ship signal.
2. Land #606 or an equivalent async bridge fix before #612. Rebase #612 and remove stale B0 bridge changes.
3. Land #610 or an equivalent DSSE body-binding and subject-arity fix before #614/#615/#617. Rebase those branches until they contain only their own lane work.
4. Fix #611 by carrying admission-time receipt negotiation into persistence before treating B2 as closed.
5. Consolidate Kani source plus manifest state across #605/#607/#613.
6. Pick one mutation aggregate owner. Merge per-crate evidence PRs, then regenerate aggregate mutation docs/scripts from merged `main`.
7. Keep #618 last. Regenerate release notes, `releases.toml`, ship-bar docs, and fixtures from integrated `main`.
8. Make #620 strict for release mode so PARTIAL rows fail the close gate.

## Bottom Line

Trajectory 5 has useful work in the branches, but the current PR set is not release-ready and not honestly closed. The highest-risk pattern is structural: sibling PRs are carrying stale copies of foundational security files and aggregate truth artifacts. Fixing individual comments inside each branch is not sufficient; the merge topology needs to be simplified and then revalidated from merged `main`.
