# Trajectory 5 Comprehensive Code And Security Audit

Date: 2026-05-08
Repository: `bb-connor/arc`
Scope: open Trajectory 5 pull requests #601 through #622 and their cross-PR release state.

## Severity Rubric

- P0: significant bug, security flaw, design or structure issue, bad Trajectory 5 idea that should be replaced, merge-order hazard that can publish false release truth, or evidence that materially overclaims what was proven.
- P1: missing or low test coverage, weak verification, stale or inflated evidence count, or AI/process metadata in committed code comments or production-adjacent test comments.

## Audit Method

- Wave 1 split review by lane: mutation evidence, formal evidence, Lane B protocol primitives, Lane C demo/release packaging, cross-PR integration, and broad security audit.
- Wave 2 validated high-impact P0 candidates across receipt negotiation, async dispatch, bilateral verifier behavior, mutation evidence integrity, Kani enrollment, Lane C release claims, and stacked PR merge hazards.
- Evidence came from live GitHub PR metadata, changed-file lists, targeted PR patches, and local repo context. No PR code was modified during the audit.

## Executive Summary

Trajectory 5 is not release-ready as currently shaped. The open PR set contains strong pieces of useful work, but it is not a clean fan-out. Multiple PRs are stacked on earlier PRs while still targeting `main`, duplicate security-sensitive implementation files, and independently rewrite aggregate truth artifacts. The highest-risk issues are not style nits: several P0s can allow tool side effects before a negotiated fail-closed receipt error, overstate DSSE and 17-step verifier conformance, publish partial mutation results as target satisfaction, and mark release lanes MET when their scripts or cryptographic implementations are stubs.

Recommended release posture: keep #618 blocked until foundational PRs are merged and all aggregate evidence and fixtures are regenerated from merged `main`.

## P0 Findings

### T5-AUDIT-P0-001 - Receipt negotiation downgrade is checked after tool dispatch

- PR: #611
- Files: `crates/chio-kernel/src/kernel/responses.rs`, `crates/chio-kernel/src/kernel/mod.rs`
- Evidence: `record_chio_receipt_with_federation` resolves `kernel_receipt_version_for_remote` while recording the receipt. The main `evaluate_tool_call_blocking` path dispatches the tool through `dispatch_tool_call_with_cost_*` before receipt recording.
- Impact: a request naming a stale or never-pinned federation peer can execute a state-changing tool, then fail when receipt persistence attempts to reject a v2-to-v1 downgrade. That is not fail-closed at the trust boundary.
- Fix: move named-peer freshness and negotiated receipt-version rejection into pre-dispatch admission. Preserve a signed deny receipt path that does not execute the tool.

### T5-AUDIT-P0-002 - Async ToolServerConnection bridge can deadlock on current-thread Tokio

- PRs: #606, #612
- File: `crates/chio-kernel/src/kernel/mod.rs`
- Evidence: the sync bridge uses `futures::executor::block_on` when no multi-thread Tokio runtime is available, including current-thread runtime contexts. Tokio timers and I/O used by real async tool servers cannot progress while the same thread is parked.
- Impact: the async migration can pass in-process sync-like tests while deadlocking or failing for real async servers under common current-thread runtime deployments.
- Fix: remove sync bridge usage from async evaluation paths. If a legacy sync API must remain, fail explicitly on current-thread Tokio for futures that require Tokio I/O, or move the whole evaluator path to async.

### T5-AUDIT-P0-003 - DSSE keyid hashing contradicts the stated raw-key contract

- PRs: #610, #614, #615
- File: `crates/chio-federation/src/bilateral_dsse.rs`
- Evidence: comments and PR text say Ed25519 keyids are SHA-256 over raw public-key bytes, but implementations and tests in some PR versions hash `public_key.to_hex().as_bytes()`. Other PR versions changed the implementation but left tests expecting the old hex-text digest.
- Impact: Rust-produced envelopes and non-Rust verifiers can compute different keyids for the same passport key. Peer pinning and signature lookup become non-interoperable.
- Fix: define exactly one keyid preimage in the spec and implementation. For Ed25519, hash raw key bytes if that is the desired contract. Update unit tests and pinned fixtures accordingly.

### T5-AUDIT-P0-004 - DSSE subject digest binds the wrong receipt shape

- PRs: #610, #614, #615
- File: `crates/chio-federation/src/bilateral_dsse.rs`
- Evidence: `build_statement` hashes canonical JSON of the full signed `ChioReceipt`, while comments and verifier framing describe binding the receipt body.
- Impact: a verifier resolving receipt bodies from a store derives a different subject digest from the emitted envelope. Cross-implementation verification can fail, and the signed subject does not match the stated contract.
- Fix: hash canonical `ChioReceiptBody` bytes, not the full signed receipt wrapper, or update the spec and all verifier stores to consistently resolve the full receipt object.

### T5-AUDIT-P0-005 - DSSE verifier does not require exactly one subject

- PRs: #610, #615
- File: `crates/chio-federation/src/bilateral_dsse.rs`, `crates/chio-federation/src/bilateral_verifier.rs`
- Evidence: the verifier rejects an empty `subject` list but accepts multiple subjects and validates only `subject[0]`.
- Impact: downstream consumers may treat the whole signed Statement as verified while extra subjects are never checked.
- Fix: require `statement.subject.len() == 1` for the bilateral envelope profile and add a negative test with an extra subject.

### T5-AUDIT-P0-006 - 17-step verifier defaults missing action classes to Routine

- PR: #615
- File: `crates/chio-federation/src/bilateral_verifier.rs`
- Evidence: the verifier uses `action_classes.get(&pred.tool_name).copied().unwrap_or(ActionClassKind::Routine)`.
- Impact: a new or misspelled tool name silently skips governance receipt enforcement. Missing local policy is treated as low-risk routine behavior, which is fail-open.
- Fix: reject unknown tool names unless an explicit fail-closed default policy is configured. Add a negative test for a missing action class.

### T5-AUDIT-P0-007 - 17-step verifier is not schema-complete but is presented as conformance

- PR: #615
- Files: `crates/chio-federation/src/bilateral_dsse.rs`, `crates/chio-federation/src/bilateral_verifier.rs`
- Evidence: the predicate lacks or rejects required fields such as `tool_args_hash`, signs internal non-schema fields, uses the wrong receipt digest shape, and maps parseable-base64 malformed Statement JSON to `dsse.malformed` rather than `statement.malformed`.
- Impact: the verifier advertises CHIODOS step coverage while rejecting or accepting artifacts under a profile that is not the actual schema.
- Fix: implement the complete predicate schema before calling it a 17-step verifier, or downgrade the claim to a partial local verifier.

### T5-AUDIT-P0-008 - Receipt explain emits a verifier trace without cryptographic verification

- PR: #617
- File: `crates/chio-cli/src/cli/trust_commands.rs`
- Evidence: `--explain-bilateral` prints a "17-step verifier trace", while Ed25519 signature verification steps are marked `bounded` or inspected rather than actually verified.
- Impact: operators can read output that looks like verification even though the CLI did not validate passport public keys or DSSE signatures.
- Fix: either require passport public keys and call the real DSSE verifier, or rename the mode to an inspection trace and remove verifier wording.

### T5-AUDIT-P0-009 - Selective disclosure is named as `zk` while implemented as a SHA-256 stub

- PRs: #617, #618
- Files: `crates/chio-federation/src/selective_disclosure.rs`, `crates/chio-federation/Cargo.toml`, `releases.toml`, release notes
- Evidence: the Cargo feature is named `zk`, release metadata marks C5 as MET, but the implementation states it is not zero-knowledge and uses a SHA-256 commitment placeholder over withheld messages.
- Impact: the trajectory and release language overclaim cryptographic privacy. This is a bad idea in its current form because it gives a stub a production-sounding security label.
- Fix: rename the feature and API to a stub or projection name, mark C5 PARTIAL, and reserve `zk` for real BBS+/BLS implementation.

### T5-AUDIT-P0-010 - Selective disclosure rehashes malformed Hx fields instead of rejecting

- PR: #617
- File: `crates/chio-federation/src/selective_disclosure.rs`
- Evidence: malformed `content_hash` or `policy_hash` values fall back to SHA-256 of the raw string while still being labeled `Hx`.
- Impact: invalid receipt integrity fields are accepted and projected under a different value than the receipt actually carried. This violates fail-closed behavior and creates non-interoperable auditor views.
- Fix: return a typed error unless each `Hx` field decodes to exactly 32 bytes. Add negative tests for malformed and wrong-length hex.

### T5-AUDIT-P0-011 - Selective disclosure verifier ignores disclosed encoding tampering

- PR: #617
- File: `crates/chio-federation/src/selective_disclosure.rs`
- Evidence: `verify_audit_view` checks disclosed `field` and `bytes_hex`, but not `encoding`.
- Impact: downstream decoders can be misled about how verified bytes should be interpreted while the verifier still accepts the view.
- Fix: compare `encoding` against the pinned projection and include disclosed metadata in the proof binding.

### T5-AUDIT-P0-012 - KB MCP integration script is a dry run by default

- PRs: #614, #618
- File: `examples/chiodome-bilateral/scripts/run-with-kb-mcp.sh`
- Evidence: the actual `chio mcp serve` command is commented out and receipt assertion is skipped unless `CHIODOME_DEMO_ASSERT_RECEIPTS=1`.
- Impact: C3 is marked MET, but the committed script can pass without mediating an MCP tool call through Chio or emitting a receipt.
- Fix: add a noninteractive JSON-RPC replay fixture and make receipt emission part of the default smoke gate. Otherwise mark C3 PARTIAL.

### T5-AUDIT-P0-013 - Demo checkpoint root uses the wrong hash convention

- PR: #614
- File: `examples/chiodome-bilateral/src/main.rs`
- Evidence: the demo checkpoint root is raw `SHA256(canonical_json(receipt))`, while existing checkpoint/Merkle code uses RFC6962-style leaf hashing.
- Impact: pinned fixture checkpoint roots may not verify against Chio's own Merkle inclusion/checkpoint machinery.
- Fix: use the existing `MerkleTree::from_leaves` or `leaf_hash` helper for the single-leaf root.

### T5-AUDIT-P0-014 - Release regeneration command is not runnable from the packaging branch

- PR: #618
- File: `releases/v0.1.0-bounded-chiodome/RELEASE-NOTES.md`
- Evidence: release docs publish `cargo run --bin chiodome-bilateral-demo`, but the packaging PR file list does not contain the example crate target that provides the binary.
- Impact: the release package cannot reproduce its own fixture generation command from the branch being reviewed.
- Fix: base packaging on merged demo code or include the example crate before setting release status to `ready_for_tag`.

### T5-AUDIT-P0-015 - Fixture reproducibility claim conflicts with fresh key generation

- PRs: #614, #618
- Files: `examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/README.md`, `examples/chiodome-bilateral/src/main.rs`
- Evidence: fixture docs say deterministic synthetic keypairs are hard-coded, but the demo generates fresh keypairs.
- Impact: documented fixture hashes cannot be regenerated deterministically as claimed.
- Fix: use fixed test seeds for release fixtures or describe the fixtures as pinned snapshots, not deterministic regeneration outputs.

### T5-AUDIT-P0-016 - Kani manifest exits success when no harnesses match

- PR: #607
- File: `scripts/run-kani-manifest.sh`
- Evidence: if no harnesses match, the script prints "no harnesses matched" and exits 0 for normal runs, not only for `--list` or `--dry-run`.
- Impact: a lane typo, manifest bug, or bad exclude can silently skip all Kani proofs while CI stays green.
- Fix: exit nonzero on empty matches unless an explicit `--allow-empty` flag is present.

### T5-AUDIT-P0-017 - Anchor and weights Kani harnesses are not enrolled in the runner

- PRs: #607, #613
- Files: `.kani/harnesses.toml`, `crates/chio-anchor/src/kani_public_harnesses.rs`, `crates/chio-weights/src/kani_public_harnesses.rs`
- Evidence: #607 only includes anchor and weights harness entries as commented TOML examples. #613 adds harness files but does not activate manifest entries or record live runs.
- Impact: proof files can exist without being enforced by CI, repeating the "proof-present, gate-not-running" failure mode Trajectory 5 is supposed to close.
- Fix: add real `[[harness]]` entries, run the manifest by crate, and record actual `VERIFICATION: SUCCESSFUL` outputs.

### T5-AUDIT-P0-018 - Several Kani harnesses prove model helpers instead of production entries

- PRs: #605, #613
- Files: `crates/chio-attest-verify/src/kani_public_harnesses.rs`, `crates/chio-anchor/src/kani_public_harnesses.rs`
- Evidence: Nitro, SEV-SNP, TDX, and anchor witness-policy harnesses prove local `model_*` functions for decision algebra instead of the named production verifier implementations.
- Impact: Kani can pass while production `verify_quote` or `evaluate_witness_policy` regresses.
- Fix: extract the checked decision logic into production helpers used by both runtime and Kani, or relabel the harnesses as model-only evidence and keep status partial.

### T5-AUDIT-P0-019 - Chio-guards mutation baseline uses a small hand-picked subset

- PR: #621
- Files: `audits/evidence/mutants/chio-guards/README.md`, `audits/mutation/per-crate-configs/chio-guards.toml`
- Evidence: the PR claims `chio-guards` exceeds the >=65% target, but measures only 119 of 1291 mutants across 8 of 27 files.
- Impact: a 9.2% hand-picked subset cannot retire a full crate baseline or satisfy a crate-level target.
- Fix: label it `PARTIAL-SUBSET`, keep target status unresolved, and use a full run or pre-registered statistically defensible sampling scheme.

### T5-AUDIT-P0-020 - Chio-guards config excludes files already flagged as decision-capable

- PRs: #603, #621
- File: `audits/mutation/per-crate-configs/chio-guards.toml`
- Evidence: `text_utils.rs` and `spider_sense.rs` are excluded as advisory/helper files even though #603's audit flags both as decision-capable `FOR-REMOVAL-CANDIDATE` files.
- Impact: the guards baseline is biased upward by excluding known canonicalization and deny-path logic.
- Fix: re-include those files and itemize any true pass-through exclusions.

### T5-AUDIT-P0-021 - Chio-anchor target satisfaction is claimed from a partial capped run

- PR: #622
- File: `audits/mutation/2026-05-08-per-crate-baseline.md`
- Evidence: `chio-anchor` is reported as exceeding target while only 214 of 262 mutants were evaluated under a 60-minute cap.
- Impact: the unevaluated 48 mutants can materially change the full-crate rate and could drop it below target.
- Fix: mark the run PARTIAL and do not claim target satisfaction until the run completes or the partial methodology is formally accepted.

### T5-AUDIT-P0-022 - Chio-credentials mutation baseline omits included verification logic

- PR: #603
- Files: `audits/evidence/mutants/chio-credentials/2026-05-08.json`, `audits/evidence/mutation exclusion audit/exclude-audit.md`
- Evidence: the JSON records a crate-level kill rate while the audit notes cargo-mutants did not cover 13 `include!`d files containing credential verification logic.
- Impact: aggregate tooling treats 74.1% as a crate baseline despite major decision code outside the mutation surface.
- Fix: convert included files to modules or explicitly mark the result as partial with machine-readable `examine_scope` caveats.

### T5-AUDIT-P0-023 - Threat rows are closed with weaker evidence than their names imply

- PR: #616
- Files: `audits/evidence/threats/pq_signature_downgrade.json`, `tool_server_escape.json`, corresponding conformance tests
- Evidence: `pq_signature_downgrade` is marked closed by a classical Ed25519 rejection under `PqRequired`, while hybrid artifact downgrade behavior is deferred. `tool_server_escape` is marked closed with Wasmtime guard import/fuel tests rather than kernel tool-server sandbox escape coverage.
- Impact: threat coverage overstates closure of two security rows.
- Fix: split each row into narrower claims or mark them partial until the actual hybrid downgrade and tool-server dispatch sandbox tests exist.

### T5-AUDIT-P0-024 - Stacked PRs duplicate security-sensitive code while targeting `main`

- PRs: #606, #610, #612, #614, #615, #617
- Evidence: #612 repeats the async migration from #606. #614, #615, and #617 repeatedly vendor `bilateral_dsse.rs` and B4 conformance files from #610 while still targeting `main`.
- Impact: reviewers are not seeing isolated changes. Merge order can silently change security-sensitive DSSE and async dispatch behavior.
- Fix: merge foundational PRs first and rebase dependent PRs to contain only their own lane work. Suggested order: #606 before #612, #610 before #615/#617/#614.

### T5-AUDIT-P0-025 - Mutation aggregate PRs can overwrite each other's truth

- PRs: #603, #619, #621, #622
- Files: `audits/mutation/2026-05-08-per-crate-baseline.md`, `.planning/trajectory-5/baselines/BAR-1-MUTATION.md`
- Evidence: the same aggregate files are independently rewritten. #621 records guards measured; #622 still marks guards as `BASELINE-GAP` while adding anchor.
- Impact: whichever PR lands later can erase or contradict another PR's measurement state.
- Fix: establish one owner PR for shared mutation infrastructure and aggregate files, then rebase/regenerate in strict order.

### T5-AUDIT-P0-026 - Release package is stale and must be last

- PR: #618
- Files: `releases.toml`, release notes, pinned fixtures
- Evidence: #618 packages #601-#617 and marks many lanes MET, while later #619/#621/#622 change mutation truth and #620 adds/overlaps planning artifacts.
- Impact: `ready_for_tag` would publish stale provenance and incomplete ship-bar status.
- Fix: hold #618 until all non-release PRs are merged and regenerate release notes, fixture hashes, provenance, ship-bar status, and `releases.toml` from merged `main`.

### T5-AUDIT-P0-027 - Planning ownership and gate paths are wrong or non-runnable

- PR: #620
- Files: `.planning/trajectory-5/OWNERS.toml`, `.planning/trajectory-5/SHIP-BAR-TRACKER.md`
- Evidence: Lane C ownership covers `examples/bounded-chiodome/**`, while the actual demo path is `examples/chiodome-bilateral/**`. The assurance tracker is consumed by `scripts/check-bounded-ship-bar.sh`.
- Impact: owner routing misses the main demo artifact and the advertised close gate is a paper gate.
- Fix: add the correct demo path to OWNERS and either add the ship-bar checker or point the tracker at the implemented preflight gate.

## P1 Findings

### T5-AUDIT-P1-001 - Chio-attest-verify mutation coverage is too low for a trust-boundary crate

- PR: #619
- Evidence: `chio-attest-verify` reports 44.1% with 38 missed mutants, mostly in Sigstore verification paths, against a stated >=80% target.
- Fix: add negative tests for signature length, bundle leaf/Rekor extraction, identity matching, certificate validity, and error mapping before treating A1 coverage as healthy.

### T5-AUDIT-P1-002 - Chio-credentials schema mutants time out

- PR: #603
- Evidence: 7 viable mutants time out in schema-recognition functions.
- Fix: add deterministic negative tests that fail quickly rather than allowing validation retry loops.

### T5-AUDIT-P1-003 - Chio-anchor mutation config skips a local failing test

- PR: #622
- File: `audits/mutation/per-crate-configs/chio-anchor.toml`
- Evidence: the run skips `evm::tests::validate_rpc_egress_contract_accepts_hostname_rpc`.
- Fix: fix or isolate the failing test first, then rerun without `--skip`; otherwise label the result as scoped diagnostic evidence only.

### T5-AUDIT-P1-004 - TLA+ negative specs are local-only

- PR: #602
- File: `formal/apalache/_negative_tests/README.md`
- Evidence: negative specs are explicitly not run by the CI safety workflow.
- Fix: add an inverted CI wrapper that succeeds only when the broken specs produce the expected counterexample or failure.

### T5-AUDIT-P1-005 - Threat evidence rows cite missing revert recipes

- PR: #604
- Files: threat JSON rows and corresponding conformance tests
- Evidence: JSON notes claim test headers document revert-to-prove-it-fails recipes, but several corresponding headers only describe coverage strategy.
- Fix: add exact revert recipes or remove the claim from evidence rows.

### T5-AUDIT-P1-006 - Tee quote forgery caught count appears inflated

- PRs: #608, #616
- Files: `audits/evidence/threats/tee_quote_forgery.json`, `crates/chio-conformance/tests/threats/tee_quote_forgery.rs`
- Evidence: `caught: 4` is claimed, but review found three deny assertions plus a genuine-frame round trip and file-existence pins.
- Fix: set `caught` to 3 or add a fourth real deny vector.

### T5-AUDIT-P1-007 - Selective-disclosure tests miss fail-closed negatives

- PR: #617
- File: `crates/chio-conformance/tests/c5_selective_disclosure_zk.rs`
- Evidence: tests cover happy path and some tampering, but not malformed Hx rejection or disclosed encoding tamper.
- Fix: add negative tests for invalid `content_hash`, invalid `policy_hash`, and changed `DisclosedMessage.encoding`.

### T5-AUDIT-P1-008 - Standalone verdict matrix may miss async-trait dependency

- PR: #606
- Files: `crates/chio-conformance/verdict_matrix/src/driver.rs`, nested `Cargo.toml`
- Evidence: the standalone verdict matrix uses `async_trait`; review did not find the dependency declared in the nested crate.
- Fix: add `async-trait` to the nested crate or remove the attribute from that target.

### T5-AUDIT-P1-009 - AI/process metadata is committed in code or production-adjacent comments

- PRs: #601, #603, #608, #609, #610, #612, #613, #614, #617, #620, #621, #622
- Evidence: examples include `codex[bot] P1 on PR #610`, `cursor[bot] LOW on PR #612`, `Kani harness evidence`, `W1.3`, `trj4 closeout audit`, `R4 BLOCKER`, revert-procedure chatter, and "Claude" executor context in code, tests, scripts, and OWNERS comments.
- Impact: these comments age poorly and match the user's rubric for AI slop or planning metadata leakage.
- Fix: move provenance to PR bodies or planning logs. Keep committed code and test comments focused on durable behavior and protocol rationale.

## Merge Order And Blocking Recommendation

Do not merge #618 until it is regenerated last.

Recommended high-level order:

1. Merge planning once: #620 after fixing ownership and non-runnable gate references.
2. Merge foundational formal/evidence pieces that do not duplicate later code: #601, #602, #604, #605, #608, #616 after evidence-label fixes.
3. Merge B0 first: #606, then rebase #612 to B1-only.
4. Merge DSSE foundation: #610, then rebase #615, #617, and #614 to remove vendored DSSE code.
5. Reconcile mutation evidence: #603, #619, #621, #622 in a strict order with one aggregate owner and regenerated BAR-1 truth after each merge.
6. Rebase and regenerate #618 only after all non-release PRs land. The final package must rebuild fixtures, release notes, `releases.toml`, and ship-bar status from merged `main`.

## Open Validation Notes

- Some PRs include useful work and may become acceptable after rebasing and claim repair. The audit should not be read as "throw away Trajectory 5"; it should be read as "do not publish release truth from this PR graph as-is."
- #601 had no substantive proof-soundness defect found in the Lane A depth review, but its comments still need process-metadata cleanup under the P1 rubric.
- This log intentionally preserves partial evidence findings. Partial baselines and stubs are acceptable when labeled honestly; they become P0s when used to satisfy release bars or MET status.
