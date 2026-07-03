# Steering prompt for the PR #937 execution agent (seventh-review close-out)

Copy-paste everything in the fenced block below to the execution agent.

---

```
You are closing out the SEVENTH launch-readiness review of PR #937 (Chio, formerly ARC) in /Users/connor/backbay/arc. Read these first and treat them as your work list:
- docs/superpowers/research/chio-launch/PR-937-launch-readiness-review.md   (section "SEVENTH RE-REVIEW (2026-07-03)")
- docs/superpowers/research/chio-launch/PR-937-remediation-roadmap.md       (section "SEVENTH RE-REVIEW additions")

CONTEXT
- Your mid-review merge (4f1c58ef1) was verified correct: both lanes are ancestors, the origin security fixes (fail-open verdict close, SSRF egress pin, fail-closed xtask verdict) came through byte-exact, and it is pushed. Good. fmt/build/clippy were measured green first-hand at d5049b588; stub-surfaces passes; sixth-review Phase 0 is confirmed genuinely closed.
- The review found a PATTERN you must break: this is the THIRD time the split campaign hollowed a path-keyed gate (sigstore mutants glob, then compiler/response_sanitization/evm mutants globs). Until the guard detects hollow shims, every future split risks repeating it. Stop splitting until Phase 0 below is done.
- House rules bind: no em dashes; fail-closed; clippy unwrap/expect deny; conventional commits with HONEST messages (two prior findings exist because commit messages hid semantic changes). Full one-liner before declaring ready: cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check.

PHASE 0 (do first)
1. SEVEN-MUT-02: the mutation gate is hollow again for three trust crates. In .cargo/mutants.toml change the examine entries for crates/guards/chio-policy/src/compiler.rs, crates/guards/chio-guards/src/response_sanitization.rs, crates/economy/chio-anchor/src/evm.rs to their <mod>/*.rs directory forms (as you did for sigstore); update the mirrors (chio-policy/mutants.toml:16, chio-guards/mutants.toml:29, chio-anchor/mutants.toml:20, audits/mutation/per-crate-configs/*). Then HARDEN scripts/check-mutants-examine-globs.py: fail when a glob's matched files contain no (or trivially few) fn items, and fail when the workspace config itself is missing. Prove: the hardened script is RED on the pre-fix configs and GREEN after; cargo mutants --list shows the three module trees.
2. SEVEN-CI-MERGED: confirm GitHub CI is green on 4f1c58ef1; run cargo run -p xtask -- verify launch-acceptance and cargo test --workspace on the merged tree (neither has been measured on it). Watch disk: free the regenerable target/debug/incremental first if below ~8 GiB.

PHASE 1
3. SEVEN-FAILOPEN-SIB-01: port the 269c70dad fail-open fix to chio-cli/src/cli/dispatch/proof.rs merge_family_verifier_reports (lines ~1338-1382): derive verdict/accepted/state from the family reports instead of hardcoding "verified"/true; add a negative test with a failed family report asserting the merged report is NOT verified.
4. SEVEN-A2A-01: amend the record (SW-STD-04/RR2-COPY entries in the roadmap) to the corrected A2A truth (v1.0.0; the crate pins major "1."). Decide and document whether a replacement lint banning stale 0.3.0 claims is warranted, since 4acd236d5 deleted the old rule + 2 test assertions.
5. SEVEN-WASM-SKIP-01: the python-guard round-trip deny tests skip everywhere because no lane builds the wasm artifact. Build it in one CI lane (preferred) or mark the skip as a loud, documented known gap.
6. SEVEN-DSSE-01 + SEVEN-SPEC-DRIFT-01 + SEVEN-RUNBOOK-01: restore #[must_use] on pae() and the verify_dsse security-contract comments (f2c410b92 dropped them); re-align the f73fddfc4 settlement-RPC spec text with the post-049e46d7a egress-pinned call path; retire or re-scope docs/brainstorm/CHIO-M2-MERGE-RUNBOOK.md and record the real 4f1c58ef1 merge.

PHASE 2 - THE STANDING BACKLOG YOU HAVE BEEN DEFERRING
The sixth review's Phase 1-3 items are ALL still open and are now the oldest debt. Work them BEFORE resuming any split campaign, in this order:
7. SIX-SETTLE-TEST-01: online independent-head readback test seam (injectable transport / test-only egress override for CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL), success + mismatch paths. Do not weaken the production egress pin.
8. SIX-QUICKSTART-01: make docs/start-here/PROOF_ROOM_QUICKSTART.md work from a clean checkout (fixture trust-anchor env exports or preamble script); name the env var in the signer-untrusted error; add a doc-truth test.
9. SIX-PROTO-TXN-01: normative spec/PROTOCOL.md sections for ALL FOUR families (transaction-passport, commerce, disclosure/lineage, agent-web envelope) - f73fddfc4 closed none of them.
10. Then the sixth-review MEDIUM tail (PASSPORT-FIELDS, CLAIMSET-DIGEST, SETTLE-REG five IDs, RT05-FIXTURE, DOCKER-CI, ACP-COPY, HYGIENE-SCOPE - note the allowlist expiry 2026-07-31 is four weeks out and none of the four mandated files has been split) and the LOW tails from both reviews (the roadmap enumerates them).

WORKING RULES
- Do NOT re-litigate refuted items (fork-process findings - overtaken by your merge; hygiene-expiry duplicate; A2A projection-lane concern).
- Fix at the trust boundary; never close a finding by widening an allowlist or deleting a lint without recording it.
- Check each roadmap box with one-line first-hand evidence as you go; never mark [x] without running the proving command.
- Commit messages must disclose EVERYTHING a commit changes, especially gate configs and test semantics.
- Do NOT push without the full one-liner green plus scripts/check-stub-surfaces.py and scripts/check-mutants-examine-globs.py green; after push, confirm GitHub CI green on the new head before claiming mergeable.
```
