# Steering prompt for the PR #937 execution agent (sixth-review close-out)

Copy-paste everything in the fenced block below to the execution agent.

---

```
You are closing out the SIXTH launch-readiness review of PR #937 (Chio, formerly ARC) in /Users/connor/backbay/arc. A read-only review pass just landed findings in two docs; read them first and treat them as your work list:
- docs/superpowers/research/chio-launch/PR-937-launch-readiness-review.md  (section "SIXTH RE-REVIEW (2026-07-02)")
- docs/superpowers/research/chio-launch/PR-937-remediation-roadmap.md      (section "SIXTH RE-REVIEW additions")

CONTEXT YOU MUST INTERNALIZE BEFORE TOUCHING CODE
- Two trees differ. The PUSHED PR head (eea18fd9c) is CI-green and launch-ready. The LOCAL committed HEAD (a3d5218cd + your live WIP) is +22 unpushed commits of module-split refactors and is NOT CI-validated. Every finding is about the local tree. Do NOT push until Phase 0 is green.
- None of these findings is a fail-open security regression. They are: (a) gate configs your module splits broke or hollowed, (b) a documentation-integrity issue, and (c) real launch-doc completeness gaps five prior passes missed. Fail-closed behavior is correct; do not "fix" it by loosening.
- House rules still bind: no em dashes (U+2014) anywhere; fail-closed (errors deny, invalid policies reject at load); clippy unwrap_used/expect_used = deny; conventional commits. Before declaring anything ready, the full one-liner must pass:
  cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check

DO PHASE 0 FIRST (these are CI merge blockers on push; the review did NOT run the cargo one-liner, so you must)
1. SIX-STUB-01 (confirmed RED first-hand, EXIT=1): fix scripts/check-stub-surfaces.py. Rekey the stale ALLOWLIST/ALLOWLIST_MATCHES entries for the deleted cli/session.rs -> cli/session/test_support.rs and the deleted guard.rs; re-allowlist the two guard/new.rs:31,:49 template strings; OR teach classify() to treat test_support.rs / cfg(test)-only modules as tests. Prove: python3 scripts/check-stub-surfaces.py && bash scripts/tests/check-stub-surfaces.test.sh both exit 0.
2. SIX-MUT-01: in .cargo/mutants.toml:146, audits/mutation/per-crate-configs/chio-attest-verify.toml:20, crates/trust/chio-attest-verify/mutants.toml:16, replace the deleted examine path crates/trust/chio-attest-verify/src/sigstore.rs with crates/trust/chio-attest-verify/src/sigstore/*.rs. Add a repo check that fails when an examine glob matches zero files (cargo-mutants does not).
3. SIX-BLESS-PATH-01: scripts/bless-replay-goldens.sh:153 SOURCE_PATTERN third alternative -> crates/kernel/chio-kernel/src/receipt_support/ (drop the \.rs$ anchor); fix usage text lines 6, 37.
4. SIX-REG-CI-01: add `bash ./scripts/check-chio-schema-registry.sh` and `bash ./scripts/tests/check-chio-schema-registry.test.sh` to the Workspace structural gates step in .github/workflows/ci.yml (next to the release-truth lint).
5. SIX-VERIFY-CI: run the full CLAUDE.md one-liner on the FINAL local tree. It was not run this pass and your 22 unpushed refactor commits are cargo-unverified. Do not push until it is green AND Phase 0 items 1-4 pass.

THEN PHASE 1 (HIGH completeness / documentation-integrity)
6. SIX-SETTLE-TEST-01: the review already recorded the doc-integrity correction (commit 9b4b62348 silently rewrote three proof_verify.rs public-settlement assertions under a misattributed message, so "all gates GREEN first-hand at 714d14498" was overstated - the proof_verify suite was red there). Your job is the code half: restore online independent-head readback coverage via a test seam (injectable transport or a test-only egress override for CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL) that exercises BOTH readback-success and readback-mismatch; keep the loopback-deny test as an added negative. Do NOT relax deny_loopback in production.
7. SIX-QUICKSTART-01: make docs/start-here/PROOF_ROOM_QUICKSTART.md work from a clean checkout - add the fixture trust-anchor env exports (CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS, CHIO_TRANSACTION_TRUSTED_ROOT_KEYS, CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS with the checked-in fixture key hexes) or ship an env-preamble script; extend the proof-room.signature.signer-untrusted error to name the missing env var; add a doc-truth test that runs the quickstart commands verbatim from a clean env.
8. SIX-PROTO-TXN-01: add a normative spec/PROTOCOL.md section for the transaction-passport family (envelope fields, signature/canonicalization rule, digest bindings, evidence-graph DAG rules, claim-set semantics, omission statuses, verifier-policy gates, the 14 transaction failure codes), mirroring the existing comptroller-report and swarm-admission sections. Satisfies plans/01 Phase 0 Task 1.

THEN PHASE 2 and PHASE 3 exactly as enumerated in the roadmap "SIXTH RE-REVIEW additions" (MEDIUM: passport minimum fields, in-library claim-set digest binding, five unregistered settlement schema IDs, missing policy-activation-receipt fixture, docker-quickstart CI + run-bound evidence, bare-ACP copy rewrites + lint scope, hygiene over-limit file splits; LOW: NC-pin the max-depth fixture, widen the risk-code floor test, add the two swarm witness-chain negative tests, robustify the commerce claims guard, omission-path assembler + fixture, disclosure timestamp timing rule, restore the two dropped security-comment blocks, refresh the stale ARCHITECTURE.md maps + operator-report witness paths, make rustfmt reach the chio-cli main.rs tree, align the signed-artifact mirror, route canonical parsers, add the trust-market overclaim lint).

WORKING RULES
- Do NOT re-litigate the two refuted items (drop-guard visibility; composition alignment gate) - they were adversarially cleared.
- Fix each finding at its trust boundary, not by widening an allowlist or loosening a gate. Where a finding says "or correct the closure text," prefer the real fix; only fall back to the doc correction with an explicit owner-accepted deviation note.
- As you close each item, check its box in PR-937-remediation-roadmap.md with a one-line evidence pointer (the command that proves it), the way prior rounds did. Do not mark [x] without first-hand evidence.
- Commit in logical groups with conventional-commit messages that accurately describe the change (the SIX-SETTLE-TEST-01 finding exists specifically because a commit message hid a semantic test change - do not repeat that).
- Do NOT commit/push/stash/reset unless the user explicitly authorizes it. When Phase 0 is green and you are authorized, push and confirm GitHub CI is green on the new head before claiming mergeable.
```
