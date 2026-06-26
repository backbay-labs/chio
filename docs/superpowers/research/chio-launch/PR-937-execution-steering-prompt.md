# PR #937 - Execution steering prompt (fourth re-review, 2026-06-25)

Copy-paste the block below to the execution agent.

---

You are closing out PR #937 (feat: add Chio proof room product surface, branch chio/autonomous-commerce-brainstorm) against `docs/superpowers/research/chio-launch/`. Start from live tree truth, not older review memory.

Current live status from the latest local pass (2026-06-26): the prior RR4 red gates are fixed. Verified locally: `cargo run -p xtask -- verify launch-acceptance --out target/proof-room/public-bundle`, `bash scripts/tests/check-chio-proof-room-launch-acceptance.test.sh`, `cargo fmt --all -- --check`, `bash scripts/check-chio-schema-registry.sh`, focused proof-doctor checks, and the R-T01-17 transaction failure-code tests. Do not redo RR4-LAUNCHACC-01, RR4-FMT-01, R-T01-17, RR4-ARD-01, RR4-COMPLETE-01, or the WFENT/DISC tail items already marked fixed or scoped in `PR-937-remediation-roadmap.md`.

Rules: fail closed; no em dashes; no `unwrap`/`expect` outside tests; use TDD for real verifier changes; do not weaken tests or fixtures. Do NOT git commit, git push, git stash, or git reset unless explicitly authorized later.

STEP 0 - current blocker:
- RR2-COMMIT remains open only because commits and pushes are currently forbidden. Keep history alone. If the user authorizes commits later, commit the WIP intentionally with load-bearing files included and re-run the release gates.

STEP 1 - live PR/CI frontier:
- Remote PR checks are stale against pushed head `3931b972f`. Local WIP fixes the known remote launch-acceptance, proof-doctor, v1-only, and protobuf apt-source failures. Do not treat unresolved GitHub review threads as current until you verify the live code path; many unresolved comments are stale and already fixed.
- For any still-actionable P1/P2 thread, add a failing behavior test first, implement the narrow fail-closed fix, then run the targeted test and relevant gate.

STEP 2 - final acceptance:
- With commit authorization, run or schedule the full gate set: `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check`, `cargo run -p xtask -- verify launch-acceptance --out target/proof-room/public-bundle`, schema registry, launch copy lint, and PR CI.
- Done means all 15 INDEX non-negotiables hold, all 11 verification gates are satisfiable, the four fixture stages and named negatives pass, homepage-copy claims map to verified claim ids, and a fresh re-review finds zero open findings.
