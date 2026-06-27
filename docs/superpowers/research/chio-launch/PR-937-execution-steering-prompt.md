# PR #937 - Execution steering prompt (fifth re-review, 2026-06-26)

Copy-paste the block below to the execution agent.

---

You are closing out PR #937 (feat: add Chio proof room product surface, branch chio/autonomous-commerce-brainstorm) against docs/superpowers/research/chio-launch/. Start from live tree truth. The FIFTH re-review findings are in PR-937-launch-readiness-review.md ("FIFTH RE-REVIEW") and the prioritized backlog with done-when gates is in PR-937-remediation-roadmap.md ("FIFTH RE-REVIEW additions"). Read both first.

Current live status, re-verified first-hand at committed HEAD 714d14498 (= origin head, clean tree): ALL mandated gates are GREEN - cargo build --workspace, cargo clippy --workspace -- -D warnings, cargo fmt --all -- --check, cargo run -p xtask -- verify launch-acceptance --out target/proof-room/public-bundle, scripts/check-chio-schema-registry.sh, scripts/check-chio-proof-room-release-truth.sh. The launch-acceptance gate (RED in the THIRD and FOURTH rounds) is now green. 43 prior findings are genuinely closed and the 6-commit regression hunt is clean. Do NOT redo any of: RR4-LAUNCHACC-01, RR4-FMT-01, R-T01-17, RR4-ARD-01/02, RR4-COMPLETE-01/02, the T05/T03/T06/RT/T08 items, or the retired WFENT/DISC tail - all verified fixed. Do NOT re-litigate the refuted disk-pressure findings (RR5-COMPLETE-01 "clippy broken", RR5-COMPLETE-02 "build unknown") - both gates are green on a clean run.

Rules: fail closed; no em dashes; no unwrap/expect outside tests; TDD for real verifier changes; do not weaken tests, fixtures, or gates to pass. Do NOT git commit, git push, git stash, or git reset unless explicitly authorized later - leave history and the remote alone.

STEP 1 - the one open code-level finding:
- R-T03-17 (medium): the swarm max-depth check is enforced (crates/kernel/chio-swarm-authority/src/verifier.rs:765-767) and unit-tested (tests/swarm_authority_stage0.rs:339), but the public negative-control catalog fixtures/proof-room/public-stages/recursive-runtime-swarm/proof-room-bundle/negatives/catalog/ has 10 cases and none is max-depth-exceeded. Add a recursive-runtime-swarm-max-depth-exceeded negative fixture (a graph node with depth > max_depth), regenerate the signed bundle, and add the case to the launch-acceptance negative-control set so the floor is complete. Done when: the fixture rejects fail-closed via the CLI verifier, it appears in the negative catalog, and cargo run -p xtask -- verify launch-acceptance --out target/proof-room/public-bundle stays green. Write the failing reject test first.

STEP 2 - commit blocker (process-only; needs your authorization):
- RR2-COMMIT is the only remaining "blocker" and it is open solely because commits/pushes are forbidden in the review session. The work is already committed locally at 714d14498 = origin head, so the PR remote reflects the green code. If the user authorizes it, confirm GitHub CI is green on the pushed head 714d14498 (the BAC-609 CI gate runs build+clippy+fmt; the launch-acceptance job runs xtask + the contract test). If CI shows stale red from an older head, push is not needed (head already matches) - just re-trigger CI or confirm the latest run.

STEP 3 - final acceptance:
- Run the full gate set once R-T03-17 lands: cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check && cargo run -p xtask -- verify launch-acceptance --out target/proof-room/public-bundle && bash scripts/check-chio-schema-registry.sh && bash scripts/check-chio-proof-room-release-truth.sh.
- Done means: all 15 INDEX non-negotiables hold (currently 15/15 gate-backed with R-T03-17 the only residual demonstrability fixture), all 11 verification gates satisfiable, the four fixture stages and every named negative (including max-depth-exceeded) pass, homepage-copy claims map to verified claim ids, and a fresh re-review finds zero open findings. Paste the command output that proves each step - do not assert green without it.
