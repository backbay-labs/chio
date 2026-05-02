# Trajectory-2 Independent Code Review + Security Audit - Final Report

## Audit methodology

- Eight audit categories applied per milestone: A trust-boundary security, B concurrency / TOCTOU, C resource exhaustion, D error handling, E test coverage, F formal verification, G spec / wire-format, H bot review threads as the final cross-check.
- Categories A-G were auditor-driven: code reading, adversarial reasoning, targeted local gates, formal gates, and workspace gates. Category H was used only to verify external bot signal against the code.
- Scope was P0/P1/P2 only. Lower-severity tangents were left out or carried forward in follow-up artifacts.

## Per-milestone audit summary

| Milestone | Audit PR | Findings (P0/P1/P2) | Trust-boundary | Notes |
| --- | --- | --- | --- | --- |
| M01 | #426 | 0/0/4 | no | LSP UTF-16 range handling, `chio doctor --fix` creation race, passport error domains, and guard lifecycle error taxonomy fixed. |
| M02 | #427 | 0/3/2 | no | Verdict-matrix corpus pinning, cross-language gate registration, and receipt-store flake fixed. Mutation aggregate remains carried forward. |
| M03 | #428 | 2/2/1 | yes | TDX quote signature verification, Nitro freshness, TEE parser caps, SEV-SNP signature wire support, and Lean axiom removal fixed. |
| M04 | #429 | 0/2/1 | yes | Delegation parent-authentication, revocation-view freshness, and revocation-gossip zero-capacity error classification fixed. |
| M05 | #430 | 0/2/1 | yes | Tenant policy input caps, WASM policy-bundle read bounds, and policy-loader freshness regression clarity fixed. |
| M06 | #431 | 0/3/1 | no | Receipt-store bounded channel, OTEL sink batch caps, metric constant drift, and loom lane compilation fixed. |
| M07 | #432 | 0/1/1 | no | MCP stdio frame and queue bounds fixed; Ollama localhost replay shape tightened. |
| M08 | #433 | 0/0/2 | no | Arena replay scenario-id path validation and evolve budget caps fixed. |
| M09 | #434 | 0/1/2 | no | IOU insert atomicity, marketplace no-clobber install semantics, and IOU schema bootstrap drift fixed. |
| M10 | #435 | 0/1/4 | yes | Passkey nonce hard caps, model-card canonical input enforcement, audience MSB coverage, lineage error propagation, and passkey SDK size budget fixed. |

Additional closeout PRs:

| PR | Purpose | Notes |
| --- | --- | --- |
| #436 | Cross-cutting workspace audit findings | Workspace-wide C-G cleanup, clippy/test fixes, and final cross-cutting repair pass. |
| #437 | Final MCP cancellation gate repair | Stabilized task cancellation behavior found during final workspace gates. |
| #438 | Formal Kani gate stabilization | Replaced brittle heap-heavy Kani delegation harnesses with bounded algebraic models while preserving runtime RFC8785 coverage. |
| #439 | MCP HTTP flake repair | Routed shared-owner HTTP startup through bind-retry readiness handling. |
| final report PR | Final formal metadata and report | The theorem inventory now records zero Lean assumptions and the formal proof checker accepts an empty allowed-axiom set while still failing on any actual axiom. |

## Workspace gate evidence

- `cargo build --workspace`: PASS on `a17d95832`; evidence `/tmp/trj3/final-main-build-a17d958.txt`.
- `cargo test --workspace`: PASS on `a17d95832`; evidence `/tmp/trj3/final-main-test-a17d958-rerun.txt`.
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS on `a17d95832`; evidence `/tmp/trj3/final-main-clippy-a17d958.txt`.
- `cargo fmt --all -- --check`: PASS on `a17d95832`; evidence `/tmp/trj3/final-main-fmt-a17d958.txt`.
- `git diff --check`: PASS after final formal metadata update; evidence `/tmp/trj3/final-formal-metadata-diff-check.txt`.
- Flake rate: two flakes were found during final gates, both investigated and repaired or isolated. `mcp_serve_http_shared_owner_jwt_sessions_keep_weak_compatibility_continuity` passed 5/5 isolation before the startup hardening in #439 and the full workspace test passed after #439. `kernel::tests::delegated_tool_call_without_delegate_operation_denies` failed once, passed 5/5 isolation, and the full `chio-kernel` lib suite passed before the final workspace rerun passed.

## Formal-verifier evidence

- Lean: PASS, 17 jobs, zero source-level `sorry` and zero source-level `axiom`; evidence `/tmp/trj3/formal-lean-no-axiom-metadata.txt`.
- Formal proof metadata: PASS, theorem inventory assumptions are empty and `allowed_axioms = []`; evidence `/tmp/trj3/check-formal-proofs-no-axiom-metadata2.txt`.
- Kani: PASS for smoke lane and public core lane; evidence `/tmp/trj3/check-kani-smoke-ca63fe6.txt` and `/tmp/trj3/check-kani-public-core-stabilized2.txt`. The broad `cargo kani -p chio-kernel-core` path remains superseded by the mapped public-core lane because the broad run still expands into an impractical `memcmp` path.
- Apalache: PASS for `DelegationDepthBound` and `RevocationPropagation` configured invariants through length 6; evidence `/tmp/trj3/apalache-delegation-depth-length6-7200953.txt` and `/tmp/trj3/apalache-revocation-safety-length6-7200953.txt`.
- Threat coverage: PASS, covered=6, partial=0, pending=11, uncovered=0; evidence `/tmp/trj3/check-threat-coverage-ca63fe6.txt`.
- Mapping: PASS, every enforced property is mapped; evidence `/tmp/trj3/check-mapping-no-axiom-metadata.txt`.
- Adversarial-link: PASS, 40 valid vector threat links, invalid=0; evidence `/tmp/trj3/check-adversarial-threat-link-ca63fe6.txt`.

## Mutation lane status

- Aggregate kill-score: 30.7 percent baseline across the tracked trust-boundary mutation baseline (`docs/fuzzing/trust-boundary-mutants-baseline.toml`).
- Lane state: advisory by configuration. `scripts/mutants-gate.sh` passes because `cycle_end_tag` is empty and the evidence streak is 0/2; evidence `/tmp/trj3/mutants-gate-7200953.txt`.
- Activation evidence: `releases.toml: activation_evidence` points to `.planning/trajectory/sweep/M02-FOLLOWUPS.md`. The carry-forward owner is the mutation activation lane, which requires two consecutive full nightly sweeps at >=80 percent across the six configured trust-boundary crates before the gate can become blocking.

## Spec / wire-format audit

- `PROTOCOL.md` alignment: PASS for audited trajectory-2 wire surfaces after the per-milestone and cross-cutting fixes.
- v3.18 receipt / PQ migration: PASS with `--features pq`; evidence `/tmp/trj3/v318-migration-ca63fe6.txt`.
- Verdict-matrix cross-language: PASS, 0 divergences across Rust and WASM-browser required/subset drivers; evidence `/tmp/trj3/verdict-matrix-ca63fe6.txt`.
- Error code stability: PASS, generated `chio-errors` registry output is in sync; evidence `/tmp/trj3/errors-regen-ca63fe6.txt`.

## Residual carried-forward items

- Mutation activation remains the only P1 carry-forward: the baseline is below 80 percent and the gate is intentionally advisory until the documented nightly evidence exists.
- SDK verdict-driver expansion remains tracked in `.planning/trajectory/sweep/M02-FOLLOWUPS.md` for Python, TypeScript node-http, Go HTTP, and WASM-browser partial-capability coverage.
- No files exist under `.planning/trajectory-2/deferred/` at closeout; the directory is absent/empty.

## Ship verdict

trajectory-2 independent audit complete. M01-M10 were audited through categories A-H, P0/P1/P2 findings were fixed or explicitly carried forward, workspace gates passed locally, formal gates passed for the configured release lanes, and spec / wire-format checks passed. Ready for external security review with the mutation lane called out as advisory carry-forward rather than satisfied by an >=80 percent score.
