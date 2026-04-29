# M02: Mutation Gate + Cross-SDK Verdict Differential

**Wave:** W1  |  **Trust-boundary:** no  |  **Tickets:** 30  |  **Effort:** 40.00 days

## In one paragraph

M02 calibrates the trajectory-1 test mass by flipping a `cargo-mutants` >= 80%-kill gate on six trust-boundary crates and ships a cross-SDK semantic verdict-matrix harness that diffs Rust/Python/TypeScript/WASM-browser/Go kernels against a hash-pinned scenario corpus. It gates M07 SDK regressions and is the referee oracle for the M05 adversarial suite and M08 arena.

## Phases at a glance

| Phase | Tickets | One-liner |
|---|---|---|
| P0 | 2 | Audit doc snapshot + Cargo.lock bump and `cargo-mutants` re-pin |
| P1 | 6 | Mutation baseline per crate (chio-policy, -credentials, -attest-verify, -kernel-core, -guards, -anchor) |
| P2 | 6 | Targeted test work to raise per-crate kill rate to >= 80% |
| P3 | 5 | Mutation-gate flip to required-CI; PR-comment + auto-issue + README banner |
| P4 | 5 | `verdict_matrix/` harness scaffold + Rust kernel driver + diff oracle |
| P5 | 6 | Python / TypeScript / WASM-browser / Go drivers + cross-language gate |

## Load-bearing artifacts

- `mutants-baseline.toml` and per-crate `mutants.toml` (M02.P1.T6)
- `.github/workflows/mutants.yml` required-CI lane (M02.P3.T1)
- `crates/chio-conformance/verdict_matrix/` (M02.P4.T1 scaffolds)
- `verdict_matrix/manifest.toml` hash-pinned corpus (M02.P4.T4)
- `verdict_matrix/drivers/{rust,python,typescript,wasm-browser,go}/` (P4.T3, P5.T1-T4)
- `.github/workflows/verdict-matrix.yml` (M02.P5.T5)

## Cross-trajectory deps

- trajectory-1 M01 canonical-JSON vectors - consumed as the encoding oracle (soft_dep)
- trajectory-1 M07 fabric trait - cross-SDK matrix exercises this surface (soft_dep)
- trajectory-2 M01 error registry - verdict differential classifies failures by `urn:chio:error:*` code
- trajectory-2 M05 adversarial suite manifest - matrix oracle input (soft_dep on M05.P2.T4)
- trajectory-2 M07 - new framework adapters must pass the matrix; M07 P3.T6 / P4.T5 references

## Locked decisions

- D06 Mutation gate covers six trust-boundary crates (adds chio-attest-verify and chio-anchor)
- D07 Cross-SDK matrix covers five primary kernels (Rust, Python, TS-node-http, WASM-browser, Go); JVM/dotnet/lambda/k8s deferred to M07

## Active freezes

none.

## When this milestone is done

- `.cargo/mutants.toml` scopes the six trust-boundary crates; per-crate `mutants.toml` files exist with rationale-annotated skip lists.
- `mutants-baseline.toml` checked in with date-stamped initial kill scores; nightly `mutants-nightly` reports >= 80% caught two consecutive runs before P3.T1.
- `mutants-pr` job runs in required mode for PRs touching the six crates; PR-comment surface and auto-issue path live.
- `crates/chio-conformance/verdict_matrix/` ships scenario format spec, hash-pinned `manifest.toml`, scenario corpus, five drivers, and `diff_oracle.rs`.
- `.github/workflows/verdict-matrix.yml` runs all five drivers as required-CI on SDK paths; divergence count = 0.
- Audit doc at `.planning/audits/M02-mutation-and-verdict-matrix.md` records before/after kill scores, scenario count, corpus hash.
