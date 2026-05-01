# M02 P0/P1/P2 Sweep Fix List

Source inventory: 10 unresolved Codex-bot review threads across M02 PRs #319,
#334, #335, #345, and #347. No `.planning/trajectory-2/deferred/m02-*.md`
files exist. The M02 audit also lists mutation activation and partial
non-Rust verdict drivers as residual risk.

| Source | Severity | File path | Intended fix one-liner | Gate command |
| --- | --- | --- | --- | --- |
| PR #319 comment 3164371422 | P1 | `.planning/trajectory-2/mutants-baseline.toml` | Verified already addressed on current main: TOML now parses without duplicate keys. | `python3 -c 'import pathlib,tomllib; tomllib.loads(pathlib.Path(".planning/trajectory-2/mutants-baseline.toml").read_text())'` |
| PR #334 comment 3165600404 | P2 | `crates/chio-conformance/verdict_matrix/src/lib.rs` | Verified already addressed on current main: `scope_set` normalization sorts without deduping and has a regression test. | `cargo test -p chio-conformance verdict_tuple_normalizes_scope_set_without_deduping --quiet` |
| PR #335 comment 3165596476 | P2 | `.planning/trajectory-2/mutants-baseline.toml` | Verified already addressed on current main: aggregate unviable total matches per-crate sums. | `python3 -c 'import pathlib,tomllib; d=tomllib.loads(pathlib.Path(".planning/trajectory-2/mutants-baseline.toml").read_text()); assert d["aggregate"]["unviable_total"] == sum(c.get("unviable_count",0) for c in d["crate"].values())'` |
| PR #345 comment 3168137000 | P2 | `.github/workflows/mutants.yml` | Verified already addressed on current main: comment and issue filing run before the gate result is enforced. | `rg -n "continue-on-error: true|Enforce mutation gate result" .github/workflows/mutants.yml` |
| PR #345 comment 3168275020 | P1 | `scripts/mutants-gate.sh` | Verified already addressed on current main: blocking mode enforces `target_catch_ratio_percent`. | `bash -n scripts/mutants-gate.sh` |
| PR #345 comment 3168321125 | P2 | `.github/workflows/mutants.yml` | Verified already addressed on current main: survivor cap is read from `releases.toml`. | `rg -n "pr_survivor_issue_budget|survivor-cap" .github/workflows/mutants.yml` |
| PR #345 comment 3168742908 | P1 | `scripts/mutants-gate.sh` | Verified already addressed on current main: caught ratio is scored against scoreable mutants, excluding unviable outcomes. | `bash -n scripts/mutants-gate.sh` |
| PR #347 comment 3168189218 | P2 | `crates/chio-conformance/verdict_matrix/src/driver.rs` | Treat Rust kernel feature requirements as supported while still rejecting sidecar-only driver requirements. | `cargo test -p chio-conformance --test verdict_matrix_rust_driver --quiet` |
| PR #347 comment 3168189227 | P2 | `.github/workflows/verdict-matrix.yml` | Verified already addressed on current main: reason registry changes trigger the verdict-matrix workflow. | `rg -n "spec/errors/registry.yaml" .github/workflows/verdict-matrix.yml` |
| PR #347 comment 3168362819 | P2 | `.github/workflows/verdict-matrix.yml` | Add `chio-core` and `chio-core-types` to verdict-matrix workflow path filters. | `rg -n "crates/chio-core" .github/workflows/verdict-matrix.yml` |
| Pre-existing baseline regression | P2 | `crates/chio-conformance/verdict_matrix/Cargo.toml` | Add the browser-kernel dependency and explicit JSON type so the verdict-matrix sub-workspace test compiles. | `cargo test --manifest-path crates/chio-conformance/verdict_matrix/Cargo.toml` |
| M02 audit residual | P1 | `releases.toml`, `.planning/audits/M02-mutation-and-verdict-matrix.md` | Carry forward mutation activation until two full nightly sweeps meet the >= 80 percent target. | `rg -n "activation_evidence|M02 sweep tracking note" releases.toml .planning/audits/M02-mutation-and-verdict-matrix.md` |
| M02 audit residual | P2 | `.planning/trajectory/sweep/M02-FOLLOWUPS.md` | Carry forward partial Python, TypeScript, Go, and WASM driver coverage to their owning SDK or browser surfaces. | `rg -n "python-sdk|typescript-node-http|go-http-sdk|wasm-browser" .planning/trajectory/sweep/M02-FOLLOWUPS.md` |
