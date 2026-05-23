# Chio legacy Chio CLI gate

## Objective

Remove the default public `chio ...` compatibility surface from normal
CLI execution. Historical signed-artifact verification must use the explicit
Chio path `chio attest buyer verify-proof`. Direct `chio ...`
commands are blocked by default, and the env-gated legacy path is limited to
hidden help or command-tree inspection so it cannot emit artifacts.

## Plan

1. Capture the failing behavior: `chio help` succeeds by default and
   prints the hidden compatibility tree.
2. Add a pre-parse guard that rejects direct `chio ...` requests unless
   `CHIO_ENABLE_LEGACY_CHIO_CLI` is set.
3. Keep root `chio help` free of Chio entries and keep the explicit
   `chio attest buyer verify-proof` parser path.
4. Add focused unit tests for the guard helper.
5. Run direct CLI checks, focused parser tests, formatting, whitespace, and dash
   scan.

## Follow-up Plan: No Artifact Execution

1. Capture the failing behavior: with `CHIO_ENABLE_LEGACY_CHIO_CLI=1`,
   `chio attest buyer verify-proof` reaches the legacy verifier and exits from file IO
   rather than from the command boundary.
2. Add an integration regression proving env-gated `chio attest buyer verify-proof`
   exits with status 2 before dispatch and writes no report.
3. Preserve env-gated `chio help` for hidden command-tree inspection.
4. Add a post-parse guard that rejects any parsed `Commands::Chio` before
   the command match can call legacy handlers.
5. Update the architecture note and rerun focused CLI gates.

## Verification

- [x] `cargo run -p chio-cli --bin chio -- chio help` succeeds before implementation.
- [x] `cargo run -p chio-cli --bin chio -- chio help` fails by default.
- [x] `CHIO_ENABLE_LEGACY_CHIO_CLI=0 cargo run -p chio-cli --bin chio -- chio help` fails.
- [x] `CHIO_ENABLE_LEGACY_CHIO_CLI=1 cargo run -p chio-cli --bin chio -- chio help` succeeds for hidden inspection.
- [x] `cargo run -p chio-cli --bin chio -- help | rg -n "chio|Chio"` returns no matches.
- [x] `cargo test -p chio-cli --bin chio legacy_chio_cli`
- [x] `cargo test -p chio-cli --bin chio legacy_chio_cli_env_requires_explicit_truthy_value`
- [x] `cargo test -p chio-cli --bin chio_attest_legacy_chio_v1_verify_surface_parses`
- [x] `cargo test -p chio-cli --test legacy_chio_cli` fails before implementation because env-gated `chio attest buyer verify-proof` dispatches.
- [x] `cargo test -p chio-cli --test legacy_chio_cli` passes after the post-parse execution guard.
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
- [x] `cargo clippy -p chio-cli --all-targets -- -D warnings`
