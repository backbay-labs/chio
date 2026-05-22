# Chio runtime facade boundary

## Objective

Introduce a Chio-named `chio-runtime` crate boundary for runtime admission,
orchestration, operations, and signing surfaces that are still implemented by
the historical runtime core. Public `chio runtime ...` CLI dispatch should use
the Chio-named dependency rather than naming `chio_runtime_core` directly.

## Plan

1. Capture the current gap with a grep showing CLI runtime dispatch modules
   still call `chio_runtime_core::`.
2. Add `crates/chio-runtime` as a workspace facade over the historical runtime
   core.
3. Move CLI runtime dispatch references to `chio_runtime::`.
4. Run focused facade, CLI runtime dispatch, clippy, formatting, whitespace,
   and dash checks.

## Verification

- [x] `rg -n "chio_runtime_core::" crates/chio-cli/src/cli/chio/dispatch/runtime crates/chio-cli/src/cli/chio/dispatch/runtime.rs` finds direct old-crate references before implementation.
- [x] `rg -n "chio_runtime_core::" crates/chio-cli/src/cli/chio/dispatch/runtime crates/chio-cli/src/cli/chio/dispatch/runtime.rs` returns no matches.
- [x] `cargo test -p chio-runtime`
- [x] `cargo test -p chio-cli --bin chio_runtime`
- [x] `cargo clippy -p chio-runtime --all-targets -- -D warnings`
- [x] `cargo clippy -p chio-cli --bin chio -- -D warnings`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
