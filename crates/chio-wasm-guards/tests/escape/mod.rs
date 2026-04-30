//! WASM guard escape harness (M05.P3).
//!
//! Eight named escape classes drive adversarial-but-well-formed WASM
//! modules through the `chio-wasm-guards` runtime and assert that every
//! attempt yields a typed [`chio_wasm_guards::WasmGuardError`] (never a
//! panic, never an escape from linear memory, never an undeclared host
//! import).
//!
//! Source of truth: `.planning/trajectory-2/05-adversarial-escape-threat-model.md`
//! (Phase 3). Companion fuzz target: `fuzz/fuzz_targets/wasm_guard_escape.rs`.
//!
//! The frozen runtime-limit snapshot at
//! `crates/chio-wasm-guards/tests/escape/config.frozen.toml` guards
//! against silent config drift: if the live `MAX_MEMORY_BYTES`,
//! `DEFAULT_MAX_MODULE_SIZE`, or escape fuel ceiling change, every
//! fixture in this harness fails until the snapshot and the live
//! constants are realigned through a CODEOWNERS review.

#![cfg(feature = "wasmtime-runtime")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

// First batch (M05.P3.T2): undeclared host imports, oversized linear
// memory, fuel-budget exhaustion mid-call.
mod fuel_exhaustion;
mod oversize_memory;
mod undeclared_imports;

// Second batch (M05.P3.T3): table grow / abuse, stack overflow via
// deep recursion, host re-entry abuse.
mod deep_recursion;
mod host_reentry;
mod table_grow;

// Third batch (M05.P3.T4): malformed component-model encoding,
// signed-but-malicious modules.
mod malformed_component;
mod signed_but_malicious;

// Determinism gate (M05.P3.T5): aggregate every escape class and
// pin the taxonomy at N=8.
mod aggregate;
