//! Trust-boundary fuzz target for `chio_wasm_guards` runtime-execution path.
//!
//! Companion to `wasm_preinstantiate_validate.rs`: this target drives the
//! post-load `evaluate` surface and covers the eight WASM-guard escape
//! classes catalogued at
//! `.planning/trajectory-2/05-adversarial-escape-threat-model.md` (P3):
//! undeclared host imports, oversized linear memory, fuel-budget exhaustion,
//! table grow/abuse, stack overflow via deep recursion, host reentry,
//! malformed component-model encoding, and signed-but-malicious modules.

#![no_main]

use chio_wasm_guards::fuzz::fuzz_wasm_guard_escape;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_wasm_guard_escape(data);
});
