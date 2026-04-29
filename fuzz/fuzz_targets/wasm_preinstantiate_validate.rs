//! Trust-boundary fuzz target for `chio_wasm_guards` preinstantiate-validate path (`ComponentBackend::load_module`, `WasmtimeBackend::load_module`, `detect_wasm_format`).

#![no_main]

use chio_wasm_guards::fuzz::fuzz_wasm_preinstantiate_validate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_wasm_preinstantiate_validate(data);
});
