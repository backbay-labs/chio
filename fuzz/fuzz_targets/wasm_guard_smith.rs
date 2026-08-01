#![no_main]

use chio_wasm_guards::fuzz::fuzz_wasm_guard_smith;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_wasm_guard_smith(data);
});
