//! Trust-boundary fuzz target for `chio-a2a-adapter` SSE-decode and per-envelope fan-out.

#![no_main]

use chio_a2a_adapter::fuzz::fuzz_a2a_envelope_decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_a2a_envelope_decode(data);
});
