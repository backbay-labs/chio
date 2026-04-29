//! Trust-boundary fuzz target for `chio_wasm_guards` WIT host-call boundary serde (`GuardRequest`, `GuestDenyResponse`).

#![no_main]

use chio_wasm_guards::fuzz::fuzz_wit_host_call_boundary;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_wit_host_call_boundary(data);
});
