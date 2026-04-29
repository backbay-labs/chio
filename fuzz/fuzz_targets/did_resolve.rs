//! Trust-boundary fuzz target for `chio-did` DID URI parsing and document resolution.

#![no_main]

use chio_did::fuzz::fuzz_did_resolve;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_did_resolve(data);
});
