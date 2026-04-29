//! Trust-boundary fuzz target for `chio-anchor` proof-bundle and checkpoint publication records.

#![no_main]

use chio_anchor::fuzz::fuzz_anchor_bundle_verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_anchor_bundle_verify(data);
});
