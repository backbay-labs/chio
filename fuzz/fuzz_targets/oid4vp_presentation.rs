//! Trust-boundary fuzz target for `chio_credentials::verify_oid4vp_direct_post_response`.

#![no_main]

use chio_credentials::fuzz::fuzz_oid4vp_presentation;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_oid4vp_presentation(data);
});
