//! Trust-boundary fuzz target for `chio_credentials::verify_chio_passport_jwt_vc_json`.

#![no_main]

use chio_credentials::fuzz::fuzz_jwt_vc_verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_jwt_vc_verify(data);
});
