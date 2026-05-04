//! Trust-boundary fuzz target for `chio-eval-receipt` bundle verification.

#![no_main]

use chio_eval_receipt::verify_bundle;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle_json) = std::str::from_utf8(data) {
        let _ = verify_bundle(bundle_json);
    }
});
