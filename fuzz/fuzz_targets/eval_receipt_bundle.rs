//! Trust-boundary fuzz target for `chio-eval-receipt` bundle verification.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    chio_fuzz::entries::eval_receipt_bundle(data);
});
