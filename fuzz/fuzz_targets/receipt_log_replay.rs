//! Trust-boundary fuzz target for `chio-kernel-core` NDJSON receipt-log decode, signature verify, and chain-invariant check.

#![no_main]

use chio_kernel_core::fuzz::fuzz_receipt_log_replay;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_receipt_log_replay(data);
});
