//! Trust-boundary fuzz target for the hosted Firecracker worker protocol.

#![no_main]

use chio_fuzz::entries::finding_worker_protocol;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    finding_worker_protocol(data);
});
