//! Trust-boundary fuzz target: structure-aware canonical-JSON mutator self-driver.

#![no_main]

use chio_fuzz::canonical_json::canonical_json_mutate;
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

fuzz_target!(|data: &[u8]| {
    // Round-trip through serde_json::Value. We do not unwrap because
    // the mutator deliberately returns garbage bytes when it cannot
    // produce a valid canonical-JSON output (libFuzzer's contract
    // permits invalid candidates; the SUT here is the mutator, not the
    // parser). This call exists to give the harness a coverage-bearing
    // body so libFuzzer schedules iterations.
    let _ = serde_json::from_slice::<serde_json::Value>(data);
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
