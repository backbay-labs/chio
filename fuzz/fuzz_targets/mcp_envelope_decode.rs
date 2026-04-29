//! Trust-boundary fuzz target for `chio-mcp-edge` NDJSON decode and evaluator dispatch.

#![no_main]

use chio_fuzz::canonical_json::canonical_json_mutate;
use chio_mcp_edge::fuzz::fuzz_mcp_envelope_decode;
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

fuzz_target!(|data: &[u8]| {
    fuzz_mcp_envelope_decode(data);
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
