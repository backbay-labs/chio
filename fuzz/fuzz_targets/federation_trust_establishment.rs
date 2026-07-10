//! Trust-boundary fuzz target for `chio-federation` kernel trust establishment.

#![no_main]

use chio_fuzz::canonical_json::canonical_json_mutate;
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

fuzz_target!(|data: &[u8]| {
    chio_fuzz::entries::federation_trust_establishment(data);
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
