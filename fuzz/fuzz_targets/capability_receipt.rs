//! Trust-boundary fuzz target for `chio-core-types` `CapabilityToken` and `ChioReceipt` canonical-JSON deserialization.

#![no_main]

use chio_core_types::{CapabilityToken, ChioReceipt};
use chio_fuzz::canonical_json::canonical_json_mutate;
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

fuzz_target!(|data: &[u8]| {
    // Try CapabilityToken first; on success, drive the verify path.
    if let Ok(token) = serde_json::from_slice::<CapabilityToken>(data) {
        // Signature verification is fail-closed: we accept Ok(false) /
        // Err(_) as expected outcomes. The point is that the call must
        // not panic on any structurally valid CapabilityToken.
        let _ = token.verify_signature();
    }

    // Try ChioReceipt independently. Same byte stream, different typed
    // deserializer, different fail-closed surface.
    if let Ok(receipt) = serde_json::from_slice::<ChioReceipt>(data) {
        let _ = receipt.verify_signature();
    }
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
