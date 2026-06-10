//! libFuzzer entry-point module for `chio-anchor`. Gated behind `fuzz` feature.

use chio_kernel::checkpoint::CheckpointTransparencySummary;

use crate::{verify_checkpoint_publication_records, verify_proof_bundle, AnchorProofBundle};

pub fn fuzz_anchor_bundle_verify(data: &[u8]) {
    if let Ok(bundle) = serde_json::from_slice::<AnchorProofBundle>(data) {
        let _ = verify_proof_bundle(&bundle);
    }
    if let Ok(transparency) = serde_json::from_slice::<CheckpointTransparencySummary>(data) {
        let _ = verify_checkpoint_publication_records(&transparency);
    }
}
