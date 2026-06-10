//! Canonical invocation-hash dedupe for redacted capture frames.

use std::collections::HashMap;

use chio_core::{canonical_json_bytes, sha256_hex};
use chio_tee_frame::Frame;

use crate::Result;

/// A frame retained by dedupe, paired with its canonical invocation hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupedFrame {
    /// Lowercase SHA-256 hex of the RFC 8785 canonical JSON `invocation`.
    pub invocation_hash: String,
    /// The final frame observed for this invocation hash.
    pub frame: Frame,
}

/// Compute the stable dedupe key for a frame invocation.
pub fn invocation_hash(invocation: &serde_json::Value) -> Result<String> {
    let canonical = canonical_json_bytes(invocation)?;
    Ok(sha256_hex(&canonical))
}

/// Deduplicate already-redacted frames by canonical invocation hash.
///
/// Later frames replace earlier frames with the same canonical invocation
/// hash. Returned survivors are ordered by the index of their final
/// occurrence in the input stream.
pub fn dedupe_last_wins<I>(frames: I) -> Result<Vec<DedupedFrame>>
where
    I: IntoIterator<Item = Frame>,
{
    let mut by_hash: HashMap<String, (usize, Frame)> = HashMap::new();

    for (index, frame) in frames.into_iter().enumerate() {
        let hash = invocation_hash(&frame.invocation)?;
        by_hash.insert(hash, (index, frame));
    }

    let mut retained: Vec<(usize, DedupedFrame)> = by_hash
        .into_iter()
        .map(|(invocation_hash, (index, frame))| {
            (
                index,
                DedupedFrame {
                    invocation_hash,
                    frame,
                },
            )
        })
        .collect();
    retained.sort_by_key(|(index, _)| *index);

    Ok(retained.into_iter().map(|(_, frame)| frame).collect())
}
