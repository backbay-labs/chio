// Incremental synthetic-root accumulator for `chio replay`.
//
// Computes SHA-256(receipt_canonical_bytes_0 || ... || receipt_canonical_bytes_n-1)
// in streaming fashion, matching the derivation in
// `tests/replay/src/cross_version/reverify.rs`. The output is bit-identical to
// a one-shot digest over the same concatenated input.

use sha2::{Digest, Sha256};

/// Length, in bytes, of the synthetic root produced by
/// [`MerkleAccumulator::finalize`].
pub const ROOT_LEN: usize = 32;

/// Streaming SHA-256 accumulator for the replay-corpus synthetic root.
///
/// Construct with [`MerkleAccumulator::new`], feed each receipt's
/// canonical-JSON bytes via [`MerkleAccumulator::append`], then call
/// [`MerkleAccumulator::finalize`] to obtain the 32-byte root. The
/// finalization step consumes the accumulator so a single instance
/// cannot accidentally produce two different roots.
///
/// The accumulator also tracks the receipt count so callers can sanity
/// check that the corpus was non-empty without re-walking the input.
#[derive(Debug, Clone)]
pub struct MerkleAccumulator {
    hasher: Sha256,
    count: usize,
}

impl MerkleAccumulator {
    /// Construct a fresh accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            count: 0,
        }
    }

    /// Fold one receipt's canonical-JSON bytes into the running root.
    ///
    /// Bytes MUST be the RFC 8785 / JCS canonicalization of the receipt
    /// (no trailing newline, no leading whitespace). Feeding raw NDJSON
    /// lines (which carry a `\n` terminator) would diverge from the
    /// corpus_smoke / reverify reference derivation.
    pub fn append(&mut self, receipt_canonical_bytes: &[u8]) {
        self.hasher.update(receipt_canonical_bytes);
        self.count = self.count.saturating_add(1);
    }

    /// Number of receipts folded into the root so far.
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Consume the accumulator and emit the 32-byte synthetic root.
    ///
    /// An accumulator with zero appended receipts returns the SHA-256 of
    /// the empty byte string. The replay command is expected to gate on
    /// the empty-corpus case at the reader layer (the log reader
    /// returns [`ReadError::Empty`] before any append happens), so this
    /// shape is a defensive default rather than a documented contract
    /// for downstream consumers.
    #[must_use]
    pub fn finalize(self) -> [u8; ROOT_LEN] {
        let digest = self.hasher.finalize();
        let mut root = [0u8; ROOT_LEN];
        root.copy_from_slice(&digest);
        root
    }

    /// Finalize and return the lowercase-hex encoding of the root (64 chars).
    #[must_use]
    pub fn finalize_hex(self) -> String {
        hex::encode(self.finalize())
    }
}

impl Default for MerkleAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_merkle_tests {
    use super::*;

    /// Helper: one-shot SHA-256 over the concatenation of the input
    /// slices. Mirrors the corpus_smoke / reverify derivation so the
    /// equivalence test below pins the streaming path against the
    /// reference.
    fn one_shot(chunks: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for c in chunks {
            hasher.update(c);
        }
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    #[test]
    fn append_single_receipt_matches_one_shot() {
        let bytes = br#"{"id":"rcpt-1","ok":true}"#;
        let mut acc = MerkleAccumulator::new();
        acc.append(bytes);
        assert_eq!(acc.count(), 1);
        let streamed = acc.finalize();
        let oneshot = one_shot(&[bytes]);
        assert_eq!(streamed, oneshot);
    }

    #[test]
    fn append_three_receipts_matches_concatenation() {
        let r0 = br#"{"id":"rcpt-0"}"#.as_slice();
        let r1 = br#"{"id":"rcpt-1"}"#.as_slice();
        let r2 = br#"{"id":"rcpt-2"}"#.as_slice();
        let mut acc = MerkleAccumulator::new();
        acc.append(r0);
        acc.append(r1);
        acc.append(r2);
        assert_eq!(acc.count(), 3);
        let streamed = acc.finalize();
        let oneshot = one_shot(&[r0, r1, r2]);
        assert_eq!(streamed, oneshot);
    }

    #[test]
    fn incremental_matches_one_shot_over_one_thousand_receipts() {
        // Synthesize 1k receipts, fold them through the accumulator, and
        // also build the equivalent one-shot input. Pin the accumulator
        // against the one-shot reference so any future change to the
        // streaming path that breaks byte-identity surfaces here.
        let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(1000);
        for i in 0..1000 {
            chunks.push(format!(r#"{{"id":"rcpt-{i}","seq":{i}}}"#).into_bytes());
        }
        let mut acc = MerkleAccumulator::new();
        for c in &chunks {
            acc.append(c);
        }
        assert_eq!(acc.count(), 1000);
        let streamed = acc.finalize();

        let mut hasher = Sha256::new();
        for c in &chunks {
            hasher.update(c);
        }
        let digest = hasher.finalize();
        let mut oneshot = [0u8; 32];
        oneshot.copy_from_slice(&digest);
        assert_eq!(streamed, oneshot);
    }

    #[test]
    fn finalize_hex_is_lowercase_64_chars() {
        let mut acc = MerkleAccumulator::new();
        acc.append(b"x");
        let hex = acc.finalize_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn empty_accumulator_returns_empty_sha256() {
        // Defensive: documents the zero-receipts edge as the SHA-256 of
        // the empty byte string. The replay command is expected to
        // reject the empty-corpus case at the reader layer (see
        // `replay::reader::ReadError::Empty`) so this branch only
        // surfaces in unit tests.
        let acc = MerkleAccumulator::new();
        assert_eq!(acc.count(), 0);
        let hex = acc.finalize_hex();
        // SHA-256 of "" pinned by RFC 6234 / NIST CAVP test vector.
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    #[test]
    fn append_empty_slice_is_no_op_for_bytes_but_advances_count() {
        // Folding an empty slice into SHA-256 leaves the running state
        // unchanged. The accumulator still counts the call so a corrupt
        // empty receipt is observable to the caller.
        let mut acc_empty = MerkleAccumulator::new();
        acc_empty.append(b"");
        let acc_skipped = MerkleAccumulator::new();
        // Same digest expected: appending b"" must not change the hash.
        let with_empty = acc_empty.clone().finalize();
        let baseline = acc_skipped.clone().finalize();
        assert_eq!(with_empty, baseline);
        // But the count must reflect the call.
        acc_empty.append(b"");
        assert_eq!(acc_empty.count(), 2);
        // And acc_skipped which did not receive any append stays at 0.
        let _ = acc_skipped.finalize();
    }
}
