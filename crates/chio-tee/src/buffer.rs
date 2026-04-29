//! Raw-payload buffer with zeroize-on-drop semantics (M10 Phase 1 Task 6).
//!
//! The trajectory doc (`.planning/trajectory/10-tee-replay-harness.md`,
//! line 21 and line 566) requires that raw, pre-redaction payloads
//! observed by the tee never reach disk and never outlive the redactor
//! pass. [`RawPayloadBuffer`] is the in-memory carrier: a thin wrapper
//! around `Vec<u8>` that derives [`zeroize::Zeroize`] and
//! [`zeroize::ZeroizeOnDrop`] so the underlying allocation is wiped on
//! drop.
//!
//! Design notes:
//!
//! - There is intentionally NO accessor that returns owned bytes
//!   (`into_inner`, `to_vec`, etc.). Callers that need a copy of the
//!   plaintext must reach for [`RawPayloadBuffer::as_slice`] and copy
//!   explicitly; this keeps the zeroize-on-drop guarantee scoped to a
//!   single owner. Once the redactor returns, the redacted payload
//!   lives in a separate, unprotected `Vec<u8>` (it has already been
//!   stripped of secrets) while this buffer is dropped and zeroized.
//! - The struct is `#[derive(Zeroize, ZeroizeOnDrop)]`. No manual `Drop`
//!   impl is needed; the derive expands to the correct combination.
//! - The crate forbids `unsafe_code` (see `src/lib.rs`), so the zeroize
//!   guarantee is whatever the `zeroize` crate's safe-Rust path
//!   provides. That path uses `core::ptr::write_volatile` under the
//!   hood and is the strongest guarantee available without `unsafe` in
//!   downstream code.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// In-memory buffer holding pre-redaction payload bytes.
///
/// Drop wipes the inner `Vec<u8>`; the heap allocation is overwritten
/// with zeros before deallocation. See module-level docs for the
/// scoping rules callers MUST follow.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RawPayloadBuffer {
    inner: Vec<u8>,
}

impl core::fmt::Debug for RawPayloadBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawPayloadBuffer")
            .field("len", &self.inner.len())
            .finish()
    }
}

impl RawPayloadBuffer {
    /// Construct from an owned byte vector.
    ///
    /// Ownership transfers; the caller's previous `Vec<u8>` is moved
    /// into the buffer and will be zeroed on drop.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    /// Construct by copying from a borrowed slice.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self {
            inner: bytes.to_vec(),
        }
    }

    /// Borrow the underlying bytes.
    ///
    /// The slice is only valid for as long as `&self` is alive. Holding
    /// a reference past the buffer's lifetime is a borrow-check error,
    /// not a logic error.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Length of the buffered payload in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl AsRef<[u8]> for RawPayloadBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_round_trips_bytes() {
        let buf = RawPayloadBuffer::new(b"hello".to_vec());
        assert_eq!(buf.as_slice(), b"hello");
        assert_eq!(buf.len(), 5);
        assert!(!buf.is_empty());
    }

    #[test]
    fn from_slice_copies_bytes() {
        let src = b"world".to_vec();
        let buf = RawPayloadBuffer::from_slice(&src);
        assert_eq!(buf.as_slice(), b"world");
        // Original is still intact (we copied).
        assert_eq!(src, b"world");
    }

    #[test]
    fn is_empty_reports_correctly() {
        let empty = RawPayloadBuffer::new(Vec::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn manual_zeroize_clears_bytes() {
        // Sanity-check: calling `Zeroize::zeroize` directly should empty
        // the buffer. Drop ordering is the same path; this is the
        // closest test we can write without poking at freed memory.
        let mut buf = RawPayloadBuffer::new(b"sensitive".to_vec());
        buf.zeroize();
        assert!(buf.is_empty(), "zeroize should truncate the inner vec");
    }

    #[test]
    fn implements_zeroize_on_drop() {
        // Compile-time assertion: the public buffer type carries the
        // ZeroizeOnDrop trait bound. Replacing this with a plain Vec
        // would fail to compile.
        fn assert_zod<T: ZeroizeOnDrop>() {}
        assert_zod::<RawPayloadBuffer>();
    }

    #[test]
    fn debug_redacts_plaintext_bytes() {
        let buf = RawPayloadBuffer::new(b"sensitive-token".to_vec());
        let debug = std::format!("{buf:?}");
        assert!(debug.contains("len"));
        assert!(!debug.contains("sensitive-token"));
    }
}
