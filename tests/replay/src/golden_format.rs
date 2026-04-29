//! Shared on-disk format contract for the M04 replay-gate goldens.
//!
//! This module is the single source of truth for the constants that
//! the writer ([`crate::golden_writer`]) emits and the reader
//! ([`crate::golden_reader`]) verifies. Co-locating them eliminates
//! the writer-reader desync risk from earlier revisions where each
//! module redeclared its own copy of the filenames and length
//! invariants.
//!
//! It also re-exports the canonical JSON serializer the goldens are
//! built against. The replay-gate corpus uses the workspace-wide RFC
//! 8785 implementation in
//! [`chio_core_types::canonical::canonicalize`] so a single canonical
//! JSON definition governs receipts, checkpoints, signed plans, and
//! every other deterministic-bytes artifact in the project. Earlier
//! revisions of the writer hand-rolled their own BTreeMap-based
//! reshape with `serde_json::to_string`; for the ASCII-only goldens
//! that ship in the corpus the bytes coincide, but the duplication
//! risked drift the day a non-ASCII string entered the receipt stream.

use std::io;

use chio_core_types::canonical::canonicalize as core_canonicalize;
use serde_json::Value;

/// Length, in bytes, of a Merkle root hash produced by the kernel.
pub const ROOT_LEN: usize = 32;

/// Length, in characters, of a 32-byte root encoded as lowercase hex.
pub const ROOT_HEX_LEN: usize = ROOT_LEN * 2;

/// Filename for the per-scenario NDJSON receipt stream.
pub const RECEIPTS_FILENAME: &str = "receipts.ndjson";

/// Filename for the per-scenario canonical-JSON checkpoint.
pub const CHECKPOINT_FILENAME: &str = "checkpoint.json";

/// Filename for the per-scenario raw-hex Merkle root.
pub const ROOT_FILENAME: &str = "root.hex";

/// Suffix for staged temporary writes (renamed into place on commit).
pub const TMP_SUFFIX: &str = ".tmp";

/// Canonicalize a [`serde_json::Value`] to its RFC 8785 byte form.
///
/// Thin wrapper over [`chio_core_types::canonical::canonicalize`] that
/// adapts the chio-core error into a `std::io::Error`. The replay
/// gate's writer / reader / synthesis surfaces uniformly want either
/// "raw bytes" or an `io::Error`; this keeps the call sites linear
/// without leaking the chio-core error type into module APIs.
///
/// The output is byte-for-byte stable across `serde_json` versions
/// because the canonicaliser does not depend on `serde_json`'s
/// internal map ordering: it walks the value tree, sorts object keys
/// by UTF-16 code unit, and emits the bytes itself.
pub fn canonical_json_bytes(value: &Value) -> io::Result<Vec<u8>> {
    core_canonicalize(value)
        .map(String::into_bytes)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("canonicalize: {err}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn root_hex_len_matches_root_len_doubled() {
        assert_eq!(ROOT_HEX_LEN, ROOT_LEN * 2);
        assert_eq!(ROOT_HEX_LEN, 64);
    }

    #[test]
    fn canonical_json_bytes_sorts_object_keys() {
        let v = json!({"b": 1, "a": 2});
        let bytes = canonical_json_bytes(&v).unwrap();
        assert_eq!(bytes, br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn canonical_json_bytes_recurses() {
        let v = json!({"x": {"d": 1, "c": 2}});
        let bytes = canonical_json_bytes(&v).unwrap();
        assert_eq!(bytes, br#"{"x":{"c":2,"d":1}}"#);
    }

    #[test]
    fn canonical_json_bytes_no_whitespace() {
        let v = json!({"a": [1, 2, 3]});
        let bytes = canonical_json_bytes(&v).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(!s.contains(' '));
        assert!(!s.contains('\n'));
    }
}
