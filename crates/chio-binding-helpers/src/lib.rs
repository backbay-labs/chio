//! Bindings-friendly invariant helpers for multi-language Chio SDKs.
//!
//! This crate intentionally exposes a small surface over `chio-core`:
//!
//! - canonical JSON from raw JSON strings
//! - capability parsing and verification helpers
//! - hashing and signing helpers
//! - signed manifest parsing and verification helpers
//! - receipt parsing and verification helpers
//!
//! Session runtime, transport, auth, and callback orchestration stay in the
//! language-native SDKs.

pub mod canonical;
pub mod capability;
pub mod error;
pub mod hashing;
pub mod manifest;
pub mod receipt;
pub mod signing;

pub use canonical::canonicalize_json_str;
pub use capability::{
    capability_body_canonical_json, parse_capability_json, verify_capability,
    verify_capability_json, CapabilityTimeStatus, CapabilityVerification,
};
pub use error::{Error, ErrorCode, Result};
pub use hashing::{sha256_hex_bytes, sha256_hex_utf8};
pub use manifest::{
    parse_signed_manifest_json, signed_manifest_body_canonical_json, verify_signed_manifest,
    verify_signed_manifest_json, ManifestVerification,
};
pub use receipt::{
    parse_receipt_json, receipt_body_canonical_json, verify_receipt, verify_receipt_json,
    verify_receipt_json_with_trusted_signer_hex, verify_receipt_with_trusted_signer_hex,
    verify_receipt_with_trusted_signers, ReceiptDecisionKind, ReceiptVerification,
};
pub use signing::{
    is_valid_public_key_hex, is_valid_signature_hex, public_key_hex_matches, sign_json_str_ed25519,
    sign_utf8_message_ed25519, verify_json_str_signature_ed25519, verify_utf8_message_ed25519,
    CanonicalJsonSignature, Utf8MessageSignature,
};
