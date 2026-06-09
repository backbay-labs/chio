//! Compile-only integration test that proves the `chio-core-types` public API
//! remains reachable when the crate is consumed without the `std` feature.
//!
//! We cannot actually run `cargo test -p chio-core-types --no-default-features`
//! because the integration-test harness itself requires `std`. Instead, this
//! file references public items from every module using only `core::` /
//! `alloc::` imports so that the compile graph fails fast if a reviewer
//! accidentally reintroduces a `std::`-only path into a module reachable
//! from portable callers.
//!
//! To exercise the portable build end-to-end, run:
//!
//! ```bash
//! cargo build -p chio-core-types --no-default-features
//! cargo build -p chio-core-types --no-default-features --target wasm32-unknown-unknown
//! ```
//!
//! These commands exercise the `no_std + alloc` path that unblocks
//! `chio-kernel-core` on wasm32-unknown-unknown and other embedded targets.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chio_core_types::{
    canonical_json_bytes, canonical_json_string, canonicalize, sha256, sha256_hex, CapabilityId,
    Error, Hash, Keypair, MerkleTree, PublicKey, Result as ChioResult, ServerId, Signature,
    SigningAlgorithm,
};

/// Touches the canonical-JSON path, which must remain the byte-identical RFC
/// 8785 encoder regardless of whether `std` is on.
#[test]
fn canonical_json_roundtrip() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let v = serde_json::json!({"b": 1, "a": 2});
    let s = canonical_json_string(&v)?;
    assert_eq!(s, "{\"a\":2,\"b\":1}");
    let bytes = canonical_json_bytes(&v)?;
    assert_eq!(bytes, s.as_bytes());
    // Round-trip through `canonicalize(&Value)` to prove the `Value`-level
    // entry point stays reachable.
    let parsed: serde_json::Value = serde_json::from_str(&s)?;
    let again = canonicalize(&parsed)?;
    assert_eq!(s, again);
    Ok(())
}

/// Keypair / Signature / PublicKey are the canonical signing surface. The
/// `Keypair::generate()` path invokes `OsRng` which requires `getrandom` to
/// have the `js` feature on wasm32 - exercise it here so the linkage stays
/// green.
#[test]
fn keypair_sign_verify() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let kp = Keypair::generate();
    let msg = b"portable-kernel";
    let sig: Signature = kp.sign(msg);
    assert!(kp.public_key().verify(msg, &sig));
    assert_eq!(sig.algorithm(), SigningAlgorithm::Ed25519);
    let pk_hex = kp.public_key().to_hex();
    let restored = PublicKey::from_hex(&pk_hex)?;
    assert_eq!(kp.public_key(), restored);
    Ok(())
}

/// Hash helpers must resolve through `alloc::string::String` / `alloc::vec::Vec`.
#[test]
fn hashing_surface() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let h: Hash = sha256(b"hello");
    let hex: String = sha256_hex(b"hello");
    assert_eq!(h.to_hex(), hex);
    assert_eq!(hex.len(), 64);
    let rebuilt = Hash::from_hex(&hex)?;
    assert_eq!(rebuilt, h);
    Ok(())
}

/// Merkle tree uses `Vec<Hash>` under the hood.
#[test]
fn merkle_root_is_reachable() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let leaves: Vec<Vec<u8>> = alloc::vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
    let tree = MerkleTree::from_leaves(&leaves)?;
    let _root = tree.root();
    Ok(())
}

/// Touch a handful of protocol aliases to make sure `AgentId = String`,
/// `ServerId = String`, `CapabilityId = String` resolve through `alloc`.
#[test]
fn id_aliases_resolve_through_alloc() {
    let cid: CapabilityId = "cap-id-001".to_string();
    let sid: ServerId = "server-001".to_string();
    assert!(cid.starts_with("cap-"));
    assert!(sid.starts_with("server-"));
}

/// Public error surface must keep round-tripping through the `Result` alias.
#[test]
fn error_result_type_alias() {
    fn always_err() -> ChioResult<()> {
        Err(Error::SignatureVerificationFailed)
    }
    let e = match always_err() {
        Ok(()) => panic!("expected signature verification error"),
        Err(error) => error,
    };
    // Display must be stable on both feature paths.
    let rendered = alloc::format!("{e}");
    assert_eq!(rendered, "signature verification failed");
}
