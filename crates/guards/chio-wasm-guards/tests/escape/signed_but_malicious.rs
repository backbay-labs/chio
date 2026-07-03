//! Escape class: signed but malicious modules.
//!
//! Threat: an attacker who controls a signing key (or whose key has
//! been transitively trusted) signs a perfectly-malformed-or-malicious
//! module. The cosign / ed25519 signing layer cannot tell the
//! difference between a benign and a malicious module: it only
//! certifies provenance. The runtime guard layer is therefore the
//! second line of defense, and a "signed-but-malicious" module must
//! still trip a typed `WasmGuardError`.
//!
//! Defense: `verify_signed_module` checks SHA-256 of the bytes and the
//! ed25519 signature against the trusted key; it accepts a malicious
//! module that hashes correctly and was signed by the trusted key.
//! Loading and running that module then surfaces the malicious
//! behavior through the standard escape paths (ImportViolation,
//! ModuleTooLarge, FuelExhausted, Trap...).
//!
//! Cross-link: chio-guard-registry cosign-verified fixtures live in
//! `crates/guards/chio-guard-registry/tests/`. The sigstore-bundle path is
//! content-agnostic in exactly the same way as the ed25519 sidecar
//! path; using ed25519 here keeps the harness self-contained and avoids
//! pulling sigstore into the unit-test dependency closure.

use chio_wasm_guards::abi::WasmGuardAbi;
use chio_wasm_guards::error::WasmGuardError;
use chio_wasm_guards::manifest::{signed_module_message, verify_signed_module, SignedWasmModule};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::Digest;

use super::common::{fresh_wasmtime_backend, load_frozen_config};

/// Build a `SignedWasmModule` for `bytes` using `sk`. Mirrors the
/// helper in `manifest.rs::tests::make_signed`.
fn sign_bytes(sk: &SigningKey, bytes: &[u8], name: &str, version: &str) -> SignedWasmModule {
    let module_hash = hex::encode(sha2::Sha256::digest(bytes));
    let signer_public_key = hex::encode(sk.verifying_key().to_bytes());
    let message = signed_module_message(&module_hash, name, version, &signer_public_key);
    let signature = sk.sign(&message);
    SignedWasmModule {
        module_hash,
        module_name: name.to_string(),
        version: version.to_string(),
        signer_public_key,
        signature: hex::encode(signature.to_bytes()),
    }
}

/// A module that imports `wasi_snapshot_preview1.fd_write`, signed
/// with a freshly-generated ed25519 key. The signing layer accepts the
/// signature; the runtime layer rejects the import via the import-namespace check.
#[test]
fn signed_undeclared_import_is_rejected() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    // Sign it.
    let sk = SigningKey::generate(&mut OsRng);
    let signed = sign_bytes(&sk, &bytes, "evil", "1.0.0");
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    // Signing layer accepts: the bytes hash correctly, the signature
    // verifies. This is the "signed-but-malicious" precondition.
    verify_signed_module(&bytes, &signed, &pk_hex)
        .expect("malicious module is correctly signed; signing layer accepts it");

    // Runtime layer catches it.
    let (_engine, mut backend) = fresh_wasmtime_backend();
    let err = backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect_err("runtime must reject the undeclared import");

    match err {
        WasmGuardError::ImportViolation { module, .. } => {
            assert_eq!(module, "wasi_snapshot_preview1");
        }
        other => panic!("expected ImportViolation, got {other:?}"),
    }
}

/// A module that declares 1024 pages of linear memory, signed.
/// Signing layer accepts; runtime layer surfaces a Trap when the
/// per-Store memory limiter denies instantiation.
#[test]
fn signed_oversize_memory_is_caught_at_instantiate() {
    let cfg = load_frozen_config();
    let wat = r#"
        (module
          (memory (export "memory") 1024)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat).expect("wat compile");

    let sk = SigningKey::generate(&mut OsRng);
    let signed = sign_bytes(&sk, &bytes, "evil-mem", "1.0.0");
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    verify_signed_module(&bytes, &signed, &pk_hex).expect("malicious module is correctly signed");

    let (_engine, mut backend) = fresh_wasmtime_backend();
    backend
        .load_module(&bytes, cfg.escape_fuel_limit)
        .expect("oversize-memory module loads");

    let request = super::common::minimal_request();
    let err = backend
        .evaluate(&request)
        .expect_err("instantiation must trap on oversize declared memory");

    match err {
        WasmGuardError::Trap(_) => {}
        other => panic!("expected Trap, got {other:?}"),
    }
}

/// Hash-grafting attempt: an attacker tries to substitute different
/// bytes into the slot referenced by a valid signature. The signing
/// layer catches this BEFORE the runtime ever sees the bytes; the
/// fixture documents that the trust-boundary order is signing-first,
/// runtime-second.
#[test]
fn grafted_bytes_are_caught_at_signing_layer() {
    let cfg = load_frozen_config();
    let _ = cfg; // frozen-config drift assertion runs as a side effect

    let wat_a = r#"
        (module
          (memory (export "memory") 1)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
    "#;
    let wat_b = r#"
        (module
          (memory (export "memory") 2)
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 1)))
    "#;
    let bytes_a = wat::parse_str(wat_a).expect("wat compile A");
    let bytes_b = wat::parse_str(wat_b).expect("wat compile B");

    let sk = SigningKey::generate(&mut OsRng);
    // Signature is over bytes_a; we present bytes_b at verify time.
    let signed = sign_bytes(&sk, &bytes_a, "evil-graft", "1.0.0");
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    let err = verify_signed_module(&bytes_b, &signed, &pk_hex)
        .expect_err("grafted bytes must be rejected at the signing layer");
    match err {
        WasmGuardError::HashMismatch { .. } => {}
        other => panic!("expected HashMismatch, got {other:?}"),
    }
}
