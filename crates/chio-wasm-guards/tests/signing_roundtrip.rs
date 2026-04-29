//! Integration test for Phase 1.3 WASM guard module signing.
//!
//! Covers:
//!
//! - sign a wasm module + load it through `load_signed_guard` succeeds.
//! - tampering with the wasm bytes after signing causes load to fail.
//! - a missing sidecar without `allow_unsigned` causes load to fail with a
//!   clear "not signed" error.
//! - `allow_unsigned: true` with no sidecar loads successfully (warning path).

#![cfg(feature = "wasmtime-runtime")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use chio_wasm_guards::manifest::{
    signed_module_message, write_signature_sidecar, GuardManifest, SignedWasmModule,
    REQUIRED_WIT_WORLD, SIGNATURE_SUFFIX,
};
use chio_wasm_guards::{load_signed_guard, WasmGuardError};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use wasmtime::Engine;

/// A minimal valid core WASM module (empty but recognized by wasmparser).
const MINIMAL_WASM: &[u8] = b"\x00asm\x01\x00\x00\x00";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_wasm(dir: &Path, filename: &str) -> std::path::PathBuf {
    let p = dir.join(filename);
    std::fs::write(&p, MINIMAL_WASM).unwrap();
    p
}

fn make_manifest(
    name: &str,
    version: &str,
    wasm_filename: &str,
    wasm_sha256: &str,
    signer_public_key: Option<String>,
    allow_unsigned: bool,
) -> GuardManifest {
    GuardManifest {
        name: name.to_string(),
        version: version.to_string(),
        abi_version: "1".to_string(),
        wit_world: Some(REQUIRED_WIT_WORLD.to_string()),
        wasm_path: wasm_filename.to_string(),
        wasm_sha256: wasm_sha256.to_string(),
        config: HashMap::new(),
        signer_public_key,
        allow_unsigned,
    }
}

fn sign_bytes(sk: &SigningKey, bytes: &[u8], name: &str, version: &str) -> SignedWasmModule {
    let module_hash = sha256_hex(bytes);
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

#[test]
fn signed_module_loads_successfully() {
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = write_wasm(dir.path(), "g.wasm");

    let sk = SigningKey::generate(&mut OsRng);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    let signed = sign_bytes(&sk, MINIMAL_WASM, "g", "0.1.0");
    write_signature_sidecar(wasm_path.to_str().unwrap(), &signed).unwrap();

    let manifest = make_manifest(
        "g",
        "0.1.0",
        "g.wasm",
        &sha256_hex(MINIMAL_WASM),
        Some(pk_hex),
        false,
    );

    let engine = Arc::new(Engine::default());
    let backend = match load_signed_guard(engine, wasm_path.to_str().unwrap(), 1_000_000, &manifest)
    {
        Ok(b) => b,
        Err(e) => panic!("signed module should load: {e}"),
    };
    assert_eq!(backend.backend_name(), "wasmtime");
}

#[test]
fn tampered_bytes_fail_to_load() {
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = dir.path().join("g.wasm");

    // Sign over the original bytes.
    let sk = SigningKey::generate(&mut OsRng);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    let signed = sign_bytes(&sk, MINIMAL_WASM, "g", "0.1.0");

    // But write DIFFERENT bytes to disk after signing.
    let mut tampered = MINIMAL_WASM.to_vec();
    tampered.push(0x00); // extra byte changes digest
    std::fs::write(&wasm_path, &tampered).unwrap();
    write_signature_sidecar(wasm_path.to_str().unwrap(), &signed).unwrap();

    let manifest = make_manifest(
        "g",
        "0.1.0",
        "g.wasm",
        &signed.module_hash, // manifest hash matches signed (both over MINIMAL_WASM)
        Some(pk_hex),
        false,
    );

    let engine = Arc::new(Engine::default());
    let result = load_signed_guard(engine, wasm_path.to_str().unwrap(), 1_000_000, &manifest);
    let err = match result {
        Ok(_) => panic!("tampered bytes must fail"),
        Err(e) => e,
    };
    match err {
        WasmGuardError::HashMismatch { .. } => {}
        other => panic!("expected HashMismatch, got: {other:?}"),
    }
}

#[test]
fn missing_sidecar_without_opt_out_fails_with_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = write_wasm(dir.path(), "g.wasm");
    // No sidecar written.

    let manifest = make_manifest(
        "g",
        "0.1.0",
        "g.wasm",
        &sha256_hex(MINIMAL_WASM),
        None,  // no signer key set either
        false, // not opted out
    );

    let engine = Arc::new(Engine::default());
    let result = load_signed_guard(engine, wasm_path.to_str().unwrap(), 1_000_000, &manifest);
    let err = match result {
        Ok(_) => panic!("unsigned load must fail"),
        Err(e) => e,
    };

    // The error must name the file and explain that the module is not signed.
    let msg = format!("{err}");
    assert!(msg.contains("g.wasm"), "error should name the file: {msg}");
    assert!(
        msg.contains("not signed"),
        "error should say not signed: {msg}"
    );
}

#[test]
fn allow_unsigned_opt_out_permits_missing_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = write_wasm(dir.path(), "g.wasm");
    // No sidecar written.

    let manifest = make_manifest(
        "g",
        "0.1.0",
        "g.wasm",
        &sha256_hex(MINIMAL_WASM),
        None,
        true, // opted out
    );

    let engine = Arc::new(Engine::default());
    let backend = match load_signed_guard(engine, wasm_path.to_str().unwrap(), 1_000_000, &manifest)
    {
        Ok(b) => b,
        Err(e) => panic!("allow_unsigned=true should permit missing sidecar: {e}"),
    };
    assert_eq!(backend.backend_name(), "wasmtime");
}

#[test]
fn signature_sidecar_has_sig_suffix() {
    // Regression: confirm the sidecar filename is derived deterministically.
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = write_wasm(dir.path(), "h.wasm");

    let sk = SigningKey::generate(&mut OsRng);
    let signed = sign_bytes(&sk, MINIMAL_WASM, "h", "0.1.0");
    let sidecar_path = write_signature_sidecar(wasm_path.to_str().unwrap(), &signed).unwrap();

    let expected = dir.path().join(format!("h.wasm{SIGNATURE_SUFFIX}"));
    assert_eq!(sidecar_path, expected);
    assert!(sidecar_path.exists());
}
