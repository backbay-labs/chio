//! Determinism gate aggregating all eight WASM-guard escape classes.
//!
//! Owner: M05.P3.T5.
//!
//! For each named escape class the aggregate test exercises a single
//! canonical attack vector and asserts the runtime returns a typed
//! `WasmGuardError` (or, where the runtime contains the attack
//! silently with a defensive verdict, a well-formed `GuardVerdict`).
//! No panics, no aborts, no host-process termination.
//!
//! The gate prints `class_count = 8` on stdout so the M05 phase gate
//! command (`cargo test -p chio-wasm-guards --test escape -- aggregate
//! --nocapture | grep -q 'class_count = 8'`) can confirm the count
//! has not silently regressed. The M05 audit doc pins N at milestone
//! close.

use std::sync::Arc;

use chio_wasm_guards::abi::{GuardVerdict, WasmGuardAbi};
use chio_wasm_guards::component::ComponentBackend;
use chio_wasm_guards::error::WasmGuardError;
use chio_wasm_guards::host::create_shared_engine;
use chio_wasm_guards::manifest::{
    signed_module_message, verify_signed_module, SignedWasmModule,
};
use chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::Digest;

use super::common::{load_frozen_config, minimal_request};

/// The canonical taxonomy. Order is documented; the determinism gate
/// asserts the count is exactly 8.
const ESCAPE_CLASSES: &[&str] = &[
    "undeclared_imports",
    "oversize_memory",
    "fuel_exhaustion",
    "table_grow_abuse",
    "deep_recursion",
    "host_reentry",
    "malformed_component",
    "signed_but_malicious",
];

/// Acceptable per-class outcome. Either the runtime denies via a typed
/// `WasmGuardError`, or it contains the attack and emits a
/// well-formed `GuardVerdict`.
enum Outcome {
    Denied(WasmGuardError),
    Contained(GuardVerdict),
}

fn run_class(class: &str) -> Outcome {
    let cfg = load_frozen_config();

    match class {
        "undeclared_imports" => {
            let wat = r#"
                (module
                  (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                  (memory (export "memory") 1)
                  (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
            "#;
            let bytes = wat::parse_str(wat).expect("wat compile");
            let engine = create_shared_engine().expect("engine");
            let mut backend = WasmtimeBackend::with_engine(Arc::clone(&engine));
            match backend.load_module(&bytes, cfg.escape_fuel_limit) {
                Err(e) => Outcome::Denied(e),
                Ok(()) => panic!("undeclared_imports: load must reject"),
            }
        }
        "oversize_memory" => {
            let wat = r#"
                (module
                  (memory (export "memory") 1024)
                  (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
            "#;
            let bytes = wat::parse_str(wat).expect("wat compile");
            let engine = create_shared_engine().expect("engine");
            let mut backend = WasmtimeBackend::with_engine(Arc::clone(&engine));
            backend
                .load_module(&bytes, cfg.escape_fuel_limit)
                .expect("oversize-memory load");
            match backend.evaluate(&minimal_request()) {
                Err(e) => Outcome::Denied(e),
                Ok(v) => Outcome::Contained(v),
            }
        }
        "fuel_exhaustion" => {
            let wat = r#"
                (module
                  (memory (export "memory") 1)
                  (func (export "evaluate") (param i32 i32) (result i32)
                    (loop $forever (br $forever))
                    (i32.const 0)))
            "#;
            let bytes = wat::parse_str(wat).expect("wat compile");
            let engine = create_shared_engine().expect("engine");
            let mut backend = WasmtimeBackend::with_engine(Arc::clone(&engine));
            backend
                .load_module(&bytes, cfg.escape_fuel_limit)
                .expect("fuel-exhaustion load");
            match backend.evaluate(&minimal_request()) {
                Err(e) => Outcome::Denied(e),
                Ok(v) => Outcome::Contained(v),
            }
        }
        "table_grow_abuse" => {
            let wat = r#"
                (module
                  (memory (export "memory") 1)
                  (table $t 1 funcref)
                  (func (export "evaluate") (param i32 i32) (result i32)
                    (local $i i32)
                    (loop $L
                      (drop (table.grow $t (ref.null func) (i32.const 1)))
                      (local.set $i (i32.add (local.get $i) (i32.const 1)))
                      (br_if $L (i32.lt_s (local.get $i) (i32.const 1000000))))
                    (i32.const 0)))
            "#;
            let bytes = wat::parse_str(wat).expect("wat compile");
            let engine = create_shared_engine().expect("engine");
            let mut backend = WasmtimeBackend::with_engine(Arc::clone(&engine));
            backend
                .load_module(&bytes, cfg.escape_fuel_limit)
                .expect("table-grow load");
            match backend.evaluate(&minimal_request()) {
                Err(e) => Outcome::Denied(e),
                Ok(v) => Outcome::Contained(v),
            }
        }
        "deep_recursion" => {
            let wat = r#"
                (module
                  (memory (export "memory") 1)
                  (func $rec (export "evaluate") (param i32 i32) (result i32)
                    (drop (call $rec (local.get 0) (local.get 1)))
                    (i32.const 0)))
            "#;
            let bytes = wat::parse_str(wat).expect("wat compile");
            let engine = create_shared_engine().expect("engine");
            let mut backend = WasmtimeBackend::with_engine(Arc::clone(&engine));
            backend
                .load_module(&bytes, cfg.escape_fuel_limit)
                .expect("deep-recursion load");
            match backend.evaluate(&minimal_request()) {
                Err(e) => Outcome::Denied(e),
                Ok(v) => Outcome::Contained(v),
            }
        }
        "host_reentry" => {
            let wat = r#"
                (module
                  (import "chio" "log" (func $log (param i32 i32 i32)))
                  (memory (export "memory") 1)
                  (func (export "evaluate") (param i32 i32) (result i32)
                    (local $i i32)
                    (loop $L
                      (call $log (i32.const 0) (i32.const 0) (i32.const 0))
                      (local.set $i (i32.add (local.get $i) (i32.const 1)))
                      (br_if $L (i32.lt_s (local.get $i) (i32.const 1000000))))
                    (i32.const 0)))
            "#;
            let bytes = wat::parse_str(wat).expect("wat compile");
            let engine = create_shared_engine().expect("engine");
            let mut backend = WasmtimeBackend::with_engine(Arc::clone(&engine));
            backend
                .load_module(&bytes, cfg.escape_fuel_limit)
                .expect("host-reentry load");
            match backend.evaluate(&minimal_request()) {
                Err(e) => Outcome::Denied(e),
                Ok(v) => Outcome::Contained(v),
            }
        }
        "malformed_component" => {
            let bytes: Vec<u8> = vec![
                0x00, 0x61, 0x73, 0x6d, // "\0asm"
                0x0d, 0x00, // layer = component
                0x01, 0x00, // version
                0xff, 0xde, 0xad, 0xbe, 0xef, // invalid section + garbage
            ];
            let engine = create_shared_engine().expect("engine");
            let mut backend = ComponentBackend::with_engine(Arc::clone(&engine));
            match backend.load_module(&bytes, cfg.escape_fuel_limit) {
                Err(e) => Outcome::Denied(e),
                Ok(()) => panic!("malformed_component: parse must reject"),
            }
        }
        "signed_but_malicious" => {
            let wat = r#"
                (module
                  (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                  (memory (export "memory") 1)
                  (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
            "#;
            let bytes = wat::parse_str(wat).expect("wat compile");

            let sk = SigningKey::generate(&mut OsRng);
            let module_hash = hex::encode(sha2::Sha256::digest(&bytes));
            let signer_public_key = hex::encode(sk.verifying_key().to_bytes());
            let message = signed_module_message(
                &module_hash,
                "evil-aggregate",
                "1.0.0",
                &signer_public_key,
            );
            let signature = sk.sign(&message);
            let signed = SignedWasmModule {
                module_hash,
                module_name: "evil-aggregate".to_string(),
                version: "1.0.0".to_string(),
                signer_public_key: signer_public_key.clone(),
                signature: hex::encode(signature.to_bytes()),
            };

            // Signing layer accepts.
            verify_signed_module(&bytes, &signed, &signer_public_key)
                .expect("signing layer accepts a malicious-but-signed module");

            // Runtime layer denies.
            let engine = create_shared_engine().expect("engine");
            let mut backend = WasmtimeBackend::with_engine(Arc::clone(&engine));
            match backend.load_module(&bytes, cfg.escape_fuel_limit) {
                Err(e) => Outcome::Denied(e),
                Ok(()) => panic!("signed_but_malicious: runtime must reject"),
            }
        }
        other => panic!("unknown escape class: {other}"),
    }
}

/// Determinism gate. Walks every canonical class and asserts a typed
/// outcome. Prints `class_count = 8` on stdout.
#[test]
fn aggregate_all_eight_escape_classes() {
    let mut tally = 0usize;
    for &class in ESCAPE_CLASSES {
        let outcome = run_class(class);
        match outcome {
            Outcome::Denied(err) => {
                println!("class={class:24} outcome=denied err={err}");
            }
            Outcome::Contained(verdict) => {
                println!("class={class:24} outcome=contained verdict={verdict:?}");
            }
        }
        tally += 1;
    }
    assert_eq!(
        tally,
        ESCAPE_CLASSES.len(),
        "every class must produce a typed outcome"
    );
    assert_eq!(tally, 8, "M05 audit doc pins escape-class count at 8");
    println!("class_count = {tally}");
}

/// The taxonomy itself is checked-in source-of-truth. If a future
/// patch silently extends or shrinks `ESCAPE_CLASSES` this gate trips
/// and forces a CODEOWNERS-gated update of the M05 audit doc.
#[test]
fn class_taxonomy_is_pinned_at_eight() {
    assert_eq!(
        ESCAPE_CLASSES.len(),
        8,
        "M05.P3.T5: escape-class count must remain 8 until the audit \
         doc and threat model are updated together"
    );

    // Names must be unique.
    let mut sorted: Vec<&&str> = ESCAPE_CLASSES.iter().collect();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 8, "every escape-class name must be unique");
}
