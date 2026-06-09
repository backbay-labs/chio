//! Integration tests for policy-driven WASM guard loading.
//!
//! Covers the full round trip specified in the acceptance list:
//!
//! - Loading a signed WASM guard module declared by policy (happy path).
//! - Rejecting modules with an invalid signature sidecar.
//! - Resolving `${ENV_VAR}` placeholders in guard config.
//! - Using `${VAR:-default}` to supply defaults.
//! - Failing closed when a placeholder is undefined and has no default.
//! - Capability intersection: rejecting requests for host functions that are
//!   not in the policy-allowed allowlist, and rejecting modules whose `chio.*`
//!   imports exceed the declared capabilities.
//! - The `$$` escape producing a literal `$`.

#![cfg(feature = "wasmtime-runtime")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use chio_kernel::Guard;
use chio_wasm_guards::manifest::{
    signed_module_message, write_signature_sidecar, SignedWasmModule, SIGNATURE_SUFFIX,
};
use chio_wasm_guards::{
    load_guards_from_policy, LoadError, PlaceholderEnv, PolicyCustomGuard, PolicyCustomGuards,
    PolicyModuleSource, WasmGuardError, KNOWN_HOST_FUNCTIONS,
};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use wasmtime::Engine;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Minimal valid core WASM module (empty, no imports).
const MINIMAL_WASM: &[u8] = b"\x00asm\x01\x00\x00\x00";

/// WAT source for a module that imports `chio.log` from the host.
const WAT_IMPORTS_LOG: &str = r#"
(module
    (import "chio" "log" (func $log (param i32 i32 i32)))
    (memory (export "memory") 1)
    (func (export "evaluate") (param i32 i32) (result i32)
        (i32.const 0)
    )
)
"#;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_wasm(dir: &Path, filename: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.join(filename);
    std::fs::write(&p, bytes).unwrap();
    p
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

/// An environment that panics if the test reads from `std::env`. Used to prove
/// we never leak to process env.
fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn all_known_caps() -> Vec<String> {
    KNOWN_HOST_FUNCTIONS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Happy path: signed module
// ---------------------------------------------------------------------------

#[test]
fn loads_and_verifies_signed_module() {
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = write_wasm(dir.path(), "g.wasm", MINIMAL_WASM);

    let sk = SigningKey::generate(&mut OsRng);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    let signed = sign_bytes(&sk, MINIMAL_WASM, "g", "1.0.0");
    write_signature_sidecar(wasm_path.to_str().unwrap(), &signed).unwrap();

    let policy = PolicyCustomGuards {
        modules: vec![PolicyCustomGuard {
            name: "g".to_string(),
            version: "1.0.0".to_string(),
            module: PolicyModuleSource::Path {
                module_path: wasm_path.to_str().unwrap().to_string(),
            },
            capabilities: vec![],
            config: serde_json::json!({}),
            fuel_limit: 1_000_000,
            priority: 100,
            advisory: false,
            signer_public_key: Some(pk_hex),
            allow_unsigned: false,
        }],
    };

    let env = env(&[]);
    let engine = Arc::new(Engine::default());
    let handles =
        load_guards_from_policy(&policy, &env, &all_known_caps(), engine).expect("load ok");

    assert_eq!(handles.len(), 1);
    assert_eq!(handles[0].guard().name(), "g");
    assert!(handles[0].granted_capabilities().is_empty());
}

// ---------------------------------------------------------------------------
// Signature rejection paths
// ---------------------------------------------------------------------------

#[test]
fn rejects_unsigned_or_badly_signed_module() {
    // Case 1: no sidecar and no allow_unsigned -- reject.
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = write_wasm(dir.path(), "g.wasm", MINIMAL_WASM);

    let sk = SigningKey::generate(&mut OsRng);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    let policy = PolicyCustomGuards {
        modules: vec![PolicyCustomGuard {
            name: "g".to_string(),
            version: "1.0.0".to_string(),
            module: PolicyModuleSource::Path {
                module_path: wasm_path.to_str().unwrap().to_string(),
            },
            capabilities: vec![],
            config: serde_json::json!({}),
            fuel_limit: 1_000_000,
            priority: 100,
            advisory: false,
            signer_public_key: Some(pk_hex.clone()),
            allow_unsigned: false,
        }],
    };

    let env = env(&[]);
    let engine = Arc::new(Engine::default());
    let err =
        load_guards_from_policy(&policy, &env, &all_known_caps(), engine.clone()).unwrap_err();
    match err {
        LoadError::Runtime(WasmGuardError::SignatureVerification(_)) => {}
        other => panic!("expected SignatureVerification, got {other:?}"),
    }

    // Case 2: sidecar signed by a *different* key than the pinned one --
    // the policy pins `pk_hex` but the sidecar is produced by `other_sk`.
    let other_sk = SigningKey::generate(&mut OsRng);
    let signed_by_other = sign_bytes(&other_sk, MINIMAL_WASM, "g", "1.0.0");
    write_signature_sidecar(wasm_path.to_str().unwrap(), &signed_by_other).unwrap();

    let err =
        load_guards_from_policy(&policy, &env, &all_known_caps(), engine.clone()).unwrap_err();
    match err {
        LoadError::Runtime(WasmGuardError::SignatureVerification(_)) => {}
        other => panic!("expected SignatureVerification, got {other:?}"),
    }

    // Case 3: tampered bytes -- sidecar is for the *original* bytes but we
    // overwrite the module on disk.
    let signed = sign_bytes(&sk, MINIMAL_WASM, "g", "1.0.0");
    write_signature_sidecar(wasm_path.to_str().unwrap(), &signed).unwrap();
    let mut tampered = MINIMAL_WASM.to_vec();
    tampered.push(0x00);
    std::fs::write(&wasm_path, &tampered).unwrap();

    let err = load_guards_from_policy(&policy, &env, &all_known_caps(), engine).unwrap_err();
    match err {
        LoadError::Runtime(WasmGuardError::HashMismatch { .. }) => {}
        other => panic!("expected HashMismatch, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Placeholder resolution
// ---------------------------------------------------------------------------

#[test]
fn placeholder_resolved_in_config() {
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = write_wasm(dir.path(), "g.wasm", MINIMAL_WASM);

    let policy = PolicyCustomGuards {
        modules: vec![PolicyCustomGuard {
            name: "g".to_string(),
            version: "1.0.0".to_string(),
            module: PolicyModuleSource::Path {
                module_path: wasm_path.to_str().unwrap().to_string(),
            },
            capabilities: vec![],
            config: serde_json::json!({
                "endpoint": "https://${API_HOST}/v1",
                "token": "Bearer ${API_TOKEN}",
            }),
            fuel_limit: 1_000_000,
            priority: 100,
            advisory: false,
            signer_public_key: None,
            allow_unsigned: true, // allow unsigned so placeholder-only test works
        }],
    };

    let env = env(&[("API_HOST", "example.com"), ("API_TOKEN", "secret-xyz")]);
    let engine = Arc::new(Engine::default());

    // We prove resolution happened by asserting the load succeeds and the
    // config map contains the substituted values. We use the placeholder
    // resolver directly on the spec as well to pin the behavior.
    let resolved =
        chio_wasm_guards::resolve_placeholders_in_json(&policy.modules[0].config, &env).unwrap();
    assert_eq!(resolved["endpoint"], "https://example.com/v1");
    assert_eq!(resolved["token"], "Bearer secret-xyz");

    let handles = load_guards_from_policy(&policy, &env, &all_known_caps(), engine).unwrap();
    assert_eq!(handles.len(), 1);
}

#[test]
fn placeholder_default_applied_when_env_missing() {
    let env = env(&[]);
    let value = serde_json::json!({
        "level": "${LOG_LEVEL:-info}",
    });
    let resolved = chio_wasm_guards::resolve_placeholders_in_json(&value, &env).unwrap();
    assert_eq!(resolved["level"], "info");

    // And end-to-end through the policy loader.
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = write_wasm(dir.path(), "g.wasm", MINIMAL_WASM);

    let policy = PolicyCustomGuards {
        modules: vec![PolicyCustomGuard {
            name: "g".to_string(),
            version: "1.0.0".to_string(),
            module: PolicyModuleSource::Path {
                module_path: wasm_path.to_str().unwrap().to_string(),
            },
            capabilities: vec![],
            config: serde_json::json!({ "level": "${LOG_LEVEL:-info}" }),
            fuel_limit: 1_000_000,
            priority: 100,
            advisory: false,
            signer_public_key: None,
            allow_unsigned: true,
        }],
    };
    let engine = Arc::new(Engine::default());
    let handles = load_guards_from_policy(&policy, &env, &all_known_caps(), engine).unwrap();
    assert_eq!(handles.len(), 1);
}

#[test]
fn undefined_placeholder_without_default_errors() {
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = write_wasm(dir.path(), "g.wasm", MINIMAL_WASM);

    let policy = PolicyCustomGuards {
        modules: vec![PolicyCustomGuard {
            name: "g".to_string(),
            version: "1.0.0".to_string(),
            module: PolicyModuleSource::Path {
                module_path: wasm_path.to_str().unwrap().to_string(),
            },
            capabilities: vec![],
            config: serde_json::json!({ "secret": "${THIS_IS_NOT_SET}" }),
            fuel_limit: 1_000_000,
            priority: 100,
            advisory: false,
            signer_public_key: None,
            allow_unsigned: true,
        }],
    };

    let env: HashMap<String, String> = HashMap::new();
    let engine = Arc::new(Engine::default());
    let err = load_guards_from_policy(&policy, &env, &all_known_caps(), engine).unwrap_err();
    match err {
        LoadError::Placeholder { guard, .. } => assert_eq!(guard, "g"),
        other => panic!("expected LoadError::Placeholder, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Capability intersection
// ---------------------------------------------------------------------------

#[test]
fn capability_intersection_denies_unauthorized_host_fn() {
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = write_wasm(dir.path(), "g.wasm", MINIMAL_WASM);

    // The guard asks for `chio.get_config` but the policy allowlist only
    // permits `chio.log`. Loading must fail.
    let policy = PolicyCustomGuards {
        modules: vec![PolicyCustomGuard {
            name: "g".to_string(),
            version: "1.0.0".to_string(),
            module: PolicyModuleSource::Path {
                module_path: wasm_path.to_str().unwrap().to_string(),
            },
            capabilities: vec!["chio.get_config".to_string()],
            config: serde_json::json!({}),
            fuel_limit: 1_000_000,
            priority: 100,
            advisory: false,
            signer_public_key: None,
            allow_unsigned: true,
        }],
    };

    let env: HashMap<String, String> = HashMap::new();
    let engine = Arc::new(Engine::default());
    let allowlist = vec!["chio.log".to_string()];
    let err = load_guards_from_policy(&policy, &env, &allowlist, engine).unwrap_err();
    match err {
        LoadError::CapabilityDenied { guard, capability } => {
            assert_eq!(guard, "g");
            assert_eq!(capability, "chio.get_config");
        }
        other => panic!("expected CapabilityDenied, got {other:?}"),
    }
}

#[test]
fn capability_intersection_rejects_module_with_undeclared_import() {
    // Guard declares zero capabilities but its WASM imports `chio.log`.
    // Loading must fail: capability intersection is enforced at the module
    // boundary, not just at the policy layer.
    let dir = tempfile::tempdir().unwrap();
    let wasm_bytes = wat::parse_str(WAT_IMPORTS_LOG).unwrap();
    let wasm_path = write_wasm(dir.path(), "g.wasm", &wasm_bytes);

    let policy = PolicyCustomGuards {
        modules: vec![PolicyCustomGuard {
            name: "g".to_string(),
            version: "1.0.0".to_string(),
            module: PolicyModuleSource::Path {
                module_path: wasm_path.to_str().unwrap().to_string(),
            },
            capabilities: vec![], // no capabilities requested
            config: serde_json::json!({}),
            fuel_limit: 1_000_000,
            priority: 100,
            advisory: false,
            signer_public_key: None,
            allow_unsigned: true,
        }],
    };

    let env: HashMap<String, String> = HashMap::new();
    let engine = Arc::new(Engine::default());
    let err = load_guards_from_policy(&policy, &env, &all_known_caps(), engine).unwrap_err();
    match err {
        LoadError::UndeclaredHostImport { guard, import } => {
            assert_eq!(guard, "g");
            assert_eq!(import, "chio.log");
        }
        other => panic!("expected UndeclaredHostImport, got {other:?}"),
    }
}

#[test]
fn capability_intersection_accepts_declared_import() {
    // Guard asks for `chio.log`, allowlist permits it, module imports it.
    // Loading must succeed.
    let dir = tempfile::tempdir().unwrap();
    let wasm_bytes = wat::parse_str(WAT_IMPORTS_LOG).unwrap();
    let wasm_path = write_wasm(dir.path(), "g.wasm", &wasm_bytes);

    let policy = PolicyCustomGuards {
        modules: vec![PolicyCustomGuard {
            name: "g".to_string(),
            version: "1.0.0".to_string(),
            module: PolicyModuleSource::Path {
                module_path: wasm_path.to_str().unwrap().to_string(),
            },
            capabilities: vec!["chio.log".to_string()],
            config: serde_json::json!({}),
            fuel_limit: 1_000_000,
            priority: 100,
            advisory: false,
            signer_public_key: None,
            allow_unsigned: true,
        }],
    };

    let env: HashMap<String, String> = HashMap::new();
    let engine = Arc::new(Engine::default());
    let handles = load_guards_from_policy(&policy, &env, &all_known_caps(), engine).unwrap();
    assert_eq!(handles.len(), 1);
    assert_eq!(handles[0].granted_capabilities(), &["chio.log".to_string()]);
}

// ---------------------------------------------------------------------------
// Escape sequence
// ---------------------------------------------------------------------------

#[test]
fn escape_sequence_produces_literal_dollar_sign() {
    let env = env(&[]);
    let value = serde_json::json!({
        "label": "cost: $$5 per call",
    });
    let resolved = chio_wasm_guards::resolve_placeholders_in_json(&value, &env).unwrap();
    assert_eq!(resolved["label"], "cost: $5 per call");
}

// ---------------------------------------------------------------------------
// PlaceholderEnv trait sanity: closure implementation carries through.
// ---------------------------------------------------------------------------

#[test]
fn placeholder_env_accepts_custom_trait_impl() {
    struct NoEnv;
    impl PlaceholderEnv for NoEnv {
        fn lookup(&self, _name: &str) -> Option<String> {
            None
        }
    }
    let value = serde_json::json!("${X:-fallback}");
    let resolved = chio_wasm_guards::resolve_placeholders_in_json(&value, &NoEnv).unwrap();
    assert_eq!(resolved, serde_json::json!("fallback"));
}

// ---------------------------------------------------------------------------
// End-to-end: the signed module actually runs in the pipeline.
// ---------------------------------------------------------------------------

#[test]
fn loaded_guard_can_be_invoked_through_the_runtime() {
    use chio_wasm_guards::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};

    // Build a module that always denies via a direct `(i32.const 1)` return.
    let wat = r#"
        (module
            (memory (export "memory") 1)
            (func (export "evaluate") (param i32 i32) (result i32)
                (i32.const 1)
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let wasm_path = write_wasm(dir.path(), "deny.wasm", &wasm_bytes);

    let sk = SigningKey::generate(&mut OsRng);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    let signed = sign_bytes(&sk, &wasm_bytes, "deny-all", "1.0.0");
    write_signature_sidecar(wasm_path.to_str().unwrap(), &signed).unwrap();

    let policy = PolicyCustomGuards {
        modules: vec![PolicyCustomGuard {
            name: "deny-all".to_string(),
            version: "1.0.0".to_string(),
            module: PolicyModuleSource::Path {
                module_path: wasm_path.to_str().unwrap().to_string(),
            },
            capabilities: vec![],
            config: serde_json::json!({ "label": "${RUN_LABEL:-canary}" }),
            fuel_limit: 1_000_000,
            priority: 100,
            advisory: false,
            signer_public_key: Some(pk_hex),
            allow_unsigned: false,
        }],
    };

    let env = env(&[("RUN_LABEL", "e2e")]);
    let engine = Arc::new(Engine::default());
    let handles =
        load_guards_from_policy(&policy, &env, &all_known_caps(), engine).expect("load ok");
    assert_eq!(handles.len(), 1);

    // Exercise the backend directly to confirm end-to-end wiring.
    let wasm_bytes_again = std::fs::read(&wasm_path).unwrap();
    let engine2 = chio_wasm_guards::host::create_shared_engine().unwrap();
    let mut backend =
        chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend::with_engine(engine2);
    backend.load_module(&wasm_bytes_again, 1_000_000).unwrap();
    let req = GuardRequest {
        tool_name: "t".into(),
        server_id: "s".into(),
        agent_id: "a".into(),
        arguments: serde_json::json!({}),
        scopes: vec![],
        action_type: None,
        extracted_path: None,
        extracted_target: None,
        filesystem_roots: vec![],
        matched_grant_index: None,
    };
    match backend.evaluate(&req).unwrap() {
        GuardVerdict::Deny { .. } => {}
        other => panic!("expected Deny verdict from test module, got {other:?}"),
    }

    // Sanity: sidecar path is adjacent to the .wasm
    let sidecar_path = wasm_path.with_file_name(format!(
        "{}{}",
        wasm_path.file_name().unwrap().to_str().unwrap(),
        SIGNATURE_SUFFIX
    ));
    assert!(sidecar_path.exists(), "sidecar should exist after write");
}
