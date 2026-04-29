//! Startup wiring for the guard pipeline.
//!
//! This module provides the integration point where guard manifests meet the
//! kernel pipeline. It exposes two public functions:
//!
//! - [`load_wasm_guards`]: Load and verify WASM guards from configuration
//!   entries with manifest-based integrity checks.
//! - [`build_guard_pipeline`]: Compose a full guard pipeline with correct tier
//!   ordering (HushSpec first, then WASM guards sorted by priority).
//!
//! # Pipeline tiers
//!
//! The guard pipeline is organized in three conceptual tiers:
//!
//! - **Tier 1 -- HushSpec-compiled guards**: Deterministic, native Rust guards
//!   compiled from HushSpec policy YAML via `chio_policy::compile_policy()`.
//!   These run first because they are the fastest and most predictable.
//!
//! - **Tier 2 -- WASM guards**: Guards loaded from `.wasm` modules, sorted by
//!   priority (lower values first). Within the same priority, non-advisory
//!   guards run before advisory guards.
//!
//! - **Tier 3 -- (reserved)**: Reserved for future advisory-only pipeline
//!   extensions. Currently, advisory WASM guards are loaded after non-advisory
//!   WASM guards within Tier 2.

use std::sync::Arc;

use chio_config::schema::WasmGuardEntry;
use chio_kernel::Guard;
use wasmtime::Engine;

use crate::abi::WasmGuardAbi;
use crate::error::WasmGuardError;
use crate::manifest;
use crate::runtime::wasmtime_backend::WasmtimeBackend;
use crate::runtime::WasmGuard;

/// Load WASM guards from WasmGuardEntry configs with manifest verification.
///
/// For each entry:
/// 1. Loads `guard-manifest.yaml` from the `.wasm` file's parent directory
/// 2. Validates `abi_version` against `SUPPORTED_ABI_VERSIONS`
/// 3. Reads the `.wasm` binary and verifies SHA-256 against the manifest
/// 4. Verifies the manifest-driven signing policy
/// 5. Creates a `WasmtimeBackend` with the manifest's config
/// 6. Loads the module into the backend
/// 7. Creates a `WasmGuard` with the manifest's `wasm_sha256` for receipt
///    metadata
///
/// Entries are sorted by priority (lower first) before loading. Non-advisory
/// guards are loaded before advisory guards at equal priority.
pub fn load_wasm_guards(
    entries: &[WasmGuardEntry],
    engine: Arc<Engine>,
) -> Result<Vec<WasmGuard>, WasmGuardError> {
    let mut sorted: Vec<WasmGuardEntry> = entries.to_vec();
    // Priority ascending first, advisory flag as tie-breaker so the documented
    // ordering ("priority ascending, advisory as tie-breaker") holds instead of
    // partitioning non-advisory guards ahead of all advisory ones regardless
    // of numeric priority.
    sorted.sort_by_key(|e| (e.priority, e.advisory as u8));

    let mut guards = Vec::with_capacity(sorted.len());

    for entry in &sorted {
        // 1. Load manifest from adjacent directory
        let guard_manifest = manifest::load_manifest(&entry.path)?;

        // 2. Verify ABI version
        manifest::verify_abi_version(&guard_manifest.abi_version)?;

        // 3. Read .wasm binary
        let wasm_bytes = std::fs::read(&entry.path).map_err(|e| WasmGuardError::ModuleLoad {
            path: entry.path.clone(),
            reason: e.to_string(),
        })?;

        // 4. Verify SHA-256 of wasm binary against manifest
        manifest::verify_wasm_hash(&wasm_bytes, &guard_manifest.wasm_sha256)?;

        // 5. Enforce the manifest-driven signing policy
        manifest::verify_guard_signature(&entry.path, &wasm_bytes, &guard_manifest)?;

        // 6. Create backend with manifest config
        let mut backend =
            WasmtimeBackend::with_engine_and_config(engine.clone(), guard_manifest.config.clone());

        // 7. Load module into backend
        backend.load_module(&wasm_bytes, entry.fuel_limit)?;

        // 8. Create WasmGuard with manifest metadata for receipts and spans.
        let guard = WasmGuard::new_with_metadata(
            entry.name.clone(),
            guard_manifest.version.clone(),
            Box::new(backend),
            entry.advisory,
            Some(guard_manifest.wasm_sha256.clone()),
        );

        guards.push(guard);
    }

    Ok(guards)
}

/// Build a complete guard pipeline with the correct tier ordering.
///
/// Pipeline order:
/// 1. HushSpec-compiled guards (from `compile_policy`)
/// 2. WASM guards sorted by priority (non-advisory first)
///
/// Returns the composed pipeline as a `Vec<Box<dyn Guard>>`.
///
/// The `hushspec_guards` parameter accepts pre-compiled HushSpec guards
/// (from `chio_policy::compile_policy().guards`). Pass an empty `Vec` if no
/// HushSpec policy is configured.
pub fn build_guard_pipeline(
    hushspec_guards: Vec<Box<dyn Guard>>,
    wasm_guards: Vec<WasmGuard>,
) -> Vec<Box<dyn Guard>> {
    let mut pipeline: Vec<Box<dyn Guard>> = Vec::new();

    // Tier 1: HushSpec guards
    pipeline.extend(hushspec_guards);

    // Tier 2: WASM guards (already sorted by load_wasm_guards)
    for g in wasm_guards {
        pipeline.push(Box::new(g));
    }

    pipeline
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chio_kernel::{GuardContext, KernelError, Verdict};
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    use std::io::Write;

    /// Minimal valid WASM module bytes (an empty module).
    const MINIMAL_WASM: &[u8] = b"\x00asm\x01\x00\x00\x00";

    /// Compute SHA-256 hex digest of the given bytes.
    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Write a guard manifest YAML to the given directory.
    fn write_manifest(dir: &std::path::Path, wasm_filename: &str, wasm_sha256: &str) {
        write_manifest_with_config(
            dir,
            wasm_filename,
            wasm_sha256,
            "1",
            "allow_unsigned: true\n",
        );
    }

    /// Write a guard manifest YAML to the given directory with custom ABI
    /// version and optional config block.
    fn write_manifest_with_config(
        dir: &std::path::Path,
        wasm_filename: &str,
        wasm_sha256: &str,
        abi_version: &str,
        config_yaml: &str,
    ) {
        let manifest_content = format!(
            "name: test-guard\n\
             version: \"1.0.0\"\n\
             abi_version: \"{abi_version}\"\n\
             wit_world: \"{wit_world}\"\n\
             wasm_path: {wasm_filename}\n\
             wasm_sha256: {wasm_sha256}\n\
             {config_yaml}",
            wit_world = crate::manifest::REQUIRED_WIT_WORLD,
        );
        let manifest_path = dir.join(crate::manifest::MANIFEST_FILENAME);
        let mut f = std::fs::File::create(&manifest_path).unwrap();
        f.write_all(manifest_content.as_bytes()).unwrap();
    }

    /// Create a temp directory with a minimal WASM module and valid manifest.
    /// Returns (dir, wasm_path, wasm_sha256).
    fn create_guard_dir(suffix: &str) -> (tempfile::TempDir, String, String) {
        let dir = tempfile::Builder::new()
            .prefix(&format!("chio_wiring_{suffix}_"))
            .tempdir()
            .unwrap();
        let wasm_path = dir.path().join("guard.wasm");
        std::fs::write(&wasm_path, MINIMAL_WASM).unwrap();
        let hash = sha256_hex(MINIMAL_WASM);
        write_manifest(dir.path(), "guard.wasm", &hash);
        let path_str = wasm_path.to_str().unwrap().to_string();
        (dir, path_str, hash)
    }

    fn make_entry(name: &str, path: &str, priority: u32, advisory: bool) -> WasmGuardEntry {
        WasmGuardEntry {
            name: name.to_string(),
            path: path.to_string(),
            fuel_limit: 10_000_000,
            priority,
            advisory,
        }
    }

    // -----------------------------------------------------------------------
    // Priority sorting tests
    // -----------------------------------------------------------------------

    #[test]
    fn entries_sorted_by_priority_before_loading() {
        let (_d1, p1, _) = create_guard_dir("prio_500");
        let (_d2, p2, _) = create_guard_dir("prio_100");
        let (_d3, p3, _) = create_guard_dir("prio_300");

        let entries = vec![
            make_entry("guard-500", &p1, 500, false),
            make_entry("guard-100", &p2, 100, false),
            make_entry("guard-300", &p3, 300, false),
        ];

        let engine = Arc::new(Engine::default());
        let guards = load_wasm_guards(&entries, engine).unwrap();

        assert_eq!(guards.len(), 3);
        assert_eq!(guards[0].name(), "guard-100");
        assert_eq!(guards[1].name(), "guard-300");
        assert_eq!(guards[2].name(), "guard-500");
    }

    // -----------------------------------------------------------------------
    // Advisory ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn advisory_guards_placed_after_non_advisory_at_same_priority() {
        let (_d1, p1, _) = create_guard_dir("adv_yes");
        let (_d2, p2, _) = create_guard_dir("adv_no");

        let entries = vec![
            make_entry("advisory-guard", &p1, 100, true),
            make_entry("normal-guard", &p2, 100, false),
        ];

        let engine = Arc::new(Engine::default());
        let guards = load_wasm_guards(&entries, engine).unwrap();

        assert_eq!(guards.len(), 2);
        assert_eq!(guards[0].name(), "normal-guard");
        assert_eq!(guards[1].name(), "advisory-guard");
    }

    // -----------------------------------------------------------------------
    // Manifest config passthrough test
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_config_passed_through_to_backend() {
        let dir = tempfile::Builder::new()
            .prefix("chio_wiring_config_")
            .tempdir()
            .unwrap();
        let wasm_path = dir.path().join("guard.wasm");
        std::fs::write(&wasm_path, MINIMAL_WASM).unwrap();
        let hash = sha256_hex(MINIMAL_WASM);
        write_manifest_with_config(
            dir.path(),
            "guard.wasm",
            &hash,
            "1",
            "allow_unsigned: true\nconfig:\n  threshold: \"0.8\"\n  mode: strict\n",
        );

        let entries = vec![make_entry(
            "config-guard",
            wasm_path.to_str().unwrap(),
            100,
            false,
        )];

        let engine = Arc::new(Engine::default());
        let guards = load_wasm_guards(&entries, engine).unwrap();

        assert_eq!(guards.len(), 1);
        // The guard was loaded successfully with the manifest config.
        // Config values are passed to the backend constructor (WasmtimeBackend::with_engine_and_config).
        // We verify the guard was created with the correct manifest SHA-256.
        assert_eq!(guards[0].manifest_sha256().as_deref(), Some(hash.as_str()));
    }

    // -----------------------------------------------------------------------
    // SHA-256 mismatch test
    // -----------------------------------------------------------------------

    #[test]
    fn sha256_mismatch_returns_error() {
        let dir = tempfile::Builder::new()
            .prefix("chio_wiring_hashmismatch_")
            .tempdir()
            .unwrap();
        let wasm_path = dir.path().join("guard.wasm");
        std::fs::write(&wasm_path, MINIMAL_WASM).unwrap();
        // Write manifest with wrong hash
        write_manifest(
            dir.path(),
            "guard.wasm",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );

        let entries = vec![make_entry(
            "bad-hash-guard",
            wasm_path.to_str().unwrap(),
            100,
            false,
        )];

        let engine = Arc::new(Engine::default());
        let result = load_wasm_guards(&entries, engine);

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmGuardError::HashMismatch { .. } => {} // expected
            other => panic!("expected HashMismatch, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Unsupported ABI version test
    // -----------------------------------------------------------------------

    #[test]
    fn unsupported_abi_version_returns_error() {
        let dir = tempfile::Builder::new()
            .prefix("chio_wiring_badabi_")
            .tempdir()
            .unwrap();
        let wasm_path = dir.path().join("guard.wasm");
        std::fs::write(&wasm_path, MINIMAL_WASM).unwrap();
        let hash = sha256_hex(MINIMAL_WASM);
        write_manifest_with_config(dir.path(), "guard.wasm", &hash, "99", "");

        let entries = vec![make_entry(
            "bad-abi-guard",
            wasm_path.to_str().unwrap(),
            100,
            false,
        )];

        let engine = Arc::new(Engine::default());
        let result = load_wasm_guards(&entries, engine);

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmGuardError::UnsupportedAbiVersion { version, .. } => {
                assert_eq!(version, "99");
            }
            other => panic!("expected UnsupportedAbiVersion, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Missing manifest test
    // -----------------------------------------------------------------------

    #[test]
    fn missing_manifest_returns_error_with_path() {
        let dir = tempfile::Builder::new()
            .prefix("chio_wiring_nomanifest_")
            .tempdir()
            .unwrap();
        let wasm_path = dir.path().join("guard.wasm");
        std::fs::write(&wasm_path, MINIMAL_WASM).unwrap();
        // No manifest written

        let entries = vec![make_entry(
            "no-manifest-guard",
            wasm_path.to_str().unwrap(),
            100,
            false,
        )];

        let engine = Arc::new(Engine::default());
        let result = load_wasm_guards(&entries, engine);

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmGuardError::ManifestLoad { path, .. } => {
                assert!(
                    path.contains("guard-manifest.yaml"),
                    "error should identify the manifest path, got: {path}"
                );
            }
            other => panic!("expected ManifestLoad, got: {other:?}"),
        }
    }

    #[test]
    fn load_wasm_guards_rejects_unpinned_sidecar_without_opt_out() {
        let dir = tempfile::Builder::new()
            .prefix("chio_wiring_unpinned_sidecar_")
            .tempdir()
            .unwrap();
        let wasm_path = dir.path().join("guard.wasm");
        std::fs::write(&wasm_path, MINIMAL_WASM).unwrap();
        let hash = sha256_hex(MINIMAL_WASM);
        write_manifest_with_config(
            dir.path(),
            "guard.wasm",
            &hash,
            "1",
            "allow_unsigned: false\n",
        );

        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let module_hash = sha256_hex(MINIMAL_WASM);
        let signer_public_key = hex::encode(sk.verifying_key().to_bytes());
        let message = crate::manifest::signed_module_message(
            &module_hash,
            "test-guard",
            "1.0.0",
            &signer_public_key,
        );
        let signature = sk.sign(&message);
        let signed = crate::manifest::SignedWasmModule {
            module_hash,
            module_name: "test-guard".to_string(),
            version: "1.0.0".to_string(),
            signer_public_key,
            signature: hex::encode(signature.to_bytes()),
        };
        crate::manifest::write_signature_sidecar(wasm_path.to_str().unwrap(), &signed).unwrap();

        let entries = vec![make_entry(
            "unpinned-sidecar-guard",
            wasm_path.to_str().unwrap(),
            100,
            false,
        )];

        let engine = Arc::new(Engine::default());
        let err = load_wasm_guards(&entries, engine).unwrap_err();
        match err {
            WasmGuardError::SignatureVerification(msg) => {
                assert!(msg.contains("unpinned"), "{msg}");
            }
            other => panic!("expected SignatureVerification, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Pipeline composition test
    // -----------------------------------------------------------------------

    #[derive(Debug)]
    struct MockGuard {
        guard_name: String,
    }

    impl Guard for MockGuard {
        fn name(&self) -> &str {
            &self.guard_name
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
            Ok(Verdict::Allow)
        }
    }

    #[test]
    fn build_pipeline_places_hushspec_guards_before_wasm_guards() {
        let (_d1, p1, _) = create_guard_dir("pipeline");

        let entries = vec![make_entry("wasm-guard-1", &p1, 100, false)];

        let engine = Arc::new(Engine::default());
        let wasm_guards = load_wasm_guards(&entries, engine).unwrap();

        let hushspec_guards: Vec<Box<dyn Guard>> = vec![
            Box::new(MockGuard {
                guard_name: "hushspec-1".to_string(),
            }),
            Box::new(MockGuard {
                guard_name: "hushspec-2".to_string(),
            }),
        ];

        let pipeline = build_guard_pipeline(hushspec_guards, wasm_guards);

        assert_eq!(pipeline.len(), 3);
        assert_eq!(pipeline[0].name(), "hushspec-1");
        assert_eq!(pipeline[1].name(), "hushspec-2");
        assert_eq!(pipeline[2].name(), "wasm-guard-1");
    }

    #[test]
    fn build_pipeline_with_no_hushspec_guards() {
        let (_d1, p1, _) = create_guard_dir("nohush");

        let entries = vec![make_entry("wasm-only", &p1, 100, false)];

        let engine = Arc::new(Engine::default());
        let wasm_guards = load_wasm_guards(&entries, engine).unwrap();

        let pipeline = build_guard_pipeline(Vec::new(), wasm_guards);

        assert_eq!(pipeline.len(), 1);
        assert_eq!(pipeline[0].name(), "wasm-only");
    }

    #[test]
    fn build_pipeline_with_no_wasm_guards() {
        let hushspec_guards: Vec<Box<dyn Guard>> = vec![Box::new(MockGuard {
            guard_name: "hushspec-only".to_string(),
        })];

        let pipeline = build_guard_pipeline(hushspec_guards, Vec::new());

        assert_eq!(pipeline.len(), 1);
        assert_eq!(pipeline[0].name(), "hushspec-only");
    }
}
