//! Guard manifest parsing, SHA-256 verification, and ABI version gating.
//!
//! Each WASM guard is shipped alongside a `guard-manifest.yaml` that declares
//! its name, version, ABI version, WASM binary path, expected SHA-256 hash,
//! and optional configuration. The functions in this module load and validate
//! the manifest before the guard is instantiated.
//!
//! # Signing (Phase 1.3)
//!
//! The manifest may also carry a `signer_public_key` (hex-encoded Ed25519
//! public key) and an optional `allow_unsigned` opt-out flag. If
//! `signer_public_key` is set, the loader requires a `.wasm.sig` sidecar file
//! adjacent to the WASM binary carrying a detached Ed25519 signature over a
//! canonical envelope (see [`signed_module_message`]). Missing or malformed
//! signatures are fail-closed unless `allow_unsigned: true` is set, in which
//! case loading proceeds with a runtime warning.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::WasmGuardError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ABI versions supported by this version of the WASM guard runtime.
pub const SUPPORTED_ABI_VERSIONS: &[&str] = &["1"];

/// WIT world supported by this version of the Component Model guard runtime.
pub const REQUIRED_WIT_WORLD: &str = "chio:guard/guard@0.2.0";

/// Operator-facing migration guide for 0.1.x WIT guard components.
pub const WIT_WORLD_MIGRATION_GUIDE: &str = "docs/guards/MIGRATION-0.1-to-0.2.md";

/// Well-known filename for the guard manifest.
pub const MANIFEST_FILENAME: &str = "guard-manifest.yaml";

/// Suffix appended to the `.wasm` filename to produce the signature sidecar
/// path (i.e., `my-guard.wasm` -> `my-guard.wasm.sig`).
pub const SIGNATURE_SUFFIX: &str = ".sig";

/// Domain separator prepended to every signed module envelope. Bumping this
/// string invalidates all previously issued signatures, so keep it stable.
const SIGNED_MODULE_DOMAIN: &str = "chio-wasm-guard-v1";

// ---------------------------------------------------------------------------
// GuardManifest
// ---------------------------------------------------------------------------

/// Parsed representation of a `guard-manifest.yaml` file.
///
/// The manifest lives in the same directory as the `.wasm` binary and carries
/// integrity and versioning metadata that the loader verifies before
/// instantiation.
#[derive(Debug, Clone, Deserialize)]
pub struct GuardManifest {
    /// Human-readable guard name (e.g. "pii-scanner").
    pub name: String,
    /// Semantic version of the guard (e.g. "1.0.0").
    pub version: String,
    /// ABI version the guard was compiled against (must be in
    /// [`SUPPORTED_ABI_VERSIONS`]).
    pub abi_version: String,
    /// WIT world the guard component was compiled against.
    ///
    /// Loading enforces [`REQUIRED_WIT_WORLD`] fail-closed so 0.1.x components
    /// cannot be admitted silently after the M06 WIT bump.
    #[serde(default)]
    pub wit_world: Option<String>,
    /// Relative or absolute path to the `.wasm` binary.
    pub wasm_path: String,
    /// Hex-encoded SHA-256 digest of the `.wasm` binary.
    pub wasm_sha256: String,
    /// Optional guard-specific configuration key-value pairs.
    #[serde(default)]
    pub config: HashMap<String, String>,
    /// Hex-encoded Ed25519 public key of the trusted signer, if any.
    ///
    /// When set, the loader verifies that the `.wasm.sig` sidecar carries a
    /// signature produced by this key. When `None`, the module is treated as
    /// unsigned and the loader falls back to the `allow_unsigned` flag.
    #[serde(default)]
    pub signer_public_key: Option<String>,
    /// If `true`, permit loading a guard that has no `.wasm.sig` sidecar.
    ///
    /// This is an explicit opt-out that should only be used in development
    /// workflows. Production deployments should always require a signature.
    #[serde(default)]
    pub allow_unsigned: bool,
}

// ---------------------------------------------------------------------------
// SignedWasmModule
// ---------------------------------------------------------------------------

/// JSON envelope stored in the `.wasm.sig` sidecar alongside a guard binary.
///
/// The sidecar pins the signer's public key, the module identity
/// (`module_name`, `version`), and the hash of the bytes that were signed.
/// Binding the signature to all of these fields prevents an attacker from
/// swapping a signature across modules or across versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedWasmModule {
    /// Hex-encoded SHA-256 digest of the signed `.wasm` bytes.
    pub module_hash: String,
    /// Module name (must match `GuardManifest.name` when both are present).
    pub module_name: String,
    /// Module version string (must match `GuardManifest.version`).
    pub version: String,
    /// Hex-encoded Ed25519 public key of the signer.
    pub signer_public_key: String,
    /// Hex-encoded Ed25519 signature over [`signed_module_message`].
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/// Load and parse a `guard-manifest.yaml` from the parent directory of the
/// given WASM file path.
///
/// For example, if `wasm_path` is `/opt/guards/pii/pii.wasm`, this function
/// reads `/opt/guards/pii/guard-manifest.yaml`.
pub fn load_manifest(wasm_path: &str) -> Result<GuardManifest, WasmGuardError> {
    let wasm = Path::new(wasm_path);
    let parent = wasm.parent().ok_or_else(|| WasmGuardError::ManifestLoad {
        path: wasm_path.to_string(),
        reason: "wasm path has no parent directory".to_string(),
    })?;

    let manifest_path = parent.join(MANIFEST_FILENAME);
    let contents =
        std::fs::read_to_string(&manifest_path).map_err(|e| WasmGuardError::ManifestLoad {
            path: manifest_path.display().to_string(),
            reason: e.to_string(),
        })?;

    let manifest = serde_yml::from_str::<GuardManifest>(&contents)
        .map_err(|e| WasmGuardError::ManifestParse(e.to_string()))?;
    verify_wit_world(manifest.wit_world.as_deref())?;
    Ok(manifest)
}

/// Verify that the SHA-256 digest of `wasm_bytes` matches the
/// hex-encoded `expected_hex` string from the manifest.
pub fn verify_wasm_hash(wasm_bytes: &[u8], expected_hex: &str) -> Result<(), WasmGuardError> {
    let mut hasher = Sha256::new();
    hasher.update(wasm_bytes);
    let actual_hex = hex::encode(hasher.finalize());

    if actual_hex != expected_hex {
        return Err(WasmGuardError::HashMismatch {
            expected: expected_hex.to_string(),
            actual: actual_hex,
        });
    }
    Ok(())
}

/// Verify that the given ABI version string is in [`SUPPORTED_ABI_VERSIONS`].
pub fn verify_abi_version(version: &str) -> Result<(), WasmGuardError> {
    if SUPPORTED_ABI_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err(WasmGuardError::UnsupportedAbiVersion {
            version: version.to_string(),
            supported: SUPPORTED_ABI_VERSIONS.join(", "),
        })
    }
}

/// Verify that the manifest declares the required WIT world.
pub fn verify_wit_world(wit_world: Option<&str>) -> Result<(), WasmGuardError> {
    match wit_world.map(str::trim).filter(|world| !world.is_empty()) {
        Some(REQUIRED_WIT_WORLD) => Ok(()),
        Some(world) => Err(WasmGuardError::UnsupportedWitWorld {
            declared: format!("\"{world}\""),
            required: REQUIRED_WIT_WORLD.to_string(),
            migration: WIT_WORLD_MIGRATION_GUIDE,
        }),
        None => Err(WasmGuardError::UnsupportedWitWorld {
            declared: "<missing>".to_string(),
            required: REQUIRED_WIT_WORLD.to_string(),
            migration: WIT_WORLD_MIGRATION_GUIDE,
        }),
    }
}

// ---------------------------------------------------------------------------
// Signing helpers (Phase 1.3)
// ---------------------------------------------------------------------------

/// Produce the canonical byte sequence that a signer signs when attesting a
/// WASM guard module.
///
/// The envelope binds together:
///
/// 1. a fixed domain separator ([`SIGNED_MODULE_DOMAIN`]);
/// 2. the hex-encoded SHA-256 hash of the module bytes;
/// 3. the module name;
/// 4. the module version;
/// 5. the signer's public key (hex-encoded).
///
/// All fields are separated by newlines. Signatures produced over this
/// envelope cannot be replayed across different modules, versions, or
/// signers without invalidating the binding.
pub fn signed_module_message(
    module_hash_hex: &str,
    module_name: &str,
    version: &str,
    signer_public_key_hex: &str,
) -> Vec<u8> {
    format!(
        "{SIGNED_MODULE_DOMAIN}\n{module_hash_hex}\n{module_name}\n{version}\n{signer_public_key_hex}"
    )
    .into_bytes()
}

/// Compute the path at which the signature sidecar for `wasm_path` lives.
///
/// For example, given `/opt/guards/pii/pii.wasm` this returns
/// `/opt/guards/pii/pii.wasm.sig`.
pub fn signature_sidecar_path(wasm_path: &str) -> PathBuf {
    let mut p = PathBuf::from(wasm_path);
    // We append the suffix to the whole path (not just the extension) so that
    // "foo.wasm" becomes "foo.wasm.sig" rather than "foo.sig".
    let as_os = p.as_os_str().to_os_string();
    let mut combined = as_os;
    combined.push(SIGNATURE_SUFFIX);
    p = PathBuf::from(combined);
    p
}

/// Load a signature sidecar from the path returned by
/// [`signature_sidecar_path`]. Returns `Ok(None)` if the sidecar does not
/// exist (so callers can distinguish "missing" from "corrupt").
pub fn load_signature_sidecar(wasm_path: &str) -> Result<Option<SignedWasmModule>, WasmGuardError> {
    let sidecar = signature_sidecar_path(wasm_path);
    if !sidecar.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&sidecar).map_err(|e| WasmGuardError::ManifestLoad {
        path: sidecar.display().to_string(),
        reason: e.to_string(),
    })?;
    let signed: SignedWasmModule = serde_json::from_str(&contents)
        .map_err(|e| WasmGuardError::ManifestParse(e.to_string()))?;
    Ok(Some(signed))
}

/// Serialize the sidecar to JSON and write it to
/// [`signature_sidecar_path`]. Returns the path written.
pub fn write_signature_sidecar(
    wasm_path: &str,
    signed: &SignedWasmModule,
) -> Result<PathBuf, WasmGuardError> {
    let sidecar = signature_sidecar_path(wasm_path);
    let contents = serde_json::to_string_pretty(signed)
        .map_err(|e| WasmGuardError::ManifestParse(e.to_string()))?;
    std::fs::write(&sidecar, contents).map_err(|e| WasmGuardError::ManifestLoad {
        path: sidecar.display().to_string(),
        reason: e.to_string(),
    })?;
    Ok(sidecar)
}

/// Normalize a hex string: trim whitespace and strip an optional `0x` prefix.
fn normalize_hex(s: &str) -> &str {
    let t = s.trim();
    t.strip_prefix("0x").unwrap_or(t)
}

/// Verify a [`SignedWasmModule`] against the raw WASM bytes on disk and a
/// trusted hex-encoded Ed25519 public key.
///
/// Checks, in order:
///
/// 1. `trusted_signer_pk_hex` matches `signed.signer_public_key`;
/// 2. the SHA-256 of `wasm_bytes` matches `signed.module_hash`;
/// 3. the signature decodes as a valid Ed25519 signature;
/// 4. the signature verifies over [`signed_module_message`] under the
///    declared public key using `verify_strict`.
pub fn verify_signed_module(
    wasm_bytes: &[u8],
    signed: &SignedWasmModule,
    trusted_signer_pk_hex: &str,
) -> Result<(), WasmGuardError> {
    let trusted = normalize_hex(trusted_signer_pk_hex).to_ascii_lowercase();
    let declared = normalize_hex(&signed.signer_public_key).to_ascii_lowercase();
    if trusted != declared {
        return Err(WasmGuardError::SignatureVerification(format!(
            "sidecar signer_public_key {declared} does not match trusted key {trusted}"
        )));
    }

    let actual_hash = hex::encode(Sha256::digest(wasm_bytes));
    if actual_hash != normalize_hex(&signed.module_hash).to_ascii_lowercase() {
        return Err(WasmGuardError::HashMismatch {
            expected: signed.module_hash.clone(),
            actual: actual_hash,
        });
    }

    let pk_bytes = hex::decode(&declared).map_err(|e| {
        WasmGuardError::SignatureVerification(format!("signer_public_key is not valid hex: {e}"))
    })?;
    let pk_array: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| {
        WasmGuardError::SignatureVerification(format!(
            "signer_public_key must be 32 bytes, got {}",
            pk_bytes.len()
        ))
    })?;
    let verifying_key = VerifyingKey::from_bytes(&pk_array).map_err(|e| {
        WasmGuardError::SignatureVerification(format!(
            "signer_public_key is not a valid Ed25519 key: {e}"
        ))
    })?;

    let sig_bytes = hex::decode(normalize_hex(&signed.signature)).map_err(|e| {
        WasmGuardError::SignatureVerification(format!("signature is not valid hex: {e}"))
    })?;
    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        WasmGuardError::SignatureVerification(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ))
    })?;
    let signature = Signature::from_bytes(&sig_array);

    let message = signed_module_message(
        &signed.module_hash,
        &signed.module_name,
        &signed.version,
        &signed.signer_public_key,
    );

    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|e| {
            WasmGuardError::SignatureVerification(format!("ed25519 verification failed: {e}"))
        })?;

    Ok(())
}

/// Enforce the Phase 1.3 signing policy for a guard about to be loaded.
///
/// The policy is:
///
/// - If `guard-manifest.yaml` pins a `signer_public_key`, the `.wasm.sig`
///   sidecar MUST exist and MUST carry a valid signature under that key.
/// - If the manifest does NOT pin a signer_public_key, any `.wasm.sig`
///   sidecar is treated as informational only. It is NOT a trust anchor by
///   itself. Loading is permitted only when `manifest.allow_unsigned` is
///   `true` (a `WARN` is emitted through `tracing`). Otherwise loading is
///   rejected with a clear "not signed" error.
/// - If the manifest pins a signer but allow_unsigned is also true and the
///   sidecar is missing, the pinning still wins and loading is rejected.
///   Operators who want to opt out must remove the `signer_public_key`.
/// - If the manifest declares a name/version and the sidecar declares a
///   different name/version, loading is rejected (defense against sidecar
///   mismatch).
pub fn verify_guard_signature(
    wasm_path: &str,
    wasm_bytes: &[u8],
    manifest: &GuardManifest,
) -> Result<(), WasmGuardError> {
    if manifest.signer_public_key.is_none() && manifest.allow_unsigned {
        tracing::warn!(
            wasm_path = %wasm_path,
            guard = %manifest.name,
            version = %manifest.version,
            "loading unsigned WASM guard: allow_unsigned=true in manifest"
        );
        return Ok(());
    }

    let sidecar = load_signature_sidecar(wasm_path)?;

    match (&manifest.signer_public_key, sidecar) {
        (Some(pk_hex), Some(signed)) => {
            // Defense-in-depth: bind the sidecar's identity to the manifest's.
            if signed.module_name != manifest.name {
                return Err(WasmGuardError::SignatureVerification(format!(
                    "signature sidecar module_name {:?} does not match manifest name {:?}",
                    signed.module_name, manifest.name
                )));
            }
            if signed.version != manifest.version {
                return Err(WasmGuardError::SignatureVerification(format!(
                    "signature sidecar version {:?} does not match manifest version {:?}",
                    signed.version, manifest.version
                )));
            }
            verify_signed_module(wasm_bytes, &signed, pk_hex)
        }
        (Some(_), None) => Err(WasmGuardError::SignatureVerification(format!(
            "guard module {wasm_path} is not signed: manifest pins signer_public_key but no {SIGNATURE_SUFFIX} sidecar was found"
        ))),
        (None, Some(signed)) => {
            if signed.module_name != manifest.name {
                return Err(WasmGuardError::SignatureVerification(format!(
                    "signature sidecar module_name {:?} does not match manifest name {:?}",
                    signed.module_name, manifest.name
                )));
            }
            if signed.version != manifest.version {
                return Err(WasmGuardError::SignatureVerification(format!(
                    "signature sidecar version {:?} does not match manifest version {:?}",
                    signed.version, manifest.version
                )));
            }
            if manifest.allow_unsigned {
                tracing::warn!(
                    wasm_path = %wasm_path,
                    guard = %manifest.name,
                    version = %manifest.version,
                    "ignoring unpinned WASM signature sidecar: allow_unsigned=true and manifest does not pin signer_public_key"
                );
                Ok(())
            } else {
                Err(WasmGuardError::SignatureVerification(format!(
                    "guard module {wasm_path} has an unpinned {SIGNATURE_SUFFIX} sidecar but manifest does not declare signer_public_key"
                )))
            }
        }
        (None, None) => {
            Err(WasmGuardError::SignatureVerification(format!(
                "guard module {wasm_path} is not signed: no {SIGNATURE_SUFFIX} sidecar found and allow_unsigned is false"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // -- Deserialization tests ------------------------------------------------

    #[test]
    fn manifest_deserializes_from_valid_yaml() {
        let yaml = r#"
name: pii-scanner
version: "1.0.0"
abi_version: "1"
wit_world: "chio:guard/guard@0.2.0"
wasm_path: pii.wasm
wasm_sha256: abc123
config:
  threshold: "0.8"
  mode: strict
"#;
        let manifest: GuardManifest = serde_yml::from_str(yaml).unwrap();
        assert_eq!(manifest.name, "pii-scanner");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.abi_version, "1");
        assert_eq!(manifest.wit_world.as_deref(), Some(REQUIRED_WIT_WORLD));
        assert_eq!(manifest.wasm_path, "pii.wasm");
        assert_eq!(manifest.wasm_sha256, "abc123");
        assert_eq!(manifest.config.len(), 2);
        assert_eq!(manifest.config.get("threshold").unwrap(), "0.8");
        assert_eq!(manifest.config.get("mode").unwrap(), "strict");
    }

    #[test]
    fn manifest_deserializes_with_empty_config() {
        let yaml = r#"
name: simple-guard
version: "0.1.0"
abi_version: "1"
wit_world: "chio:guard/guard@0.2.0"
wasm_path: simple.wasm
wasm_sha256: deadbeef
"#;
        let manifest: GuardManifest = serde_yml::from_str(yaml).unwrap();
        assert_eq!(manifest.name, "simple-guard");
        assert!(
            manifest.config.is_empty(),
            "config should default to empty HashMap"
        );
    }

    #[test]
    fn manifest_rejects_missing_required_fields() {
        // Missing name
        let yaml = r#"
version: "1.0.0"
abi_version: "1"
wasm_sha256: abc123
wasm_path: foo.wasm
"#;
        let result = serde_yml::from_str::<GuardManifest>(yaml);
        assert!(result.is_err(), "should reject YAML missing 'name'");

        // Missing abi_version
        let yaml = r#"
name: test
version: "1.0.0"
wasm_sha256: abc123
wasm_path: foo.wasm
"#;
        let result = serde_yml::from_str::<GuardManifest>(yaml);
        assert!(result.is_err(), "should reject YAML missing 'abi_version'");

        // Missing wasm_sha256
        let yaml = r#"
name: test
version: "1.0.0"
abi_version: "1"
wasm_path: foo.wasm
"#;
        let result = serde_yml::from_str::<GuardManifest>(yaml);
        assert!(result.is_err(), "should reject YAML missing 'wasm_sha256'");
    }

    // -- verify_wasm_hash tests -----------------------------------------------

    #[test]
    fn verify_wasm_hash_accepts_matching_digest() {
        let data = b"hello wasm module";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let expected = hex::encode(hasher.finalize());

        assert!(verify_wasm_hash(data, &expected).is_ok());
    }

    #[test]
    fn verify_wasm_hash_rejects_mismatching_digest() {
        let data = b"hello wasm module";
        let result = verify_wasm_hash(
            data,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmGuardError::HashMismatch { expected, actual } => {
                assert_eq!(
                    expected,
                    "0000000000000000000000000000000000000000000000000000000000000000"
                );
                assert!(!actual.is_empty());
                assert_ne!(actual, expected);
            }
            other => panic!("expected HashMismatch, got: {other:?}"),
        }
    }

    // -- verify_abi_version tests ---------------------------------------------

    #[test]
    fn verify_abi_version_accepts_supported_version() {
        assert!(verify_abi_version("1").is_ok());
    }

    #[test]
    fn verify_abi_version_rejects_unsupported_version() {
        let result = verify_abi_version("99");
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmGuardError::UnsupportedAbiVersion { version, supported } => {
                assert_eq!(version, "99");
                assert_eq!(supported, "1");
            }
            other => panic!("expected UnsupportedAbiVersion, got: {other:?}"),
        }
    }

    // -- load_manifest tests --------------------------------------------------

    #[test]
    fn load_manifest_reads_adjacent_yaml() {
        let dir = std::env::temp_dir().join("chio_manifest_test_load");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let manifest_content = r#"
name: test-guard
version: "0.1.0"
abi_version: "1"
wit_world: "chio:guard/guard@0.2.0"
wasm_path: test.wasm
wasm_sha256: abcdef0123456789
config:
  key: value
"#;
        let manifest_path = dir.join(MANIFEST_FILENAME);
        let mut f = std::fs::File::create(&manifest_path).unwrap();
        f.write_all(manifest_content.as_bytes()).unwrap();

        let wasm_path = dir.join("test.wasm");
        let manifest = load_manifest(wasm_path.to_str().unwrap()).unwrap();
        assert_eq!(manifest.name, "test-guard");
        assert_eq!(manifest.abi_version, "1");
        assert_eq!(manifest.config.get("key").unwrap(), "value");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_manifest_returns_error_when_file_missing() {
        let result = load_manifest("/nonexistent/path/guard.wasm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WasmGuardError::ManifestLoad { path, reason } => {
                assert!(
                    path.contains("guard-manifest.yaml"),
                    "path should contain manifest filename, got: {path}"
                );
                assert!(!reason.is_empty());
            }
            other => panic!("expected ManifestLoad, got: {other:?}"),
        }
    }

    // -- Error display tests --------------------------------------------------

    #[test]
    fn error_display_manifest_parse() {
        let err = WasmGuardError::ManifestParse("bad yaml".to_string());
        assert_eq!(err.to_string(), "failed to parse guard manifest: bad yaml");
    }

    #[test]
    fn error_display_hash_mismatch() {
        let err = WasmGuardError::HashMismatch {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        assert_eq!(err.to_string(), "wasm hash mismatch: expected aaa, got bbb");
    }

    #[test]
    fn error_display_unsupported_abi() {
        let err = WasmGuardError::UnsupportedAbiVersion {
            version: "99".to_string(),
            supported: "1".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "unsupported abi_version \"99\" (supported: 1)"
        );
    }

    #[test]
    fn error_display_manifest_load() {
        let err = WasmGuardError::ManifestLoad {
            path: "/foo/bar".to_string(),
            reason: "not found".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to load guard manifest for /foo/bar: not found"
        );
    }

    // -- Signing tests (Phase 1.3) --------------------------------------------

    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    const SIGN_TEST_WASM: &[u8] = b"\x00asm\x01\x00\x00\x00dummy-guard-bytes";

    fn make_signed(sk: &SigningKey, bytes: &[u8], name: &str, version: &str) -> SignedWasmModule {
        let module_hash = hex::encode(Sha256::digest(bytes));
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
    fn signed_module_message_is_canonical_newline_separated() {
        let msg = signed_module_message("deadbeef", "g", "1.0.0", "aa11");
        let s = std::str::from_utf8(&msg).unwrap();
        assert_eq!(s, "chio-wasm-guard-v1\ndeadbeef\ng\n1.0.0\naa11");
    }

    #[test]
    fn signature_sidecar_path_appends_sig_suffix() {
        let p = signature_sidecar_path("/opt/guards/pii/pii.wasm");
        assert_eq!(p.to_string_lossy(), "/opt/guards/pii/pii.wasm.sig");
    }

    #[test]
    fn verify_signed_module_accepts_valid_signature() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = make_signed(&sk, SIGN_TEST_WASM, "g", "0.1.0");
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        verify_signed_module(SIGN_TEST_WASM, &signed, &pk_hex).unwrap();
    }

    #[test]
    fn verify_signed_module_rejects_tampered_bytes() {
        let sk = SigningKey::generate(&mut OsRng);
        let signed = make_signed(&sk, SIGN_TEST_WASM, "g", "0.1.0");
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());

        let mut tampered = SIGN_TEST_WASM.to_vec();
        tampered.push(0xAA);
        let err = verify_signed_module(&tampered, &signed, &pk_hex).unwrap_err();
        match err {
            WasmGuardError::HashMismatch { .. } => {}
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_signed_module_rejects_wrong_signer_key() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let signed = make_signed(&sk, SIGN_TEST_WASM, "g", "0.1.0");
        let other_pk = hex::encode(other.verifying_key().to_bytes());
        let err = verify_signed_module(SIGN_TEST_WASM, &signed, &other_pk).unwrap_err();
        match err {
            WasmGuardError::SignatureVerification(msg) => {
                assert!(msg.contains("does not match trusted key"), "{msg}");
            }
            other => panic!("expected SignatureVerification, got {other:?}"),
        }
    }

    #[test]
    fn verify_signed_module_rejects_forged_signature() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut signed = make_signed(&sk, SIGN_TEST_WASM, "g", "0.1.0");
        // Flip one byte in the signature hex.
        let mut sig_bytes = hex::decode(&signed.signature).unwrap();
        sig_bytes[0] ^= 0x01;
        signed.signature = hex::encode(&sig_bytes);

        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let err = verify_signed_module(SIGN_TEST_WASM, &signed, &pk_hex).unwrap_err();
        match err {
            WasmGuardError::SignatureVerification(msg) => {
                assert!(msg.contains("ed25519"), "{msg}");
            }
            other => panic!("expected SignatureVerification, got {other:?}"),
        }
    }

    #[test]
    fn verify_guard_signature_accepts_valid_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("g.wasm");
        std::fs::write(&wasm_path, SIGN_TEST_WASM).unwrap();

        let sk = SigningKey::generate(&mut OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let signed = make_signed(&sk, SIGN_TEST_WASM, "g", "0.1.0");
        write_signature_sidecar(wasm_path.to_str().unwrap(), &signed).unwrap();

        let manifest = GuardManifest {
            name: "g".to_string(),
            version: "0.1.0".to_string(),
            abi_version: "1".to_string(),
            wit_world: Some(REQUIRED_WIT_WORLD.to_string()),
            wasm_path: "g.wasm".to_string(),
            wasm_sha256: hex::encode(Sha256::digest(SIGN_TEST_WASM)),
            config: HashMap::new(),
            signer_public_key: Some(pk_hex),
            allow_unsigned: false,
        };

        verify_guard_signature(wasm_path.to_str().unwrap(), SIGN_TEST_WASM, &manifest).unwrap();
    }

    #[test]
    fn verify_guard_signature_rejects_missing_sidecar_without_opt_out() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("g.wasm");
        std::fs::write(&wasm_path, SIGN_TEST_WASM).unwrap();
        // No sidecar.

        let manifest = GuardManifest {
            name: "g".to_string(),
            version: "0.1.0".to_string(),
            abi_version: "1".to_string(),
            wit_world: Some(REQUIRED_WIT_WORLD.to_string()),
            wasm_path: "g.wasm".to_string(),
            wasm_sha256: hex::encode(Sha256::digest(SIGN_TEST_WASM)),
            config: HashMap::new(),
            signer_public_key: None,
            allow_unsigned: false,
        };

        let err = verify_guard_signature(wasm_path.to_str().unwrap(), SIGN_TEST_WASM, &manifest)
            .unwrap_err();
        match err {
            WasmGuardError::SignatureVerification(msg) => {
                assert!(msg.contains("not signed"), "{msg}");
            }
            other => panic!("expected SignatureVerification, got {other:?}"),
        }
    }

    #[test]
    fn verify_guard_signature_allows_unsigned_when_opted_in() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("g.wasm");
        std::fs::write(&wasm_path, SIGN_TEST_WASM).unwrap();
        // No sidecar.

        let manifest = GuardManifest {
            name: "g".to_string(),
            version: "0.1.0".to_string(),
            abi_version: "1".to_string(),
            wit_world: Some(REQUIRED_WIT_WORLD.to_string()),
            wasm_path: "g.wasm".to_string(),
            wasm_sha256: hex::encode(Sha256::digest(SIGN_TEST_WASM)),
            config: HashMap::new(),
            signer_public_key: None,
            allow_unsigned: true,
        };

        // Succeeds (with warning log).
        verify_guard_signature(wasm_path.to_str().unwrap(), SIGN_TEST_WASM, &manifest).unwrap();
    }

    #[test]
    fn verify_guard_signature_ignores_malformed_sidecar_when_unsigned_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("g.wasm");
        let sidecar_path = dir.path().join(format!("g.wasm{SIGNATURE_SUFFIX}"));
        std::fs::write(&wasm_path, SIGN_TEST_WASM).unwrap();
        std::fs::write(&sidecar_path, b"{not-json").unwrap();

        let manifest = GuardManifest {
            name: "g".to_string(),
            version: "0.1.0".to_string(),
            abi_version: "1".to_string(),
            wit_world: Some(REQUIRED_WIT_WORLD.to_string()),
            wasm_path: "g.wasm".to_string(),
            wasm_sha256: hex::encode(Sha256::digest(SIGN_TEST_WASM)),
            config: HashMap::new(),
            signer_public_key: None,
            allow_unsigned: true,
        };

        verify_guard_signature(wasm_path.to_str().unwrap(), SIGN_TEST_WASM, &manifest).unwrap();
    }

    #[test]
    fn verify_guard_signature_rejects_name_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("g.wasm");
        std::fs::write(&wasm_path, SIGN_TEST_WASM).unwrap();

        let sk = SigningKey::generate(&mut OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        // Sidecar claims name "evil" but manifest declares "g".
        let signed = make_signed(&sk, SIGN_TEST_WASM, "evil", "0.1.0");
        write_signature_sidecar(wasm_path.to_str().unwrap(), &signed).unwrap();

        let manifest = GuardManifest {
            name: "g".to_string(),
            version: "0.1.0".to_string(),
            abi_version: "1".to_string(),
            wit_world: Some(REQUIRED_WIT_WORLD.to_string()),
            wasm_path: "g.wasm".to_string(),
            wasm_sha256: hex::encode(Sha256::digest(SIGN_TEST_WASM)),
            config: HashMap::new(),
            signer_public_key: Some(pk_hex),
            allow_unsigned: false,
        };

        let err = verify_guard_signature(wasm_path.to_str().unwrap(), SIGN_TEST_WASM, &manifest)
            .unwrap_err();
        match err {
            WasmGuardError::SignatureVerification(msg) => {
                assert!(msg.contains("module_name"), "{msg}");
            }
            other => panic!("expected SignatureVerification, got {other:?}"),
        }
    }

    #[test]
    fn verify_guard_signature_rejects_unpinned_sidecar_without_opt_out() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_path = dir.path().join("g.wasm");
        std::fs::write(&wasm_path, SIGN_TEST_WASM).unwrap();

        let sk = SigningKey::generate(&mut OsRng);
        let signed = make_signed(&sk, SIGN_TEST_WASM, "g", "0.1.0");
        write_signature_sidecar(wasm_path.to_str().unwrap(), &signed).unwrap();

        let manifest = GuardManifest {
            name: "g".to_string(),
            version: "0.1.0".to_string(),
            abi_version: "1".to_string(),
            wit_world: Some(REQUIRED_WIT_WORLD.to_string()),
            wasm_path: "g.wasm".to_string(),
            wasm_sha256: hex::encode(Sha256::digest(SIGN_TEST_WASM)),
            config: HashMap::new(),
            signer_public_key: None,
            allow_unsigned: false,
        };

        let err = verify_guard_signature(wasm_path.to_str().unwrap(), SIGN_TEST_WASM, &manifest)
            .unwrap_err();
        match err {
            WasmGuardError::SignatureVerification(msg) => {
                assert!(msg.contains("unpinned"), "{msg}");
            }
            other => panic!("expected SignatureVerification, got {other:?}"),
        }
    }

    #[test]
    fn manifest_deserializes_with_signature_fields() {
        let yaml = r#"
name: g
version: "1.0.0"
abi_version: "1"
wasm_path: g.wasm
wasm_sha256: deadbeef
signer_public_key: "aabbccdd"
allow_unsigned: false
"#;
        let m: GuardManifest = serde_yml::from_str(yaml).unwrap();
        assert_eq!(m.signer_public_key.as_deref(), Some("aabbccdd"));
        assert!(!m.allow_unsigned);
    }

    #[test]
    fn manifest_allow_unsigned_defaults_false() {
        let yaml = r#"
name: g
version: "1.0.0"
abi_version: "1"
wasm_path: g.wasm
wasm_sha256: deadbeef
"#;
        let m: GuardManifest = serde_yml::from_str(yaml).unwrap();
        assert!(m.signer_public_key.is_none());
        assert!(!m.allow_unsigned, "allow_unsigned should default to false");
    }
}
