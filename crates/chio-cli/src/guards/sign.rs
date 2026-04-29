//! Implementation of `chio guard sign` and `chio guard verify`.
//!
//! `sign` reads a `.wasm` file, loads an Ed25519 signing seed from a file,
//! and writes a JSON `.wasm.sig` sidecar next to the WASM binary.
//!
//! `verify` reads a `.wasm` file and its `.wasm.sig` sidecar and verifies the
//! signature. If a `guard-manifest.yaml` is adjacent, it is consulted for the
//! trusted `signer_public_key`; otherwise the sidecar's embedded public key is
//! trusted on its own (useful for operators who only have a `.sig` file).

use std::fs;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use chio_wasm_guards::manifest::{
    load_manifest, load_signature_sidecar, signed_module_message, verify_signed_module,
    write_signature_sidecar, SignedWasmModule,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use crate::CliError;

/// `chio guard sign` -- sign a `.wasm` module and write a `.sig` sidecar.
///
/// - `wasm_path`: path to the `.wasm` binary.
/// - `key_path`: path to a file containing a hex-encoded 32-byte Ed25519 seed.
/// - `name`: module name to embed in the signed envelope (typically matches
///   the `name` field in `guard-manifest.yaml`).
/// - `version`: module version to embed in the signed envelope.
pub fn cmd_guard_sign(
    wasm_path: &Path,
    key_path: &Path,
    name: &str,
    version: &str,
) -> Result<(), CliError> {
    let wasm_bytes = fs::read(wasm_path).map_err(|e| {
        CliError::Other(format!(
            "failed to read wasm module {}: {e}",
            wasm_path.display()
        ))
    })?;

    let signing_key = load_signing_key(key_path)?;
    let signer_public_key = hex::encode(signing_key.verifying_key().to_bytes());

    let module_hash = hex::encode(Sha256::digest(&wasm_bytes));
    let message = signed_module_message(&module_hash, name, version, &signer_public_key);
    let signature = signing_key.sign(&message);

    let signed = SignedWasmModule {
        module_hash: module_hash.clone(),
        module_name: name.to_string(),
        version: version.to_string(),
        signer_public_key: signer_public_key.clone(),
        signature: hex::encode(signature.to_bytes()),
    };

    let wasm_path_str = wasm_path_to_str(wasm_path)?;
    let sidecar_path = write_signature_sidecar(wasm_path_str, &signed)
        .map_err(|e| CliError::Other(format!("failed to write signature sidecar: {e}")))?;

    println!("signed {}", wasm_path.display());
    println!("  sidecar:   {}", sidecar_path.display());
    println!("  signer_pk: {signer_public_key}");
    println!("  module:    {name}@{version}");
    println!("  digest:    {module_hash}");

    Ok(())
}

/// `chio guard verify` -- verify the `.sig` sidecar for a `.wasm` module.
///
/// Returns `Ok(())` (exit code 0) on success and `Err(CliError)` (exit code 1)
/// on any failure: missing sidecar, hash mismatch, untrusted signer, or bad
/// signature. If `guard-manifest.yaml` is adjacent to the `.wasm` file, its
/// `signer_public_key` is used as the trust anchor; otherwise the sidecar's
/// embedded key is trusted on its own.
pub fn cmd_guard_verify(wasm_path: &Path) -> Result<(), CliError> {
    let wasm_bytes = fs::read(wasm_path).map_err(|e| {
        CliError::Other(format!(
            "failed to read wasm module {}: {e}",
            wasm_path.display()
        ))
    })?;

    let wasm_path_str = wasm_path_to_str(wasm_path)?;

    let signed = load_signature_sidecar(wasm_path_str)
        .map_err(|e| CliError::Other(format!("failed to load signature sidecar: {e}")))?
        .ok_or_else(|| {
            CliError::Other(format!(
                "guard module {} is not signed (missing {}.sig sidecar)",
                wasm_path.display(),
                wasm_path.display()
            ))
        })?;

    // Prefer the manifest's declared signer_public_key if adjacent. Only a
    // genuine "no manifest here" falls back to the sidecar-embedded key;
    // parse errors, permission errors, or any other I/O failure must reject
    // fail-closed so a malformed or unreadable manifest cannot silently
    // bypass the pinned trust anchor.
    let manifest_parent = wasm_path.parent().ok_or_else(|| {
        CliError::Other(format!(
            "wasm path {} has no parent directory; cannot locate adjacent guard-manifest.yaml",
            wasm_path.display()
        ))
    })?;
    let manifest_path = manifest_parent.join(chio_wasm_guards::manifest::MANIFEST_FILENAME);
    // Distinguish a real "not found" (fall back to sidecar key) from any
    // other I/O failure (permission denied, broken symlink, etc.), which
    // must abort verification instead of silently reverting to the
    // sidecar-embedded trust anchor.
    let manifest_exists = match manifest_path.try_exists() {
        Ok(v) => v,
        Err(e) => {
            return Err(CliError::Other(format!(
                "failed to stat adjacent guard-manifest.yaml at {}: {e}",
                manifest_path.display()
            )));
        }
    };

    let trusted_key = if manifest_exists {
        let manifest = load_manifest(wasm_path_str).map_err(|e| {
            CliError::Other(format!(
                "failed to load adjacent guard-manifest.yaml for {}: {e}",
                wasm_path.display()
            ))
        })?;
        match manifest.signer_public_key {
            Some(k) => k,
            None => {
                // Manifest exists but does not pin a signer -- reject per
                // fail-closed policy so operators add the key to the manifest.
                return Err(CliError::Other(format!(
                    "adjacent guard-manifest.yaml does not declare signer_public_key; \
                     refusing to verify {}",
                    wasm_path.display()
                )));
            }
        }
    } else {
        // No adjacent manifest. Fall back to trusting the key embedded in the
        // sidecar. Useful for standalone verification of a `.wasm` + `.sig`
        // pair outside a guard project.
        signed.signer_public_key.clone()
    };

    verify_signed_module(&wasm_bytes, &signed, &trusted_key).map_err(|e| {
        CliError::Other(format!(
            "signature verification failed for {}: {e}",
            wasm_path.display()
        ))
    })?;

    println!("verified {}", wasm_path.display());
    println!("  signer_pk: {}", signed.signer_public_key);
    println!("  module:    {}@{}", signed.module_name, signed.version);
    println!("  digest:    {}", signed.module_hash);

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn wasm_path_to_str(path: &Path) -> Result<&str, CliError> {
    path.to_str().ok_or_else(|| {
        CliError::Other(format!(
            "wasm path is not valid UTF-8: {}",
            path.display()
        ))
    })
}

/// Read a 32-byte Ed25519 seed from the given file.
///
/// The file must contain hex-encoded bytes (with optional `0x` prefix and
/// trailing whitespace). This matches the `.chio-authority-seed` format used
/// by other CLI commands.
fn load_signing_key(path: &Path) -> Result<SigningKey, CliError> {
    let contents = fs::read_to_string(path).map_err(|e| {
        CliError::Other(format!(
            "failed to read signing key file {}: {e}",
            path.display()
        ))
    })?;
    let trimmed = contents.trim();
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(hex_str).map_err(|e| {
        CliError::Other(format!(
            "signing key file {} is not valid hex: {e}",
            path.display()
        ))
    })?;
    if bytes.len() != 32 {
        return Err(CliError::Other(format!(
            "signing key file {} must contain 32 bytes (got {})",
            path.display(),
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

/// Generate a random Ed25519 seed and write it (hex-encoded) to `path`.
/// Intended for tests and local development bootstrap; the production
/// `.chio-authority-seed` flow is handled in chio-control-plane.
#[cfg(test)]
fn write_random_seed(path: &Path) -> Result<SigningKey, CliError> {
    use rand_core::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let hex_seed = hex::encode(sk.to_bytes());
    fs::write(path, hex_seed).map_err(|e| {
        CliError::Other(format!(
            "failed to write seed file {}: {e}",
            path.display()
        ))
    })?;
    Ok(sk)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const MINIMAL_WASM: &[u8] = b"\x00asm\x01\x00\x00\x00";

    fn write_minimal_wasm(dir: &Path, filename: &str) -> PathBuf {
        let p = dir.join(filename);
        fs::write(&p, MINIMAL_WASM).unwrap();
        p
    }

    #[test]
    fn sign_writes_sidecar_with_expected_contents() {
        let dir = tempfile::tempdir().unwrap();
        let wasm = write_minimal_wasm(dir.path(), "g.wasm");
        let seed_path = dir.path().join("key.seed");
        let sk = write_random_seed(&seed_path).unwrap();

        cmd_guard_sign(&wasm, &seed_path, "g", "0.1.0").unwrap();

        let sidecar = dir.path().join("g.wasm.sig");
        assert!(sidecar.exists(), "sidecar should have been written");

        let signed: SignedWasmModule =
            serde_json::from_str(&fs::read_to_string(&sidecar).unwrap()).unwrap();
        assert_eq!(signed.module_name, "g");
        assert_eq!(signed.version, "0.1.0");
        assert_eq!(
            signed.signer_public_key,
            hex::encode(sk.verifying_key().to_bytes())
        );
        assert_eq!(signed.module_hash, hex::encode(Sha256::digest(MINIMAL_WASM)));
    }

    #[test]
    fn verify_succeeds_after_sign_when_no_manifest_present() {
        let dir = tempfile::tempdir().unwrap();
        let wasm = write_minimal_wasm(dir.path(), "g.wasm");
        let seed_path = dir.path().join("key.seed");
        let _sk = write_random_seed(&seed_path).unwrap();

        cmd_guard_sign(&wasm, &seed_path, "g", "0.1.0").unwrap();
        cmd_guard_verify(&wasm).unwrap();
    }

    #[test]
    fn verify_succeeds_when_manifest_matches_signer() {
        let dir = tempfile::tempdir().unwrap();
        let wasm = write_minimal_wasm(dir.path(), "g.wasm");
        let seed_path = dir.path().join("key.seed");
        let sk = write_random_seed(&seed_path).unwrap();

        cmd_guard_sign(&wasm, &seed_path, "g", "0.1.0").unwrap();

        // Write a manifest pinning the same signer key.
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let manifest = format!(
            "name: g\n\
             version: \"0.1.0\"\n\
             abi_version: \"1\"\n\
             wit_world: \"chio:guard/guard@0.2.0\"\n\
             wasm_path: g.wasm\n\
             wasm_sha256: {}\n\
             signer_public_key: \"{pk_hex}\"\n",
            hex::encode(Sha256::digest(MINIMAL_WASM))
        );
        fs::write(dir.path().join("guard-manifest.yaml"), manifest).unwrap();

        cmd_guard_verify(&wasm).unwrap();
    }

    #[test]
    fn verify_fails_when_manifest_pins_different_signer() {
        let dir = tempfile::tempdir().unwrap();
        let wasm = write_minimal_wasm(dir.path(), "g.wasm");
        let seed_path = dir.path().join("key.seed");
        let _sk = write_random_seed(&seed_path).unwrap();

        cmd_guard_sign(&wasm, &seed_path, "g", "0.1.0").unwrap();

        // Manifest pins a DIFFERENT signer.
        let other_seed = dir.path().join("other.seed");
        let other_sk = write_random_seed(&other_seed).unwrap();
        let other_pk_hex = hex::encode(other_sk.verifying_key().to_bytes());
        let manifest = format!(
            "name: g\n\
             version: \"0.1.0\"\n\
             abi_version: \"1\"\n\
             wit_world: \"chio:guard/guard@0.2.0\"\n\
             wasm_path: g.wasm\n\
             wasm_sha256: {}\n\
             signer_public_key: \"{other_pk_hex}\"\n",
            hex::encode(Sha256::digest(MINIMAL_WASM))
        );
        fs::write(dir.path().join("guard-manifest.yaml"), manifest).unwrap();

        let err = cmd_guard_verify(&wasm).unwrap_err();
        match err {
            CliError::Other(msg) => {
                assert!(msg.contains("signature verification failed"), "{msg}");
            }
            other => panic!("expected CliError::Other, got: {other:?}"),
        }
    }

    #[test]
    fn verify_fails_when_sidecar_missing() {
        let dir = tempfile::tempdir().unwrap();
        let wasm = write_minimal_wasm(dir.path(), "g.wasm");
        let err = cmd_guard_verify(&wasm).unwrap_err();
        match err {
            CliError::Other(msg) => {
                assert!(msg.contains("not signed"), "{msg}");
            }
            other => panic!("expected CliError::Other, got: {other:?}"),
        }
    }

    #[test]
    fn verify_fails_when_wasm_bytes_tampered_after_signing() {
        let dir = tempfile::tempdir().unwrap();
        let wasm = write_minimal_wasm(dir.path(), "g.wasm");
        let seed_path = dir.path().join("key.seed");
        let _sk = write_random_seed(&seed_path).unwrap();

        cmd_guard_sign(&wasm, &seed_path, "g", "0.1.0").unwrap();

        // Modify the wasm bytes in place.
        let mut tampered = MINIMAL_WASM.to_vec();
        tampered.push(0xAA);
        fs::write(&wasm, &tampered).unwrap();

        let err = cmd_guard_verify(&wasm).unwrap_err();
        match err {
            CliError::Other(msg) => {
                assert!(
                    msg.contains("verification failed") || msg.contains("hash"),
                    "{msg}"
                );
            }
            other => panic!("expected CliError::Other, got: {other:?}"),
        }
    }

    #[test]
    fn load_signing_key_rejects_non_hex_seed_file() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("bad.seed");
        fs::write(&seed_path, "not-hex!!!").unwrap();
        let err = load_signing_key(&seed_path).unwrap_err();
        match err {
            CliError::Other(msg) => assert!(msg.contains("not valid hex"), "{msg}"),
            other => panic!("expected Other, got: {other:?}"),
        }
    }

    #[test]
    fn load_signing_key_rejects_wrong_length_seed_file() {
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("short.seed");
        fs::write(&seed_path, "aabbccdd").unwrap();
        let err = load_signing_key(&seed_path).unwrap_err();
        match err {
            CliError::Other(msg) => assert!(msg.contains("must contain 32 bytes"), "{msg}"),
            other => panic!("expected Other, got: {other:?}"),
        }
    }
}
