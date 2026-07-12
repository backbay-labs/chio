#![cfg(not(target_arch = "wasm32"))]

//! Anchored-root tamper regression.
//!
//! The canary replay fixture is used to build the same
//! `(receipt_id, leaf_hash, inclusion_proof, root)` tuple shape as the
//! differential anchored-root harness. The tests mutate a receipt byte, reverse
//! odd-index sibling order, truncate a path, and pad a path. Rust and TypeScript
//! must reject the same malformed tuples.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chio_anchor::AnchorError;
use chio_core::canonical::canonical_json_bytes;
use chio_core::hashing::Hash;
use chio_core::merkle::{leaf_hash, MerkleProof, MerkleTree};
use serde_json::{json, Value};

const EXPECTED_FIXTURE_COUNT: usize = 50;
const FIXED_CLOCK_EPOCH_MS: u64 = 1_767_225_600_000;
const CANARY_RECEIPT_ID: &str = "allow_simple/01_basic_capability";
const CANARY_FIXTURE_PATH: &str = "tests/replay/fixtures/allow_simple/01_basic_capability.json";
const TYPESCRIPT_TAMPER_SCRIPT: &str = r#"
try {
  const fixturesRoot = process.env.CHIO_REPLAY_FIXTURES_ROOT;
  const expectedCount = Number(process.env.CHIO_REPLAY_EXPECTED_COUNT);
  const receiptId = process.env.CHIO_REPLAY_RECEIPT_ID;
  if (fixturesRoot == null || fixturesRoot.length === 0) {
    throw new Error("CHIO_REPLAY_FIXTURES_ROOT must be set");
  }
  if (!Number.isSafeInteger(expectedCount) || expectedCount < 1) {
    throw new Error("CHIO_REPLAY_EXPECTED_COUNT must be a positive safe integer");
  }
  if (receiptId == null || receiptId.length === 0) {
    throw new Error("CHIO_REPLAY_RECEIPT_ID must be set");
  }

  const {
    ReplayScenarioError,
    leafHash,
    runReplayScenarios,
    verifyInclusionProof,
  } = await import("./src/replay.ts");
  const outputs = await runReplayScenarios({ fixturesRoot, expectedCount });
  const output = outputs.find((candidate) => candidate.scenario.name === receiptId);
  if (output == null) {
    throw new Error(`missing replay output for ${receiptId}`);
  }

  const tamperedLeafBytes = new Uint8Array(output.receiptBytes);
  tamperedLeafBytes[0] ^= 0x01;
  let changedBytes = 0;
  for (let index = 0; index < tamperedLeafBytes.length; index += 1) {
    if (tamperedLeafBytes[index] !== output.receiptBytes[index]) {
      changedBytes += 1;
    }
  }
  if (changedBytes !== 1) {
    throw new Error(`expected exactly one mutated leaf byte, found ${changedBytes}`);
  }

  const tamperedLeafHash = leafHash(tamperedLeafBytes);
  if (verifyInclusionProof(
    tamperedLeafHash,
    output.anchoredRoot.inclusion_proof,
    output.anchoredRoot.root,
  )) {
    throw new Error("tampered TypeScript leaf unexpectedly verified");
  }

  throw new ReplayScenarioError("receipt inclusion Merkle proof verification failed");
} catch (error) {
  const name = error && error.name ? error.name : "Error";
  const message = error && error.message ? error.message : String(error);
  if (
    name === "ReplayScenarioError" &&
    message.includes("receipt inclusion Merkle proof verification failed")
  ) {
    process.stdout.write(JSON.stringify({ error_name: name, error_message: message }));
    process.exit(0);
  }

  process.stderr.write(error && error.stack ? error.stack : `${name}: ${message}`);
  process.exit(1);
}
"#;
const TYPESCRIPT_PROOF_SCRIPT: &str = r#"
try {
  const input = JSON.parse(process.env.CHIO_MERKLE_PROOF_CASE ?? "");
  const { verifyInclusionProof } = await import("./src/replay.ts");
  process.stdout.write(JSON.stringify({
    verified: verifyInclusionProof(input.leaf_hash, input.proof, input.root),
  }));
} catch (error) {
  process.stderr.write(error && error.stack ? error.stack : String(error));
  process.exit(1);
}
"#;

#[derive(Debug)]
struct RustAnchoredRootPath {
    leaf_bytes: Vec<u8>,
    proof: MerkleProof,
    root: Hash,
}

#[derive(Debug)]
struct TypeScriptTamperError {
    error_name: String,
    error_message: String,
}

#[derive(Debug)]
struct TypeScriptProofResult {
    verified: bool,
}

mod formal {
    pub mod anchored_root_tamper {
        use chio_anchor::AnchorError;

        use crate::{
            assert_proof_rejected_by_both, build_rust_anchored_root_path, byte_diff_count,
            mutate_one_leaf_byte, require_bun, run_typescript_leaf_tamper,
            verify_rust_anchored_root_path, CANARY_RECEIPT_ID,
        };
        use chio_core::hashing::Hash;
        use chio_core::merkle::{node_hash, MerkleProof, MerkleTree};

        #[test]
        fn single_byte_flip_fails_closed_on_both() -> Result<(), String> {
            require_bun()?;
            let path = build_rust_anchored_root_path()?;
            let tampered_leaf_bytes = mutate_one_leaf_byte(&path.leaf_bytes)?;
            assert_eq!(
                byte_diff_count(&path.leaf_bytes, &tampered_leaf_bytes),
                1,
                "tamper harness must mutate exactly one leaf byte",
            );

            let rust_error =
                verify_rust_anchored_root_path(&tampered_leaf_bytes, &path.proof, &path.root)
                    .err()
                    .ok_or_else(|| "tampered Rust leaf unexpectedly verified".to_string())?;
            assert!(
                matches!(rust_error, AnchorError::Verification(_)),
                "tampered Rust leaf must fail closed with AnchorError::Verification, got {rust_error:?}",
            );

            let typescript_error = run_typescript_leaf_tamper(CANARY_RECEIPT_ID)?;
            assert_eq!(typescript_error.error_name, "ReplayScenarioError");
            assert!(
                typescript_error
                    .error_message
                    .contains("receipt inclusion Merkle proof verification failed"),
                "tampered TypeScript leaf must fail closed with the replay verification error, got {}",
                typescript_error.error_message,
            );

            Ok(())
        }

        #[test]
        fn odd_index_cannot_reverse_sibling_order() -> Result<(), String> {
            let leaf = Hash::from_bytes([0x11; 32]);
            let sibling = Hash::from_bytes([0x22; 32]);
            let proof = MerkleProof {
                tree_size: 2,
                leaf_index: 1,
                audit_path: vec![sibling],
            };
            let reversed_root = node_hash(&leaf, &sibling);

            assert_proof_rejected_by_both(leaf, &proof, reversed_root)
        }

        #[test]
        fn padded_path_fails_closed_on_both() -> Result<(), String> {
            let hashes: Vec<Hash> = (1..=5).map(|byte| Hash::from_bytes([byte; 32])).collect();
            let tree = MerkleTree::from_hashes(hashes.clone())
                .map_err(|error| format!("build five-leaf tree: {error}"))?;
            let mut proof = tree
                .inclusion_proof(4)
                .map_err(|error| format!("build five-leaf proof: {error}"))?;
            proof.audit_path.push(Hash::zero());

            assert_proof_rejected_by_both(hashes[4], &proof, tree.root())
        }

        #[test]
        fn truncated_path_fails_closed_on_both() -> Result<(), String> {
            let hashes: Vec<Hash> = (1..=8).map(|byte| Hash::from_bytes([byte; 32])).collect();
            let tree = MerkleTree::from_hashes(hashes.clone())
                .map_err(|error| format!("build eight-leaf tree: {error}"))?;
            let mut proof = tree
                .inclusion_proof(3)
                .map_err(|error| format!("build eight-leaf proof: {error}"))?;
            proof.audit_path.pop();

            assert_proof_rejected_by_both(hashes[3], &proof, tree.root())
        }
    }
}

fn build_rust_anchored_root_path() -> Result<RustAnchoredRootPath, String> {
    let manifest_path = workspace_root().join(CANARY_FIXTURE_PATH);
    let manifest = load_manifest(&manifest_path)?;
    if string_field(&manifest, "name")? != CANARY_RECEIPT_ID {
        return Err(format!(
            "canary fixture {} did not contain receipt ID {CANARY_RECEIPT_ID}",
            manifest_path.display(),
        ));
    }

    let leaf_bytes = receipt_bytes_from_manifest(&manifest)?;
    let leaves = vec![leaf_bytes.clone()];
    let tree = MerkleTree::from_leaves(&leaves)
        .map_err(|error| format!("build Merkle tree for {CANARY_RECEIPT_ID}: {error}"))?;
    let proof = tree
        .inclusion_proof(0)
        .map_err(|error| format!("build inclusion proof for {CANARY_RECEIPT_ID}: {error}"))?;
    let root = tree.root();

    if leaf_hash(&leaf_bytes) != root {
        return Err(format!(
            "single-receipt root does not match leaf hash for {CANARY_RECEIPT_ID}",
        ));
    }
    verify_rust_anchored_root_path(&leaf_bytes, &proof, &root)
        .map_err(|error| format!("canary inclusion proof failed before tamper: {error}"))?;

    Ok(RustAnchoredRootPath {
        leaf_bytes,
        proof,
        root,
    })
}

fn verify_rust_anchored_root_path(
    leaf_bytes: &[u8],
    proof: &MerkleProof,
    expected_root: &Hash,
) -> Result<(), AnchorError> {
    if proof.verify(leaf_bytes, expected_root) {
        Ok(())
    } else {
        Err(AnchorError::Verification(
            "receipt inclusion Merkle proof verification failed".to_string(),
        ))
    }
}

fn require_bun() -> Result<(), String> {
    let available = Command::new("bun")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if available {
        Ok(())
    } else {
        Err("anchored-root differential requires bun on PATH".to_string())
    }
}

fn run_typescript_leaf_tamper(receipt_id: &str) -> Result<TypeScriptTamperError, String> {
    let conformance_dir = workspace_root().join("sdks/typescript/packages/conformance");
    let fixtures_root = workspace_root().join("tests/replay/fixtures");
    let output = Command::new("bun")
        .arg("--silent")
        .arg("--eval")
        .arg(TYPESCRIPT_TAMPER_SCRIPT)
        .current_dir(&conformance_dir)
        .env("CHIO_REPLAY_FIXTURES_ROOT", fixtures_root.as_os_str())
        .env(
            "CHIO_REPLAY_EXPECTED_COUNT",
            EXPECTED_FIXTURE_COUNT.to_string(),
        )
        .env("CHIO_REPLAY_RECEIPT_ID", receipt_id)
        .output()
        .map_err(|error| {
            format!(
                "spawn TypeScript anchored-root tamper runner in {}: {error}",
                conformance_dir.display(),
            )
        })?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "TypeScript anchored-root tamper runner failed: status={} stdout={} stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim(),
        ));
    }

    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse TypeScript anchored-root tamper output: {error}"))?;
    Ok(TypeScriptTamperError {
        error_name: json_string_field(
            &value,
            "error_name",
            "TypeScript anchored-root tamper output",
        )?
        .to_string(),
        error_message: json_string_field(
            &value,
            "error_message",
            "TypeScript anchored-root tamper output",
        )?
        .to_string(),
    })
}

fn assert_proof_rejected_by_both(
    leaf: Hash,
    proof: &MerkleProof,
    root: Hash,
) -> Result<(), String> {
    if proof.verify_hash(leaf, &root) {
        return Err("malformed Rust inclusion proof unexpectedly verified".to_string());
    }
    require_bun()?;
    let result = run_typescript_proof(leaf, proof, root)?;
    if result.verified {
        return Err("malformed TypeScript inclusion proof unexpectedly verified".to_string());
    }
    Ok(())
}

fn run_typescript_proof(
    leaf: Hash,
    proof: &MerkleProof,
    root: Hash,
) -> Result<TypeScriptProofResult, String> {
    let conformance_dir = workspace_root().join("sdks/typescript/packages/conformance");
    let case = json!({
        "leaf_hash": leaf.to_hex_prefixed(),
        "proof": proof,
        "root": root.to_hex_prefixed(),
    });
    let case_json = serde_json::to_string(&case)
        .map_err(|error| format!("serialize inclusion-proof case: {error}"))?;
    let output = Command::new("bun")
        .arg("--silent")
        .arg("--eval")
        .arg(TYPESCRIPT_PROOF_SCRIPT)
        .current_dir(&conformance_dir)
        .env("CHIO_MERKLE_PROOF_CASE", case_json)
        .output()
        .map_err(|error| {
            format!(
                "spawn TypeScript inclusion-proof runner in {}: {error}",
                conformance_dir.display(),
            )
        })?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "TypeScript inclusion-proof runner failed: status={} stdout={} stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim(),
        ));
    }

    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse TypeScript inclusion-proof output: {error}"))?;
    let verified = value
        .get("verified")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            "TypeScript inclusion-proof output missing boolean field verified".to_string()
        })?;
    Ok(TypeScriptProofResult { verified })
}

fn mutate_one_leaf_byte(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut tampered = bytes.to_vec();
    let first = tampered
        .first_mut()
        .ok_or_else(|| "cannot tamper empty leaf bytes".to_string())?;
    *first ^= 0x01;
    if byte_diff_count(bytes, &tampered) != 1 {
        return Err("leaf byte tamper changed more than one byte".to_string());
    }
    Ok(tampered)
}

fn byte_diff_count(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right)
        .filter(|(left_byte, right_byte)| left_byte != right_byte)
        .count()
        + left.len().abs_diff(right.len())
}

fn receipt_bytes_from_manifest(manifest: &Value) -> Result<Vec<u8>, String> {
    let receipt_id = string_field(manifest, "name")?.to_string();
    let receipt = json!({
        "scenario": receipt_id,
        "verdict": string_field(manifest, "expected_verdict")?,
        "nonce": nonce_hex_for_seed_index(u64_field(manifest, "fixed_nonce_seed_index")?),
    });
    canonical_json_bytes(&receipt)
        .map_err(|error| format!("canonicalize receipt for {receipt_id}: {error}"))
}

fn load_manifest(path: &Path) -> Result<Value, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("read replay manifest {}: {error}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|error| format!("parse replay manifest {}: {error}", path.display()))
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| format!("manifest missing non-empty string field {key}"))
}

fn json_string_field<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| format!("{context} missing non-empty string field {key}"))
}

fn u64_field(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("manifest missing non-negative integer field {key}"))
}

fn nonce_hex_for_seed_index(seed_index: u64) -> String {
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&FIXED_CLOCK_EPOCH_MS.to_be_bytes());
    nonce[8..].copy_from_slice(&seed_index.to_be_bytes());
    hex_lower(&nonce)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
