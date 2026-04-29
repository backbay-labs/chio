#![cfg(not(target_arch = "wasm32"))]

//! Differential anchored-root tuple harness for M04 Phase 6.
//!
//! This Cargo-recognized integration test emits the Rust-side
//! `(receipt_id, leaf_hash, inclusion_proof, root)` tuple shape for the
//! replay fixture corpus. The TypeScript conformance runner emits the same
//! shape from `sdks/typescript/packages/conformance/src/replay.ts`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chio_core::canonical::canonical_json_bytes;
use chio_core::merkle::{leaf_hash, MerkleTree};
use serde_json::{json, Value};

const EXPECTED_FIXTURE_COUNT: usize = 50;
const FIXED_CLOCK_EPOCH_MS: u64 = 1_767_225_600_000;
const CANARY_RECEIPT_ID: &str = "allow_simple/01_basic_capability";
const CANARY_LEAF_HASH: &str = "0xe4b0ab524d5ed0a97dec2d92d0dceba4d1b8abb551acacfafff9df69a16436bb";
const HASH_BYTE_LENGTH: usize = 32;
const HASH_HEX_LENGTH: usize = HASH_BYTE_LENGTH * 2;
const TYPESCRIPT_ANCHORED_ROOT_SCRIPT: &str = r#"
try {
  const fixturesRoot = process.env.CHIO_REPLAY_FIXTURES_ROOT;
  const expectedCount = Number(process.env.CHIO_REPLAY_EXPECTED_COUNT);
  if (fixturesRoot == null || fixturesRoot.length === 0) {
    throw new Error("CHIO_REPLAY_FIXTURES_ROOT must be set");
  }
  if (!Number.isSafeInteger(expectedCount) || expectedCount < 1) {
    throw new Error("CHIO_REPLAY_EXPECTED_COUNT must be a positive safe integer");
  }

  const { runReplayAnchoredRootTuples } = await import("./src/replay.ts");
  const tuples = await runReplayAnchoredRootTuples({ fixturesRoot, expectedCount });
  process.stdout.write(JSON.stringify(tuples));
} catch (error) {
  process.stderr.write(error && error.stack ? error.stack : String(error));
  process.exit(1);
}
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnchoredRootTuple {
    receipt_id: String,
    leaf_hash: String,
    inclusion_proof: InclusionProofTuple,
    root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InclusionProofTuple {
    tree_size: usize,
    leaf_index: usize,
    audit_path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProofPath {
    tree_size: usize,
    leaf_index: usize,
    audit_path: Vec<[u8; HASH_BYTE_LENGTH]>,
}

#[test]
fn rust_anchored_root_tuples_emit_in_deterministic_order() -> Result<(), String> {
    let tuples = emit_anchored_root_tuples()?;

    assert_eq!(
        tuples.len(),
        EXPECTED_FIXTURE_COUNT,
        "tuple count must match the replay fixture corpus"
    );

    for pair in tuples.windows(2) {
        assert!(
            pair[0].receipt_id < pair[1].receipt_id,
            "tuple receipt IDs must be byte-sorted: {} then {}",
            pair[0].receipt_id,
            pair[1].receipt_id,
        );
    }

    for tuple in &tuples {
        assert_eq!(
            tuple.leaf_hash, tuple.root,
            "single-receipt scenario root must equal leaf hash for {}",
            tuple.receipt_id,
        );
        assert_eq!(
            tuple.inclusion_proof.tree_size, 1,
            "single-receipt proof tree_size must be one for {}",
            tuple.receipt_id,
        );
        assert_eq!(
            tuple.inclusion_proof.leaf_index, 0,
            "single-receipt proof leaf_index must be zero for {}",
            tuple.receipt_id,
        );
        assert!(
            tuple.inclusion_proof.audit_path.is_empty(),
            "single-receipt proof audit_path must be empty for {}",
            tuple.receipt_id,
        );
    }

    let canary = tuples
        .iter()
        .find(|tuple| tuple.receipt_id == CANARY_RECEIPT_ID)
        .ok_or_else(|| format!("missing canary tuple {CANARY_RECEIPT_ID}"))?;
    assert_eq!(canary.leaf_hash, CANARY_LEAF_HASH);
    assert_eq!(canary.root, CANARY_LEAF_HASH);

    Ok(())
}

#[test]
fn rust_and_typescript_anchored_root_tuples_match_by_root_bytes_and_proof_structure(
) -> Result<(), String> {
    let fixtures_root = workspace_root().join("tests/replay/fixtures");
    let rust_tuples = emit_anchored_root_tuples_from(&fixtures_root)?;
    let typescript_tuples = emit_typescript_anchored_root_tuples_from(&fixtures_root)?;

    assert_eq!(
        typescript_tuples.len(),
        rust_tuples.len(),
        "TypeScript and Rust tuple counts must match"
    );

    for (index, (rust_tuple, typescript_tuple)) in
        rust_tuples.iter().zip(&typescript_tuples).enumerate()
    {
        assert_eq!(
            typescript_tuple.receipt_id, rust_tuple.receipt_id,
            "tuple {index} receipt_id differs between TypeScript and Rust"
        );

        let rust_root = hex_hash_bytes(
            &rust_tuple.root,
            &format!("Rust root for {}", rust_tuple.receipt_id),
        )?;
        let typescript_root = hex_hash_bytes(
            &typescript_tuple.root,
            &format!("TypeScript root for {}", rust_tuple.receipt_id),
        )?;
        assert_eq!(
            typescript_root, rust_root,
            "Merkle root bytes differ for {}",
            rust_tuple.receipt_id,
        );

        let rust_path = proof_path_structure(
            &rust_tuple.inclusion_proof,
            &format!("Rust proof for {}", rust_tuple.receipt_id),
        )?;
        let typescript_path = proof_path_structure(
            &typescript_tuple.inclusion_proof,
            &format!("TypeScript proof for {}", rust_tuple.receipt_id),
        )?;
        assert_eq!(
            typescript_path, rust_path,
            "inclusion proof path structure differs for {}",
            rust_tuple.receipt_id,
        );
    }

    Ok(())
}

#[test]
fn rust_anchored_root_tuples_fail_closed_on_invalid_fixture_root() {
    let result = emit_anchored_root_tuples_from(&workspace_root().join("tests/replay/missing"));
    assert!(
        result.is_err(),
        "missing replay fixture root must fail closed"
    );
}

fn emit_anchored_root_tuples() -> Result<Vec<AnchoredRootTuple>, String> {
    emit_anchored_root_tuples_from(&workspace_root().join("tests/replay/fixtures"))
}

fn emit_anchored_root_tuples_from(root: &Path) -> Result<Vec<AnchoredRootTuple>, String> {
    let manifests = enumerate_manifests(root)?;
    if manifests.len() != EXPECTED_FIXTURE_COUNT {
        return Err(format!(
            "expected {EXPECTED_FIXTURE_COUNT} replay manifests under {}, found {}",
            root.display(),
            manifests.len(),
        ));
    }

    manifests
        .iter()
        .map(|path| {
            let manifest = load_manifest(path)?;
            build_tuple_from_manifest(&manifest)
        })
        .collect()
}

fn emit_typescript_anchored_root_tuples_from(
    root: &Path,
) -> Result<Vec<AnchoredRootTuple>, String> {
    let conformance_dir = workspace_root().join("sdks/typescript/packages/conformance");
    let output = Command::new("bun")
        .arg("--silent")
        .arg("--eval")
        .arg(TYPESCRIPT_ANCHORED_ROOT_SCRIPT)
        .current_dir(&conformance_dir)
        .env("CHIO_REPLAY_FIXTURES_ROOT", root.as_os_str())
        .env(
            "CHIO_REPLAY_EXPECTED_COUNT",
            EXPECTED_FIXTURE_COUNT.to_string(),
        )
        .output()
        .map_err(|error| {
            format!(
                "spawn TypeScript anchored-root tuple runner in {}: {error}",
                conformance_dir.display()
            )
        })?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "TypeScript anchored-root tuple runner failed: status={} stdout={} stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim(),
        ));
    }

    parse_anchored_root_tuple_list(&output.stdout, "TypeScript anchored-root tuple output")
}

fn build_tuple_from_manifest(manifest: &Value) -> Result<AnchoredRootTuple, String> {
    let receipt_id = string_field(manifest, "name")?.to_string();
    let receipt = json!({
        "scenario": receipt_id,
        "verdict": string_field(manifest, "expected_verdict")?,
        "nonce": nonce_hex_for_seed_index(u64_field(manifest, "fixed_nonce_seed_index")?),
    });
    let receipt_bytes = canonical_json_bytes(&receipt)
        .map_err(|error| format!("canonicalize receipt for {receipt_id}: {error}"))?;
    let leaves = vec![receipt_bytes.clone()];
    let tree = MerkleTree::from_leaves(&leaves)
        .map_err(|error| format!("build Merkle tree for {receipt_id}: {error}"))?;
    let proof = tree
        .inclusion_proof(0)
        .map_err(|error| format!("build inclusion proof for {receipt_id}: {error}"))?;
    let computed_leaf_hash = leaf_hash(&receipt_bytes);
    let root = tree.root();

    if !proof.verify(&receipt_bytes, &root) {
        return Err(format!("inclusion proof failed to verify for {receipt_id}"));
    }
    if computed_leaf_hash != root {
        return Err(format!(
            "single-receipt root does not match leaf hash for {receipt_id}"
        ));
    }

    Ok(AnchoredRootTuple {
        receipt_id,
        leaf_hash: computed_leaf_hash.to_hex_prefixed(),
        inclusion_proof: InclusionProofTuple {
            tree_size: proof.tree_size,
            leaf_index: proof.leaf_index,
            audit_path: proof
                .audit_path
                .iter()
                .map(chio_core::hashing::Hash::to_hex_prefixed)
                .collect(),
        },
        root: root.to_hex_prefixed(),
    })
}

fn parse_anchored_root_tuple_list(
    raw: &[u8],
    context: &str,
) -> Result<Vec<AnchoredRootTuple>, String> {
    let value: Value =
        serde_json::from_slice(raw).map_err(|error| format!("parse {context} as JSON: {error}"))?;
    let tuples = value
        .as_array()
        .ok_or_else(|| format!("{context} must be a JSON array"))?;

    tuples
        .iter()
        .enumerate()
        .map(|(index, tuple)| parse_anchored_root_tuple(tuple, &format!("{context}[{index}]")))
        .collect()
}

fn parse_anchored_root_tuple(value: &Value, context: &str) -> Result<AnchoredRootTuple, String> {
    let proof = value
        .get("inclusion_proof")
        .ok_or_else(|| format!("{context} missing inclusion_proof"))?;

    Ok(AnchoredRootTuple {
        receipt_id: json_string_field(value, "receipt_id", context)?.to_string(),
        leaf_hash: json_string_field(value, "leaf_hash", context)?.to_string(),
        inclusion_proof: InclusionProofTuple {
            tree_size: json_usize_field(proof, "tree_size", context)?,
            leaf_index: json_usize_field(proof, "leaf_index", context)?,
            audit_path: json_string_array_field(proof, "audit_path", context)?,
        },
        root: json_string_field(value, "root", context)?.to_string(),
    })
}

fn json_string_field<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| format!("{context} missing non-empty string field {key}"))
}

fn json_usize_field(value: &Value, key: &str, context: &str) -> Result<usize, String> {
    let raw = value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{context} missing non-negative integer field {key}"))?;
    usize::try_from(raw)
        .map_err(|error| format!("{context} field {key} does not fit usize: {error}"))
}

fn json_string_array_field(value: &Value, key: &str, context: &str) -> Result<Vec<String>, String> {
    let array = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{context} missing array field {key}"))?;

    array
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_str()
                .filter(|field| !field.is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("{context} field {key}[{index}] must be a non-empty string"))
        })
        .collect()
}

fn proof_path_structure(proof: &InclusionProofTuple, context: &str) -> Result<ProofPath, String> {
    let audit_path = proof
        .audit_path
        .iter()
        .enumerate()
        .map(|(index, hash)| hex_hash_bytes(hash, &format!("{context} audit_path[{index}]")))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ProofPath {
        tree_size: proof.tree_size,
        leaf_index: proof.leaf_index,
        audit_path,
    })
}

fn hex_hash_bytes(value: &str, context: &str) -> Result<[u8; HASH_BYTE_LENGTH], String> {
    let hex = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{context} must start with 0x"))?;
    if hex.len() != HASH_HEX_LENGTH {
        return Err(format!(
            "{context} must contain {HASH_HEX_LENGTH} hex chars, found {}",
            hex.len(),
        ));
    }

    let mut out = [0u8; HASH_BYTE_LENGTH];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|error| {
            format!("{context} contains non-UTF-8 hex at byte {index}: {error}")
        })?;
        out[index] = u8::from_str_radix(pair, 16).map_err(|error| {
            format!("{context} contains invalid hex pair {pair:?} at byte {index}: {error}")
        })?;
    }

    Ok(out)
}

fn enumerate_manifests(root: &Path) -> Result<Vec<PathBuf>, String> {
    let root_meta = fs::metadata(root)
        .map_err(|error| format!("stat replay fixture root {}: {error}", root.display()))?;
    if !root_meta.is_dir() {
        return Err(format!(
            "replay fixture root is not a directory: {}",
            root.display(),
        ));
    }

    let mut out = Vec::new();
    walk_json_files(root, &mut out)?;
    out.sort_by(|left, right| path_bytes(root, left).cmp(&path_bytes(root, right)));
    Ok(out)
}

fn walk_json_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries = fs::read_dir(dir)
        .map_err(|error| format!("read replay fixture directory {}: {error}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!(
                "read replay fixture directory entry {}: {error}",
                dir.display()
            )
        })?;
    entries.sort_by(|left, right| left.file_name().cmp(&right.file_name()));

    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("stat replay fixture entry {}: {error}", path.display()))?;
        if file_type.is_dir() {
            walk_json_files(&path, out)?;
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            out.push(path);
        } else if file_type.is_symlink() {
            return Err(format!(
                "symlink in replay fixture tree: {}",
                path.display()
            ));
        }
    }

    Ok(())
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

fn path_bytes(root: &Path, path: &Path) -> Vec<u8> {
    path.strip_prefix(root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
        .into_bytes()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
