//! # chiodome-bilateral-demo
//!
//! ## Scenario
//!
//! - Org A is the origin kernel that holds the user-issued capability and
//!   the budget root. It runs the agent that wants to issue a refund.
//! - Org B is the tool-host kernel that owns the `payments.refund` tool.
//! - The agent on Org A invokes `payments.refund` via the cross-org
//!   federation hop. Both kernels sign a DSSE signature-slice envelope over
//!   an in-toto Statement carrying the local bilateral predicate. The resulting
//!   `(ChioReceipt, DsseEnvelope)` pair is what a signature-slice verifier
//!   consumes.
//!
//! ## What is **not** claimed
//!
//! ## Lane primitives consumed

use std::error::Error as StdError;
use std::path::PathBuf;

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::Keypair;
use chio_core::hashing::Hash;
use chio_core::merkle::{leaf_hash, MerkleTree};
use chio_core::receipt::{
    ActorRef, BoundaryClass, ChioReceipt, ChioReceiptBody, Decision, FinancialReceiptMetadata,
    ReceiptKind, RedactionMode, SettlementStatus, ToolCallAction, ToolOrigin, TrustLevel,
};
use chio_federation::bilateral_dsse::{sign_dsse_envelope, verify_dsse_envelope, DsseEnvelope};
use chio_web3::{Web3CheckpointStatement, CHIO_CHECKPOINT_STATEMENT_SCHEMA};
use sha2::{Digest, Sha256};

/// Stable timestamp for the synthetic refund (seconds; deterministic so the
/// emitted fixture is byte-stable across runs that don't change the demo
/// inputs).
const REFUND_TIMESTAMP_SECS: u64 = 1_730_000_000;
/// Wall-clock used by Org B at canonicalisation (milliseconds; spec §6
/// `timestamp_unix_ms` field).
const REFUND_TIMESTAMP_MS: u64 = 1_730_000_000_000;

/// Output paths emitted by the demo.
struct OutputPaths {
    receipt_json: PathBuf,
    envelope_json: PathBuf,
    checkpoint_json: PathBuf,
}

impl OutputPaths {
    fn under(dir: &str) -> Self {
        let base = PathBuf::from(dir);
        Self {
            receipt_json: base.join("receipt.json"),
            envelope_json: base.join("envelope.json"),
            checkpoint_json: base.join("checkpoint.json"),
        }
    }
}

/// Parse `--release-fixture-seed=<u64>` from the process argv.
///
/// Returns `Ok(Some("42"))` when the flag is present (caller validates the
/// numeric form), `Ok(None)` if absent, or `Err` if the flag is given
/// without a value.
fn parse_fixture_seed_arg(
    args: impl IntoIterator<Item = String>,
) -> Result<Option<String>, Box<dyn StdError>> {
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if let Some(rest) = arg.strip_prefix("--release-fixture-seed=") {
            return Ok(Some(rest.to_string()));
        }
        if arg == "--release-fixture-seed" {
            return iter.next().map(Some).ok_or_else(|| -> Box<dyn StdError> {
                "--release-fixture-seed requires a value".into()
            });
        }
    }
    Ok(None)
}

/// Derive a 32-byte ed25519 seed deterministically from a numeric seed and a
/// per-role label. The role label keeps Org A and Org B distinct under the
/// same outer seed.
fn derive_seed_bytes(seed: u64, role: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"chiodome-bilateral.fixture-seed/v1");
    hasher.update(seed.to_be_bytes());
    hasher.update([0u8]);
    hasher.update(role);
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

fn main() -> Result<(), Box<dyn StdError>> {
    let out_dir = std::env::var("CHIODOME_DEMO_OUT")
        .unwrap_or_else(|_| "examples/chiodome-bilateral/fixtures".to_string());
    let paths = OutputPaths::under(&out_dir);

    println!("[chiodome-bilateral] starting demo");
    println!("[chiodome-bilateral] output dir: {}", out_dir);

    // 1. Generate identities for Org A (origin) and Org B (tool host).
    //
    // Deterministic mode: pass `--release-fixture-seed=<u64>` on the CLI or
    // set `CHIODOME_DEMO_FIXTURE_SEED=<u64>` to seed both keypairs from a
    // fixed 32-byte vector derived from the seed. Running twice with the
    // same seed produces byte-identical fixtures; this is what the
    // release-packaging fixture pinning relies on.
    let seed_opt = parse_fixture_seed_arg(std::env::args())?
        .or_else(|| std::env::var("CHIODOME_DEMO_FIXTURE_SEED").ok())
        .map(|s| {
            s.parse::<u64>()
                .map_err(|e| -> Box<dyn StdError> { format!("invalid fixture seed: {e}").into() })
        })
        .transpose()?;
    let (kp_org_a, kp_org_b) = match seed_opt {
        Some(seed) => {
            println!(
                "[chiodome-bilateral] deterministic mode: seed={} (org_a/org_b derived)",
                seed
            );
            (
                Keypair::from_seed(&derive_seed_bytes(seed, b"org-a")),
                Keypair::from_seed(&derive_seed_bytes(seed, b"org-b")),
            )
        }
        None => (Keypair::generate(), Keypair::generate()),
    };
    println!(
        "[chiodome-bilateral] org_a kernel public key: {}",
        kp_org_a.public_key().to_hex()
    );
    println!(
        "[chiodome-bilateral] org_b kernel public key: {}",
        kp_org_b.public_key().to_hex()
    );

    // 2. Build a refund receipt on Org B (tool host signs).
    let receipt = build_refund_receipt(&kp_org_b)?;
    println!("[chiodome-bilateral] receipt id: {}", receipt.id);

    let envelope = cross_org_refund(&receipt, &kp_org_a, &kp_org_b)?;
    println!(
        "[chiodome-bilateral] DSSE envelope signatures.len = {} (expect 2)",
        envelope.signatures.len()
    );

    // 4. Self-verify under both public keys.
    let statement = verify_dsse_envelope(&envelope, &kp_org_a.public_key(), &kp_org_b.public_key())
        .map_err(|e| -> Box<dyn StdError> { format!("verify_dsse_envelope failed: {e}").into() })?;
    println!(
        "[chiodome-bilateral] verified envelope: predicate_type = {}",
        statement.predicate_type
    );

    // 5. Build a synthetic anchor checkpoint statement covering the receipt.
    let checkpoint_statement = emit_anchor_statement(&receipt, &kp_org_b)?;
    println!(
        "[chiodome-bilateral] anchor checkpoint seq = {}, merkle_root = {}",
        checkpoint_statement.checkpoint_seq,
        checkpoint_statement.merkle_root.to_hex()
    );

    // 6. Emit fixtures.
    std::fs::create_dir_all(&out_dir)?;
    write_json(&paths.receipt_json, &receipt)?;
    write_json(&paths.envelope_json, &envelope)?;
    write_json(&paths.checkpoint_json, &checkpoint_statement)?;
    println!(
        "[chiodome-bilateral] wrote {}",
        paths.receipt_json.display()
    );
    println!(
        "[chiodome-bilateral] wrote {}",
        paths.envelope_json.display()
    );
    println!(
        "[chiodome-bilateral] wrote {}",
        paths.checkpoint_json.display()
    );

    // 7. Final assertion: at least one receipt was emitted. The
    //    cross-org refund path emits the signed receipt below; the KB
    //    MCP path appends one receipt for each tool call.
    if !matches!(receipt.decision, Some(Decision::Allow)) {
        return Err("scenario expects an Allow receipt for the refund".into());
    }
    println!("[chiodome-bilateral] demo OK: 1 receipt + 1 DSSE envelope + 1 checkpoint emitted");
    Ok(())
}

/// Build a `payments.refund` receipt signed by Org B (tool-host kernel).
///
/// Carries `FinancialReceiptMetadata` so the receipt is eligible for IOU
/// minting through `chio-credit::LocalCreditAccount` if a runner wires the
/// hook (the demo prints the financial fields but does not run the
/// underwriting hook in this slice).
fn build_refund_receipt(kp_org_b: &Keypair) -> Result<ChioReceipt, Box<dyn StdError>> {
    let financial = FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged: 5_000, // 50.00 USD in cents
        currency: "USD".to_string(),
        budget_remaining: 95_000,
        budget_total: 100_000,
        delegation_depth: 1,
        root_budget_holder: "tenant-org-a".to_string(),
        payment_reference: Some("refund-demo-0001".to_string()),
        settlement_status: SettlementStatus::Pending,
        cost_breakdown: None,
        oracle_evidence: None,
        attempted_cost: None,
    };
    let metadata = serde_json::json!({ "financial": financial });

    let action = ToolCallAction::from_parameters(serde_json::json!({
        "order_id": "ord-9c1f-2a40",
        "amount_minor_units": 5_000,
        "currency": "USD",
        "reason": "customer-requested",
    }))
    .map_err(|e| -> Box<dyn StdError> { format!("action build: {e}").into() })?;

    let body = ChioReceiptBody {
        id: "rcpt-c-refund-demo-0001".to_string(),
        timestamp: REFUND_TIMESTAMP_SECS,
        capability_id: "cap-org-a-refund-demo".to_string(),
        tool_server: "srv-org-b-payments".to_string(),
        tool_name: "payments.refund".to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: vec![
            ActorRef {
                actor_id: "user:tenant-org-a/owner".to_string(),
                actor_kind: Some("user".to_string()),
            },
            ActorRef {
                actor_id: "agent:org-a/refund-bot".to_string(),
                actor_kind: Some("agent".to_string()),
            },
        ],
        content_hash: sha256_hex_bytes(b"{\"refund\":\"ok\"}"),
        policy_hash: "policy-c-demo".to_string(),
        evidence: Vec::new(),
        metadata: Some(metadata),
        trust_level: TrustLevel::default(),
        tenant_id: Some("tenant-org-a".to_string()),
        kernel_key: kp_org_b.public_key(),
    };
    ChioReceipt::sign(body, kp_org_b)
        .map_err(|e| -> Box<dyn StdError> { format!("receipt sign: {e}").into() })
}

/// Drive the DSSE signature-slice cross-org bilateral co-sign via
/// [`sign_dsse_envelope`].
fn cross_org_refund(
    receipt: &ChioReceipt,
    kp_org_a: &Keypair,
    kp_org_b: &Keypair,
) -> Result<DsseEnvelope, Box<dyn StdError>> {
    sign_dsse_envelope(
        receipt,
        kp_org_a,
        kp_org_b,
        "kernel.org-a.demo",
        "kernel.org-b.demo",
        "payments.refund",
        REFUND_TIMESTAMP_MS,
    )
    .map_err(|e| -> Box<dyn StdError> { format!("sign_dsse_envelope: {e}").into() })
}

/// Build a `Web3CheckpointStatement` covering this single receipt.
///
/// The single-leaf root is computed via `chio_core::merkle::leaf_hash` (RFC
/// 6962-style: `SHA256(0x00 || canonical_json(receipt))`), matching the
/// convention used by `chio_anchor::batch` and `chio_anchor::evm`.
/// Equivalently, this is `MerkleTree::from_leaves(&[receipt_bytes]).root()`.
fn emit_anchor_statement(
    receipt: &ChioReceipt,
    kp_org_b: &Keypair,
) -> Result<Web3CheckpointStatement, Box<dyn StdError>> {
    let receipt_bytes = canonical_json_bytes(receipt)
        .map_err(|e| -> Box<dyn StdError> { format!("canonical receipt: {e}").into() })?;
    // Single-leaf RFC6962 root.
    let merkle_root = leaf_hash(&receipt_bytes);
    // Sanity: the single-leaf MerkleTree root must equal leaf_hash.
    let tree = MerkleTree::from_leaves(&[&receipt_bytes])
        .map_err(|e| -> Box<dyn StdError> { format!("merkle build: {e}").into() })?;
    if tree.root() != merkle_root {
        return Err("single-leaf merkle root must equal leaf_hash(canonical(receipt))".into());
    }

    // The `Web3CheckpointStatement` body is unsigned by construction (the
    // signature field carries the kernel's signature over a kernel-checkpoint
    // body whose canonical layout includes these fields). Signing over the
    // canonical bytes of the body fields directly keeps the emitted statement
    // self-consistent under the same key that signed the receipt.
    let unsigned = UnsignedCheckpointBody {
        schema: CHIO_CHECKPOINT_STATEMENT_SCHEMA,
        checkpoint_seq: 1,
        batch_start_seq: 1,
        batch_end_seq: 1,
        tree_size: 1,
        merkle_root,
        issued_at: REFUND_TIMESTAMP_SECS,
        previous_checkpoint_sha256: None,
        kernel_key: kp_org_b.public_key().to_hex(),
    };
    let body_bytes = canonical_json_bytes(&unsigned)
        .map_err(|e| -> Box<dyn StdError> { format!("canonical checkpoint body: {e}").into() })?;
    let signature = kp_org_b.sign(&body_bytes);

    Ok(Web3CheckpointStatement {
        schema: CHIO_CHECKPOINT_STATEMENT_SCHEMA.to_string(),
        checkpoint_seq: unsigned.checkpoint_seq,
        batch_start_seq: unsigned.batch_start_seq,
        batch_end_seq: unsigned.batch_end_seq,
        tree_size: unsigned.tree_size,
        merkle_root,
        issued_at: unsigned.issued_at,
        previous_checkpoint_sha256: unsigned.previous_checkpoint_sha256,
        kernel_key: kp_org_b.public_key(),
        signature,
    })
}

/// Helper used only for canonicalising the demo's checkpoint body before
/// signing. Production code uses
/// `chio_kernel::checkpoint::build_checkpoint`; this struct simply mirrors
/// the same fields without the chio-kernel dep so the example crate stays
/// thin.
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct UnsignedCheckpointBody {
    schema: &'static str,
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    tree_size: u64,
    merkle_root: Hash,
    issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_checkpoint_sha256: Option<String>,
    kernel_key: String,
}

fn write_json<T: serde::Serialize>(path: &PathBuf, value: &T) -> Result<(), Box<dyn StdError>> {
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::write(path, bytes)?;
    Ok(())
}

fn sha256_hex_bytes(b: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_federation::bilateral_dsse::{
        verify_dsse_envelope, DEFAULT_COSIGN_MODE, PAYLOAD_TYPE_IN_TOTO, PREDICATE_TYPE_BILATERAL,
    };

    #[test]
    fn cross_org_refund_emits_signature_slice_envelope() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = build_refund_receipt(&kp_b).unwrap();
        let envelope = cross_org_refund(&receipt, &kp_a, &kp_b).unwrap();

        // Wire shape: payloadType + 2 signatures.
        assert_eq!(envelope.payload_type, PAYLOAD_TYPE_IN_TOTO);
        assert_eq!(envelope.signatures.len(), 2);

        // Round-trips under the signature-slice verifier.
        let statement =
            verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key()).unwrap();
        assert_eq!(statement.predicate_type, PREDICATE_TYPE_BILATERAL);
        assert_eq!(statement.predicate.co_sign, DEFAULT_COSIGN_MODE);
        assert_eq!(statement.predicate.tool_name, "payments.refund");
    }

    /// The receipt's `kernel_key` MUST be Org B's. This is what
    /// underwriters / IOU mints will key on.
    #[test]
    fn refund_receipt_is_signed_by_org_b() {
        let kp_b = Keypair::generate();
        let receipt = build_refund_receipt(&kp_b).unwrap();
        assert_eq!(receipt.kernel_key.to_hex(), kp_b.public_key().to_hex());
        assert!(receipt.verify_signature().unwrap());
    }

    /// Anchor statement `merkle_root` MUST equal RFC6962
    /// `leaf_hash(canonical(receipt))` for this single-leaf bounded claim
    /// (matching the convention used elsewhere in chio-anchor).
    #[test]
    fn anchor_statement_root_binds_receipt_canonical_bytes() {
        let kp_b = Keypair::generate();
        let receipt = build_refund_receipt(&kp_b).unwrap();
        let statement = emit_anchor_statement(&receipt, &kp_b).unwrap();

        let receipt_bytes = canonical_json_bytes(&receipt).unwrap();
        let want = leaf_hash(&receipt_bytes);
        assert_eq!(statement.merkle_root, want);

        // Also confirm raw SHA256 (the *previous*, non-RFC6962 convention)
        // does NOT match. Guards against accidental regression.
        let mut raw = Sha256::new();
        raw.update(&receipt_bytes);
        let raw_bytes: [u8; 32] = raw.finalize().as_slice().try_into().unwrap();
        assert_ne!(statement.merkle_root, Hash::from_bytes(raw_bytes));
    }

    /// Negative: an envelope from kp_a/kp_b MUST NOT verify under a third
    /// party's public key. This is the signature-slice verifier guard.
    #[test]
    fn envelope_does_not_verify_under_unrelated_public_key() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_attacker = Keypair::generate();
        let receipt = build_refund_receipt(&kp_b).unwrap();
        let envelope = cross_org_refund(&receipt, &kp_a, &kp_b).unwrap();

        let result = verify_dsse_envelope(&envelope, &kp_attacker.public_key(), &kp_b.public_key());
        assert!(
            result.is_err(),
            "attacker public key must not verify org_a slot"
        );
    }
}
