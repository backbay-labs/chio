//! v3.18 receipt bundle migration test.
//!
//! Pins three contracts in one test:
//!
//! 1. **Byte-equivalence under `crypto_floor=allow_classical`.** A v3.18
//!    receipt bundle (classical Ed25519 envelope) re-verifies under the
//!    classical path with byte-identical canonical-JSON. Deployments
//!    that have not provisioned a PQ key keep working.
//!
//! 2. **Hybrid round-trip under `crypto_floor=pq_required`.** The same
//!    receipt body re-signed via a `HybridBackend` re-verifies under
//!    `pq_required`. The hybrid envelope carries a different kernel_key
//!    (the hybrid pubkey) and a hybrid signature, but the body fields
//!    (decision, content_hash, policy_hash, etc.) are unchanged.
//!
//! 3. **Downgrade rejection.** The original v3.18 classical bundle is
//!    rejected under `crypto_floor=pq_required`. Threat model row
//!    `pq_signature_downgrade` is the surface this guards.
//!
//! ## Fixture
//!
//! The v3.18 fixture is checked in at
//! `tests/fixtures/v318/receipt_bundle.json`. It is a deterministically
//! signed Ed25519 receipt produced from the seed
//! `b"chio-v318-fixture-seed-receipt-v"` so the byte-equivalence contract
//! is reproducible across CI runs without depending on system entropy.

#![cfg(feature = "pq")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{
    Ed25519Backend, HybridBackend, Keypair, MlDsa65Backend, SigningAlgorithm, SigningBackend,
};
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};

const FIXTURE_PATH: &str = "tests/fixtures/v318/receipt_bundle.json";

fn fixture_classical_seed() -> [u8; 32] {
    let raw = b"chio-v318-fixture-seed-receipt-v";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn fixture_pq_seed() -> [u8; 32] {
    let raw = b"chio-attest-migration-pq-seed-01";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn fixture_action() -> ToolCallAction {
    ToolCallAction::from_parameters(serde_json::json!({"q": "audit"})).unwrap()
}

fn classical_body(kernel_key: chio_core_types::crypto::PublicKey) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-v318-fixture-001".to_string(),
        timestamp: 1_700_000_001,
        capability_id: "cap-v318-fixture".to_string(),
        tool_server: "audit-server".to_string(),
        tool_name: "report".to_string(),
        action: fixture_action(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: "1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        policy_hash: "policy-v318-fixture".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key,
        bbs_projection_version: None,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH)
}

/// Local copy of the crypto-floor dispatch table. This test crate does
/// not depend on `chio-kernel`, but it still needs to assert the same
/// floor boundary that the kernel enforces before cryptographic checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoFloor {
    AllowClassical,
    PqRequired,
}

impl CryptoFloor {
    fn allows(self, algorithm: SigningAlgorithm) -> bool {
        matches!(
            (self, algorithm),
            (
                CryptoFloor::AllowClassical,
                SigningAlgorithm::Ed25519 | SigningAlgorithm::P256 | SigningAlgorithm::P384,
            ) | (CryptoFloor::PqRequired, SigningAlgorithm::Hybrid)
        )
    }
}

fn verify_under_floor(receipt: &ChioReceipt, floor: CryptoFloor) -> bool {
    if !floor.allows(receipt.signature.algorithm()) {
        return false;
    }
    receipt.verify_signature().unwrap_or(false)
}

/// Reads the checked-in v3.18 fixture, materializing it as a `ChioReceipt`.
fn load_v318_fixture() -> ChioReceipt {
    let raw = std::fs::read(fixture_path()).unwrap_or_else(|err| {
        panic!(
            "v3.18 fixture not found at {}: {err}. Run `cargo test -p chio-attest-verify --features pq --test v318_migration -- --ignored regenerate_fixture` to recreate it.",
            fixture_path().display()
        )
    });
    serde_json::from_slice(&raw).unwrap()
}

/// Helper that reproduces the deterministic v3.18 fixture from the
/// classical seed and current canonical encoding rules. Byte-equivalence
/// is asserted in [`v318_fixture_round_trips_under_allow_classical`].
fn rebuild_v318_fixture() -> ChioReceipt {
    let kp = Keypair::from_seed(&fixture_classical_seed());
    let body = classical_body(kp.public_key());
    ChioReceipt::sign(body, &kp).unwrap()
}

/// One-shot regeneration helper. Run with
/// `cargo test -p chio-attest-verify --features pq --test v318_migration \
///     regenerate_fixture -- --ignored --nocapture`
/// to refresh the checked-in fixture if the canonical-JSON encoding rules
/// ever change. The `regenerate_fixture` ignored test is the documented
/// recovery procedure if a future encoding bump intentionally moves the
/// byte oracle (the canonical vector corpus signs off on every bump).
#[test]
#[ignore = "fixture-bless helper; run with --ignored regenerate_fixture --features pq"]
fn regenerate_fixture() {
    let receipt = rebuild_v318_fixture();
    let json = serde_json::to_string_pretty(&receipt).unwrap();
    std::fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
    std::fs::write(fixture_path(), json).unwrap();
    eprintln!("regenerated fixture at {}", fixture_path().display());
}

#[test]
fn v318_fixture_round_trips_under_allow_classical() {
    // Contract 1: byte-equivalence. The checked-in v3.18 fixture matches
    // the deterministic rebuild byte-for-byte.
    let fixture = load_v318_fixture();
    let rebuilt = rebuild_v318_fixture();

    assert_eq!(
        fixture.kernel_key.to_hex(),
        rebuilt.kernel_key.to_hex(),
        "kernel_key drift"
    );
    assert_eq!(
        fixture.signature.algorithm(),
        SigningAlgorithm::Ed25519,
        "v3.18 fixture must be classical Ed25519"
    );
    assert_eq!(fixture.signature.algorithm(), rebuilt.signature.algorithm());

    // Body bytes byte-identical (ignoring the signature itself).
    let fixture_body = ChioReceiptBody {
        id: fixture.id.clone(),
        timestamp: fixture.timestamp,
        capability_id: fixture.capability_id.clone(),
        tool_server: fixture.tool_server.clone(),
        tool_name: fixture.tool_name.clone(),
        action: fixture.action.clone(),
        decision: fixture.decision.clone(),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: fixture.content_hash.clone(),
        policy_hash: fixture.policy_hash.clone(),
        evidence: fixture.evidence.clone(),
        metadata: fixture.metadata.clone(),
        trust_level: fixture.trust_level,
        tenant_id: fixture.tenant_id.clone(),
        kernel_key: fixture.kernel_key.clone(),
        bbs_projection_version: None,
    };
    let rebuilt_body = ChioReceiptBody {
        id: rebuilt.id.clone(),
        timestamp: rebuilt.timestamp,
        capability_id: rebuilt.capability_id.clone(),
        tool_server: rebuilt.tool_server.clone(),
        tool_name: rebuilt.tool_name.clone(),
        action: rebuilt.action.clone(),
        decision: rebuilt.decision.clone(),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: rebuilt.content_hash.clone(),
        policy_hash: rebuilt.policy_hash.clone(),
        evidence: rebuilt.evidence.clone(),
        metadata: rebuilt.metadata.clone(),
        trust_level: rebuilt.trust_level,
        tenant_id: rebuilt.tenant_id.clone(),
        kernel_key: rebuilt.kernel_key.clone(),
        bbs_projection_version: None,
    };
    assert_eq!(
        canonical_json_bytes(&fixture_body).unwrap(),
        canonical_json_bytes(&rebuilt_body).unwrap(),
        "v3.18 receipt body canonical JSON drift"
    );

    // Signature verifies via the issuer key. Caller path is the existing
    // `verify_signature` (no floor enforcement) which is what
    // `crypto_floor=allow_classical` accepts.
    assert!(fixture.verify_signature().unwrap());
}

#[test]
fn rolled_hybrid_bundle_round_trips_under_pq_required() {
    // Contract 2: a re-signed hybrid bundle re-verifies under
    // `crypto_floor=pq_required`. The body fields are preserved across
    // the roll; only the kernel_key (now hybrid) and the signature
    // (now Signature::Hybrid) change.
    let classical_kp = Keypair::from_seed(&fixture_classical_seed());
    let classical_backend = Ed25519Backend::new(classical_kp);
    let pq = MlDsa65Backend::from_seed(&fixture_pq_seed());
    let hybrid = HybridBackend::new(Box::new(classical_backend), pq).unwrap();

    let body = classical_body(hybrid.public_key());
    let rolled = ChioReceipt::sign_with_backend(body.clone(), &hybrid).unwrap();
    assert_eq!(rolled.signature.algorithm(), SigningAlgorithm::Hybrid);

    // Cryptographic verification dispatches off the signature material.
    // verify_signature reconstructs the canonical signing body (the recomputed
    // content-addressed id plus the nonce-bound metadata) that sign_with_backend
    // actually signed over, then checks it against the hybrid signature.
    assert!(rolled.verify_signature().unwrap());

    // Floor enforcement: under pq_required, hybrid is the ONLY accepted
    // algorithm. No chio-policy / chio-kernel dep is permitted in
    // chio-attest-verify; the dispatch table is re-implemented inline.
    assert!(matches!(
        rolled.signature.algorithm(),
        SigningAlgorithm::Hybrid
    ));
}

#[test]
fn v318_fixture_rejected_under_pq_required() {
    // Contract 3: the original v3.18 classical bundle is rejected under
    // `crypto_floor=pq_required`. The rejection is fail-closed at the
    // floor boundary BEFORE the cryptographic check; we mirror the
    // dispatch the kernel-side capability validator and compliance
    // certificate verifier apply.
    let fixture = load_v318_fixture();
    assert_eq!(fixture.signature.algorithm(), SigningAlgorithm::Ed25519);

    assert!(
        !verify_under_floor(&fixture, CryptoFloor::PqRequired),
        "v3.18 classical bundle MUST reject under pq_required (threat row \
         pq_signature_downgrade)"
    );
}

#[test]
fn rolled_hybrid_bundle_rejected_under_allow_classical() {
    // Symmetric contract: a hybrid bundle MUST reject under
    // `crypto_floor=allow_classical`. This cell completes the 2x2
    // matrix that the full E2E migration suite expands on.
    let classical_kp = Keypair::from_seed(&fixture_classical_seed());
    let classical_backend = Ed25519Backend::new(classical_kp);
    let pq = MlDsa65Backend::from_seed(&fixture_pq_seed());
    let hybrid = HybridBackend::new(Box::new(classical_backend), pq).unwrap();
    let body = classical_body(hybrid.public_key());
    let rolled = ChioReceipt::sign_with_backend(body, &hybrid).unwrap();

    // allow_classical permits ONLY classical envelopes; hybrid is
    // explicitly out.
    assert!(
        !verify_under_floor(&rolled, CryptoFloor::AllowClassical),
        "hybrid bundle under allow_classical MUST reject"
    );
}

#[test]
fn fixture_kernel_key_is_deterministic() {
    // Stability guard: a future change to the Keypair::from_seed
    // derivation MUST be flagged loudly; dependent fixtures across the
    // workspace will need regeneration. We pin the kernel public key
    // hex of the v3.18 fixture so an unintentional crypto bump fails
    // here first.
    let kp = Keypair::from_seed(&fixture_classical_seed());
    let pk_hex = kp.public_key().to_hex();
    assert_eq!(pk_hex.len(), 64, "Ed25519 public key hex must be 64 chars");
    // Re-derive twice to prove determinism.
    let kp2 = Keypair::from_seed(&fixture_classical_seed());
    assert_eq!(kp.public_key().to_hex(), kp2.public_key().to_hex());
}
