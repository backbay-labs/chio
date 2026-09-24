//! End-to-end PQ migration test.
//!
//! Drives a v3.18 receipt bundle through three crypto-floor stages with
//! a PQ key roll inserted between stages 2 and 3:
//!
//! 1. **`allow_classical`.** The pre-migration v3.18 bundle re-verifies
//!    byte-identically. PQ key NOT provisioned. (Pre-migration baseline.)
//! 2. **`allow_hybrid`.** Operator opts into hybrid; the kernel key
//!    composes the same classical Ed25519 with an initial ML-DSA-65
//!    seed. Newly issued bundles are hybrid; classical bundles
//!    are still accepted under `allows_classical_only=true`.
//! 3. **`pq_required`.** Operator rolls the ML-DSA-65 key to a fresh
//!    seed (the rotation event between stages 2 and 3) and tightens the
//!    floor. New bundles are signed by the rolled hybrid backend; the
//!    original v3.18 classical bundle is rejected (threat-model row
//!    `pq_signature_downgrade`).
//!
//! The deterministic per-stage seeds and expected key algorithms are
//! pinned in `tests/fixtures/migration/key_roll_state.json` so the
//! migration narrative is auditable and reproducible across CI runs.
//!
//! Threat-model rows guarded: `pq_signature_downgrade`,
//! `tee_quote_forgery` (the latter is exercised separately in
//! `cross_backend_conformance.rs` but the migration suite is the
//! `pq_signature_downgrade` enforcement surface).

#![cfg(feature = "pq")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{
    Ed25519Backend, HybridBackend, Keypair, MlDsa65Backend, PublicKey, SigningAlgorithm,
    SigningBackend,
};
use chio_core_types::receipt::{
    body::chio_receipt_id, body::ChioReceipt, body::ChioReceiptBody, decision::Decision,
    decision::ToolCallAction, kinds::TrustLevel, signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY,
};
use serde_json::Value;

const V318_FIXTURE_PATH: &str = "tests/fixtures/v318/receipt_bundle.json";
const KEY_ROLL_STATE_PATH: &str = "tests/fixtures/migration/key_roll_state.json";

fn fixture_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Wire-stable wrapper for a `crypto_floor` enum value the migration
/// suite enforces. Mirrors `chio_kernel::KernelCryptoFloor` and
/// `chio_policy::CryptoFloor` exactly so the test can re-implement the
/// dispatch table locally without taking either crate as a dev-dep
/// (`chio-attest-verify` does not depend on `chio-kernel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoFloor {
    AllowClassical,
    AllowHybrid,
    PqRequired,
}

impl CryptoFloor {
    fn allows(self, alg: SigningAlgorithm) -> bool {
        match (self, alg) {
            // Classical-only floors accept Ed25519/P-256/P-384.
            (
                CryptoFloor::AllowClassical,
                SigningAlgorithm::Ed25519 | SigningAlgorithm::P256 | SigningAlgorithm::P384,
            ) => true,
            // allow_hybrid accepts both classical and hybrid.
            (
                CryptoFloor::AllowHybrid,
                SigningAlgorithm::Ed25519
                | SigningAlgorithm::P256
                | SigningAlgorithm::P384
                | SigningAlgorithm::Hybrid,
            ) => true,
            // pq_required accepts only hybrid.
            (CryptoFloor::PqRequired, SigningAlgorithm::Hybrid) => true,
            _ => false,
        }
    }
}

fn classical_seed() -> [u8; 32] {
    // Mirror the v3.18 fixture seed pinned in `v318_migration.rs` so the
    // bundle re-verifies byte-identically under stage 1.
    let raw = b"chio-v318-fixture-seed-receipt-v";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn stage2_pq_seed() -> [u8; 32] {
    let raw = b"chio-attest-stage2-pq-seed-aaaaa";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn stage3_pq_seed() -> [u8; 32] {
    let raw = b"chio-attest-stage3-rotpq-seed-aa";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn fixture_action() -> ToolCallAction {
    ToolCallAction::from_parameters(serde_json::json!({"q": "audit"})).unwrap()
}

fn migration_body(kernel_key: PublicKey) -> ChioReceiptBody {
    let mut body = ChioReceiptBody {
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
    };
    // Mirror the canonical signing-nonce binding that ChioReceipt::sign_with_backend
    // applies before signing: the pre-binding id is recorded as the signing nonce in
    // metadata, then the content-addressed id is recomputed over the body that
    // includes it. This keeps the expected body byte-identical to the signed fixture.
    let nonce = body.id.clone();
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY.to_string(),
        Value::String(nonce),
    );
    body.metadata = Some(Value::Object(metadata));
    body.id = chio_receipt_id(&body).unwrap();
    body
}

fn load_v318_fixture() -> ChioReceipt {
    let raw = std::fs::read(fixture_path(V318_FIXTURE_PATH)).unwrap();
    serde_json::from_slice(&raw).unwrap()
}

/// Floor-aware verification helper: enforces `crypto_floor` BEFORE the
/// cryptographic check, mirroring the kernel-side capability validator
/// and compliance certificate verifier dispatch.
fn verify_under_floor(receipt: &ChioReceipt, floor: CryptoFloor) -> bool {
    if !floor.allows(receipt.signature.algorithm()) {
        return false;
    }
    receipt.verify_signature().unwrap_or(false)
}

fn build_classical_backend() -> Ed25519Backend {
    let kp = Keypair::from_seed(&classical_seed());
    Ed25519Backend::new(kp)
}

fn build_hybrid_backend(pq_seed: &[u8; 32]) -> HybridBackend {
    let classical = build_classical_backend();
    let pq = MlDsa65Backend::from_seed(pq_seed);
    HybridBackend::new(Box::new(classical), pq).unwrap()
}

#[test]
fn key_roll_state_fixture_is_consistent() {
    // Lock the fixture against accidental drift: deterministic seeds
    // are 32-byte ASCII, and the recorded stage progression matches
    // the literal seeds the test uses.
    let raw = std::fs::read(fixture_path(KEY_ROLL_STATE_PATH)).unwrap();
    let value: Value = serde_json::from_slice(&raw).unwrap();
    let stages = value.get("stages").and_then(Value::as_array).unwrap();
    assert_eq!(stages.len(), 3, "migration suite locks three stages");

    // Stage 1: classical baseline.
    assert_eq!(stages[0]["crypto_floor"], "allow_classical");
    assert_eq!(stages[0]["kernel_key_alg"], "Ed25519");
    assert!(stages[0]["pq_seed_ascii"].is_null());
    assert_eq!(
        stages[0]["classical_seed_ascii"].as_str().unwrap().len(),
        32,
        "classical seed must be exactly 32 ASCII bytes"
    );

    // Stage 2: hybrid opt-in.
    assert_eq!(stages[1]["crypto_floor"], "allow_hybrid");
    assert_eq!(stages[1]["kernel_key_alg"], "Hybrid");
    assert_eq!(
        stages[1]["pq_seed_ascii"].as_str().unwrap().len(),
        32,
        "stage 2 PQ seed must be exactly 32 ASCII bytes"
    );

    // Stage 3: rolled PQ key, pq_required.
    assert_eq!(stages[2]["crypto_floor"], "pq_required");
    assert_eq!(stages[2]["kernel_key_alg"], "Hybrid");
    let stage3_seed = stages[2]["pq_seed_ascii"].as_str().unwrap();
    assert_eq!(
        stage3_seed.len(),
        32,
        "stage 3 PQ seed must be exactly 32 ASCII bytes"
    );
    let key_roll_between = stages[2]["key_roll_between"].as_array().unwrap();
    assert_eq!(key_roll_between.len(), 2);
    assert_eq!(key_roll_between[0], 2);
    assert_eq!(key_roll_between[1], 3);

    // Cross-check: stage 2 and stage 3 PQ seeds differ (the actual roll).
    assert_ne!(
        stages[1]["pq_seed_ascii"], stages[2]["pq_seed_ascii"],
        "key roll requires distinct stage 2 / stage 3 PQ seeds"
    );

    // Sanity-check: the literal seeds in the test code match the fixture.
    assert_eq!(
        stages[1]["pq_seed_ascii"].as_str().unwrap(),
        std::str::from_utf8(&stage2_pq_seed()).unwrap()
    );
    assert_eq!(
        stages[2]["pq_seed_ascii"].as_str().unwrap(),
        std::str::from_utf8(&stage3_pq_seed()).unwrap()
    );
}

#[test]
fn stage1_allow_classical_accepts_v318_bundle_byte_identically() {
    // Stage 1: pre-migration deployment that has not opted into PQ.
    // The v3.18 bundle re-verifies byte-identically under
    // `allow_classical`; the body canonical-JSON does not drift.
    let fixture = load_v318_fixture();
    assert_eq!(fixture.signature.algorithm(), SigningAlgorithm::Ed25519);
    assert!(verify_under_floor(&fixture, CryptoFloor::AllowClassical));

    // Byte-identity guard: re-encoding the body produces the exact
    // bytes the classical verifier signed over.
    let body_bytes = canonical_json_bytes(&migration_body(fixture.kernel_key.clone())).unwrap();
    let fixture_body_bytes = canonical_json_bytes(&ChioReceiptBody {
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
    })
    .unwrap();
    assert_eq!(body_bytes, fixture_body_bytes, "stage 1 byte drift");
}

#[test]
fn stage2_allow_hybrid_accepts_both_classical_and_hybrid_bundles() {
    // Stage 2: operator flips the floor to `allow_hybrid` and rolls in
    // the initial ML-DSA-65 seed. New bundles are hybrid; classical bundles
    // are still accepted (the migration window).
    let hybrid = build_hybrid_backend(&stage2_pq_seed());
    let body = migration_body(hybrid.public_key());
    let hybrid_bundle = ChioReceipt::sign_with_backend(body, &hybrid).unwrap();
    assert_eq!(
        hybrid_bundle.signature.algorithm(),
        SigningAlgorithm::Hybrid
    );
    assert!(verify_under_floor(&hybrid_bundle, CryptoFloor::AllowHybrid));

    // Legacy bundle still accepted under allow_hybrid (allows_classical_only=true).
    let fixture = load_v318_fixture();
    assert!(verify_under_floor(&fixture, CryptoFloor::AllowHybrid));
}

#[test]
fn stage3_pq_required_accepts_rolled_hybrid_and_rejects_v318_bundle() {
    // Stage 3: PQ key has been rolled (stage2 seed -> stage3 seed) and
    // `crypto_floor=pq_required` is in force. The newly signed bundle
    // re-verifies; the original v3.18 classical bundle is rejected
    // (threat-model row `pq_signature_downgrade`).
    let stage2 = build_hybrid_backend(&stage2_pq_seed());
    let stage3 = build_hybrid_backend(&stage3_pq_seed());

    // The roll: the public key under stage 3 differs from stage 2
    // because the PQ half changed (classical half is identical).
    assert_ne!(
        stage2.public_key(),
        stage3.public_key(),
        "key roll MUST produce a fresh kernel public key"
    );

    let body = migration_body(stage3.public_key());
    let rolled_bundle = ChioReceipt::sign_with_backend(body, &stage3).unwrap();
    assert_eq!(
        rolled_bundle.signature.algorithm(),
        SigningAlgorithm::Hybrid
    );
    assert!(verify_under_floor(&rolled_bundle, CryptoFloor::PqRequired));

    // Threat row pq_signature_downgrade: the classical bundle MUST
    // reject under pq_required even though its signature would still
    // crypto-verify; the floor enforces the downgrade refusal BEFORE
    // the cryptographic check.
    let fixture = load_v318_fixture();
    assert!(
        !verify_under_floor(&fixture, CryptoFloor::PqRequired),
        "classical v3.18 bundle MUST reject under pq_required"
    );

    // Cross-stage rejection: a stage-2-signed hybrid bundle MUST reject
    // when the rolled stage-3 verifier is the trust anchor (the rolled
    // public key does not match), so a stale-key receipt does not slip
    // through after the roll. The floor allows the algorithm; the
    // cryptographic check is what fails (different PQ half).
    let stage2_body = migration_body(stage2.public_key());
    let stage2_bundle = ChioReceipt::sign_with_backend(stage2_body, &stage2).unwrap();
    // Rebind the bundle's kernel_key to the rolled stage3 key to
    // simulate an attacker who copies the body but swaps the kernel_key
    // header. The signature MUST NOT verify under the rolled key.
    let mut stale_bundle = stage2_bundle;
    stale_bundle.kernel_key = stage3.public_key();
    assert!(
        !verify_under_floor(&stale_bundle, CryptoFloor::PqRequired),
        "stage-2 PQ signature must not verify under rolled stage-3 key"
    );
}

#[test]
fn end_to_end_migration_walks_three_stages() {
    // Compose the per-stage assertions into a single E2E walk:
    // allow_classical -> allow_hybrid -> pq_required, with the PQ key
    // roll between stages 2 and 3.
    //
    // This test is the operator-facing narrative oracle: if any
    // individual stage assertion drifts, this walk fails first with a
    // single clear `stage = N` panic message.

    // Stage 1.
    let fixture = load_v318_fixture();
    assert!(
        verify_under_floor(&fixture, CryptoFloor::AllowClassical),
        "stage = 1 (allow_classical) MUST accept v3.18 bundle"
    );

    // Stage 2: roll in the initial PQ key.
    let stage2 = build_hybrid_backend(&stage2_pq_seed());
    let stage2_bundle =
        ChioReceipt::sign_with_backend(migration_body(stage2.public_key()), &stage2).unwrap();
    assert!(
        verify_under_floor(&stage2_bundle, CryptoFloor::AllowHybrid),
        "stage = 2 (allow_hybrid) MUST accept new hybrid bundle"
    );
    assert!(
        verify_under_floor(&fixture, CryptoFloor::AllowHybrid),
        "stage = 2 (allow_hybrid) MUST keep accepting v3.18 bundle"
    );

    // The roll: PQ key changes between stage 2 and stage 3.
    let stage3 = build_hybrid_backend(&stage3_pq_seed());
    assert_ne!(
        stage2.public_key(),
        stage3.public_key(),
        "stage 2 -> stage 3 key roll MUST change the kernel public key"
    );

    // Stage 3: tighten the floor and verify the rolled bundle.
    let stage3_bundle =
        ChioReceipt::sign_with_backend(migration_body(stage3.public_key()), &stage3).unwrap();
    assert!(
        verify_under_floor(&stage3_bundle, CryptoFloor::PqRequired),
        "stage = 3 (pq_required) MUST accept rolled hybrid bundle"
    );
    assert!(
        !verify_under_floor(&fixture, CryptoFloor::PqRequired),
        "stage = 3 (pq_required) MUST reject v3.18 classical bundle (pq_signature_downgrade)"
    );
}
