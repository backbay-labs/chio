//! DPoP proof-of-possession tests.
//!
//! Tests verify all six verification steps: schema, sender constraint,
//! binding fields, freshness, signature, and nonce replay.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_kernel::{
    verify_dpop_proof, DpopConfig, DpopNonceStore, DpopProof, DpopProofBody, DPOP_SCHEMA,
};

/// Helper: create a signed capability where `subject` is the provided public key.
fn make_capability(agent_kp: &Keypair) -> CapabilityToken {
    let issuer_kp = Keypair::generate();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let body = CapabilityTokenBody {
        id: "cap-dpop-test-01".to_string(),
        issuer: issuer_kp.public_key(),
        subject: agent_kp.public_key(),
        scope: ChioScope::default(),
        issued_at: now,
        expires_at: now + 3600,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, &issuer_kp).expect("sign capability")
}

/// Helper: build a valid DPoP proof body.
fn make_proof_body(capability: &CapabilityToken, agent_kp: &Keypair) -> DpopProofBody {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    DpopProofBody {
        schema: DPOP_SCHEMA.to_string(),
        capability_id: capability.id.clone(),
        tool_server: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        action_hash: sha256_hex(b"{}"),
        nonce: "nonce-abc-123".to_string(),
        issued_at: now,
        agent_key: agent_kp.public_key(),
    }
}

/// Helper: default DPoP config.
fn default_config() -> DpopConfig {
    DpopConfig::default()
}

/// Helper: default nonce store.
fn default_store(config: &DpopConfig) -> DpopNonceStore {
    DpopNonceStore::new(
        config.nonce_store_capacity,
        Duration::from_secs(config.proof_ttl_secs),
    )
}

// ---------------------------------------------------------------------------
// Test 1: Valid proof is accepted
// ---------------------------------------------------------------------------

#[test]
fn dpop_valid_proof_accepted() {
    let agent_kp = Keypair::generate();
    let cap = make_capability(&agent_kp);
    let body = make_proof_body(&cap, &agent_kp);
    let proof = DpopProof::sign(body, &agent_kp).expect("sign proof");

    let config = default_config();
    let store = default_store(&config);

    let result = verify_dpop_proof(
        &proof,
        &cap,
        "srv-a",
        "read_file",
        &sha256_hex(b"{}"),
        &store,
        &config,
    );

    assert!(result.is_ok(), "valid proof should be accepted: {result:?}");
}

// ---------------------------------------------------------------------------
// Test 2: Wrong action_hash is rejected (cross-invocation replay)
// ---------------------------------------------------------------------------

#[test]
fn dpop_wrong_action_hash_rejected() {
    let agent_kp = Keypair::generate();
    let cap = make_capability(&agent_kp);
    let body = make_proof_body(&cap, &agent_kp);
    let proof = DpopProof::sign(body, &agent_kp).expect("sign proof");

    let config = default_config();
    let store = default_store(&config);

    // Provide a different action_hash than what the proof was signed over.
    let wrong_hash = sha256_hex(b"{\"different\": \"args\"}");
    let result = verify_dpop_proof(
        &proof,
        &cap,
        "srv-a",
        "read_file",
        &wrong_hash,
        &store,
        &config,
    );

    assert!(result.is_err(), "wrong action_hash should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("binding fields do not match"),
        "unexpected error message: {err_msg}"
    );
}

fn assert_dpop_binding_mismatch_rejected(
    body: DpopProofBody,
    agent_kp: &Keypair,
    cap: &CapabilityToken,
) {
    let proof = DpopProof::sign(body, agent_kp).expect("sign proof");
    let config = default_config();
    let store = default_store(&config);

    let result = verify_dpop_proof(
        &proof,
        cap,
        "srv-a",
        "read_file",
        &sha256_hex(b"{}"),
        &store,
        &config,
    );

    assert!(result.is_err(), "binding mismatch should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("binding fields do not match"),
        "unexpected error message: {err_msg}"
    );
}

#[test]
fn dpop_wrong_capability_id_rejected() {
    let agent_kp = Keypair::generate();
    let cap = make_capability(&agent_kp);
    let mut body = make_proof_body(&cap, &agent_kp);
    body.capability_id = "cap-other".to_string();

    assert_dpop_binding_mismatch_rejected(body, &agent_kp, &cap);
}

#[test]
fn dpop_wrong_tool_server_rejected() {
    let agent_kp = Keypair::generate();
    let cap = make_capability(&agent_kp);
    let mut body = make_proof_body(&cap, &agent_kp);
    body.tool_server = "srv-b".to_string();

    assert_dpop_binding_mismatch_rejected(body, &agent_kp, &cap);
}

#[test]
fn dpop_wrong_tool_name_rejected() {
    let agent_kp = Keypair::generate();
    let cap = make_capability(&agent_kp);
    let mut body = make_proof_body(&cap, &agent_kp);
    body.tool_name = "write_file".to_string();

    assert_dpop_binding_mismatch_rejected(body, &agent_kp, &cap);
}

// ---------------------------------------------------------------------------
// Test 3: Proof signed by wrong agent key is rejected
// ---------------------------------------------------------------------------

#[test]
fn dpop_wrong_agent_key_rejected() {
    let agent_kp = Keypair::generate();
    let attacker_kp = Keypair::generate();
    let cap = make_capability(&agent_kp);

    // Build a proof body that claims to be from the agent but is signed by attacker.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let body = DpopProofBody {
        schema: DPOP_SCHEMA.to_string(),
        capability_id: cap.id.clone(),
        tool_server: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        action_hash: sha256_hex(b"{}"),
        nonce: "nonce-attacker-001".to_string(),
        issued_at: now,
        // attacker sets their own key in the body
        agent_key: attacker_kp.public_key(),
    };
    let proof = DpopProof::sign(body, &attacker_kp).expect("sign proof");

    let config = default_config();
    let store = default_store(&config);

    let result = verify_dpop_proof(
        &proof,
        &cap,
        "srv-a",
        "read_file",
        &sha256_hex(b"{}"),
        &store,
        &config,
    );

    assert!(result.is_err(), "wrong agent key should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("agent_key does not match"),
        "unexpected error message: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Expired proof is rejected
// ---------------------------------------------------------------------------

#[test]
fn dpop_expired_proof_rejected() {
    let agent_kp = Keypair::generate();
    let cap = make_capability(&agent_kp);

    // issued_at = 0 is far in the past and will fail the freshness check.
    let body = DpopProofBody {
        schema: DPOP_SCHEMA.to_string(),
        capability_id: cap.id.clone(),
        tool_server: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        action_hash: sha256_hex(b"{}"),
        nonce: "nonce-expired-001".to_string(),
        issued_at: 0,
        agent_key: agent_kp.public_key(),
    };
    let proof = DpopProof::sign(body, &agent_kp).expect("sign proof");

    let config = default_config();
    let store = default_store(&config);

    let result = verify_dpop_proof(
        &proof,
        &cap,
        "srv-a",
        "read_file",
        &sha256_hex(b"{}"),
        &store,
        &config,
    );

    assert!(result.is_err(), "expired proof should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("proof expired"),
        "unexpected error message: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Nonce reuse within TTL window is rejected
// ---------------------------------------------------------------------------

#[test]
fn dpop_nonce_replay_within_ttl_rejected() {
    let agent_kp = Keypair::generate();
    let cap = make_capability(&agent_kp);

    let config = default_config();
    // Large TTL so the nonce stays live between calls.
    let store = DpopNonceStore::new(config.nonce_store_capacity, Duration::from_secs(3600));

    // First invocation -- different nonce each time.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let shared_nonce = "nonce-replay-test-shared";

    let body1 = DpopProofBody {
        schema: DPOP_SCHEMA.to_string(),
        capability_id: cap.id.clone(),
        tool_server: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        action_hash: sha256_hex(b"{}"),
        nonce: shared_nonce.to_string(),
        issued_at: now,
        agent_key: agent_kp.public_key(),
    };
    let proof1 = DpopProof::sign(body1, &agent_kp).expect("sign proof 1");

    let result1 = verify_dpop_proof(
        &proof1,
        &cap,
        "srv-a",
        "read_file",
        &sha256_hex(b"{}"),
        &store,
        &config,
    );
    assert!(
        result1.is_ok(),
        "first use of nonce should succeed: {result1:?}"
    );

    // Second invocation reusing the same nonce -- must be rejected.
    let body2 = DpopProofBody {
        schema: DPOP_SCHEMA.to_string(),
        capability_id: cap.id.clone(),
        tool_server: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        action_hash: sha256_hex(b"{}"),
        nonce: shared_nonce.to_string(),
        issued_at: now,
        agent_key: agent_kp.public_key(),
    };
    let proof2 = DpopProof::sign(body2, &agent_kp).expect("sign proof 2");

    let result2 = verify_dpop_proof(
        &proof2,
        &cap,
        "srv-a",
        "read_file",
        &sha256_hex(b"{}"),
        &store,
        &config,
    );
    assert!(result2.is_err(), "replay within TTL should be rejected");
    let err_msg = result2.unwrap_err().to_string();
    assert!(
        err_msg.contains("nonce replayed"),
        "unexpected error message: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Nonce reuse after TTL expiry is accepted
// ---------------------------------------------------------------------------

#[test]
fn dpop_nonce_replay_after_ttl_accepted() {
    let agent_kp = Keypair::generate();
    let cap = make_capability(&agent_kp);

    let config = default_config();
    // TTL = 0 means nonces expire immediately.
    let store = DpopNonceStore::new(config.nonce_store_capacity, Duration::from_secs(0));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let reused_nonce = "nonce-after-ttl-001";

    // First use.
    let body1 = DpopProofBody {
        schema: DPOP_SCHEMA.to_string(),
        capability_id: cap.id.clone(),
        tool_server: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        action_hash: sha256_hex(b"{}"),
        nonce: reused_nonce.to_string(),
        issued_at: now,
        agent_key: agent_kp.public_key(),
    };
    let proof1 = DpopProof::sign(body1, &agent_kp).expect("sign proof 1");
    let result1 = verify_dpop_proof(
        &proof1,
        &cap,
        "srv-a",
        "read_file",
        &sha256_hex(b"{}"),
        &store,
        &config,
    );
    assert!(result1.is_ok(), "first use should succeed: {result1:?}");

    // Second use with TTL=0: the nonce expired instantly, so it should be accepted.
    let body2 = DpopProofBody {
        schema: DPOP_SCHEMA.to_string(),
        capability_id: cap.id.clone(),
        tool_server: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        action_hash: sha256_hex(b"{}"),
        nonce: reused_nonce.to_string(),
        issued_at: now,
        agent_key: agent_kp.public_key(),
    };
    let proof2 = DpopProof::sign(body2, &agent_kp).expect("sign proof 2");
    let result2 = verify_dpop_proof(
        &proof2,
        &cap,
        "srv-a",
        "read_file",
        &sha256_hex(b"{}"),
        &store,
        &config,
    );
    assert!(
        result2.is_ok(),
        "nonce reuse after TTL=0 expiry should succeed: {result2:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 7: dpop_required field roundtrip on ToolGrant
// ---------------------------------------------------------------------------

#[test]
fn dpop_required_field_roundtrip() {
    use chio_core::capability::scope::{Operation, ToolGrant};

    // Some(true) must survive a JSON roundtrip and appear in the output.
    let grant_required = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: Some(true),
    };

    let json = serde_json::to_string(&grant_required).expect("serialize");
    assert!(
        json.contains("dpop_required"),
        "dpop_required must appear in JSON when Some(true)"
    );

    let restored: ToolGrant = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.dpop_required, Some(true));

    // None must be omitted from JSON.
    let grant_none = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let json_none = serde_json::to_string(&grant_none).expect("serialize");
    assert!(
        !json_none.contains("dpop_required"),
        "dpop_required must be absent from JSON when None"
    );

    let restored_none: ToolGrant = serde_json::from_str(&json_none).expect("deserialize");
    assert_eq!(restored_none.dpop_required, None);
}

#[test]
fn dpop_issued_at_u64_max_rejected_as_future_dated() {
    let agent_kp = Keypair::generate();
    let cap = make_capability(&agent_kp);

    // u64::MAX is astronomically far in the future -- must exceed the clock-skew window.
    let body = DpopProofBody {
        schema: DPOP_SCHEMA.to_string(),
        capability_id: cap.id.clone(),
        tool_server: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        action_hash: sha256_hex(b"{}"),
        nonce: "nonce-u64-max-001".to_string(),
        issued_at: u64::MAX,
        agent_key: agent_kp.public_key(),
    };
    let proof = DpopProof::sign(body, &agent_kp).expect("sign proof");

    let config = default_config();
    let store = default_store(&config);

    let result = verify_dpop_proof(
        &proof,
        &cap,
        "srv-a",
        "read_file",
        &sha256_hex(b"{}"),
        &store,
        &config,
    );

    assert!(result.is_err(), "issued_at=u64::MAX should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("too far in the future"),
        "unexpected error message: {err_msg}"
    );
}
