#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Rust-side round-trip tests for the mobile FFI surface.
//!
//! These tests drive the `pub fn`s in `chio_kernel_mobile::*` directly
//! rather than linking the UniFFI-generated Swift/Kotlin bindings, so
//! CI can exercise the full input-parsing, verification, and output-
//! serialization path on every commit without needing an iOS simulator
//! or Android emulator.
//!
//! The invariant we are asserting: for every entry point the app-side
//! host would call, the Rust function parses JSON, calls the kernel
//! core correctly, and produces a JSON result that round-trips through
//! the expected schema.

use chio_core_types::canonical_json_bytes;
use chio_core_types::capability::{
    attenuation::{DelegationLink, DelegationLinkBody},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
use chio_kernel_core::passport_verify::{
    PortablePassportBody, PortablePassportEnvelope, PORTABLE_PASSPORT_SCHEMA,
};
use chio_kernel_mobile::{
    attest_app_attest, attest_play_integrity, evaluate, sign_receipt,
    sign_receipt_relaying_trusted_body, verify_app_attest_evidence, verify_capability,
    verify_capability_with_context, verify_mobile_receipt, verify_passport,
    verify_play_integrity_evidence, ChioMobileError,
};

const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;
const EVAL_TIME: u64 = 1_700_000_100;

fn make_capability(subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "echo".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let body = CapabilityTokenBody {
        id: "cap-ffi".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        delegation_chain: vec![],
    };
    CapabilityToken::sign(body, issuer).unwrap()
}

fn make_delegated_capability(
    id: &str,
    parent_id: &str,
    subject: &Keypair,
    issuer: &Keypair,
) -> CapabilityToken {
    let mut body = make_capability(subject, issuer).body();
    body.id = id.to_string();
    body.delegation_chain = vec![DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent_id.to_string(),
            delegator: issuer.public_key(),
            delegatee: subject.public_key(),
            attenuations: vec![],
            timestamp: ISSUED_AT,
            scope_hash: None,
        },
        issuer,
    )
    .unwrap()];
    CapabilityToken::sign(body, issuer).unwrap()
}

fn parent_budget_snapshot(parent_id: &str) -> serde_json::Value {
    serde_json::json!({
        "parent_token_id": parent_id,
        "parent_share_bps": 10_000,
        "admitted_children": [],
    })
}

fn oversubscribed_budget_snapshot(parent_id: &str) -> serde_json::Value {
    serde_json::json!({
        "parent_token_id": parent_id,
        "parent_share_bps": 10_000,
        "admitted_children": [
            {
                "child_token_id": "cap-sibling",
                "share_bps": 1,
            }
        ],
    })
}

fn make_receipt_body(keypair: &Keypair) -> ChioReceiptBody {
    make_receipt_body_with_content_hash(keypair, "0".repeat(64))
}

fn make_receipt_body_with_content_hash(keypair: &Keypair, content_hash: String) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-ffi-1".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-ffi".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash,
        policy_hash: "0".repeat(64),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    }
}

#[test]
fn evaluate_allow_roundtrip() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);

    let request_json = serde_json::json!({
        "capability": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "request": {
            "request_id": "req-1",
            "tool_name": "echo",
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
            "arguments": {"msg": "hello"},
        },
        "now_secs": EVAL_TIME as i64,
    })
    .to_string();

    let response_json = evaluate(request_json).expect("evaluate allow");
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();
    assert_eq!(response["verdict"], "allow");
    assert_eq!(response["matched_grant_index"], 0);
    assert!(response.get("reason").is_none());
}

#[test]
fn evaluate_allows_delegated_token_with_parent_budget_snapshot() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);

    let request_json = serde_json::json!({
        "capability": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "request": {
            "request_id": "req-delegated",
            "tool_name": "echo",
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
            "arguments": {"msg": "hello"},
        },
        "now_secs": EVAL_TIME as i64,
        "parent_budget_snapshots": [parent_budget_snapshot("cap-parent")],
    })
    .to_string();

    let response_json = evaluate(request_json).expect("evaluate delegated allow");
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();
    assert_eq!(response["verdict"], "allow");
    assert_eq!(response["matched_grant_index"], 0);
}

#[test]
fn evaluate_rejects_oversubscribed_delegated_sibling() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);

    let request_json = serde_json::json!({
        "capability": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "request": {
            "request_id": "req-delegated-oversub",
            "tool_name": "echo",
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
            "arguments": {"msg": "hello"},
        },
        "now_secs": EVAL_TIME as i64,
        "parent_budget_snapshots": [oversubscribed_budget_snapshot("cap-parent")],
    })
    .to_string();

    let response_json = evaluate(request_json).expect("evaluate delegated deny");
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();
    assert_eq!(response["verdict"], "deny");
    let reason = response["reason"].as_str().unwrap();
    assert!(reason.contains("budget split rejected"), "reason: {reason}");
}

#[test]
fn evaluate_deny_out_of_scope() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);

    let request_json = serde_json::json!({
        "capability": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "request": {
            "request_id": "req-2",
            "tool_name": "unknown-tool",
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
            "arguments": {},
        },
        "now_secs": EVAL_TIME as i64,
    })
    .to_string();

    let response_json = evaluate(request_json).expect("evaluate deny");
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();
    assert_eq!(response["verdict"], "deny");
    let reason = response["reason"].as_str().unwrap();
    assert!(
        reason.contains("not in capability scope"),
        "reason: {reason}"
    );
}

#[test]
fn evaluate_deny_expired_capability() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);

    let request_json = serde_json::json!({
        "capability": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "request": {
            "request_id": "req-3",
            "tool_name": "echo",
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
        },
        // Pin clock past expiry.
        "now_secs": (EXPIRES_AT + 1) as i64,
    })
    .to_string();

    let response_json = evaluate(request_json).expect("evaluate expired");
    let response: serde_json::Value = serde_json::from_str(&response_json).unwrap();
    assert_eq!(response["verdict"], "deny");
    let reason = response["reason"].as_str().unwrap();
    assert!(reason.contains("expired"), "reason: {reason}");
}

#[test]
fn evaluate_rejects_malformed_json() {
    let err = evaluate("not json".to_string()).unwrap_err();
    match err {
        ChioMobileError::InvalidJson { message } => {
            assert!(message.contains("evaluate request"));
        }
        other => panic!("expected InvalidJson, got {other:?}"),
    }
}

#[test]
fn evaluate_rejects_bad_trusted_hex() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);

    let request_json = serde_json::json!({
        "capability": capability,
        "trusted_issuers": ["not-hex"],
        "request": {
            "request_id": "req-4",
            "tool_name": "echo",
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
        },
        "now_secs": EVAL_TIME as i64,
    })
    .to_string();

    let err = evaluate(request_json).unwrap_err();
    match err {
        ChioMobileError::InvalidHex { message } => {
            assert!(message.contains("trusted issuer"));
        }
        other => panic!("expected InvalidHex, got {other:?}"),
    }
}

#[test]
fn sign_receipt_roundtrip_and_verifies() {
    // WYSIWYS: the public signer recomputes content_hash over the
    // canonical content preimage. A matching content+hash pair signs and
    // verifies.
    let keypair = Keypair::generate();
    let canonical_content = br#"{"shown":"to-the-human"}"#.to_vec();
    let content_hash = chio_core_types::crypto::sha256_hex(&canonical_content);
    let body = make_receipt_body_with_content_hash(&keypair, content_hash);
    let body_json = serde_json::to_string(&body).unwrap();
    let seed_hex = keypair.seed_hex();

    let signed_json =
        sign_receipt(body_json, hex::encode(&canonical_content), seed_hex).expect("sign receipt");
    let receipt: ChioReceipt = serde_json::from_str(&signed_json).expect("parse signed receipt");
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.kernel_key, keypair.public_key());
}

#[test]
fn sign_receipt_accepts_empty_preimage_stream_receipt() {
    // WYSIWYS: a zero-chunk stream receipt has an empty-byte canonical preimage,
    // which encodes to the empty hex string. The public mobile signer must NOT
    // reject the empty preimage: `body.content_hash` is sha256 of those empty
    // bytes, so the WYSIWYS recompute gate passes and the receipt signs.
    let keypair = Keypair::generate();
    let canonical_content: Vec<u8> = Vec::new();
    let content_hash = chio_core_types::crypto::sha256_hex(&canonical_content);
    let body = make_receipt_body_with_content_hash(&keypair, content_hash);
    let body_json = serde_json::to_string(&body).unwrap();

    // Empty preimage -> empty canonical-content hex string.
    let signed_json = sign_receipt(body_json, String::new(), keypair.seed_hex())
        .expect("empty-preimage stream receipt must sign");
    let receipt: ChioReceipt = serde_json::from_str(&signed_json).expect("parse signed receipt");
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.kernel_key, keypair.public_key());
}

#[test]
fn sign_receipt_refuses_render_a_sign_b() {
    // WYSIWYS render-A/sign-B regression: the body claims
    // hash(B) while the canonical content handed to the public signer is A.
    // The recompute-and-refuse gate inside `chio_kernel_core::sign_receipt`
    // MUST reject this fail-closed. Without the fix (relaying the trusted body
    // without recomputing) this forgery would be signed.
    let keypair = Keypair::generate();
    let content_a = br#"{"shown":"to-the-human"}"#.to_vec();
    let hash_b = chio_core_types::crypto::sha256_hex(br#"{"secretly":"signed-instead"}"#);
    let body = make_receipt_body_with_content_hash(&keypair, hash_b);
    let body_json = serde_json::to_string(&body).unwrap();

    let err = sign_receipt(body_json, hex::encode(&content_a), keypair.seed_hex())
        .expect_err("render-A/sign-B must be refused");
    match err {
        ChioMobileError::SigningFailed { message } => {
            assert!(message.contains("WYSIWYS refused"), "got: {message}");
        }
        other => panic!("expected SigningFailed (WYSIWYS), got {other:?}"),
    }
}

#[test]
fn sign_receipt_rejects_kernel_key_mismatch() {
    // Use matching content+hash so the recompute gate passes and the kernel-key
    // check (which runs after recompute) is what fires.
    let keypair_body = Keypair::generate();
    let keypair_signer = Keypair::generate();
    let canonical_content = br#"{"shown":"to-the-human"}"#.to_vec();
    let content_hash = chio_core_types::crypto::sha256_hex(&canonical_content);
    let body = make_receipt_body_with_content_hash(&keypair_body, content_hash);
    let body_json = serde_json::to_string(&body).unwrap();

    let err = sign_receipt(
        body_json,
        hex::encode(&canonical_content),
        keypair_signer.seed_hex(),
    )
    .unwrap_err();
    match err {
        ChioMobileError::KernelKeyMismatch { .. } => {}
        other => panic!("expected KernelKeyMismatch, got {other:?}"),
    }
}

#[test]
fn sign_receipt_rejects_bad_seed_hex() {
    let keypair = Keypair::generate();
    let canonical_content = br#"{"shown":"to-the-human"}"#.to_vec();
    let content_hash = chio_core_types::crypto::sha256_hex(&canonical_content);
    let body = make_receipt_body_with_content_hash(&keypair, content_hash);
    let body_json = serde_json::to_string(&body).unwrap();

    let err = sign_receipt(
        body_json,
        hex::encode(&canonical_content),
        "not-hex-seed".to_string(),
    )
    .unwrap_err();
    match err {
        ChioMobileError::InvalidHex { .. } => {}
        other => panic!("expected InvalidHex, got {other:?}"),
    }
}

#[test]
fn sign_receipt_rejects_zero_seed() {
    let zero_seed = [0u8; 32];
    let keypair = Keypair::from_seed(&zero_seed);
    let canonical_content = br#"{"shown":"to-the-human"}"#.to_vec();
    let content_hash = chio_core_types::crypto::sha256_hex(&canonical_content);
    let body = make_receipt_body_with_content_hash(&keypair, content_hash);
    let body_json_result = serde_json::to_string(&body);
    assert!(
        body_json_result.is_ok(),
        "receipt body fixture should serialize"
    );
    let body_json = body_json_result.unwrap_or_default();

    let result = sign_receipt(body_json, hex::encode(&canonical_content), "00".repeat(32));
    assert!(
        matches!(result, Err(ChioMobileError::WeakEntropy { .. })),
        "zero seed must return WeakEntropy"
    );
    if let Err(ChioMobileError::WeakEntropy { message }) = result {
        assert!(message.contains("all-zero Ed25519 seed"));
    }
}

#[test]
fn sign_receipt_relaying_trusted_body_signs_without_preimage() {
    // The explicitly named relay seam is the only path that forwards
    // a trusted body without a content preimage; it trusts `content_hash`.
    let keypair = Keypair::generate();
    let body = make_receipt_body(&keypair);
    let body_json = serde_json::to_string(&body).unwrap();

    let signed_json = sign_receipt_relaying_trusted_body(body_json, keypair.seed_hex())
        .expect("relay seam signs an upstream-trusted body");
    let receipt: ChioReceipt = serde_json::from_str(&signed_json).expect("parse signed receipt");
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.kernel_key, keypair.public_key());
}

#[test]
fn verify_capability_happy_path() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();

    // Build a capability whose validity window spans now; the
    // `verify_capability` FFI uses the MobileClock, so we can't
    // substitute a FixedClock here. A 100-year expiry covers the
    // test run comfortably.
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "echo".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let body = CapabilityTokenBody {
        id: "cap-verify".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at: 1_000_000_000,
        expires_at: 5_000_000_000,
        delegation_chain: vec![],
    };
    let capability = CapabilityToken::sign(body, &issuer).unwrap();

    let verified = verify_capability(
        serde_json::to_string(&capability).unwrap(),
        issuer.public_key().to_hex(),
    )
    .expect("verify capability");

    assert_eq!(verified.id, "cap-verify");
    assert_eq!(verified.subject_hex, subject.public_key().to_hex());
    assert_eq!(verified.issuer_hex, issuer.public_key().to_hex());
    assert!(verified.scope_json.contains("srv-a"));
    assert_eq!(verified.issued_at, 1_000_000_000);
    assert_eq!(verified.expires_at, 5_000_000_000);
}

#[test]
fn verify_capability_with_context_allows_delegated_token_with_parent_budget_snapshot() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);

    let request_json = serde_json::json!({
        "token": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "now_secs": EVAL_TIME as i64,
        "parent_budget_snapshots": [parent_budget_snapshot("cap-parent")],
    })
    .to_string();

    let verified =
        verify_capability_with_context(request_json).expect("verify delegated capability");

    assert_eq!(verified.id, "cap-child");
    assert_eq!(verified.subject_hex, subject.public_key().to_hex());
}

#[test]
fn verify_capability_with_context_rejects_oversubscribed_delegated_sibling() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_delegated_capability("cap-child", "cap-parent", &subject, &issuer);

    let request_json = serde_json::json!({
        "token": capability,
        "trusted_issuers": [issuer.public_key().to_hex()],
        "now_secs": EVAL_TIME as i64,
        "parent_budget_snapshots": [oversubscribed_budget_snapshot("cap-parent")],
    })
    .to_string();

    let err = verify_capability_with_context(request_json).unwrap_err();

    match err {
        ChioMobileError::InvalidCapability { message } => {
            assert!(
                message.contains("sibling-sum budget split"),
                "message: {message}"
            );
        }
        other => panic!("expected InvalidCapability, got {other:?}"),
    }
}

#[test]
fn verify_capability_rejects_untrusted_issuer() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let other = Keypair::generate();
    let capability = make_capability(&subject, &issuer);

    let err = verify_capability(
        serde_json::to_string(&capability).unwrap(),
        other.public_key().to_hex(),
    )
    .unwrap_err();
    match err {
        ChioMobileError::InvalidCapability { message } => {
            assert!(message.contains("trusted authority"));
        }
        other => panic!("expected InvalidCapability, got {other:?}"),
    }
}

#[test]
fn verify_passport_happy_path() {
    let issuer = Keypair::generate();
    let payload = serde_json::json!({
        "schema": "chio.agent-passport.v1",
        "subject": "did:chio:agent-mobile",
        "trustTier": "premier",
    });
    let payload_canonical_bytes = canonical_json_bytes(&payload).unwrap();
    let body = PortablePassportBody {
        schema: PORTABLE_PASSPORT_SCHEMA.to_string(),
        subject: "did:chio:agent-mobile".to_string(),
        issuer: issuer.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        payload_canonical_bytes: payload_canonical_bytes.clone(),
    };
    let (signature, _) = issuer.sign_canonical(&body).unwrap();
    let envelope = PortablePassportEnvelope { body, signature };
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let metadata = verify_passport(
        envelope_json,
        issuer.public_key().to_hex(),
        EVAL_TIME as i64,
    )
    .expect("verify passport");

    assert_eq!(metadata.subject, "did:chio:agent-mobile");
    assert_eq!(metadata.issuer_hex, issuer.public_key().to_hex());
    assert_eq!(metadata.issued_at, ISSUED_AT);
    assert_eq!(metadata.expires_at, EXPIRES_AT);
    assert_eq!(metadata.evaluated_at, EVAL_TIME);
    // hex round-trip witness.
    let decoded = hex::decode(metadata.payload_canonical_hex).unwrap();
    assert_eq!(decoded, payload_canonical_bytes);
}

#[test]
fn verify_passport_rejects_expired_envelope() {
    let issuer = Keypair::generate();
    let body = PortablePassportBody {
        schema: PORTABLE_PASSPORT_SCHEMA.to_string(),
        subject: "did:chio:agent-mobile".to_string(),
        issuer: issuer.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        payload_canonical_bytes: vec![],
    };
    let (signature, _) = issuer.sign_canonical(&body).unwrap();
    let envelope = PortablePassportEnvelope { body, signature };
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let err = verify_passport(
        envelope_json,
        issuer.public_key().to_hex(),
        (EXPIRES_AT + 1) as i64,
    )
    .unwrap_err();
    match err {
        ChioMobileError::InvalidPassport { message } => {
            assert!(message.contains("expired"), "got: {message}");
        }
        other => panic!("expected InvalidPassport, got {other:?}"),
    }
}

#[test]
fn verify_passport_rejects_untrusted_issuer() {
    let issuer = Keypair::generate();
    let other = Keypair::generate();
    let body = PortablePassportBody {
        schema: PORTABLE_PASSPORT_SCHEMA.to_string(),
        subject: "did:chio:agent-mobile".to_string(),
        issuer: issuer.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        payload_canonical_bytes: vec![],
    };
    let (signature, _) = issuer.sign_canonical(&body).unwrap();
    let envelope = PortablePassportEnvelope { body, signature };
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let err =
        verify_passport(envelope_json, other.public_key().to_hex(), EVAL_TIME as i64).unwrap_err();
    match err {
        ChioMobileError::InvalidPassport { message } => {
            assert!(message.contains("trusted authority"), "got: {message}");
        }
        other => panic!("expected InvalidPassport, got {other:?}"),
    }
}

#[test]
fn verify_passport_rejects_bad_issuer_hex() {
    let err =
        verify_passport("{}".to_string(), "not-hex".to_string(), EVAL_TIME as i64).unwrap_err();
    match err {
        ChioMobileError::InvalidHex { .. } => {}
        other => panic!("expected InvalidHex, got {other:?}"),
    }
}

#[test]
fn attest_app_attest_rejects_bad_challenge_hex() {
    let err = attest_app_attest("app-key".to_string(), "not-hex".to_string()).unwrap_err();
    match err {
        ChioMobileError::InvalidHex { message } => {
            assert!(message.contains("App Attest challenge"));
        }
        other => panic!("expected InvalidHex, got {other:?}"),
    }
}

#[test]
fn attest_app_attest_returns_bound_challenge_envelope() {
    let raw = attest_app_attest("app-key".to_string(), "01020304".to_string()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value["schema"], "chio.mobile.app-attest.challenge.v1");
    assert_eq!(value["platform"], "app_attest");
    assert_eq!(value["key_id"], "app-key");
    assert_eq!(value["challenge_hex"], "01020304");
}

#[test]
fn verify_app_attest_evidence_rejects_malformed_cbor_fail_closed() {
    let err = verify_app_attest_evidence(
        "app-key".to_string(),
        "01020304".to_string(),
        "TEAMID1234.dev.chio.patient".to_string(),
        "00".to_string(),
        -1,
    )
    .unwrap_err();
    match err {
        ChioMobileError::AttestationRejected { message } => {
            assert!(message.contains("urn:chio:error:custody:app-attest-invalid-cbor"));
        }
        other => panic!("expected AttestationRejected, got {other:?}"),
    }
}

#[test]
fn attest_play_integrity_returns_bound_nonce_envelope() {
    let raw = attest_play_integrity("0x0102030405".to_string()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value["schema"], "chio.mobile.play-integrity.challenge.v1");
    assert_eq!(value["platform"], "play_integrity");
    assert_eq!(value["nonce_hex"], "0102030405");
}

#[test]
fn verify_play_integrity_evidence_rejects_bad_jws_fail_closed() {
    let err = verify_play_integrity_evidence(
        "not-a-jws".to_string(),
        "issuer-nonce-1".to_string(),
        "dev.chio.patient".to_string(),
        "chio-mobile-issuer".to_string(),
        r#"{"keys":[]}"#.to_string(),
    )
    .unwrap_err();
    match err {
        ChioMobileError::AttestationRejected { message } => {
            assert!(message.contains("urn:chio:error:custody:play-integrity-invalid-token"));
        }
        other => panic!("expected AttestationRejected, got {other:?}"),
    }
}

#[test]
fn verify_mobile_receipt_rejects_bad_json() {
    let err = verify_mobile_receipt("not-json".to_string(), "{}".to_string()).unwrap_err();
    match err {
        ChioMobileError::InvalidJson { message } => {
            assert!(message.contains("mobile receipt"));
        }
        other => panic!("expected InvalidJson, got {other:?}"),
    }
}

#[test]
fn verify_mobile_receipt_accepts_known_attestation_platform_shape() {
    let receipt_json = serde_json::json!({
        "schema": "chio.mobile.receipt.v1",
        "receipt_id": "mobile-receipt-1"
    })
    .to_string();
    let evidence_json = serde_json::json!({
        "schema": "chio.mobile.attestation-evidence.v1",
        "platform": "app_attest"
    })
    .to_string();

    let raw = verify_mobile_receipt(receipt_json, evidence_json).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value["schema"], "chio.mobile.receipt-verification.v1");
    assert_eq!(value["status"], "shape_only");
    assert_eq!(value["receipt_kind"], "trace_observation");
    assert_eq!(value["boundary_class"], "detect_only");
    assert_eq!(value["result"], "observed");
    assert_eq!(value["authoritative"], false);
    assert_eq!(value["authorized"], false);
    assert_eq!(value["platform"], "app_attest");
}
