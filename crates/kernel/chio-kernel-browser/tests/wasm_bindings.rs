#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Wasm-bindgen integration tests.
//!
//! These tests exercise the three `#[wasm_bindgen]` entry points
//! (`evaluate`, `sign_receipt`, `verify_capability`) end-to-end with
//! fixture JSON payloads that are constructed inside the test itself.
//!
//! The tests are gated behind `cfg(target_arch = "wasm32")` so native
//! `cargo test -p chio-kernel-browser` skips them gracefully; the
//! native smoke tests in `src/lib.rs` cover the pure-logic path on the
//! host.
//!
//! Run under `wasm-bindgen-test-runner` when a headless browser is
//! installed (Chrome and Firefox both work with `wasm-bindgen-cli`):
//!
//! ```bash
//! wasm-pack test --headless --chrome crates/chio-kernel-browser
//! ```

#![cfg(target_arch = "wasm32")]

use chio_core_types::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{
    body::ChioReceiptBody, decision::Decision, decision::ToolCallAction, kinds::TrustLevel,
};
use chio_kernel_browser::wasm::{evaluate, mint_signing_seed_hex, sign_receipt, verify_capability};
use serde_wasm_bindgen::from_value;
use wasm_bindgen_test::console_log;
use wasm_bindgen_test::wasm_bindgen_test;
use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_browser);

const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;

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
        id: "cap-wasm-1".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        delegation_chain: vec![],
    };
    CapabilityToken::sign(body, issuer).unwrap()
}

#[wasm_bindgen_test]
fn evaluate_round_trip() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);

    let request_json = serde_json::json!({
        "request": {
            "request_id": "req-wasm-1",
            "tool_name": "echo",
            "server_id": "srv-a",
            "agent_id": subject.public_key().to_hex(),
            "arguments": {"msg": "hello"},
        },
        "capability": capability,
        "trusted_issuers_hex": [issuer.public_key().to_hex()],
        "clock_override_unix_secs": ISSUED_AT + 1,
    });

    let started = js_sys::Date::now();
    let verdict_js = evaluate(&request_json.to_string()).expect("evaluate returned Ok");
    let elapsed_ms = js_sys::Date::now() - started;

    // 5 ms is the target ceiling. Allow some slack in CI.
    assert!(
        elapsed_ms < 50.0,
        "evaluate round-trip took {elapsed_ms} ms; expected <50 ms"
    );
    console_log!("qualify_browser_evaluate_latency_ms={elapsed_ms}");

    let verdict: serde_json::Value = from_value(verdict_js).unwrap();
    assert_eq!(verdict["verdict"], "pending_approval");
    assert_eq!(verdict["capability_verdict"], "allow");
    assert_eq!(verdict["authorized"], false);
    assert_eq!(verdict["authorization_basis"], "capability_only");
    assert_eq!(verdict["guards_evaluated"], false);
    assert_eq!(verdict["matched_grant_index"], 0);
}

fn signable_body(content_hash: String) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-wasm-1".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-wasm-1".to_string(),
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
        kernel_key: Keypair::generate().public_key(),
        bbs_projection_version: None,
    }
}

#[wasm_bindgen_test]
fn sign_receipt_uses_webcrypto_seed() {
    let seed_hex = mint_signing_seed_hex().expect("mint seed");
    assert_eq!(seed_hex.len(), 64);

    // WYSIWYS: the PUBLIC wasm signer now requires the
    // `canonical_content` preimage and recomputes `content_hash` inside the
    // trust boundary. Supply a matching preimage (a JSON array of `u8`) so the
    // recompute gate passes; the legacy `{body}`-only shape is no longer valid.
    let canonical_content = br#"{"shown":"to-the-human"}"#.to_vec();
    let content_hash = sha256_hex(&canonical_content);
    let body = signable_body(content_hash);
    let input = serde_json::json!({ "body": body, "canonical_content": canonical_content });

    let receipt_js = sign_receipt(&input.to_string(), &seed_hex).expect("sign_receipt");
    let receipt: chio_core_types::receipt::body::ChioReceipt = from_value(receipt_js).unwrap();
    assert!(receipt.verify_signature().unwrap());
}

#[wasm_bindgen_test]
fn sign_receipt_refuses_without_canonical_content() {
    // WYSIWYS: a `{body}`-only shape (no preimage) must fail
    // closed so a caller cannot render content A while signing a body claiming
    // hash(B) by omitting the preimage.
    let seed_hex = mint_signing_seed_hex().expect("mint seed");
    let body = signable_body("0".repeat(64));
    let input = serde_json::json!({ "body": body });

    let err = sign_receipt(&input.to_string(), &seed_hex)
        .expect_err("public signer must refuse without canonical content");
    let error: serde_json::Value = from_value(err).unwrap();
    assert_eq!(error["code"], "canonical_content_required");
}

#[wasm_bindgen_test]
fn verify_capability_rejects_untrusted_issuer() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let other = Keypair::generate();
    let capability = make_capability(&subject, &issuer);

    let token_json = serde_json::to_string(&capability).unwrap();
    let result = verify_capability(&token_json, &other.public_key().to_hex());
    assert!(result.is_err(), "untrusted issuer must not verify");

    let error: serde_json::Value = from_value(result.unwrap_err()).unwrap();
    assert_eq!(error["code"], "capability_verification_failed");
}

#[wasm_bindgen_test]
fn evaluate_rejects_malformed_json() {
    let result = evaluate("not json");
    assert!(result.is_err(), "malformed JSON must surface as Err");
    let error: serde_json::Value = from_value(result.unwrap_err()).unwrap();
    assert_eq!(error["code"], "invalid_json_input");
}
