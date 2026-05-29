#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Wasm-bindgen tests for `verify_receipt`.
//!
//! Driven by the receipt-binding vector corpus
//! (`tests/bindings/vectors/receipt/v1.json`). The corpus is embedded
//! into the wasm artifact at compile time via `include_str!` because
//! `wasm-bindgen-test` runs in browser / Node sandboxes with limited
//! filesystem access.
//!
//! This file deliberately omits
//! `wasm_bindgen_test_configure!(run_in_browser)` so the gate check
//! `wasm-pack test --node crates/chio-kernel-browser` exercises the
//! verifier path. `verify_receipt` does not require Web Crypto, so
//! Node is a sufficient host.

#![cfg(target_arch = "wasm32")]

use chio_core_types::crypto::Keypair;
use chio_kernel_browser::wasm::verify_receipt;
use serde_wasm_bindgen::from_value;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

/// Receipt-binding vector corpus, embedded at compile time. The
/// path is relative to this source file. The corpus is owned by the
/// canonical-bindings track so this dependency is one-way: this
/// test consumes it, never mutates it.
const RECEIPT_BINDING_VECTORS: &str =
    include_str!("../../../tests/bindings/vectors/receipt/v1.json");

/// Find the receipt vector with `id == case_id` and return the embedded
/// receipt object as canonical-JSON bytes suitable for `verify_receipt`.
fn fixture_envelope_for(case_id: &str) -> Vec<u8> {
    let corpus: serde_json::Value = serde_json::from_str(RECEIPT_BINDING_VECTORS).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    let case = cases
        .iter()
        .find(|case| case["id"] == case_id)
        .unwrap_or_else(|| panic!("case {case_id} not in receipt corpus"));
    serde_json::to_vec(&case["receipt"]).unwrap()
}

fn fixture_case(case_id: &str) -> serde_json::Value {
    let corpus: serde_json::Value = serde_json::from_str(RECEIPT_BINDING_VECTORS).unwrap();
    corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == case_id)
        .unwrap_or_else(|| panic!("case {case_id} not in receipt corpus"))
        .clone()
}

fn fixture_cases() -> Vec<serde_json::Value> {
    let corpus: serde_json::Value = serde_json::from_str(RECEIPT_BINDING_VECTORS).unwrap();
    corpus["cases"].as_array().unwrap().clone()
}

#[wasm_bindgen_test]
fn verify_receipt_vector_corpus_matches_expected_without_pinning() {
    for case in fixture_cases() {
        let envelope = serde_json::to_vec(&case["receipt"]).unwrap();
        let result_js = verify_receipt(&envelope, &JsValue::UNDEFINED)
            .expect("verify_receipt should not error");
        let result: serde_json::Value = from_value(result_js).unwrap();
        let expected = &case["expected"];

        for field in [
            "ok",
            "signature_valid",
            "parameter_hash_valid",
            "receipt_id_valid",
            "decision",
            "receipt_kind",
            "boundary_class",
            "result",
            "authorized",
            "signer_key_hex",
            "signer_trusted",
        ] {
            assert_eq!(
                result[field], expected[field],
                "case {} field {field}",
                case["id"]
            );
        }
        assert_eq!(
            result["receipt_id"], case["receipt"]["id"],
            "case {} receipt_id",
            case["id"]
        );
    }
}

#[wasm_bindgen_test]
fn verify_receipt_allow_fixture_is_signature_only_without_pinning() {
    // Case: known-good signed allow receipt with valid parameter hash.
    let envelope = fixture_envelope_for("allow_receipt");

    let result_js = verify_receipt(&envelope, &JsValue::UNDEFINED).expect("verify_receipt Ok");
    let result: serde_json::Value = from_value(result_js).unwrap();

    assert_eq!(result["ok"], false);
    assert_eq!(result["signature_valid"], true);
    assert_eq!(result["parameter_hash_valid"], true);
    assert_eq!(result["signer_trusted"], false);
    assert_eq!(result["decision"], "allow");
    let case = fixture_case("allow_receipt");
    assert_eq!(result["receipt_id"], case["receipt"]["id"]);
    assert_eq!(result["receipt_id_valid"], true);
    assert_eq!(result["receipt_kind"], "mediated_decision");
    assert_eq!(result["boundary_class"], "prevent");
    assert_eq!(result["result"], "Authorized");
    assert_eq!(result["authorized"], false);
    assert_eq!(
        result["signer_key_hex"],
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    );
}

#[wasm_bindgen_test]
fn verify_receipt_allow_fixture_passes_with_pinned_signer() {
    let envelope = fixture_envelope_for("allow_receipt");
    let trusted_array = serde_wasm_bindgen::to_value(&vec![
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c".to_string(),
    ])
    .unwrap();

    let result_js =
        verify_receipt(&envelope, &trusted_array).expect("verify_receipt with pinned signer");
    let result: serde_json::Value = from_value(result_js).unwrap();
    assert_eq!(result["ok"], true);
    assert_eq!(result["signer_trusted"], true);
    assert_eq!(result["authorized"], true);
}

#[wasm_bindgen_test]
fn verify_receipt_rejects_untrusted_signer_when_pinned() {
    let envelope = fixture_envelope_for("allow_receipt");
    let other_key = Keypair::generate().public_key().to_hex();
    let trusted = JsValue::from_str(&other_key);

    let result_js =
        verify_receipt(&envelope, &trusted).expect("verify_receipt should not error on bad pin");
    let result: serde_json::Value = from_value(result_js).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["signature_valid"], true);
    assert_eq!(result["signer_trusted"], false);
}

#[wasm_bindgen_test]
fn verify_receipt_tampered_signature_fixture_marks_invalid() {
    // Case: signature tampered, expected `signature_valid: false`.
    let envelope = fixture_envelope_for("tampered_receipt_signature");

    let result_js =
        verify_receipt(&envelope, &JsValue::UNDEFINED).expect("verify_receipt should not error");
    let result: serde_json::Value = from_value(result_js).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["signature_valid"], false);
}

#[wasm_bindgen_test]
fn verify_receipt_rejects_malformed_envelope() {
    let result = verify_receipt(b"not a receipt", &JsValue::UNDEFINED);
    assert!(result.is_err(), "malformed envelope must surface as Err");
    let error: serde_json::Value = from_value(result.unwrap_err()).unwrap();
    assert_eq!(error["code"], "invalid_receipt_envelope");
}
