#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Integration tests for the default redactor crate.
//!
//! Real-shape inputs: JSON receipts and HTTP-like payloads carrying
//! emails, tokens, API keys, etc. The tests assert that:
//!
//! - the redacted bytes are still valid UTF-8 when input was UTF-8;
//! - canonical replacement markers appear (`[REDACTED-EMAIL]`, etc.);
//! - the manifest carries one entry per match with offsets in the
//!   *original* payload coordinate space;
//! - `pass_id` matches `PASS_ID`;
//! - failing classes are no-ops;
//! - the convenience `redact()` helper composes default-full classes.

use chio_data_guards_redactors_default::{
    redact, redact_payload, RedactClass, RedactedPayload, PASS_ID,
};
use serde_json::json;

fn full() -> RedactClass {
    RedactClass::default_full()
}

fn body(out: &RedactedPayload) -> String {
    String::from_utf8(out.bytes.clone()).expect("redacted output is valid utf-8")
}

#[test]
fn json_receipt_with_email_and_token_gets_scrubbed() {
    let receipt = json!({
        "tenant": "acme",
        "actor": {"email": "alice@example.com"},
        "session": {
            "authorization": "Bearer abcdef0123456789abcdef0123456789abcdef",
        },
        "stripe_key": "sk_live_abcdefghijklmnopqrstuvwx",
    })
    .to_string();

    let out = redact_payload(receipt.as_bytes(), full()).expect("redact ok");
    let body = body(&out);

    assert!(body.contains("[REDACTED-EMAIL]"));
    assert!(body.contains("[REDACTED-BEARER]"));
    assert!(body.contains("[REDACTED-API-KEY]"));
    assert!(!body.contains("alice@example.com"));
    assert!(!body.contains("abcdef0123456789abcdef0123456789abcdef"));
    assert!(!body.contains("sk_live_abcdefghijklmnopqrstuvwx"));

    assert_eq!(out.manifest.pass_id, PASS_ID);
    assert!(!out.manifest.matches.is_empty());

    // Manifest offsets are in the *original* receipt coordinate space.
    for m in &out.manifest.matches {
        let start = m.offset as usize;
        let end = start + m.length as usize;
        assert!(end <= receipt.len(), "match {m:?} out of bounds");
    }
}

#[test]
fn http_log_with_phone_and_ssn_get_scrubbed() {
    let log = "POST /enroll patient phone=(415) 555-2671 ssn=123-45-6789";
    let out = redact_payload(log.as_bytes(), full()).expect("redact ok");
    let body = body(&out);
    assert!(body.contains("[REDACTED-PHONE]"));
    assert!(body.contains("[REDACTED-SSN]"));
    assert!(!body.contains("555-2671"));
    assert!(!body.contains("123-45-6789"));

    let classes: Vec<&str> = out
        .manifest
        .matches
        .iter()
        .map(|m| m.class.as_str())
        .collect();
    assert!(classes.contains(&"pii.phone-us"));
    assert!(classes.contains(&"pii.ssn-us"));
}

#[test]
fn aws_key_in_env_dump_is_redacted() {
    let env = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET=secret";
    let out = redact_payload(env.as_bytes(), full()).expect("redact ok");
    let body = body(&out);
    assert!(!body.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(out
        .manifest
        .matches
        .iter()
        .any(|m| m.class == "secrets.aws-key"));
}

#[test]
fn credit_card_in_invoice_is_redacted_only_when_luhn_passes() {
    // Visa Luhn-valid test number; structurally a card.
    let invoice = "card 4111-1111-1111-1111 amount 4200";
    let out = redact_payload(invoice.as_bytes(), full()).expect("redact ok");
    let body = body(&out);
    assert!(body.contains("[REDACTED-CC]"));
    assert!(!body.contains("4111-1111-1111-1111"));
}

#[test]
fn empty_class_set_is_a_no_op_and_passes_through() {
    let payload = b"alice@example.com sk_live_abcdefghijklmnopqrstuvwx";
    let out = redact_payload(payload, RedactClass::default()).expect("redact ok");
    assert_eq!(out.bytes, payload);
    assert!(out.manifest.matches.is_empty());
    assert_eq!(out.manifest.pass_id, PASS_ID);
}

#[test]
fn convenience_redact_helper_uses_default_full_classes() {
    let bytes = redact(b"alice@example.com").expect("ok");
    let s = String::from_utf8(bytes).expect("utf-8");
    assert!(s.contains("[REDACTED-EMAIL]"));
}

#[test]
fn manifest_offsets_resolve_back_to_match_bytes() {
    let payload = b"--alice@example.com--bob@example.org--";
    let out = redact_payload(payload, full()).expect("redact ok");
    assert!(out.manifest.matches.len() >= 2);
    for m in &out.manifest.matches {
        let start = m.offset as usize;
        let end = start + m.length as usize;
        let slice = &payload[start..end];
        // The slice must be a structurally email-shaped span.
        assert!(slice.contains(&b'@'), "match {m:?} doesn't contain @");
    }
}

#[test]
fn pass_id_is_stamped_on_every_pass() {
    let payload = b"hello world (no secrets here)";
    let out = redact_payload(payload, full()).expect("redact ok");
    assert_eq!(out.manifest.pass_id, PASS_ID);
    // payload is too plain to match anything; manifest is empty.
    assert!(out.manifest.matches.is_empty());
}
