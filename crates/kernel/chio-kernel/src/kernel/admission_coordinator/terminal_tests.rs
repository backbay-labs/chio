use super::*;
use crate::finding_denial::FINDING_DENIAL_METADATA_KEY;

fn actual(bytes: &[u8]) -> ReceiptContent {
    ReceiptContent {
        content_hash: sha256_hex(bytes),
        metadata: Some(serde_json::json!({"stream": {"chunk_hashes": [sha256_hex(bytes)]}})),
        canonical_content: bytes.to_vec(),
    }
}

#[test]
fn mismatch_receipt_commitment_is_deterministic_and_payload_independent() {
    let expected = sha256_hex(b"authorized-output");
    let first = receipt_visible_delivery_content(&actual(b"secret-a"), true, Some(&expected));
    let second = receipt_visible_delivery_content(&actual(b"secret-b"), true, Some(&expected));
    assert_eq!(first.content_hash, second.content_hash);
    assert!(first
        .canonical_content
        .starts_with(DELIVERY_MISMATCH_REDACTION_DOMAIN));
    assert_eq!(first.metadata, None);
    assert_ne!(first.content_hash, sha256_hex(b"secret-a"));
    assert_ne!(first.content_hash, sha256_hex(b"secret-b"));

    let old_fixed_sentinel = sha256_hex(br#"{"schema":"chio.delivery-mismatch.redacted.v1"}"#);
    let collision_attempt =
        receipt_visible_delivery_content(&actual(b"mismatch"), true, Some(&old_fixed_sentinel));
    assert_ne!(collision_attempt.content_hash, old_fixed_sentinel);
}

#[test]
fn digest_matched_receipt_keeps_actual_binding_even_for_other_denials() {
    let actual = actual(b"authorized-output");
    let visible = receipt_visible_delivery_content(&actual, false, Some(&actual.content_hash));
    assert_eq!(visible.content_hash, actual.content_hash);
    assert_eq!(visible.canonical_content, actual.canonical_content);
    assert_eq!(visible.metadata, actual.metadata);
}

#[test]
fn durable_terminal_status_denial_records_machine_family() {
    let metadata = Some(serde_json::json!({"runtimeAdmission": "durable"}));
    let denial = FindingDenial::status_denied("finding is retracted");

    let recorded = record_terminal_finding_denial(metadata, Some(&denial));

    assert_eq!(
        recorded,
        Some(serde_json::json!({
            "runtimeAdmission": "durable",
            FINDING_DENIAL_METADATA_KEY: "status_denied"
        }))
    );
}
