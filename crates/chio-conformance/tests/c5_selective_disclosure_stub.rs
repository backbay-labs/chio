//! What this test asserts:
//!
//! 1. **Round-trip honesty.** A receipt body projected with the
//!    §5.2 alphabetical-by-serde-field-name table and disclosed
//!    against `{capability_id, id, tool_name}` produces an audit view
//!    whose `verify_audit_view` accepts under the same body and
//!    surfaces those three fields verbatim. No other field is
//!    revealed by the view.
//! 2. **Pinned-receipt binding.** The view rejects when the verifier
//!    pins a tampered body whose canonical-JSON SHA-256 does not
//!    match `view.subject_receipt_sha256_hex`. This is the §9 step 2
//!    binding.
//! 3. **Disclosure-set integrity.** A producer that tries to alter a
//!    disclosed field's bytes (without changing the receipt body)
//!    fails verification at the `DisclosedMessageMismatch` gate.
//!    This is the property an honest auditor relies on: the
//!    disclosed values bind to the projection of the pinned body.
//! 4. **Schema/version discipline.** A view with an unknown schema
//!    or unknown projection version fails closed at the
//!    `SchemaMismatch` / `ProjectionVersionMismatch` gates.

#![cfg(feature = "bbs-stub")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use chio_federation::selective_disclosure::{
    project_audit_view, verify_audit_view, BbsAuditView, DisclosureSet, SelectiveDisclosureError,
    AUDIT_VIEW_SCHEMA_STUB, PROJECTION_VERSION_RECEIPT_V1,
};

fn fixture_body(kp: &Keypair) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-c5-fixture".to_string(),
        timestamp: 1_736_500_500,
        capability_id: "cap-c5".to_string(),
        tool_server: "srv-c5-tool".to_string(),
        tool_name: "file_read".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"path": "/data/c5.txt"}))
            .unwrap(),
        decision: Decision::Allow,
        content_hash: sha256_hex(b"{\"c5\":true}"),
        policy_hash: sha256_hex(b"c5-policy"),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: Some("tenant-c5".to_string()),
        kernel_key: kp.public_key(),
    }
}

#[test]
fn audit_view_reveals_only_disclosed_indices_and_round_trips() {
    let kp = Keypair::generate();
    let body = fixture_body(&kp);

    // Disclose: capability_id (1), id (5), tool_name (11). Mirrors the
    // §6.4 worked-example shape: producer reveals only the
    // skill/tool surface, not the timestamp / kernel key / decision.
    let disclosure = DisclosureSet(vec![1, 5, 11]);
    let view = project_audit_view(&body, &disclosure).expect("projection must succeed");

    assert_eq!(
        view.schema, AUDIT_VIEW_SCHEMA_STUB,
        "audit view must declare the .stub schema so verifiers can discriminate stub vs real BBS+"
    );
    assert_eq!(view.projection_version, PROJECTION_VERSION_RECEIPT_V1);
    assert_eq!(view.disclosed.len(), 3);

    let revealed_fields: Vec<&str> = view.disclosed.iter().map(|m| m.field.as_str()).collect();
    assert_eq!(
        revealed_fields,
        vec!["capability_id", "id", "tool_name"],
        "audit view must surface the disclosed indices in §5.2 alphabetical order"
    );

    // Verify under the pinned body.
    let disclosed_back = verify_audit_view(&view, &body).expect("verify must accept");
    assert_eq!(disclosed_back.fields.len(), 3);
    // The hex-encoded bytes for the disclosed fields decode to the
    // raw values the auditor expects.
    let cap_bytes = hex::decode(
        &disclosed_back
            .fields
            .iter()
            .find(|m| m.field == "capability_id")
            .unwrap()
            .bytes_hex,
    )
    .unwrap();
    assert_eq!(cap_bytes, b"cap-c5");
    let id_bytes = hex::decode(
        &disclosed_back
            .fields
            .iter()
            .find(|m| m.field == "id")
            .unwrap()
            .bytes_hex,
    )
    .unwrap();
    assert_eq!(id_bytes, b"rcpt-c5-fixture");
    let tool_bytes = hex::decode(
        &disclosed_back
            .fields
            .iter()
            .find(|m| m.field == "tool_name")
            .unwrap()
            .bytes_hex,
    )
    .unwrap();
    assert_eq!(tool_bytes, b"file_read");

    // The view must NOT carry the withheld fields.
    let withheld = ["timestamp", "tool_server", "kernel_key", "decision"];
    for w in withheld {
        assert!(
            !view.disclosed.iter().any(|m| m.field == w),
            "audit view leaks withheld field {w}"
        );
    }
}

#[test]
fn audit_view_rejects_when_pinned_receipt_is_tampered() {
    let kp = Keypair::generate();
    let body = fixture_body(&kp);
    let view = project_audit_view(&body, &DisclosureSet(vec![5])).expect("projection must succeed");

    let mut tampered = body.clone();
    tampered.id = "rcpt-c5-fixture-FORGED".to_string();
    let result = verify_audit_view(&view, &tampered);
    assert!(
        matches!(
            result,
            Err(SelectiveDisclosureError::SubjectReceiptMismatch)
        ),
        "tampered pinned receipt MUST fail at subject_receipt_sha256 gate"
    );
}

#[test]
fn audit_view_rejects_disclosed_field_substitution() {
    let kp = Keypair::generate();
    let body = fixture_body(&kp);
    let mut view =
        project_audit_view(&body, &DisclosureSet(vec![1, 11])).expect("projection must succeed");

    view.disclosed[0].bytes_hex = hex::encode("cap-FORGED".as_bytes());
    let result = verify_audit_view(&view, &body);
    assert!(
        matches!(
            result,
            Err(SelectiveDisclosureError::DisclosedMessageMismatch(_))
        ),
        "substituted disclosed field MUST fail at the projection-rebind gate"
    );
}

#[test]
fn audit_view_rejects_unknown_schema_or_projection_version() {
    let kp = Keypair::generate();
    let body = fixture_body(&kp);
    let view = project_audit_view(&body, &DisclosureSet(vec![5])).expect("projection must succeed");

    let mut bad_schema = view.clone();
    bad_schema.schema = "chio.federation-bbs-audit-view.v1.real".to_string();
    let res = verify_audit_view(&bad_schema, &body);
    assert!(matches!(
        res,
        Err(SelectiveDisclosureError::SchemaMismatch(_))
    ));

    let mut bad_version: BbsAuditView = view;
    bad_version.projection_version = "chio.bbs-projection.receipt.v2".to_string();
    let res = verify_audit_view(&bad_version, &body);
    assert!(matches!(
        res,
        Err(SelectiveDisclosureError::ProjectionVersionMismatch(_))
    ));
}

#[test]
fn audit_view_rejects_malformed_content_hash_hex() {
    // An Hx field that does not decode to a 32-byte SHA-256 must
    // fail closed at projection. Previously the code silently
    // re-hashed the raw string while still labelling the message
    // `Hx`, which lied about the encoding to the auditor.
    let kp = Keypair::generate();
    let mut body = fixture_body(&kp);
    body.content_hash = "not-a-real-hex-string".to_string();
    let result = project_audit_view(&body, &DisclosureSet(vec![2]));
    match result {
        Err(SelectiveDisclosureError::MalformedHexField { field, .. }) => {
            assert_eq!(field, "content_hash");
        }
        other => panic!("expected MalformedHexField for content_hash, got {other:?}"),
    }
}

#[test]
fn audit_view_rejects_short_policy_hash_hex() {
    // 16-byte hex (half the required SHA-256 length) must be rejected
    // with a typed MalformedHexField error.
    let kp = Keypair::generate();
    let mut body = fixture_body(&kp);
    body.policy_hash = "ab".repeat(16);
    let result = project_audit_view(&body, &DisclosureSet(vec![8]));
    match result {
        Err(SelectiveDisclosureError::MalformedHexField { field, reason }) => {
            assert_eq!(field, "policy_hash");
            assert!(reason.contains("16 bytes"), "unexpected reason: {reason}");
        }
        other => panic!("expected MalformedHexField for policy_hash, got {other:?}"),
    }
}

#[test]
fn audit_view_rejects_empty_content_hash() {
    // Empty Hx string must fail closed.
    let kp = Keypair::generate();
    let mut body = fixture_body(&kp);
    body.content_hash = String::new();
    let result = project_audit_view(&body, &DisclosureSet(vec![2]));
    match result {
        Err(SelectiveDisclosureError::MalformedHexField { field, .. }) => {
            assert_eq!(field, "content_hash");
        }
        other => panic!("expected MalformedHexField for empty content_hash, got {other:?}"),
    }
}

#[test]
fn audit_view_rejects_disclosed_encoding_substitution() {
    // A producer that re-tags a disclosed message's encoding (e.g.
    // utf-8 -> hex) MUST be rejected. Without binding the encoding
    // into the proof commitment, downstream decoders could be misled
    // into parsing UTF-8 bytes as a hex digest.
    let kp = Keypair::generate();
    let body = fixture_body(&kp);
    let mut view = project_audit_view(&body, &DisclosureSet(vec![1, 11]))
        .expect("projection must succeed");
    // capability_id is encoded as S (utf-8 bytes). Forge it to claim
    // hex encoding instead.
    let target = view
        .disclosed
        .iter_mut()
        .find(|m| m.field == "capability_id")
        .expect("capability_id must be in the disclosure set");
    assert_eq!(
        target.encoding, "S",
        "fixture invariant: capability_id is encoded as S in §5.2"
    );
    target.encoding = "hex".to_string();

    let result = verify_audit_view(&view, &body);
    match result {
        Err(SelectiveDisclosureError::DisclosedEncodingMismatch(_)) => {}
        Err(SelectiveDisclosureError::ProofBindingFailed) => {}
        other => panic!(
            "expected DisclosedEncodingMismatch or ProofBindingFailed, got {other:?}"
        ),
    }
}

#[test]
fn audit_view_round_trips_through_json_envelope() {
    // The audit view is `Serialize + Deserialize` so it can travel
    // over the federation wire. This test asserts the round-trip
    // preserves the binding: a view serialised to JSON bytes and
    // re-parsed verifies under the same pinned body.
    let kp = Keypair::generate();
    let body = fixture_body(&kp);
    let view = project_audit_view(&body, &DisclosureSet(vec![1, 5, 11, 13]))
        .expect("projection must succeed");
    let bytes = serde_json::to_vec(&view).unwrap();
    let parsed: BbsAuditView = serde_json::from_slice(&bytes).unwrap();
    let disclosed = verify_audit_view(&parsed, &body).expect("round-trip must verify");
    assert_eq!(disclosed.fields.len(), 4);
}
