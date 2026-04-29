use std::fs;

use chio_core::Keypair;
use chio_replay_corpus::{
    write_m04_fixture, write_tee_bless_audit_entry, BlessCapture, BlessFixture, BlessOperator,
    TeeBlessAuditBody, TeeBlessAuditEntry, TEE_BLESS_CAPABILITY, TEE_BLESS_EVENT,
};
use chio_tee_frame::{Frame, FrameInputs, Otel, Provenance, Upstream, UpstreamSystem, Verdict};
use serde_json::{json, Value};

fn frame(
    event_id: &str,
    invocation: Value,
    verdict: Verdict,
) -> Result<Frame, chio_tee_frame::FrameError> {
    Frame::build(FrameInputs {
        event_id: event_id.to_string(),
        ts: "2026-04-25T18:02:11.418Z".to_string(),
        tee_id: "tee-shadow-1".to_string(),
        upstream: Upstream {
            system: UpstreamSystem::Openai,
            operation: "responses.create".to_string(),
            api_version: "2025-10-01".to_string(),
        },
        invocation,
        provenance: Provenance {
            otel: Otel {
                trace_id: "2".repeat(32),
                span_id: "3".repeat(16),
            },
            supply_chain: None,
        },
        request_blob_sha256: "c".repeat(64),
        response_blob_sha256: "d".repeat(64),
        redaction_pass_id: "m06-redactors@1.4.0+default".to_string(),
        verdict,
        deny_reason: None,
        would_have_blocked: false,
        tenant_sig: format!("ed25519:{}", "B".repeat(86)),
    })
}

#[test]
fn tee_bless_audit_event_records_required_fields_and_verifies_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::TempDir::new()?;
    let fixture_dir = tmp
        .path()
        .join("tests")
        .join("replay")
        .join("fixtures")
        .join("openai_responses_shadow")
        .join("tool_call_with_pii");
    let capture_path = "captures/01JTEE00000000000000000000.ndjson";
    let frames = vec![
        frame(
            "01H7ZZZZZZZZZZZZZZZZZZZZZA",
            json!({"tool":"send_email","args":{"email":"alice@example.com"}}),
            Verdict::Allow,
        )?,
        frame(
            "01H7ZZZZZZZZZZZZZZZZZZZZZB",
            json!({"args":{"email":"alice@example.com"},"tool":"send_email"}),
            Verdict::Allow,
        )?,
    ];
    let summary = write_m04_fixture(&fixture_dir, frames)?;
    let fixture_path = "tests/replay/fixtures/openai_responses_shadow/tool_call_with_pii/";
    let operator = BlessOperator {
        id: "did:web:integrations.chio.dev:alice".to_string(),
        git_user: "alice@chio.dev".to_string(),
    };
    let capture = BlessCapture {
        path: capture_path.to_string(),
        frames_in: summary.frames_in,
        frames_after_dedupe: summary.frames_after_dedupe,
        frames_after_redact: summary.receipt_count,
    };
    let fixture = BlessFixture {
        family: summary.scenario.family.clone(),
        name: summary.scenario.name.clone(),
        path: fixture_path.to_string(),
        receipts_root: summary.root_hex.clone(),
    };
    let body = TeeBlessAuditBody::new(
        "2026-04-25T18:02:11.418Z",
        operator,
        capture,
        fixture,
        "m06-redactors@1.4.0+default",
    );
    let keypair = Keypair::from_seed(&[7u8; 32]);
    let entry = TeeBlessAuditEntry::sign(body, &keypair)?;

    assert!(entry.signature.starts_with("ed25519:"));
    assert!(entry.verify_signature(&keypair.public_key())?);

    let receipt_store = tmp.path().join("receipt-store").join("audit.ndjson");
    write_tee_bless_audit_entry(&receipt_store, &entry)?;

    let audit_log = fs::read_to_string(receipt_store)?;
    let lines = audit_log.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    let value: Value = serde_json::from_str(lines[0])?;

    assert_eq!(value["event"], TEE_BLESS_EVENT);
    assert_eq!(
        value["operator"]["id"],
        "did:web:integrations.chio.dev:alice"
    );
    assert_eq!(value["operator"]["git_user"], "alice@chio.dev");
    assert_eq!(value["capture"]["path"], capture_path);
    assert_eq!(value["capture"]["frames_in"], summary.frames_in);
    assert_eq!(
        value["capture"]["frames_after_dedupe"],
        summary.frames_after_dedupe
    );
    assert_eq!(
        value["capture"]["frames_after_redact"],
        summary.receipt_count
    );
    assert_eq!(value["fixture"]["family"], "openai_responses_shadow");
    assert_eq!(value["fixture"]["name"], "tool_call_with_pii");
    assert_eq!(value["fixture"]["path"], fixture_path);
    assert_eq!(value["fixture"]["receipts_root"], summary.root_hex);
    assert_eq!(value["redaction_pass_id"], "m06-redactors@1.4.0+default");
    assert_eq!(value["control_plane_capability"], TEE_BLESS_CAPABILITY);
    assert!(value["signature"]
        .as_str()
        .is_some_and(|signature| signature.starts_with("ed25519:")));

    let stored_entry: TeeBlessAuditEntry = serde_json::from_value(value)?;
    assert!(stored_entry.verify_signature(&keypair.public_key())?);

    Ok(())
}
