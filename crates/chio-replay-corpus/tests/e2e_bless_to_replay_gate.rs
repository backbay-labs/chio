use std::collections::BTreeSet;
use std::fs;

use chio_replay_corpus::{
    validate_m04_scenario_dir, write_m04_fixture, CHECKPOINT_FILENAME, RECEIPTS_FILENAME,
    ROOT_FILENAME,
};
use chio_tee_frame::{Frame, FrameInputs, Otel, Provenance, Upstream, UpstreamSystem, Verdict};
use serde_json::{json, Value};

fn frame(
    event_id: &str,
    invocation: Value,
    verdict: Verdict,
    deny_reason: Option<&str>,
    would_have_blocked: bool,
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
                trace_id: "0".repeat(32),
                span_id: "1".repeat(16),
            },
            supply_chain: None,
        },
        request_blob_sha256: "a".repeat(64),
        response_blob_sha256: "b".repeat(64),
        redaction_pass_id: "m06-redactors@1.4.0+default".to_string(),
        verdict,
        deny_reason: deny_reason.map(str::to_string),
        would_have_blocked,
        tenant_sig: format!("ed25519:{}", "A".repeat(86)),
    })
}

#[test]
fn capture_redact_dedupe_bless_writes_m04_replay_gate_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::TempDir::new()?;
    let fixture_dir = tmp
        .path()
        .join("tests")
        .join("replay")
        .join("goldens")
        .join("openai_responses_shadow")
        .join("tool_call_with_pii");

    let first_duplicate = frame(
        "01H7ZZZZZZZZZZZZZZZZZZZZZA",
        json!({
            "args": {
                "email": "alice@example.com",
                "path": "/tmp/a"
            },
            "tool": "send_email"
        }),
        Verdict::Allow,
        None,
        false,
    )?;
    let distinct = frame(
        "01H7ZZZZZZZZZZZZZZZZZZZZZB",
        json!({
            "args": {
                "body": "case 123-45-6789",
                "path": "/tmp/b"
            },
            "tool": "write_file"
        }),
        Verdict::Allow,
        None,
        false,
    )?;
    let duplicate_last_wins = frame(
        "01H7ZZZZZZZZZZZZZZZZZZZZZC",
        json!({
            "tool": "send_email",
            "args": {
                "path": "/tmp/a",
                "email": "alice@example.com"
            }
        }),
        Verdict::Deny,
        Some("guard:pii.email_in_response"),
        true,
    )?;

    let summary = write_m04_fixture(
        &fixture_dir,
        vec![first_duplicate, distinct, duplicate_last_wins],
    )?;

    assert_eq!(summary.scenario.family, "openai_responses_shadow");
    assert_eq!(summary.scenario.name, "tool_call_with_pii");
    assert_eq!(summary.frames_in, 3);
    assert_eq!(summary.frames_after_dedupe, 2);
    assert_eq!(summary.receipt_count, 2);
    assert_eq!(summary.dir, fixture_dir);

    validate_m04_scenario_dir(&fixture_dir)?;
    let file_names = fs::read_dir(&fixture_dir)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<BTreeSet<_>, std::io::Error>>()?;
    assert_eq!(
        file_names,
        BTreeSet::from([
            CHECKPOINT_FILENAME.to_string(),
            RECEIPTS_FILENAME.to_string(),
            ROOT_FILENAME.to_string(),
        ])
    );

    let receipts = fs::read_to_string(fixture_dir.join(RECEIPTS_FILENAME))?;
    assert!(!receipts.contains("tenant_sig"));
    assert!(!receipts.contains("request_blob_sha256"));
    assert!(!receipts.contains("response_blob_sha256"));
    assert!(!receipts.contains("alice@example.com"));
    assert!(!receipts.contains("123-45-6789"));
    assert!(receipts.contains("[REDACTED-EMAIL]"));
    assert!(receipts.contains("[REDACTED-SSN]"));

    let receipt_lines = receipts.lines().collect::<Vec<_>>();
    assert_eq!(receipt_lines.len(), 2);
    let receipt_values = receipt_lines
        .iter()
        .map(|line| serde_json::from_str::<Value>(line))
        .collect::<Result<Vec<_>, serde_json::Error>>()?;
    assert!(receipt_values
        .iter()
        .any(|receipt| receipt["verdict"] == "deny"));
    assert!(receipt_values
        .iter()
        .all(|receipt| receipt.get("invocation").is_some()));

    let checkpoint: Value =
        serde_json::from_str(&fs::read_to_string(fixture_dir.join(CHECKPOINT_FILENAME))?)?;
    assert_eq!(checkpoint["schema"], "chio.replay.m04.bless-checkpoint/v1");
    assert_eq!(checkpoint["source_schema"], "chio-tee-frame.v1");
    assert_eq!(
        checkpoint["scenario"],
        "openai_responses_shadow/tool_call_with_pii"
    );
    assert_eq!(checkpoint["frames_in"], 3);
    assert_eq!(checkpoint["frames_after_dedupe"], 2);
    assert_eq!(
        checkpoint["redaction_pass_ids"],
        json!(["m06-redactors@1.4.0+default"])
    );

    let root = fs::read_to_string(fixture_dir.join(ROOT_FILENAME))?;
    assert_eq!(root, summary.root_hex);
    assert_eq!(root.len(), 64);
    assert!(root
        .chars()
        .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch)));

    Ok(())
}
