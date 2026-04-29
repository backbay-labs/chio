use chio_replay_corpus::{dedupe_last_wins, invocation_hash};
use chio_tee_frame::{Frame, FrameInputs, Otel, Provenance, Upstream, UpstreamSystem, Verdict};
use serde_json::json;

fn frame(
    event_id: &str,
    invocation: serde_json::Value,
) -> Result<Frame, chio_tee_frame::FrameError> {
    Frame::build(FrameInputs {
        event_id: event_id.to_string(),
        ts: "2026-04-25T18:02:11.418Z".to_string(),
        tee_id: "tee-test-1".to_string(),
        upstream: Upstream {
            system: UpstreamSystem::Openai,
            operation: "responses.create".to_string(),
            api_version: "2025-10-01".to_string(),
        },
        invocation,
        provenance: Provenance {
            otel: Otel {
                trace_id: "0".repeat(32),
                span_id: "0".repeat(16),
            },
            supply_chain: None,
        },
        request_blob_sha256: "a".repeat(64),
        response_blob_sha256: "b".repeat(64),
        redaction_pass_id: "m06-redactors@1.4.0+default".to_string(),
        verdict: Verdict::Allow,
        deny_reason: None,
        would_have_blocked: false,
        tenant_sig: format!("ed25519:{}", "A".repeat(86)),
    })
}

#[test]
fn canonical_invocation_hash_uses_last_wins() -> Result<(), Box<dyn std::error::Error>> {
    let first = frame(
        "01H7ZZZZZZZZZZZZZZZZZZZZZA",
        json!({"tool":"read","args":{"path":"/tmp/a","limit":10}}),
    )?;
    let distinct = frame(
        "01H7ZZZZZZZZZZZZZZZZZZZZZB",
        json!({"tool":"write","args":{"path":"/tmp/b","body":"ok"}}),
    )?;
    let duplicate_last = frame(
        "01H7ZZZZZZZZZZZZZZZZZZZZZC",
        json!({"args":{"limit":10,"path":"/tmp/a"},"tool":"read"}),
    )?;

    let first_hash = invocation_hash(&first.invocation)?;
    let last_hash = invocation_hash(&duplicate_last.invocation)?;
    assert_eq!(first_hash, last_hash);

    let deduped = dedupe_last_wins(vec![first, distinct, duplicate_last])?;

    assert_eq!(deduped.len(), 2);
    assert_eq!(deduped[0].frame.event_id, "01H7ZZZZZZZZZZZZZZZZZZZZZB");
    assert_eq!(deduped[1].frame.event_id, "01H7ZZZZZZZZZZZZZZZZZZZZZC");
    assert_eq!(deduped[1].invocation_hash, first_hash);
    Ok(())
}
