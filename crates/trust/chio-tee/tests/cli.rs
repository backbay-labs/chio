#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;
use std::process::{Command, Stdio};

use chio_core::canonical::canonical_json_string;
use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::message::AgentMessage;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
use chio_tee::{validate_signed, Frame, Observation, Verdict};

/// Deterministic tenant seed so the test can re-derive the public key and
/// verify the emitted `tenant_sig`.
const TENANT_SEED_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn tenant_keypair() -> Keypair {
    Keypair::from_seed_hex(TENANT_SEED_HEX).expect("seed decodes")
}

fn capability(kp: &Keypair, id: &str) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: format!("cap-{id}"),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: ChioScope::default(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, kp).expect("sign capability")
}

fn observation(
    kp: &Keypair,
    id: &str,
    params: serde_json::Value,
    decision: Decision,
) -> Observation {
    let request = AgentMessage::ToolCallRequest {
        id: id.to_string(),
        capability_token: Box::new(capability(kp, id)),
        server_id: "srv-1".to_string(),
        tool: "send_email".to_string(),
        params: Box::new(params.clone()),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
    };
    let canonical = canonical_json_string(&params).expect("canonical params");
    let parameter_hash = sha256_hex(canonical.as_bytes());
    let action = ToolCallAction {
        parameters: params,
        parameter_hash: parameter_hash.clone(),
    };
    let body = ChioReceiptBody {
        id: format!("rcpt-{id}"),
        timestamp: 1_745_603_731,
        capability_id: format!("cap-{id}"),
        tool_server: "srv-1".to_string(),
        tool_name: "send_email".to_string(),
        action,
        decision: Some(decision),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: parameter_hash,
        policy_hash: "0".repeat(64),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
        bbs_projection_version: None,
    };
    let receipt = ChioReceipt::sign(body, kp).expect("sign receipt");
    Observation { request, receipt }
}

#[test]
fn help_exits_successfully_and_is_image_smoke_safe() {
    let binary = env!("CARGO_BIN_EXE_chio-tee");
    let output = Command::new(binary)
        .arg("--help")
        .output()
        .expect("run chio-tee binary");

    assert!(output.status.success(), "--help must be image-smoke safe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage: chio-tee"),
        "stdout should include usage text: {stdout}"
    );
    assert!(
        !stdout.contains("not yet implemented") && !stdout.contains("skeleton"),
        "help text must not advertise a stub: {stdout}"
    );
}

#[test]
fn missing_command_fails_closed() {
    let binary = env!("CARGO_BIN_EXE_chio-tee");
    let output = Command::new(binary).output().expect("run chio-tee binary");
    assert!(
        !output.status.success(),
        "no command must fail closed (non-zero)"
    );
}

#[test]
fn run_without_runtime_dir_fails_closed() {
    let binary = env!("CARGO_BIN_EXE_chio-tee");
    let output = Command::new(binary)
        .arg("run")
        .env_remove("CHIO_TEE_RUNTIME_DIR")
        .env("CHIO_TEE_TENANT_KEY", "generate")
        .stdin(Stdio::null())
        .output()
        .expect("run chio-tee binary");
    assert!(
        !output.status.success(),
        "run without a runtime dir must fail closed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CHIO_TEE_RUNTIME_DIR"),
        "stderr should name the missing var: {stderr}"
    );
}

#[test]
fn run_captures_signed_redacted_frames_end_to_end() {
    let binary = env!("CARGO_BIN_EXE_chio-tee");
    let dir = tempfile::tempdir().expect("tempdir");
    let kp = tenant_keypair();

    // Two observations: one allow carrying an email (must be redacted), one
    // deny carrying a secret-shaped token. Shadow mode records divergence
    // without blocking.
    let allow = observation(
        &kp,
        "evt-allow",
        serde_json::json!({"to": "alice@example.com", "body": "ping"}),
        Decision::Allow,
    );
    let deny = observation(
        &kp,
        "evt-deny",
        serde_json::json!({"authorization": "Bearer sk-live-0123456789abcdefABCDEF0123"}),
        Decision::Deny {
            reason: "policy".to_string(),
            guard: "egress.block".to_string(),
        },
    );

    let mut stdin_body = String::new();
    stdin_body.push_str(&serde_json::to_string(&allow).unwrap());
    stdin_body.push('\n');
    stdin_body.push_str(&serde_json::to_string(&deny).unwrap());
    stdin_body.push('\n');

    let mut child = Command::new(binary)
        .arg("run")
        .env("CHIO_TEE_RUNTIME_DIR", dir.path())
        .env("CHIO_TEE_MODE", "shadow")
        .env("CHIO_TEE_TENANT_KEY", TENANT_SEED_HEX)
        .env("CHIO_TEE_TENANT_ID", "tenant-cli-test")
        .env("CHIO_TEE_ID", "tee-cli-test")
        .env("CHIO_TEE_RUN_ID", "run-cli")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio-tee run");

    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(stdin_body.as_bytes())
        .expect("write observations");

    let output = child.wait_with_output().expect("wait for chio-tee run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "shadow-mode run must succeed (never blocks): {stderr}"
    );
    assert!(
        stderr.contains("tee.mode_resolved mode=shadow"),
        "run should log the resolved mode: {stderr}"
    );

    // Read the capture file the runner wrote.
    let capture = dir.path().join("captures").join("run-cli.ndjson");
    let body = std::fs::read_to_string(&capture).expect("capture file exists");
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "two observations => two frames");

    // No plaintext secret material may appear anywhere in the capture stream.
    assert!(
        !body.contains("alice@example.com"),
        "email must be redacted out of the capture stream"
    );
    assert!(
        !body.contains("sk-live-0123456789abcdefABCDEF0123"),
        "secret token must be redacted out of the capture stream"
    );

    let pubkey = *kp.public_key().as_bytes();
    let mut verdicts = Vec::new();
    for line in &lines {
        let frame: Frame = serde_json::from_str(line).expect("well-formed frame line");
        // Each frame is structurally valid and verifies under the tenant key.
        validate_signed(&frame, &pubkey).expect("frame verifies under tenant pubkey");
        assert_eq!(frame.tee_id, "tee-cli-test");
        assert_eq!(frame.redaction_pass_id, chio_tee::DEFAULT_REDACTION_PASS_ID);
        verdicts.push((frame.verdict, frame.would_have_blocked));
    }

    // Shadow mode: allow => no block, deny => would_have_blocked true.
    assert!(verdicts.contains(&(Verdict::Allow, false)));
    assert!(verdicts.contains(&(Verdict::Deny, true)));
}

#[test]
fn run_capture_feeds_the_replay_bless_consumer_shape() {
    // The capture file produced by the runner must be consumable by the same
    // NDJSON frame iterator `chio replay --bless` uses: one serde-decodable
    // Frame per non-blank line, validating + verifying under the tenant key.
    // We assert that contract here without depending on the CLI crate.
    let binary = env!("CARGO_BIN_EXE_chio-tee");
    let dir = tempfile::tempdir().expect("tempdir");
    let kp = tenant_keypair();
    let obs = observation(
        &kp,
        "evt-bless",
        serde_json::json!({"q": "select 1"}),
        Decision::Allow,
    );

    let mut child = Command::new(binary)
        .arg("run")
        .env("CHIO_TEE_RUNTIME_DIR", dir.path())
        .env("CHIO_TEE_MODE", "verdict-only")
        .env("CHIO_TEE_TENANT_KEY", TENANT_SEED_HEX)
        .env("CHIO_TEE_RUN_ID", "run-bless")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn run");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{}\n", serde_json::to_string(&obs).unwrap()).as_bytes())
        .expect("write");
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());

    let capture = dir.path().join("captures").join("run-bless.ndjson");
    let body = std::fs::read_to_string(&capture).expect("capture exists");
    let pubkey = *kp.public_key().as_bytes();
    let mut count = 0u32;
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let frame: Frame = serde_json::from_str(line).expect("frame decodes");
        validate_signed(&frame, &pubkey).expect("frame validates + verifies");
        // verdict-only never sets would_have_blocked.
        assert!(!frame.would_have_blocked);
        count += 1;
    }
    assert_eq!(count, 1);
}
