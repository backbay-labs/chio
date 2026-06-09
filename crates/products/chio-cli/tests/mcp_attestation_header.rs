// "Chio-verified" attestation header embedded in wrapped tool
// responses.
//
// `chio mcp wrap --self-test-attestation <tool>` is a deterministic
// renderer for the attestation block; it runs the same code path that
// the e2e wrap loop uses to decorate `tools/call` responses, so a byte
// match here means downstream IDE renderers see the same shape.
//
// The attestation block carries:
//
// - `header`: the literal "Chio-verified" string IDEs render in their
//   tool-call panel.
// - `schema`: the URN identifying the attestation schema version
//   (`urn:chio:attest:tool-call/v1`). Bumping this URN is a breaking
//   change.
// - `tool`: the tool name being attested.
// - `verifier`: the crate that owns the verifier surface
//   (`chio-attest-verify`). Consumers MUST re-run that verifier against
//   the receipt before trusting the header as authority.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

fn chio_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

#[test]
fn self_test_renders_chio_verified_block() {
    let output = Command::new(chio_bin())
        .args(["mcp", "wrap", "--self-test-attestation", "echo"])
        .output()
        .expect("run chio mcp wrap --self-test-attestation");
    assert!(
        output.status.success(),
        "self-test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("self-test emits JSON");

    let header = value.get("header").expect("header block present");
    assert_eq!(
        header.get("header").and_then(|v| v.as_str()),
        Some("Chio-verified")
    );
    assert_eq!(
        header.get("schema").and_then(|v| v.as_str()),
        Some("urn:chio:attest:tool-call/v1")
    );
    assert_eq!(header.get("tool").and_then(|v| v.as_str()), Some("echo"));
    assert_eq!(
        header.get("verifier").and_then(|v| v.as_str()),
        Some("chio-attest-verify")
    );

    // The wrapped response carries the same block under `_meta`.
    let wrapped = value
        .get("wrapped_response")
        .expect("wrapped response block");
    let chio_verified = wrapped
        .pointer("/_meta/chio_verified")
        .expect("wrapped response carries _meta.chio_verified");
    assert_eq!(chio_verified, header);
}

#[test]
fn self_test_handles_arbitrary_tool_names() {
    // Header is purely additive -- any tool name that is valid JSON
    // string round-trips intact.
    for tool in ["read_file", "fs.write", "tool/with/slash", "emoji-ok"] {
        let output = Command::new(chio_bin())
            .args(["mcp", "wrap", "--self-test-attestation", tool])
            .output()
            .expect("run chio mcp wrap --self-test-attestation");
        assert!(
            output.status.success(),
            "self-test failed for {tool}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("emits JSON");
        assert_eq!(
            value.pointer("/header/tool").and_then(|v| v.as_str()),
            Some(tool),
            "tool name round-trips for {tool}"
        );
    }
}
