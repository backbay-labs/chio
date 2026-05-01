// End-to-end test wrapping a real MCP fixture server, asserting the
// verdict gate and the attestation header round-trip.
//
// This test exercises the full `arc mcp wrap` stdio orchestration loop
// without a real wrapped child by feeding the binary the
// `echo_server_fixture.json` corpus through `--e2e-fixture`. The
// fixture mirrors the mcp-adapter test fixture surface:
//
// - A `tools/list` array carrying four tools (echo, read_file,
//   delete_record, fetch_url) with annotation-driven scope hints.
// - A `responses` map keyed by tool name (the echo and read_file rows
//   are populated; the destructive and network rows deliberately deny
//   under the `allow` set).
// - An `allow` set listing the tools the user has promoted in the
//   manifest scaffold.
//
// We then drive the binary with two `tools/call` JSON-RPC frames:
//
// - An allowed call (`echo`) MUST round-trip with the wrapped response
//   plus the "Chio-verified" attestation header injected at
//   `_meta.chio_verified`.
// - A denied call (`delete_record`) MUST surface a JSON-RPC error
//   carrying the `urn:chio:error:capability:scope-exceeded` reason code.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;
use std::process::{Command, Stdio};

fn chio_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

fn fixture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp/echo_server_fixture.json")
}

#[test]
fn e2e_wrap_round_trip_attestation_and_verdict_gate() {
    let mut child = Command::new(chio_bin())
        .args(["mcp", "wrap", "--server-id", "e2e", "--e2e-fixture"])
        .arg(fixture_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp wrap");

    {
        let mut stdin = child.stdin.take().expect("stdin");
        let frames = [
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "echo", "arguments": { "text": "hello" } }
            }),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": { "name": "delete_record", "arguments": { "id": "x" } }
            }),
        ];
        for frame in frames {
            writeln!(stdin, "{frame}").expect("write frame");
        }
    }

    let output = child.wait_with_output().expect("wait_with_output");
    assert!(
        output.status.success(),
        "wrap loop failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let frames: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("frame is JSON"))
        .collect();
    assert_eq!(
        frames.len(),
        3,
        "expected 3 framed responses, got {frames:?}"
    );

    // Frame 1: tools/list passes through and carries every fixture tool.
    let list_response = &frames[0];
    assert_eq!(list_response.get("id"), Some(&serde_json::json!(1)));
    let tools = list_response
        .pointer("/result/tools")
        .and_then(serde_json::Value::as_array)
        .expect("tools array on response");
    assert_eq!(tools.len(), 4, "expected 4 tools in list response");

    // Frame 2: allowed call -- result carries the attestation header.
    let allowed = &frames[1];
    assert_eq!(allowed.get("id"), Some(&serde_json::json!(2)));
    let header = allowed
        .pointer("/result/_meta/chio_verified")
        .expect("chio_verified header present on allowed call");
    assert_eq!(
        header.get("header").and_then(|v| v.as_str()),
        Some("Chio-verified")
    );
    assert_eq!(
        header.get("schema").and_then(|v| v.as_str()),
        Some("urn:chio:attest:tool-call/v1")
    );
    assert_eq!(header.get("tool").and_then(|v| v.as_str()), Some("echo"));

    // Frame 3: denied call -- error envelope carries the chio reason code.
    let denied = &frames[2];
    assert_eq!(denied.get("id"), Some(&serde_json::json!(3)));
    let chio_code = denied
        .pointer("/error/data/chio_code")
        .and_then(serde_json::Value::as_str)
        .expect("denied frame has urn:chio: code");
    assert_eq!(chio_code, "urn:chio:error:capability:scope-exceeded");
}
