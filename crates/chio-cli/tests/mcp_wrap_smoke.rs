// Trajectory-2 M07 P2.T2 smoke test for `arc mcp wrap`.
//
// We avoid spawning a real MCP child here so the smoke test remains
// hermetic on shared CI runners. Instead, we exercise the CLI surface:
//
// - `chio mcp wrap --emit-config zed -- echo` returns Zed config JSON
//   matching the pinned schema (full byte equality is in the dedicated
//   `mcp_emit_config` test).
// - `chio mcp wrap --help` lists the wrap-only flags so the dispatch
//   wiring is confirmed end-to-end.
//
// This test is intentionally lightweight; the actual stdio orchestration
// is covered by `mcp_wrap_e2e.rs` against the trajectory-1 mcp-adapter
// fixture corpus.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

fn chio_bin() -> std::path::PathBuf {
    let target = env!("CARGO_BIN_EXE_chio");
    std::path::PathBuf::from(target)
}

#[test]
fn mcp_wrap_help_lists_emit_config_flag() {
    let output = Command::new(chio_bin())
        .args(["mcp", "wrap", "--help"])
        .output()
        .expect("run chio mcp wrap --help");
    assert!(output.status.success(), "expected help to succeed");
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert!(
        stdout.contains("--emit-config"),
        "expected --emit-config flag to appear in help: {stdout}"
    );
    assert!(
        stdout.contains("--server-id"),
        "expected --server-id flag to appear in help: {stdout}"
    );
}

#[test]
fn mcp_wrap_emit_config_smoke_zed() {
    let output = Command::new(chio_bin())
        .args([
            "mcp",
            "wrap",
            "--server-id",
            "smoke",
            "--emit-config",
            "zed",
            "--",
            "echo",
        ])
        .output()
        .expect("run chio mcp wrap --emit-config zed");
    assert!(output.status.success(), "expected emit-config to succeed");
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("emit-config output is JSON");
    assert!(
        parsed.get("context_servers").is_some(),
        "Zed config should carry context_servers, got {parsed:?}"
    );
}

#[test]
fn mcp_wrap_missing_command_exits_with_error() {
    let output = Command::new(chio_bin())
        .args(["mcp", "wrap"])
        .output()
        .expect("run chio mcp wrap with no command");
    assert!(
        !output.status.success(),
        "expected mcp wrap with no command to fail"
    );
}
