// IDE config generators for Cursor / Claude Desktop / Continue / Zed.
//
// For each target we run `chio mcp wrap --emit-config <ide> -- ...`
// against a fixed display name and wrapped command, parse the rendered
// JSON, and assert byte equality (modulo serde key ordering) against
// the pinned `tests/fixtures/ide/<target>.expected.json` corpus.
//
// Each fixture pins a specific IDE schema version (see
// `cli/mcp/ide.rs`).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

fn chio_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ide")
        .join(name)
}

fn run_emit(ide: &str) -> serde_json::Value {
    let output = Command::new(chio_bin())
        .args([
            "mcp",
            "wrap",
            "--server-id",
            "demo",
            "--display-name",
            "Demo MCP",
            "--emit-config",
            ide,
            "--",
            "node",
            "server.js",
        ])
        .output()
        .expect("run chio mcp wrap --emit-config");
    assert!(
        output.status.success(),
        "emit-config {ide} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("emit-config produces JSON")
}

fn expected(name: &str) -> serde_json::Value {
    let raw = std::fs::read(fixture(name)).expect("fixture exists");
    serde_json::from_slice(&raw).expect("fixture is JSON")
}

#[test]
fn emit_config_cursor_matches_fixture() {
    assert_eq!(run_emit("cursor"), expected("cursor.expected.json"));
}

#[test]
fn emit_config_claude_desktop_matches_fixture() {
    assert_eq!(
        run_emit("claude-desktop"),
        expected("claude_desktop.expected.json")
    );
}

#[test]
fn emit_config_continue_matches_fixture() {
    assert_eq!(run_emit("continue"), expected("continue.expected.json"));
}

#[test]
fn emit_config_zed_matches_fixture() {
    assert_eq!(run_emit("zed"), expected("zed.expected.json"));
}

#[test]
fn schema_versions_pinned() {
    // Defense-in-depth: lift the schema strings out of every fixture so
    // an accidental schema bump is caught by the test even if the
    // surrounding shape rotates.
    let cases: [(&str, &str, &str); 4] = [
        (
            "cursor.expected.json",
            "/mcpServers/demo/metadata/chioSchema",
            "cursor.mcp/2024-12",
        ),
        (
            "claude_desktop.expected.json",
            "/mcpServers/demo/chio_schema",
            "anthropic.mcp/2024-12",
        ),
        (
            "continue.expected.json",
            "/mcpServers/0/chio/schema",
            "continue.mcpServers/2025-01",
        ),
        (
            "zed.expected.json",
            "/context_servers/demo/settings/chio_schema",
            "zed.context_servers/2025-02",
        ),
    ];
    for (file, ptr, want) in cases {
        let value = expected(file);
        let got = value
            .pointer(ptr)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("fixture {file} missing pointer {ptr}"));
        assert_eq!(got, want, "schema version drift in {file}");
    }
}
