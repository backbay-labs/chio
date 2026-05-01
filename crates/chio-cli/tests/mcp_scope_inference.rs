// Per-tool capability scope inference and the default-deny manifest
// scaffold.
//
// We feed `chio mcp wrap --print-scopes --tools-fixture <path>` a static
// JSON `tools/list` corpus and assert the rendered scaffold:
//
// - Lists every tool from the fixture (4 tools).
// - Classifies them into the four expected scope buckets (read,
//   filesystem, network, destructive). The fixture deliberately covers
//   one tool per bucket plus one annotation-driven case so the test
//   exercises the annotation precedence rule.
// - Ships every capability with `allow = false` (default-deny floor).
// - Carries the `# TODO: review and promote` marker per capability so
//   the user knows the scaffold is unscoped.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

fn chio_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

fn fixture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mcp/echo_server_fixture.json")
}

#[test]
fn print_scopes_renders_default_deny_scaffold() {
    let output = Command::new(chio_bin())
        .args([
            "mcp",
            "wrap",
            "--server-id",
            "fs-test",
            "--print-scopes",
            "--tools-fixture",
        ])
        .arg(fixture_path())
        .output()
        .expect("run chio mcp wrap --print-scopes");

    assert!(
        output.status.success(),
        "print-scopes exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf-8");

    // Header markers.
    assert!(stdout.contains("server_id = \"fs-test\""));
    assert!(stdout.contains("# Default is deny."));

    // Every tool from the fixture appears.
    for tool in ["echo", "read_file", "delete_record", "fetch_url"] {
        let needle = format!("tool = \"{tool}\"");
        assert!(
            stdout.contains(&needle),
            "expected scaffold to mention tool '{tool}', got:\n{stdout}"
        );
    }

    // Annotation-driven classifications.
    let read_section = section_for_tool(&stdout, "read_file");
    assert!(
        read_section.contains("scope = \"read\""),
        "read_file should classify as read (annotation): {read_section}"
    );
    let destructive_section = section_for_tool(&stdout, "delete_record");
    assert!(
        destructive_section.contains("scope = \"destructive\""),
        "delete_record should classify as destructive (annotation): {destructive_section}"
    );

    // Schema-driven classification (network).
    let fetch_section = section_for_tool(&stdout, "fetch_url");
    assert!(
        fetch_section.contains("scope = \"network\""),
        "fetch_url should classify as network: {fetch_section}"
    );

    // Default-deny floor.
    let allow_count = stdout.matches("allow = false").count();
    assert_eq!(
        allow_count, 4,
        "all four tools should ship default-deny: {stdout}"
    );

    // TODO marker per capability.
    let todo_count = stdout.matches("# TODO: review and promote").count();
    assert_eq!(todo_count, 4, "expected one TODO per capability: {stdout}");
}

fn section_for_tool<'a>(scaffold: &'a str, tool: &str) -> &'a str {
    let needle = format!("tool = \"{tool}\"");
    let start = scaffold.find(&needle).unwrap_or(0);
    let tail = &scaffold[start..];
    let end = tail.find("[[capability]]").unwrap_or(tail.len());
    &tail[..end]
}
