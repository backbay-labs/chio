//! Host-side integration tests for the Zed extension.
//!
//! The full extension only loads inside the Zed editor (the actual
//! `zed::Extension` impl is gated on `wasm32`). These tests pin the
//! manifest and LSP-binary contract so the workspace gate
//! (`cargo test -p zed-chio --test integration`) catches drift between
//! `extension.toml`, the language config, and the `chio-lsp` invocation
//! the wasm side ships.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use toml::Value;

use zed_chio::{
    default_lsp_command, CHIO_LANGUAGE_ID, CHIO_LSP_BINARY, SETTINGS_ARGS_KEY, SETTINGS_PATH_KEY,
};

fn extension_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(file: &str) -> String {
    let path = extension_dir().join(file);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {} failed: {err}", path.display()))
}

#[test]
fn extension_manifest_advertises_chio_language_server() {
    let raw = read("extension.toml");
    let parsed: Value = toml::from_str(&raw).expect("extension.toml parses");
    let id = parsed
        .get("id")
        .and_then(Value::as_str)
        .expect("extension.toml carries id");
    assert_eq!(id, "chio");
    let lang_servers = parsed
        .get("language_servers")
        .and_then(Value::as_table)
        .expect("extension.toml declares language_servers");
    assert!(
        lang_servers.contains_key("chio-lsp"),
        "extension.toml must declare the chio-lsp language server"
    );
}

#[test]
fn language_config_targets_chio_file_suffixes() {
    let raw = read("languages/chio/config.toml");
    let parsed: Value = toml::from_str(&raw).expect("language config parses");
    assert_eq!(
        parsed.get("name").and_then(Value::as_str),
        Some(CHIO_LANGUAGE_ID)
    );
    let suffixes = parsed
        .get("path_suffixes")
        .and_then(Value::as_array)
        .expect("language config carries path_suffixes");
    let suffixes: Vec<&str> = suffixes.iter().filter_map(Value::as_str).collect();
    for expected in ["chio.yaml", "chio-manifest.yaml", "chio-guard.yaml"] {
        assert!(
            suffixes.contains(&expected),
            "language config missing suffix {expected}"
        );
    }
}

#[test]
fn highlights_pin_urn_chio_error_codes() {
    let raw = read("languages/chio/highlights.scm");
    assert!(
        raw.contains("urn:chio:error:"),
        "highlights.scm must scope urn:chio:error:* codes for editor display"
    );
}

#[test]
fn default_command_uses_chio_lsp_binary() {
    let (cmd, args) = default_lsp_command();
    assert_eq!(cmd, CHIO_LSP_BINARY);
    assert!(args.is_empty(), "default invocation forwards no extra args");
}

#[test]
fn settings_keys_match_vscode_extension() {
    // Both editor extensions document the same configuration surface
    // so editors/README.md can describe one set of LSP knobs. The
    // VSCode extension exposes `chio.lsp.path` and `chio.lsp.args`; the
    // Zed side reads the matching subkeys under `chio` settings.
    assert_eq!(SETTINGS_PATH_KEY, "lsp.path");
    assert_eq!(SETTINGS_ARGS_KEY, "lsp.args");
}
