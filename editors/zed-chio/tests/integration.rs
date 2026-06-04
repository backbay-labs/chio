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

use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

use zed_chio::{
    default_lsp_command, lsp_command_with_overrides, CHIO_LANGUAGE_ID, CHIO_LSP_BINARY,
    SETTINGS_ARGS_KEY, SETTINGS_PATH_KEY,
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
    let parsed: TomlValue = toml::from_str(&raw).expect("extension.toml parses");
    let id = parsed
        .get("id")
        .and_then(TomlValue::as_str)
        .expect("extension.toml carries id");
    assert_eq!(id, "chio");
    let lang_servers = parsed
        .get("language_servers")
        .and_then(TomlValue::as_table)
        .expect("extension.toml declares language_servers");
    assert!(
        lang_servers.contains_key("chio-lsp"),
        "extension.toml must declare the chio-lsp language server"
    );
}

#[test]
fn language_config_targets_chio_file_suffixes() {
    let raw = read("languages/chio/config.toml");
    let parsed: TomlValue = toml::from_str(&raw).expect("language config parses");
    assert_eq!(
        parsed.get("name").and_then(TomlValue::as_str),
        Some(CHIO_LANGUAGE_ID)
    );
    let suffixes = parsed
        .get("path_suffixes")
        .and_then(TomlValue::as_array)
        .expect("language config carries path_suffixes");
    let suffixes: Vec<&str> = suffixes.iter().filter_map(TomlValue::as_str).collect();
    for expected in ["chio.yaml", "chio-manifest.yaml", "chio-guard.yaml"] {
        assert!(
            suffixes.contains(&expected),
            "language config missing suffix {expected}"
        );
    }
}

#[test]
fn snippets_are_scoped_to_zed_chio_language_file() {
    assert!(
        !extension_dir().join("snippets/snippets.json").exists(),
        "snippets/snippets.json is global in Zed; Chio snippets must live in snippets/chio.json"
    );

    let raw = read("snippets/chio.json");
    let body_start = raw.find('{').expect("snippet file contains JSON object");
    let parsed: JsonValue =
        serde_json::from_str(&raw[body_start..]).expect("Chio snippets parse as JSON");
    let snippets = parsed
        .as_object()
        .expect("Chio snippets file is keyed by snippet id");
    assert!(
        snippets.contains_key("chio.manifest_skeleton"),
        "Chio snippets must include the manifest skeleton"
    );
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

#[test]
fn override_path_and_args_are_honored() {
    // The wasm extension threads `LspSettings::for_worktree` through
    // `lsp_command_with_overrides`. Pin the override contract here so
    // the host-side gate catches drift if the helper stops applying
    // user-supplied `lsp.<server>.binary.{path,arguments}` values.
    let (cmd, args) = lsp_command_with_overrides(
        Some("/opt/chio/bin/chio-lsp"),
        Some(vec!["--verbose".into()]),
    );
    assert_eq!(cmd, "/opt/chio/bin/chio-lsp");
    assert_eq!(args, vec!["--verbose".to_string()]);
}

#[test]
fn empty_override_path_falls_back_to_default_binary() {
    let (cmd, args) = lsp_command_with_overrides(Some("   "), None);
    assert_eq!(cmd, CHIO_LSP_BINARY);
    assert!(args.is_empty());
}

#[test]
fn missing_overrides_match_default_command() {
    let (cmd, args) = lsp_command_with_overrides(None, None);
    let (def_cmd, def_args) = default_lsp_command();
    assert_eq!(cmd, def_cmd);
    assert_eq!(args, def_args);
}
