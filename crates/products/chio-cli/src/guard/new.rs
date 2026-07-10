use std::fs;
use std::path::Path;

use crate::CliError;

use super::guard_io_error;

const CARGO_TOML_TEMPLATE: &str = r#"[package]
name = "{{PACKAGE_NAME}}"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
chio-guard-sdk = "0.1"
chio-guard-sdk-macros = "0.1"

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
"#;

const LIB_RS_TEMPLATE: &str = r#"use chio_guard_sdk::prelude::*;
use chio_guard_sdk_macros::chio_guard;

#[chio_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    // Replace this stub with real policy logic before shipping.
    //
    // Access request fields:
    //   req.tool_name      -- the tool being invoked
    //   req.action_type    -- pre-extracted action category
    //   req.extracted_path -- normalized file path (if applicable)
    //
    // Return GuardVerdict::allow() only after explicit checks pass.
    // Default scaffold denies until you implement the guard.
    let _ = &req;
    GuardVerdict::deny("unimplemented guard - deny by default")
}
"#;

pub(super) const MANIFEST_YAML_TEMPLATE: &str = r#"name: {{PACKAGE_NAME}}
version: "0.1.0"
abi_version: "1"
wasm_path: "target/wasm32-unknown-unknown/release/{{UNDERSCORED_NAME}}.wasm"
wasm_sha256: "TODO: run `chio guard build` and update this hash"
"#;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub(crate) fn cmd_guard_new(name: &str) -> Result<(), CliError> {
    let project_dir = Path::new(name);
    ensure_target_dir(project_dir)?;

    let dir_name = project_dir
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.trim().is_empty())
        .ok_or_else(|| {
            CliError::guard_error(format!(
                "could not derive a project name from `{}`",
                project_dir.display()
            ))
        })?;
    let package_name = sanitize_package_name(dir_name);
    let underscored_name = package_name.replace('-', "_");

    let cargo_toml = CARGO_TOML_TEMPLATE.replace("{{PACKAGE_NAME}}", &package_name);
    write_file(&project_dir.join("Cargo.toml"), &cargo_toml)?;

    let src_dir = project_dir.join("src");
    fs::create_dir_all(&src_dir)
        .map_err(|e| guard_io_error(format!("failed to create {}: {e}", src_dir.display())))?;
    write_file(&src_dir.join("lib.rs"), LIB_RS_TEMPLATE)?;

    // Write guard-manifest.yaml
    let manifest_yaml = MANIFEST_YAML_TEMPLATE
        .replace("{{PACKAGE_NAME}}", &package_name)
        .replace("{{UNDERSCORED_NAME}}", &underscored_name);
    write_file(&project_dir.join("guard-manifest.yaml"), &manifest_yaml)?;

    println!("created guard project at ./{name}");
    println!();
    println!("Next steps:");
    println!("  cd {name}");
    println!("  chio guard build");
    println!("  chio guard inspect target/wasm32-unknown-unknown/release/{underscored_name}.wasm");

    Ok(())
}

fn ensure_target_dir(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::guard_error(format!(
                "refusing to scaffold into non-directory `{}`",
                path.display()
            )));
        }
        let mut entries = path.read_dir().map_err(|e| {
            guard_io_error(format!(
                "failed to read directory `{}`: {e}",
                path.display()
            ))
        })?;
        if entries.next().is_some() {
            return Err(CliError::guard_error(format!(
                "refusing to scaffold into non-empty directory `{}`",
                path.display()
            )));
        }
        return Ok(());
    }

    fs::create_dir_all(path).map_err(|e| {
        guard_io_error(format!(
            "failed to create directory `{}`: {e}",
            path.display()
        ))
    })?;
    Ok(())
}

pub(super) fn sanitize_package_name(input: &str) -> String {
    let mut package = input
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' => ch,
            'A'..='Z' => ch.to_ascii_lowercase(),
            _ => '-',
        })
        .collect::<String>();

    while package.contains("--") {
        package = package.replace("--", "-");
    }
    package = package.trim_matches('-').to_string();

    if package.is_empty() {
        "chio-guard".to_string()
    } else {
        package
    }
}

fn write_file(path: &Path, content: &str) -> Result<(), CliError> {
    fs::write(path, content)
        .map_err(|e| guard_io_error(format!("failed to write {}: {e}", path.display())))
}
