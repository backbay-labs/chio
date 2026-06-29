use std::fs;

use crate::support::{display_path, workspace_root, TempDir};
use crate::XtaskError;

use super::CHIO_WIRE_V1_SCHEMAS;

/// Relative path (from workspace root) of the generated Rust output dir.
const CHIO_WIRE_V1_RUST_OUT: &str = "crates/core/chio-core-types/src/_generated";

pub(crate) fn errors_regen(args: Vec<String>) -> Result<(), XtaskError> {
    let mut check_only = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check_only = true,
            other => {
                return Err(XtaskError::Usage(format!(
                    "errors regen: unknown flag: {other}"
                )));
            }
        }
    }

    let workspace_root = workspace_root()?;
    let registry = workspace_root.join(chio_spec_codegen::ERROR_REGISTRY_INPUT);
    let out_dir = workspace_root.join(chio_spec_codegen::ERRORS_GENERATED_DIR);

    if check_only {
        let staging = TempDir::new("chio-errors-codegen-check").map_err(|err| {
            XtaskError::Io("<temp staging dir for errors regen --check>".into(), err)
        })?;
        chio_spec_codegen::codegen_error_codes(&registry, staging.path())
            .map_err(XtaskError::Codegen)?;

        let mut differences: Vec<String> = Vec::new();
        let mut total_bytes: u64 = 0;
        for filename in [
            chio_spec_codegen::ERROR_CODES_OUTPUT,
            chio_spec_codegen::MOD_FILE,
        ] {
            let staged = staging.path().join(filename);
            let on_disk = out_dir.join(filename);
            let staged_bytes =
                fs::read(&staged).map_err(|err| XtaskError::Io(display_path(&staged), err))?;
            if !on_disk.exists() {
                differences.push(format!(
                    "{} is missing on disk (computed {} bytes)",
                    display_path(&on_disk),
                    staged_bytes.len()
                ));
                continue;
            }
            let on_disk_bytes =
                fs::read(&on_disk).map_err(|err| XtaskError::Io(display_path(&on_disk), err))?;
            total_bytes += on_disk_bytes.len() as u64;
            if staged_bytes != on_disk_bytes {
                differences.push(format!(
                    "{} is stale (computed {} bytes, on-disk {} bytes)",
                    display_path(&on_disk),
                    staged_bytes.len(),
                    on_disk_bytes.len()
                ));
            }
        }
        if !differences.is_empty() {
            return Err(XtaskError::Drift(format!(
                "rerun `cargo xtask errors regen`:\n  - {}",
                differences.join("\n  - ")
            )));
        }
        println!(
            "errors regen: {} and {} in sync ({} bytes total)",
            display_path(&out_dir.join(chio_spec_codegen::ERROR_CODES_OUTPUT)),
            display_path(&out_dir.join(chio_spec_codegen::MOD_FILE)),
            total_bytes
        );
        return Ok(());
    }

    chio_spec_codegen::codegen_error_codes(&registry, &out_dir).map_err(XtaskError::Codegen)?;
    let out_path = out_dir.join(chio_spec_codegen::ERROR_CODES_OUTPUT);
    let mod_path = out_dir.join(chio_spec_codegen::MOD_FILE);
    let bytes = fs::metadata(&out_path).map(|m| m.len()).unwrap_or_default();
    println!(
        "errors regen: wrote {} ({} bytes) and refreshed {}",
        display_path(&out_path),
        bytes,
        display_path(&mod_path)
    );
    Ok(())
}

pub(super) fn codegen_rust(check_only: bool) -> Result<(), XtaskError> {
    let workspace_root = workspace_root()?;
    let schemas_dir = workspace_root.join(CHIO_WIRE_V1_SCHEMAS);
    let out_dir = workspace_root.join(CHIO_WIRE_V1_RUST_OUT);

    if check_only {
        // Render BOTH the consolidated chio_wire_v1.rs and the generated
        // mod.rs into a temporary staging directory and compare every file
        // byte-for-byte with the on-disk copy, so a stale or missing mod.rs
        // cannot slip past the spec-drift CI lane.
        let staging = TempDir::new("chio-codegen-rust-check").map_err(|err| {
            XtaskError::Io("<temp staging dir for codegen rust --check>".into(), err)
        })?;
        chio_spec_codegen::codegen_rust(&schemas_dir, staging.path())
            .map_err(XtaskError::Codegen)?;

        let mut differences: Vec<String> = Vec::new();
        let mut total_bytes: u64 = 0;
        for filename in [
            chio_spec_codegen::CHIO_WIRE_V1_OUTPUT,
            chio_spec_codegen::MOD_FILE,
        ] {
            let staged = staging.path().join(filename);
            let on_disk = out_dir.join(filename);
            let staged_bytes =
                fs::read(&staged).map_err(|err| XtaskError::Io(display_path(&staged), err))?;
            if !on_disk.exists() {
                differences.push(format!(
                    "{} is missing on disk (computed {} bytes)",
                    display_path(&on_disk),
                    staged_bytes.len()
                ));
                continue;
            }
            let on_disk_bytes =
                fs::read(&on_disk).map_err(|err| XtaskError::Io(display_path(&on_disk), err))?;
            total_bytes += on_disk_bytes.len() as u64;
            if staged_bytes != on_disk_bytes {
                differences.push(format!(
                    "{} is stale (computed {} bytes, on-disk {} bytes)",
                    display_path(&on_disk),
                    staged_bytes.len(),
                    on_disk_bytes.len()
                ));
            }
        }
        if !differences.is_empty() {
            return Err(XtaskError::Drift(format!(
                "rerun `cargo xtask codegen rust`:\n  - {}",
                differences.join("\n  - ")
            )));
        }
        println!(
            "codegen rust: {} and {} in sync ({} bytes total)",
            display_path(&out_dir.join(chio_spec_codegen::CHIO_WIRE_V1_OUTPUT)),
            display_path(&out_dir.join(chio_spec_codegen::MOD_FILE)),
            total_bytes
        );
        return Ok(());
    }

    chio_spec_codegen::codegen_rust(&schemas_dir, &out_dir).map_err(XtaskError::Codegen)?;
    let out_path = out_dir.join(chio_spec_codegen::CHIO_WIRE_V1_OUTPUT);
    let mod_path = out_dir.join(chio_spec_codegen::MOD_FILE);
    let bytes = fs::metadata(&out_path).map(|m| m.len()).unwrap_or_default();
    println!(
        "codegen rust: wrote {} ({} bytes) and refreshed {}",
        display_path(&out_path),
        bytes,
        display_path(&mod_path)
    );
    Ok(())
}
