use std::fs;
use std::path::Path;
use std::process::Command;

use chio_wasm_guards::manifest::GuardManifest;
use flate2::Compression;
use flate2::write::GzEncoder;

use crate::CliError;

use super::formatting::format_size;
use super::{guard_io_error, guard_yaml_error};

pub(crate) fn cmd_guard_build() -> Result<(), CliError> {
    // Verify Cargo.toml exists and contains cdylib crate-type
    let cargo_toml_contents = fs::read_to_string("Cargo.toml").map_err(|e| {
        guard_io_error(format!(
            "could not read Cargo.toml in current directory: {e}"
        ))
    })?;
    if !cargo_toml_contents.contains("cdylib") {
        return Err(CliError::guard_error(
            "current directory does not appear to be a guard project (no cdylib crate-type in Cargo.toml)"
                .to_string(),
        ));
    }

    // Extract the package name from Cargo.toml
    let package_name = cargo_toml_contents
        .lines()
        .find(|line| line.starts_with("name = "))
        .and_then(|line| {
            let trimmed = line.trim_start_matches("name = ").trim();
            let unquoted = trimmed.trim_matches('"');
            if unquoted.is_empty() {
                None
            } else {
                Some(unquoted.to_string())
            }
        })
        .ok_or_else(|| {
            CliError::guard_error("could not extract package name from Cargo.toml".to_string())
        })?;
    let underscored_name = package_name.replace('-', "_");

    // Run cargo build
    let status = Command::new("cargo")
        .args(["build", "--target", "wasm32-unknown-unknown", "--release"])
        .status()
        .map_err(|e| guard_io_error(format!("failed to run cargo: {e}")))?;

    if !status.success() {
        return Err(CliError::guard_error("cargo build failed".to_string()));
    }

    // Verify the output .wasm file exists
    let wasm_path = format!("target/wasm32-unknown-unknown/release/{underscored_name}.wasm");
    let metadata = fs::metadata(&wasm_path)
        .map_err(|e| guard_io_error(format!("expected output not found at {wasm_path}: {e}")))?;

    let size = metadata.len();
    let formatted_size = format_size(size);

    println!("build complete: {wasm_path}");
    println!("binary size: {formatted_size}");

    Ok(())
}

pub(crate) fn cmd_guard_pack() -> Result<(), CliError> {
    pack_from_dir(Path::new("."))
}

pub(super) fn pack_from_dir(project_dir: &Path) -> Result<(), CliError> {
    let manifest_path = project_dir.join("guard-manifest.yaml");
    let manifest_content = fs::read_to_string(&manifest_path)
        .map_err(|e| guard_io_error(format!("failed to read {}: {e}", manifest_path.display())))?;
    let manifest: GuardManifest = serde_yml::from_str(&manifest_content)
        .map_err(|e| guard_yaml_error(format!("failed to parse guard-manifest.yaml: {e}")))?;

    // Resolve the wasm file relative to the project directory
    let wasm_rel_path = Path::new(&manifest.wasm_path);
    let wasm_abs_path = project_dir.join(wasm_rel_path);
    let wasm_bytes = fs::read(&wasm_abs_path).map_err(|e| {
        guard_io_error(format!(
            "failed to read wasm file {}: {e}",
            wasm_abs_path.display()
        ))
    })?;

    // Derive the wasm filename (strip any directory components)
    let wasm_filename = wasm_rel_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            CliError::guard_error(format!(
                "could not derive filename from wasm_path '{}'",
                manifest.wasm_path
            ))
        })?;

    let archive_name = format!("{}-{}.arcguard", manifest.name, manifest.version);
    let archive_path = project_dir.join(&archive_name);

    let file = fs::File::create(&archive_path)
        .map_err(|e| guard_io_error(format!("failed to create {}: {e}", archive_path.display())))?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar_builder = tar::Builder::new(enc);

    // Add guard-manifest.yaml (read from disk, store as "guard-manifest.yaml")
    let manifest_bytes = manifest_content.as_bytes();
    let mut manifest_header = tar::Header::new_gnu();
    manifest_header.set_size(manifest_bytes.len() as u64);
    manifest_header.set_mode(0o644);
    manifest_header.set_cksum();
    tar_builder
        .append_data(&mut manifest_header, "guard-manifest.yaml", manifest_bytes)
        .map_err(|e| guard_io_error(format!("failed to add manifest to archive: {e}")))?;

    // Add the .wasm file (store as filename only, not full relative path)
    let mut wasm_header = tar::Header::new_gnu();
    wasm_header.set_size(wasm_bytes.len() as u64);
    wasm_header.set_mode(0o644);
    wasm_header.set_cksum();
    tar_builder
        .append_data(&mut wasm_header, wasm_filename, wasm_bytes.as_slice())
        .map_err(|e| guard_io_error(format!("failed to add wasm to archive: {e}")))?;

    let enc = tar_builder
        .into_inner()
        .map_err(|e| guard_io_error(format!("failed to finalize tar archive: {e}")))?;
    enc.finish()
        .map_err(|e| guard_io_error(format!("failed to finish gzip: {e}")))?;

    let archive_size = fs::metadata(&archive_path).map(|m| m.len()).unwrap_or(0);
    println!("packed: {archive_name} ({})", format_size(archive_size));

    Ok(())
}

const GUARD_INSTALL_ARCHIVE_LIMITS: crate::archive::SafeArchiveLimits =
    crate::archive::SafeArchiveLimits {
        max_compressed_bytes: 64 * 1024 * 1024,
        max_member_bytes: 32 * 1024 * 1024,
        max_total_bytes: 64 * 1024 * 1024,
        max_member_count: 32,
        max_decompression_ratio: 200,
    };

pub(crate) fn cmd_guard_install(archive_path: &Path, target_dir: &Path) -> Result<(), CliError> {
    // Extract to a temporary directory first, then determine guard name from
    // manifest. The temp dir name carries a unique suffix derived from the
    // archive filename.
    let archive_stem = archive_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("chio-install");
    let tmp_path = std::env::temp_dir().join(format!(
        "chio-install-{}-{}",
        archive_stem,
        std::process::id()
    ));
    if tmp_path.exists() {
        fs::remove_dir_all(&tmp_path).map_err(|e| {
            guard_io_error(format!(
                "failed to clean existing temp directory {}: {e}",
                tmp_path.display()
            ))
        })?;
    }
    fs::create_dir_all(&tmp_path).map_err(|e| {
        guard_io_error(format!(
            "failed to create temp directory {}: {e}",
            tmp_path.display()
        ))
    })?;

    let entries = crate::archive::read_tar_gz_file(
        archive_path,
        "Chio guard archive",
        GUARD_INSTALL_ARCHIVE_LIMITS,
    )?;
    crate::archive::write_entries_to_existing_dir(&tmp_path, "Chio guard archive", &entries)?;

    // Read the manifest from the temp directory to determine the guard name
    let tmp_manifest_path = tmp_path.join("guard-manifest.yaml");
    let manifest_content = fs::read_to_string(&tmp_manifest_path).map_err(|e| {
        guard_io_error(format!("archive does not contain guard-manifest.yaml: {e}"))
    })?;
    let manifest: GuardManifest = serde_yml::from_str(&manifest_content)
        .map_err(|e| guard_yaml_error(format!("failed to parse manifest from archive: {e}")))?;

    let guard_name = &manifest.name;
    let guard_dir = target_dir.join(guard_name);
    fs::create_dir_all(&guard_dir).map_err(|e| {
        guard_io_error(format!(
            "failed to create directory {}: {e}",
            guard_dir.display()
        ))
    })?;

    // Find the .wasm file in the temp directory (the non-manifest entry)
    let wasm_filename = {
        let mut found: Option<String> = None;
        for entry in fs::read_dir(&tmp_path)
            .map_err(|e| guard_io_error(format!("failed to list temp directory: {e}")))?
        {
            let entry = entry
                .map_err(|e| guard_io_error(format!("failed to read directory entry: {e}")))?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str != "guard-manifest.yaml" {
                found = Some(name_str.into_owned());
            }
        }
        found.ok_or_else(|| {
            CliError::guard_error("archive does not contain a .wasm file".to_string())
        })?
    };

    // Copy the .wasm file
    let src_wasm = tmp_path.join(&wasm_filename);
    let dst_wasm = guard_dir.join(&wasm_filename);
    fs::copy(&src_wasm, &dst_wasm)
        .map_err(|e| guard_io_error(format!("failed to copy wasm file: {e}")))?;

    // Update the manifest's wasm_path to point to the co-located filename and write it
    let updated_manifest_content = update_manifest_wasm_path(&manifest_content, &wasm_filename)?;
    fs::write(
        guard_dir.join("guard-manifest.yaml"),
        updated_manifest_content,
    )
    .map_err(|e| guard_io_error(format!("failed to write updated manifest: {e}")))?;

    // Clean up temp directory (best-effort)
    let _ = fs::remove_dir_all(&tmp_path);

    println!("installed: {guard_name} to {}/", guard_dir.display());

    Ok(())
}

/// Rewrite the `wasm_path` field in the manifest YAML to point to the given filename.
fn update_manifest_wasm_path(content: &str, new_wasm_path: &str) -> Result<String, CliError> {
    let mut value: serde_yml::Value = serde_yml::from_str(content).map_err(|e| {
        guard_yaml_error(format!(
            "failed to parse manifest for wasm_path update: {e}"
        ))
    })?;
    if let serde_yml::Value::Mapping(ref mut map) = value {
        map.insert(
            serde_yml::Value::String("wasm_path".to_string()),
            serde_yml::Value::String(new_wasm_path.to_string()),
        );
    }
    serde_yml::to_string(&value)
        .map_err(|e| guard_yaml_error(format!("failed to serialize updated manifest: {e}")))
}
