use std::fs;
use std::path::Path;
use std::process::Command;

use chio_wasm_guards::manifest::{signature_sidecar_path, verify_guard_signature, GuardManifest};
use flate2::write::GzEncoder;
use flate2::Compression;

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

    let sidecar_path = signature_sidecar_path(&wasm_abs_path.to_string_lossy());
    let signature_bytes = match fs::read(&sidecar_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(guard_io_error(format!(
                "failed to read guard signature: {error}"
            )))
        }
    };
    if manifest.signer_public_key.is_some() {
        verify_guard_signature(&wasm_abs_path.to_string_lossy(), &wasm_bytes, &manifest).map_err(
            |error| CliError::guard_error(format!("cannot package signed guard: {error}")),
        )?;
    }

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

    if let Some(bytes) = &signature_bytes {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(
                &mut header,
                format!("{wasm_filename}.sig"),
                bytes.as_slice(),
            )
            .map_err(|error| {
                guard_io_error(format!("failed to add signature to archive: {error}"))
            })?;
    }

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
    let prepared = prepare_guard_install(archive_path, target_dir)?;
    publish_guard_directory(&prepared.candidate, &prepared.destination).map_err(|error| {
        guard_io_error(format!(
            "could not publish guard update; existing installation was preserved: {error}"
        ))
    })?;
    println!(
        "installed: {} to {}/",
        prepared.name,
        prepared.destination.display()
    );
    // After an exchange the old, complete installation is in the staging
    // directory. Cleanup is best effort and cannot turn a committed update
    // into a reported failure.
    Ok(())
}

pub(super) struct PreparedGuardInstall {
    _staging: tempfile::TempDir,
    pub(super) candidate: std::path::PathBuf,
    pub(super) destination: std::path::PathBuf,
    name: String,
}

pub(super) fn prepare_guard_install(
    archive_path: &Path,
    target_dir: &Path,
) -> Result<PreparedGuardInstall, CliError> {
    let entries = crate::archive::read_tar_gz_file(
        archive_path,
        "Chio guard archive",
        GUARD_INSTALL_ARCHIVE_LIMITS,
    )?;
    fs::create_dir_all(target_dir)
        .map_err(|error| guard_io_error(format!("failed to create install directory: {error}")))?;
    // Same filesystem as the destination, with an exclusive random name and
    // private permissions. Nothing below writes into the active installation.
    let staging = tempfile::Builder::new()
        .prefix(".chio-install-")
        .tempdir_in(target_dir)
        .map_err(|error| guard_io_error(format!("failed to stage guard: {error}")))?;
    let extracted = staging.path().join("archive");
    fs::create_dir(&extracted).map_err(|error| guard_io_error(error.to_string()))?;
    crate::archive::write_entries_to_existing_dir(&extracted, "Chio guard archive", &entries)?;
    let manifest_content =
        fs::read_to_string(extracted.join("guard-manifest.yaml")).map_err(|error| {
            guard_io_error(format!(
                "archive does not contain guard-manifest.yaml: {error}"
            ))
        })?;
    let manifest: GuardManifest = serde_yml::from_str(&manifest_content).map_err(|error| {
        guard_yaml_error(format!("failed to parse manifest from archive: {error}"))
    })?;
    if manifest.name.is_empty()
        || !manifest
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(CliError::guard_error(
            "guard name must contain only letters, digits, hyphens, or underscores".to_string(),
        ));
    }
    let wasm_filename = Path::new(&manifest.wasm_path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| name.ends_with(".wasm"))
        .ok_or_else(|| CliError::guard_error("manifest must name a .wasm module".to_string()))?;
    let candidate = staging.path().join("guard");
    fs::create_dir(&candidate).map_err(|error| guard_io_error(error.to_string()))?;
    fs::copy(extracted.join(wasm_filename), candidate.join(wasm_filename))
        .map_err(|error| guard_io_error(format!("failed to stage wasm file: {error}")))?;
    let signature = format!("{wasm_filename}.sig");
    match fs::copy(extracted.join(&signature), candidate.join(&signature)) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(guard_io_error(format!(
                "failed to stage signature: {error}"
            )))
        }
    }
    fs::write(
        candidate.join("guard-manifest.yaml"),
        update_manifest_wasm_path(&manifest_content, wasm_filename)?,
    )
    .map_err(|error| guard_io_error(format!("failed to stage manifest: {error}")))?;
    if manifest.signer_public_key.is_some() {
        let source = candidate.join(wasm_filename);
        let bytes = fs::read(&source).map_err(|error| guard_io_error(error.to_string()))?;
        verify_guard_signature(&source.to_string_lossy(), &bytes, &manifest).map_err(|error| {
            CliError::guard_error(format!("cannot install signed guard: {error}"))
        })?;
    }
    for entry in fs::read_dir(&candidate).map_err(|error| guard_io_error(error.to_string()))? {
        let entry = entry.map_err(|error| guard_io_error(error.to_string()))?;
        fs::File::open(entry.path())
            .and_then(|file| file.sync_all())
            .map_err(|error| guard_io_error(format!("failed to flush staged guard: {error}")))?;
    }
    Ok(PreparedGuardInstall {
        _staging: staging,
        candidate,
        destination: target_dir.join(&manifest.name),
        name: manifest.name,
    })
}

/// Publish a complete directory in one filesystem operation. An interrupted
/// process leaves either complete version at the destination, never a mixture.
/// Filesystems without atomic exchange support refuse updates without a
/// remove/rename fallback that could lose the working installation.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
pub(super) fn publish_guard_directory(candidate: &Path, destination: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let replace = match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_dir() => true,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "guard destination is not a directory",
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    let from = CString::new(candidate.as_os_str().as_bytes())?;
    let to = CString::new(destination.as_os_str().as_bytes())?;
    // SAFETY: both C strings remain alive for the call. The OS performs an
    // exclusive initial rename or atomic exchange of the two directory entries.
    #[cfg(target_vendor = "apple")]
    let result = unsafe {
        libc::renamex_np(
            from.as_ptr(),
            to.as_ptr(),
            if replace {
                libc::RENAME_SWAP
            } else {
                libc::RENAME_EXCL
            },
        )
    };
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            if replace {
                libc::RENAME_EXCHANGE
            } else {
                libc::RENAME_NOREPLACE
            },
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
pub(super) fn publish_guard_directory(
    _candidate: &Path,
    _destination: &Path,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic guard installation requires Linux or macOS",
    ))
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
