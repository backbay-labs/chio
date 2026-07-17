use super::super::{read_json_file, write_pretty_json};
use crate::CliError;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn sorted_files(dir: &Path) -> Result<Vec<PathBuf>, CliError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read directory {}: {error}",
            dir.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!("failed to read directory entry: {error}"))
        })?;
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

pub(super) fn file_name_ends_with(path: &Path, suffix: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(suffix))
}

pub(super) const ARCHIVE_PACKAGE_MANIFEST_PATH: &str = "archive-package-manifest.json";
const ARCHIVE_PACKAGE_MAX_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const ARCHIVE_PACKAGE_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const ARCHIVE_PACKAGE_MAX_MEMBER_BYTES: u64 = 32 * 1024 * 1024;
const ARCHIVE_PACKAGE_MAX_MEMBER_COUNT: usize = 512;
const ARCHIVE_PACKAGE_MAX_TAR_MEMBER_COUNT: usize = ARCHIVE_PACKAGE_MAX_MEMBER_COUNT + 1;
const ARCHIVE_PACKAGE_MAX_DECOMPRESSION_RATIO: u64 = 200;

pub(super) fn archive_package_limits() -> crate::archive::SafeArchiveLimits {
    crate::archive::SafeArchiveLimits {
        max_compressed_bytes: ARCHIVE_PACKAGE_MAX_COMPRESSED_BYTES,
        max_member_bytes: ARCHIVE_PACKAGE_MAX_MEMBER_BYTES,
        max_total_bytes: ARCHIVE_PACKAGE_MAX_TOTAL_BYTES,
        max_member_count: ARCHIVE_PACKAGE_MAX_TAR_MEMBER_COUNT,
        max_decompression_ratio: ARCHIVE_PACKAGE_MAX_DECOMPRESSION_RATIO,
    }
}

pub(super) fn trusted_archive_packagers_from_signing_key(
    packager_id: &str,
    packager_key_id: &str,
    public_key: chio_core::crypto::PublicKey,
    local_kernel_id: String,
    now_unix_ms: u64,
) -> chio_pheromone_relay::RelayAlertAssuranceTrustedArchivePackagersDocument {
    chio_pheromone_relay::RelayAlertAssuranceTrustedArchivePackagersDocument {
        schema:
            chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA
                .to_string(),
        local_kernel_id,
        min_created_at_unix_ms: now_unix_ms,
        packagers: vec![
            chio_pheromone_relay::RelayAlertAssuranceTrustedArchivePackager {
                packager_id: packager_id.to_string(),
                key_id: packager_key_id.to_string(),
                public_key,
                valid_from_unix_ms: now_unix_ms.saturating_sub(1),
                valid_until_unix_ms: now_unix_ms.saturating_add(24 * 60 * 60 * 1000),
                status: "active".to_string(),
            },
        ],
    }
}

pub(super) fn write_relay_alert_assurance_bundle(
    out_dir: &Path,
    bundle: &chio_pheromone_relay::RelayAlertAssuranceExportBundle,
) -> Result<(), CliError> {
    ensure_clean_output_dir(out_dir)?;
    write_pretty_json(
        &out_dir.join("manifest.json"),
        &bundle.manifest,
        "Chio relay alert assurance export manifest",
    )?;
    write_pretty_json(
        &out_dir.join("relay-alert-assurance-export-report.json"),
        &bundle.report,
        "Chio relay alert assurance export report",
    )?;
    for file in &bundle.files {
        let path = safe_bundle_path(out_dir, &file.path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to create Chio relay alert assurance export dir {}: {error}",
                    parent.display()
                ))
            })?;
        }
        fs::write(&path, &file.bytes).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to write Chio relay alert assurance export file {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

pub(super) fn read_relay_alert_assurance_bundle(
    bundle_dir: &Path,
) -> Result<chio_pheromone_relay::RelayAlertAssuranceExportBundle, CliError> {
    let manifest: chio_pheromone_relay::RelayAlertAssuranceExportManifest = read_json_file(
        &bundle_dir.join("manifest.json"),
        "Chio relay alert assurance export manifest",
    )?;
    let report: chio_pheromone_relay::RelayAlertAssuranceExportReport = read_json_file(
        &bundle_dir.join("relay-alert-assurance-export-report.json"),
        "Chio relay alert assurance export report",
    )?;
    let mut files = Vec::new();
    for artifact in &manifest.body.artifacts {
        let path = safe_bundle_path(bundle_dir, &artifact.path)?;
        let bytes = fs::read(&path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chio relay alert assurance export file {}: {error}",
                path.display()
            ))
        })?;
        files.push(chio_pheromone_relay::RelayAlertAssuranceExportFile {
            path: artifact.path.clone(),
            bytes,
        });
    }
    Ok(chio_pheromone_relay::RelayAlertAssuranceExportBundle {
        manifest,
        report,
        files,
    })
}

pub(super) fn read_relay_alert_assurance_bundle_root(
    bundle_root: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceExportBundle>, CliError> {
    if bundle_root.join("manifest.json").is_file() {
        return Ok(vec![read_relay_alert_assurance_bundle(bundle_root)?]);
    }
    let entries = fs::read_dir(bundle_root).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chio relay alert assurance bundle root {}: {error}",
            bundle_root.display()
        ))
    })?;
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chio relay alert assurance bundle root entry {}: {error}",
                bundle_root.display()
            ))
        })?;
        let path = entry.path();
        if path.is_dir() && path.join("manifest.json").is_file() {
            dirs.push(path);
        }
    }
    dirs.sort();
    let mut bundles = Vec::new();
    for dir in dirs {
        bundles.push(read_relay_alert_assurance_bundle(&dir)?);
    }
    if bundles.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "Chio relay alert assurance bundle root {} contains no bundles",
            bundle_root.display()
        )));
    }
    Ok(bundles)
}

pub(super) fn read_relay_alert_assurance_archive_candidates(
    bundle_root: &Path,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate>, CliError> {
    if bundle_root.join("manifest.json").is_file() {
        return Ok(vec![read_relay_alert_assurance_archive_candidate(
            bundle_root,
        )]);
    }
    let entries = fs::read_dir(bundle_root).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chio relay alert assurance bundle root {}: {error}",
            bundle_root.display()
        ))
    })?;
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chio relay alert assurance bundle root entry {}: {error}",
                bundle_root.display()
            ))
        })?;
        let path = entry.path();
        if path.is_dir() && path.join("manifest.json").is_file() {
            dirs.push(path);
        }
    }
    dirs.sort();
    let mut candidates = Vec::new();
    for dir in dirs {
        candidates.push(read_relay_alert_assurance_archive_candidate(&dir));
    }
    if candidates.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "Chio relay alert assurance bundle root {} contains no bundles",
            bundle_root.display()
        )));
    }
    Ok(candidates)
}

pub(super) fn read_relay_alert_assurance_archive_candidate(
    bundle_dir: &Path,
) -> chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
    let bundle_path = relay_alert_assurance_bundle_label(bundle_dir);
    match read_relay_alert_assurance_bundle(bundle_dir) {
        Ok(bundle) => chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
            bundle_path,
            bundle: Some(bundle),
            error_code: None,
            error_detail: None,
        },
        Err(error) => chio_pheromone_relay::RelayAlertAssuranceArchiveBundleCandidate {
            bundle_path,
            bundle: None,
            error_code: Some("bundle_read_failed".to_string()),
            error_detail: Some(error.to_string()),
        },
    }
}

pub(super) fn relay_alert_assurance_bundle_label(bundle_dir: &Path) -> String {
    bundle_dir
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("export-bundle")
        .to_string()
}

fn ensure_clean_output_dir(out_dir: &Path) -> Result<(), CliError> {
    if out_dir.exists() {
        let mut entries = fs::read_dir(out_dir).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect Chio output directory {}: {error}",
                out_dir.display()
            ))
        })?;
        if entries
            .next()
            .transpose()
            .map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to inspect Chio output directory {}: {error}",
                    out_dir.display()
                ))
            })?
            .is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "Chio output directory {} must be empty",
                out_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(out_dir).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to create Chio output directory {}: {error}",
                out_dir.display()
            ))
        })?;
    }
    Ok(())
}

fn safe_bundle_path(root: &Path, relative: &str) -> Result<PathBuf, CliError> {
    if relative.trim() != relative
        || relative.is_empty()
        || relative.contains('\\')
        || relative.contains(':')
        || Path::new(relative).is_absolute()
    {
        return Err(CliError::cli_other_error(format!(
            "Chio relay alert assurance export path {relative} is not relative"
        )));
    }
    let mut path = root.to_path_buf();
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(CliError::cli_other_error(format!(
                "Chio relay alert assurance export path {relative} is unsafe"
            )));
        }
        path.push(segment);
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::ensure_clean_output_dir;

    #[test]
    fn output_directory_errors_use_chio_boundary_label() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        std::fs::write(tempdir.path().join("existing.json"), "{}").expect("write fixture");

        let error = ensure_clean_output_dir(tempdir.path())
            .expect_err("non-empty output dir should fail")
            .to_string();

        assert!(error.contains("Chio output directory"));
    }
}
