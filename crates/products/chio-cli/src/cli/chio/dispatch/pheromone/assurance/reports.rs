use super::archive::read_relay_alert_assurance_archive_package;
use super::super::read_json_file;
use super::support::{file_name_ends_with, sorted_files};
use crate::CliError;
use serde::de::DeserializeOwned;
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn read_archive_restore_package_reports(
    package_dir: &Path,
    source_report_dir: &Path,
    trusted_packagers: &Path,
    trusted_exporters: &Path,
    now_unix_ms: u64,
) -> Result<Vec<chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport>, CliError> {
    let trusted_packagers: chio_pheromone_relay::RelayAlertAssuranceTrustedArchivePackagersDocument =
        read_json_file(
            trusted_packagers,
            "Chio relay alert assurance trusted archive packagers",
        )?;
    let trusted_exporters: chio_pheromone_relay::RelayAlertAssuranceTrustedExportersDocument =
        read_json_file(
            trusted_exporters,
            "Chio relay alert assurance trusted exporters",
        )?;
    let mut reports = Vec::new();
    let mut package_paths = sorted_files(package_dir)?;
    retain_archive_restore_package_inputs(&mut package_paths);
    let mut source_reports = None;
    for path in package_paths {
        if file_name_ends_with(&path, ".tar.gz") || file_name_ends_with(&path, ".tgz") {
            let package = read_relay_alert_assurance_archive_package(&path)?;
            if source_reports.is_none() {
                source_reports = Some(read_archive_restore_source_reports(source_report_dir)?);
            }
            let source_reports = source_reports.as_ref().ok_or_else(|| {
                CliError::cli_other_error("Chio restore source reports missing".to_string())
            })?;
            let (archive_report, closeout_report) = source_reports.for_package(&package)?;
            let verified_report = chio_pheromone_relay::verify_relay_alert_assurance_archive_package(
                chio_pheromone_relay::RelayAlertAssuranceArchivePackageVerifyInput {
                    package: &package,
                    trusted_packagers: &trusted_packagers,
                    trusted_exporters: &trusted_exporters,
                    archive_report,
                    closeout_report,
                    now_unix_ms,
                },
            )
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chio relay alert assurance archive package restore verify: {error}"
                ))
            })?;
            let report =
                read_archive_restore_package_report_sidecar(&path, &verified_report)?
                    .unwrap_or(verified_report);
            reports.push(report);
        }
    }
    if reports.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "no archive package tarballs found in {}",
            package_dir.display()
        )));
    }
    Ok(reports)
}

fn retain_archive_restore_package_inputs(package_paths: &mut Vec<PathBuf>) {
    package_paths.retain(|path| {
        file_name_ends_with(path, ".tar.gz") || file_name_ends_with(path, ".tgz")
    });
}

fn archive_restore_package_sidecar_report_name(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_str()?;
    let package_name = file_name
        .strip_suffix(".tar.gz")
        .or_else(|| file_name.strip_suffix(".tgz"))?;
    Some(format!("{package_name}-report.json"))
}

fn read_archive_restore_package_report_sidecar(
    package_path: &Path,
    verified_report: &chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport,
) -> Result<Option<chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport>, CliError> {
    let Some(sidecar_name) = archive_restore_package_sidecar_report_name(package_path) else {
        return Ok(None);
    };
    let sidecar_path = package_path.with_file_name(sidecar_name);
    if !sidecar_path.is_file() {
        return Ok(None);
    }
    let sidecar_report: chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport =
        read_json_file(
            &sidecar_path,
            "Chio relay alert assurance archive package sidecar report",
        )?;
    if !archive_restore_package_sidecar_matches_verified_report(&sidecar_report, verified_report) {
        return Err(CliError::cli_other_error(format!(
            "Chio relay alert assurance archive package sidecar report {} does not match verified package",
            sidecar_path.display()
        )));
    }
    Ok(Some(sidecar_report))
}

fn archive_restore_package_sidecar_matches_verified_report(
    sidecar_report: &chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport,
    verified_report: &chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport,
) -> bool {
    let mut normalized_sidecar = sidecar_report.clone();
    normalized_sidecar.generated_at_unix_ms = verified_report.generated_at_unix_ms;
    normalized_sidecar == *verified_report
}

struct ArchiveRestoreSourceReports {
    archive_reports: Vec<chio_pheromone_relay::RelayAlertAssuranceArchiveReport>,
    closeout_reports: Vec<chio_pheromone_relay::RelayAlertAssuranceCloseoutReport>,
}

impl ArchiveRestoreSourceReports {
    fn for_package(
        &self,
        package: &chio_pheromone_relay::RelayAlertAssuranceArchivePackage,
    ) -> Result<
        (
            &chio_pheromone_relay::RelayAlertAssuranceArchiveReport,
            &chio_pheromone_relay::RelayAlertAssuranceCloseoutReport,
        ),
        CliError,
    > {
        let body = &package.manifest.body;
        let archive_report = find_report_by_canonical_hash(
            &self.archive_reports,
            &body.source_archive_report_sha256,
            "Chio relay alert assurance archive report",
        )?;
        let closeout_report = find_report_by_canonical_hash(
            &self.closeout_reports,
            &body.source_closeout_report_sha256,
            "Chio relay alert assurance closeout report",
        )?;
        Ok((archive_report, closeout_report))
    }
}

fn read_archive_restore_source_reports(
    source_report_dir: &Path,
) -> Result<ArchiveRestoreSourceReports, CliError> {
    let archive_reports = read_relay_report_documents(
        source_report_dir,
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA,
        "Chio relay alert assurance archive report",
    )?;
    if archive_reports.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "no Chio relay alert assurance archive reports found in {}",
            source_report_dir.display()
        )));
    }
    let closeout_reports = read_relay_report_documents(
        source_report_dir,
        chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA,
        "Chio relay alert assurance closeout report",
    )?;
    if closeout_reports.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "no Chio relay alert assurance closeout reports found in {}",
            source_report_dir.display()
        )));
    }
    Ok(ArchiveRestoreSourceReports {
        archive_reports,
        closeout_reports,
    })
}

fn find_report_by_canonical_hash<'a, T: serde::Serialize>(
    reports: &'a [T],
    expected_sha256: &str,
    label: &str,
) -> Result<&'a T, CliError> {
    let mut matched_report = None;
    for report in reports {
        let report_sha256 = chio_core::crypto::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(report).map_err(|error| {
                CliError::cli_other_error(format!("{label} canonical hash: {error}"))
            })?,
        );
        if report_sha256 == expected_sha256 {
            if matched_report.is_some() {
                return Err(CliError::cli_other_error(format!(
                    "multiple {label} documents match package manifest hash {expected_sha256}"
                )));
            }
            matched_report = Some(report);
        }
    }
    matched_report.ok_or_else(|| {
        CliError::cli_other_error(format!(
            "no {label} document matches package manifest hash {expected_sha256}"
        ))
    })
}

pub(super) fn read_relay_report_documents<T: DeserializeOwned>(
    dir: &Path,
    schema: &str,
    label: &str,
) -> Result<Vec<T>, CliError> {
    let mut reports = Vec::new();
    for path in sorted_files(dir)? {
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let value: serde_json::Value = read_json_file(&path, label)?;
        if value.get("schema").and_then(serde_json::Value::as_str) == Some(schema) {
            reports.push(serde_json::from_value(value).map_err(|error| {
                CliError::cli_json_error(format!("{label}: {error}"))
            })?);
        }
    }
    Ok(reports)
}


#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod archive_restore_input_tests {
    use super::*;

    #[test]
    fn archive_restore_inputs_keep_only_tarballs_when_json_reports_are_present() {
        let mut paths = vec![
            PathBuf::from("relay-archive-package.tar.gz"),
            PathBuf::from("relay-archive-package-report.json"),
            PathBuf::from("generation-2-package-report.json"),
            PathBuf::from("notes.txt"),
        ];

        retain_archive_restore_package_inputs(&mut paths);

        assert_eq!(
            paths,
            vec![PathBuf::from("relay-archive-package.tar.gz")]
        );
    }

    #[test]
    fn archive_restore_inputs_drop_report_json_when_no_tarballs_are_present() {
        let mut paths = vec![
            PathBuf::from("relay-archive-package-report.json"),
            PathBuf::from("notes.txt"),
        ];

        retain_archive_restore_package_inputs(&mut paths);

        assert!(paths.is_empty());
    }

    #[test]
    fn archive_restore_rejects_unverified_standalone_package_report_json() {
        let temp = tempfile::tempdir().unwrap();
        let package_dir = temp.path().join("packages");
        let source_report_dir = temp.path().join("source-reports");
        fs::create_dir_all(&package_dir).unwrap();
        fs::create_dir_all(&source_report_dir).unwrap();
        fs::write(
            package_dir.join("generation-1-package-report.json"),
            serde_json::to_vec(&archive_restore_package_report_for_test(10_000)).unwrap(),
        )
        .unwrap();
        let trusted_packagers_path = temp.path().join("trusted-packagers.json");
        fs::write(
            &trusted_packagers_path,
            serde_json::to_vec(&serde_json::json!({
                "schema": chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA,
                "localKernelId": "did:chio:buyer-kernel",
                "minCreatedAtUnixMs": 0,
                "packagers": []
            }))
            .unwrap(),
        )
        .unwrap();
        let trusted_exporters_path = temp.path().join("trusted-exporters.json");
        fs::write(
            &trusted_exporters_path,
            serde_json::to_vec(&serde_json::json!({
                "schema": chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_EXPORTERS_SCHEMA,
                "localKernelId": "did:chio:buyer-kernel",
                "minExportedAtUnixMs": 0,
                "exporters": []
            }))
            .unwrap(),
        )
        .unwrap();

        let err = read_archive_restore_package_reports(
            &package_dir,
            &source_report_dir,
            &trusted_packagers_path,
            &trusted_exporters_path,
            20_000,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("no archive package tarballs found"),
            "{err}"
        );
    }

    #[test]
    fn archive_restore_source_reports_match_by_canonical_hash() {
        let reports = vec![
            serde_json::json!({"id": "one", "schema": "test.schema.v1"}),
            serde_json::json!({"id": "two", "schema": "test.schema.v1"}),
        ];
        let expected_sha256 = chio_core::crypto::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(&reports[1]).unwrap(),
        );

        let report =
            find_report_by_canonical_hash(&reports, &expected_sha256, "test report").unwrap();

        assert_eq!(report, &reports[1]);
    }

    #[test]
    fn archive_restore_tarball_prefers_hash_stable_sidecar_report() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("relay-archive-package.tar.gz");
        std::fs::write(&package_path, b"package bytes").unwrap();
        let verified_report = archive_restore_package_report_for_test(20_000);
        let sidecar_report = archive_restore_package_report_for_test(10_000);
        let sidecar_path = temp.path().join("relay-archive-package-report.json");
        std::fs::write(
            &sidecar_path,
            serde_json::to_vec(&sidecar_report).unwrap(),
        )
        .unwrap();

        let report =
            read_archive_restore_package_report_sidecar(&package_path, &verified_report).unwrap();

        assert_eq!(report, Some(sidecar_report));
    }

    #[test]
    fn archive_restore_tarball_rejects_mismatched_sidecar_report() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join("relay-archive-package.tar.gz");
        std::fs::write(&package_path, b"package bytes").unwrap();
        let verified_report = archive_restore_package_report_for_test(20_000);
        let mut sidecar_report = archive_restore_package_report_for_test(10_000);
        sidecar_report.package_manifest_sha256 = "f".repeat(64);
        let sidecar_path = temp.path().join("relay-archive-package-report.json");
        std::fs::write(
            &sidecar_path,
            serde_json::to_vec(&sidecar_report).unwrap(),
        )
        .unwrap();

        let err =
            read_archive_restore_package_report_sidecar(&package_path, &verified_report)
                .unwrap_err();

        assert!(err.to_string().contains("sidecar report"));
    }

    fn archive_restore_package_report_for_test(
        generated_at_unix_ms: u64,
    ) -> chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport {
        chio_pheromone_relay::RelayAlertAssuranceArchivePackageReport {
            schema: chio_pheromone_relay::PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA
                .to_string(),
            accepted: true,
            code: "accepted".to_string(),
            local_kernel_id: "did:chio:buyer-kernel".to_string(),
            generated_at_unix_ms,
            package_id: "relay-archive-package-1".to_string(),
            package_generation: 1,
            previous_package_manifest_sha256: None,
            package_manifest_sha256: "1".repeat(64),
            source_archive_report_sha256: "2".repeat(64),
            source_closeout_report_sha256: "3".repeat(64),
            package_member_count: 1,
            package_total_byte_count: 128,
            bundle_count: 1,
            trusted_packager_verified: true,
            nested_exporter_verified: true,
            source_reports_matched: true,
            closeout_ready_verified: true,
            total_byte_count_matched: true,
            extractable: true,
            checks: vec![chio_pheromone_relay::RelayAlertCheck {
                code: "accepted".to_string(),
                accepted: true,
                detail: "test package report".to_string(),
            }],
        }
    }
}
