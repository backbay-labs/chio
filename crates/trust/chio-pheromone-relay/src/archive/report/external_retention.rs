use super::*;

pub(crate) enum ExternalRetentionEvidence<T> {
    Missing,
    Single(T),
    Duplicate,
}
pub(crate) struct ExternalRetentionRestoreStatus {
    pub(crate) code: String,
    pub(crate) accepted: bool,
    pub(crate) generated_at_unix_ms: u64,
    pub(crate) local_kernel_id: String,
}
pub(crate) fn external_retention_report_status(value: &str, field: &str) -> (String, bool) {
    if validate_external_retention_schema_token(value, field).is_ok() {
        return (value.to_string(), true);
    }
    ("invalid".to_string(), false)
}
pub(crate) fn external_retention_restore_status(
    restore_reports: &[RelayAlertAssuranceArchiveRestoreDrillReport],
    package_report: &RelayAlertAssuranceArchivePackageReport,
) -> ExternalRetentionEvidence<ExternalRetentionRestoreStatus> {
    let mut matches = restore_reports.iter().filter_map(|restore| {
        restore.packages.iter().find_map(|package| {
            if package.package_id == package_report.package_id
                && package.package_generation == package_report.package_generation
                && package.package_manifest_sha256 == package_report.package_manifest_sha256
            {
                Some(ExternalRetentionRestoreStatus {
                    code: package.code.clone(),
                    accepted: restore.accepted && package.accepted,
                    generated_at_unix_ms: restore.generated_at_unix_ms,
                    local_kernel_id: restore.local_kernel_id.clone(),
                })
            } else {
                None
            }
        })
    });
    let Some(first) = matches.next() else {
        return ExternalRetentionEvidence::Missing;
    };
    if matches.next().is_some() {
        return ExternalRetentionEvidence::Duplicate;
    }
    ExternalRetentionEvidence::Single(first)
}
pub(crate) fn external_retention_physical_reports<'a>(
    physical_reports: &'a [RelayAlertAssurancePhysicalArchiveDrillReport],
    package_report_sha256: &str,
    package_id: &str,
) -> Vec<&'a RelayAlertAssurancePhysicalArchiveDrillReport> {
    physical_reports
        .iter()
        .filter(|report| {
            report.package_report_sha256 == package_report_sha256 && report.package_id == package_id
        })
        .collect()
}
pub(crate) fn external_retention_handoffs<'a>(
    handoff_reports: &'a [RelayAlertAssuranceRetentionHandoffReport],
    package_report_sha256: &str,
    package_id: &str,
) -> Vec<&'a RelayAlertAssuranceRetentionHandoffReport> {
    handoff_reports
        .iter()
        .filter(|report| {
            report.package_report_sha256 == package_report_sha256 && report.package_id == package_id
        })
        .collect()
}
pub(crate) fn external_retention_sample_coverage(sampled: u64, member_count: u64) -> u64 {
    if member_count == 0 {
        return 0;
    }
    sampled.min(member_count).saturating_mul(10_000) / member_count
}
pub(crate) fn external_retention_fresh(
    generated_at_unix_ms: u64,
    since_unix_ms: u64,
    until_unix_ms: u64,
    now_unix_ms: u64,
    max_age_ms: u64,
) -> bool {
    generated_at_unix_ms >= since_unix_ms
        && generated_at_unix_ms <= until_unix_ms
        && generated_at_unix_ms <= now_unix_ms
        && now_unix_ms.saturating_sub(generated_at_unix_ms) <= max_age_ms
}
pub(crate) fn external_retention_check(
    checks: &mut Vec<RelayAlertCheck>,
    accepted: &mut bool,
    code: &mut String,
    condition: bool,
    check_code: &str,
    failure_code: &str,
    detail: &str,
) {
    checks.push(RelayAlertCheck {
        code: if condition {
            check_code.to_string()
        } else {
            failure_code.to_string()
        },
        accepted: condition,
        detail: detail.to_string(),
    });
    if !condition {
        *accepted = false;
        *code = failure_code.to_string();
    }
}
pub(crate) fn external_retention_fail(
    checks: &mut Vec<RelayAlertCheck>,
    accepted: &mut bool,
    code: &mut String,
    failure_code: &str,
    detail: &str,
) {
    external_retention_check(
        checks,
        accepted,
        code,
        false,
        failure_code,
        failure_code,
        detail,
    );
}
