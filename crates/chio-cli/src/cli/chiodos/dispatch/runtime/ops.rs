use std::path::Path;

use crate::CliError;

use super::io::{ensure_runtime_evidence_dir, sorted_child_dirs};
use super::super::{read_utf8_json_file, unix_now_ms, write_pretty_json};

pub(crate) fn cmd_chiodos_runtime_ops_tick(
    supervisor_profile: &Path,
    store: &Path,
    evidence_root: &Path,
    owner_id: &str,
    now_unix_ms: u64,
    max_runs: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    ensure_runtime_evidence_dir(evidence_root)?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let tick = store
        .scheduler_tick_report(&profile, owner_id, now_unix_ms, max_runs)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime scheduler tick: {error}"))
        })?;
    write_pretty_json(report, &tick, "Chiodos runtime scheduler tick report")
}

pub(crate) fn cmd_chiodos_runtime_ops_status(
    supervisor_profile: &Path,
    store: &Path,
    evidence_root: &Path,
    provider_bindings: Option<&Path>,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let generated_at = now_unix_ms.unwrap_or_else(unix_now_ms);
    let provider_healthy = provider_bindings
        .map(|path| {
            let bindings = load_runtime_provider_bindings(path)?;
            let health = chio_chiodos_runtime::generate_runtime_provider_health_report(
                &profile,
                &bindings,
                generated_at,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime provider health: {error}"))
            })?;
            Ok::<bool, CliError>(health.accepted)
        })
        .transpose()?
        .unwrap_or(false);
    let evidence_sink_healthy =
        runtime_ops_status_evidence_sink_healthy(&profile, evidence_root, generated_at)?;
    let status = store
        .ops_status_report(&profile, generated_at, evidence_sink_healthy, provider_healthy)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos runtime ops status: {error}")))?;
    write_pretty_json(report, &status, "Chiodos runtime ops status report")
}

pub(crate) fn runtime_ops_status_evidence_sink_healthy(
    profile: &chio_chiodos_runtime::RuntimeSupervisorProfile,
    evidence_root: &Path,
    now_unix_ms: u64,
) -> Result<bool, CliError> {
    if !evidence_root.is_dir() {
        return Ok(false);
    }
    let run_dirs = sorted_child_dirs(evidence_root)?;
    if run_dirs.is_empty() {
        return Ok(true);
    }
    for run_dir in run_dirs {
        let Some(run_id) = run_dir.file_name().and_then(|name| name.to_str()) else {
            return Ok(false);
        };
        let manifest_json = match read_utf8_json_file(
            &run_dir.join("runtime-evidence-manifest.json"),
            "Chiodos runtime evidence manifest",
        ) {
            Ok(json) => json,
            Err(_) => return Ok(false),
        };
        let manifest: chio_chiodos_runtime::RuntimeEvidenceManifest =
            match serde_json::from_str(&manifest_json) {
                Ok(manifest) => manifest,
                Err(_) => return Ok(false),
            };
        let health = match chio_chiodos_runtime::generate_runtime_evidence_sink_health_report(
            run_id,
            &run_dir,
            &manifest,
            &profile.evidence_required_roles,
            now_unix_ms,
            true,
        ) {
            Ok(health) => health,
            Err(_) => return Ok(false),
        };
        if !health.accepted {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn cmd_chiodos_runtime_ops_recovery_drill(
    supervisor_profile: &Path,
    run_id: &str,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    ensure_runtime_evidence_dir(evidence_root)?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let drill = store
        .recovery_drill_report_for_profile(&profile, run_id, now_unix_ms)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime recovery drill: {error}"))
        })?;
    write_pretty_json(report, &drill, "Chiodos runtime recovery drill report")
}

pub(crate) fn cmd_chiodos_runtime_ops_evidence_health(
    supervisor_profile: &Path,
    run_id: &str,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let _store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let evidence_dir = evidence_root.join(run_id);
    if !evidence_dir.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "Chiodos runtime evidence health requires evidence-root/run-id directory {}",
            evidence_dir.display()
        )));
    }
    let manifest_json = read_utf8_json_file(
        &evidence_dir.join("runtime-evidence-manifest.json"),
        "Chiodos runtime evidence manifest",
    )?;
    let manifest: chio_chiodos_runtime::RuntimeEvidenceManifest =
        serde_json::from_str(&manifest_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime evidence manifest: {error}"))
        })?;
    let health = chio_chiodos_runtime::generate_runtime_evidence_sink_health_report(
        run_id,
        &evidence_dir,
        &manifest,
        &profile.evidence_required_roles,
        now_unix_ms,
        true,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime evidence health: {error}"))
    })?;
    write_pretty_json(report, &health, "Chiodos runtime evidence health report")
}

pub(crate) fn cmd_chiodos_runtime_ops_provider_health(
    supervisor_profile: &Path,
    provider_bindings: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let bindings = load_runtime_provider_bindings(provider_bindings)?;
    let health = chio_chiodos_runtime::generate_runtime_provider_health_report(
        &profile,
        &bindings,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime provider health: {error}"))
    })?;
    write_pretty_json(report, &health, "Chiodos runtime provider health report")
}

pub(crate) fn load_runtime_provider_bindings(
    provider_bindings: &Path,
) -> Result<chio_chiodos_runtime::RuntimeProviderBindingsDocument, CliError> {
    chio_chiodos_runtime::runtime_provider_bindings_from_json(&read_utf8_json_file(
        provider_bindings,
        "Chiodos runtime provider bindings",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime provider bindings: {error}"))
    })
}

pub(crate) fn cmd_chiodos_runtime_ops_retention_plan(
    retention_profile: &Path,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile =
        chio_chiodos_runtime::runtime_artifact_retention_profile_from_json(&read_utf8_json_file(
            retention_profile,
            "Chiodos runtime artifact retention profile",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime artifact retention profile: {error}"))
        })?;
    let _store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    if !evidence_root.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "Chiodos runtime retention plan requires existing evidence root {}",
            evidence_root.display()
        )));
    }
    let run_ids = sorted_child_dirs(evidence_root)?
        .into_iter()
        .filter_map(|path| path.file_name().map(|name| name.to_string_lossy().to_string()))
        .collect::<Vec<_>>();
    let plan =
        chio_chiodos_runtime::generate_runtime_artifact_retention_plan(&profile, &run_ids, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime retention plan: {error}"))
            })?;
    write_pretty_json(report, &plan, "Chiodos runtime retention plan")
}

pub(crate) fn load_runtime_supervisor_profile(
    path: &Path,
) -> Result<chio_chiodos_runtime::RuntimeSupervisorProfile, CliError> {
    let profile = chio_chiodos_runtime::runtime_supervisor_profile_from_json(&read_utf8_json_file(
        path,
        "Chiodos runtime supervisor profile",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime supervisor profile: {error}"))
    })?;
    chio_chiodos_runtime::validate_runtime_supervisor_profile(&profile).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime supervisor profile: {error}"))
    })?;
    Ok(profile)
}
