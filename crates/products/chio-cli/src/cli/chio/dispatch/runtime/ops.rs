use std::collections::BTreeSet;
use std::path::Path;

use crate::CliError;

use super::super::{read_utf8_json_file, unix_now_ms, write_pretty_json};
use super::io::{ensure_runtime_evidence_dir, sorted_child_dirs};

pub(crate) fn cmd_chio_runtime_ops_tick(
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
    let store = chio_runtime::SqliteRuntimeOrchestrationStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chio runtime ops store: {error}")))?;
    let tick = store
        .scheduler_tick_report(&profile, owner_id, now_unix_ms, max_runs)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime scheduler tick: {error}"))
        })?;
    write_pretty_json(report, &tick, "Chio runtime scheduler tick report")
}

pub(crate) fn cmd_chio_runtime_ops_status(
    supervisor_profile: &Path,
    store: &Path,
    evidence_root: &Path,
    provider_bindings: Option<&Path>,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let store = chio_runtime::SqliteRuntimeOrchestrationStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chio runtime ops store: {error}")))?;
    let generated_at = now_unix_ms.unwrap_or_else(unix_now_ms);
    let provider_healthy = provider_bindings
        .map(|path| {
            let bindings = load_runtime_provider_bindings(path)?;
            let health = chio_runtime::generate_runtime_provider_health_report(
                &profile,
                &bindings,
                generated_at,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!("Chio runtime provider health: {error}"))
            })?;
            Ok::<bool, CliError>(health.accepted)
        })
        .transpose()?
        .unwrap_or(false);
    let recorded_run_ids = store.recorded_run_ids().map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime recorded runs: {error}"))
    })?;
    let evidence_sink_healthy = runtime_ops_status_evidence_sink_healthy(
        &profile,
        evidence_root,
        generated_at,
        &recorded_run_ids,
    )?;
    let status = store
        .ops_status_report(
            &profile,
            generated_at,
            evidence_sink_healthy,
            provider_healthy,
        )
        .map_err(|error| CliError::cli_other_error(format!("Chio runtime ops status: {error}")))?;
    write_pretty_json(report, &status, "Chio runtime ops status report")
}

pub(crate) fn runtime_ops_status_evidence_sink_healthy(
    profile: &chio_runtime::RuntimeSupervisorProfile,
    evidence_root: &Path,
    now_unix_ms: u64,
    recorded_run_ids: &[String],
) -> Result<bool, CliError> {
    if !evidence_root.is_dir() {
        return Ok(false);
    }
    let run_dirs = sorted_child_dirs(evidence_root)?;
    if run_dirs.is_empty() {
        return Ok(recorded_run_ids.is_empty());
    }
    let recorded_run_ids = recorded_run_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut healthy_run_ids = BTreeSet::new();
    for run_dir in run_dirs {
        let Some(run_id) = run_dir.file_name().and_then(|name| name.to_str()) else {
            return Ok(false);
        };
        let manifest_json = match read_utf8_json_file(
            &run_dir.join("runtime-evidence-manifest.json"),
            "Chio runtime evidence manifest",
        ) {
            Ok(json) => json,
            Err(_) => return Ok(false),
        };
        let manifest: chio_runtime::RuntimeEvidenceManifest =
            match serde_json::from_str(&manifest_json) {
                Ok(manifest) => manifest,
                Err(_) => return Ok(false),
            };
        let health = match chio_runtime::generate_runtime_evidence_sink_health_report(
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
        healthy_run_ids.insert(run_id.to_string());
    }
    for run_id in recorded_run_ids {
        if !healthy_run_ids.contains(run_id) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn cmd_chio_runtime_ops_recovery_drill(
    supervisor_profile: &Path,
    run_id: &str,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    ensure_runtime_evidence_dir(evidence_root)?;
    let store = chio_runtime::SqliteRuntimeOrchestrationStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chio runtime ops store: {error}")))?;
    let drill = store
        .recovery_drill_report_for_profile(&profile, run_id, now_unix_ms)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime recovery drill: {error}"))
        })?;
    write_pretty_json(report, &drill, "Chio runtime recovery drill report")
}

pub(crate) fn cmd_chio_runtime_ops_evidence_health(
    supervisor_profile: &Path,
    run_id: &str,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let _store = chio_runtime::SqliteRuntimeOrchestrationStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chio runtime ops store: {error}")))?;
    let evidence_dir = evidence_root.join(run_id);
    if !evidence_dir.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "Chio runtime evidence health requires evidence-root/run-id directory {}",
            evidence_dir.display()
        )));
    }
    let manifest_json = read_utf8_json_file(
        &evidence_dir.join("runtime-evidence-manifest.json"),
        "Chio runtime evidence manifest",
    )?;
    let manifest: chio_runtime::RuntimeEvidenceManifest = serde_json::from_str(&manifest_json)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime evidence manifest: {error}"))
        })?;
    let health = chio_runtime::generate_runtime_evidence_sink_health_report(
        run_id,
        &evidence_dir,
        &manifest,
        &profile.evidence_required_roles,
        now_unix_ms,
        true,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chio runtime evidence health: {error}")))?;
    write_pretty_json(report, &health, "Chio runtime evidence health report")
}

pub(crate) fn cmd_chio_runtime_ops_provider_health(
    supervisor_profile: &Path,
    provider_bindings: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let bindings = load_runtime_provider_bindings(provider_bindings)?;
    let health =
        chio_runtime::generate_runtime_provider_health_report(&profile, &bindings, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chio runtime provider health: {error}"))
            })?;
    write_pretty_json(report, &health, "Chio runtime provider health report")
}

pub(crate) fn load_runtime_provider_bindings(
    provider_bindings: &Path,
) -> Result<chio_runtime::RuntimeProviderBindingsDocument, CliError> {
    chio_runtime::runtime_provider_bindings_from_json(&read_utf8_json_file(
        provider_bindings,
        "Chio runtime provider bindings",
    )?)
    .map_err(|error| CliError::cli_other_error(format!("Chio runtime provider bindings: {error}")))
}

pub(crate) fn cmd_chio_runtime_ops_retention_plan(
    retention_profile: &Path,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = chio_runtime::runtime_artifact_retention_profile_from_json(&read_utf8_json_file(
        retention_profile,
        "Chio runtime artifact retention profile",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime artifact retention profile: {error}"))
    })?;
    let _store = chio_runtime::SqliteRuntimeOrchestrationStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chio runtime ops store: {error}")))?;
    if !evidence_root.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "Chio runtime retention plan requires existing evidence root {}",
            evidence_root.display()
        )));
    }
    let run_ids = sorted_child_dirs(evidence_root)?
        .into_iter()
        .filter_map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .collect::<Vec<_>>();
    let plan =
        chio_runtime::generate_runtime_artifact_retention_plan(&profile, &run_ids, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chio runtime retention plan: {error}"))
            })?;
    write_pretty_json(report, &plan, "Chio runtime retention plan")
}

pub(crate) fn load_runtime_supervisor_profile(
    path: &Path,
) -> Result<chio_runtime::RuntimeSupervisorProfile, CliError> {
    let profile = chio_runtime::runtime_supervisor_profile_from_json(&read_utf8_json_file(
        path,
        "Chio runtime supervisor profile",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime supervisor profile: {error}"))
    })?;
    chio_runtime::validate_runtime_supervisor_profile(&profile).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime supervisor profile: {error}"))
    })?;
    Ok(profile)
}
