use std::path::Path;

use crate::CliError;

use super::super::{read_utf8_json_file, write_pretty_json};
use super::io::{
    ensure_runtime_evidence_dir, load_runtime_orchestration_profile, load_runtime_run_contract,
    sorted_child_dirs,
};

pub(crate) fn cmd_chio_runtime_orchestrate_lint(
    profile: &Path,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let profile_sha256 =
        chio_runtime::runtime_orchestration_profile_sha256(&profile).map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime orchestration profile hash: {error}"))
        })?;
    let report_value = chio_runtime::RuntimeOrchestrationStatusReport {
        schema: chio_runtime::CHIO_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA.to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: profile.issued_at_unix_ms,
        profile_sha256: profile_sha256.clone(),
        store_backend: "profile_lint".to_string(),
        store_path_sha256: profile_sha256,
        run_counts: std::collections::BTreeMap::new(),
        consumed_lease_count: 0,
        trust_floor_count: 0,
        latest_failure_code: None,
        evidence_sink_healthy: true,
        ready: true,
        degraded: false,
    };
    write_pretty_json(
        report,
        &report_value,
        "Chio runtime orchestration lint report",
    )
}

pub(crate) fn cmd_chio_runtime_orchestrate_plan(
    profile: &Path,
    run_contract: &Path,
    store: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let run_contract = load_runtime_run_contract(run_contract)?;
    let store = chio_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime orchestration store: {error}"))
    })?;
    ensure_runtime_evidence_dir(evidence_dir)?;
    let plan = chio_runtime::build_runtime_orchestration_plan(&profile, &run_contract, now_unix_ms)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime orchestration plan: {error}"))
        })?;
    if plan.accepted {
        store
            .record_run_state(&plan.run_id, "planned", None, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chio runtime orchestration planned run state: {error}"
                ))
            })?;
        for step in &plan.planned_steps {
            store
                .record_run_step_state(
                    &plan.run_id,
                    chio_runtime::RuntimeOrchestrationStepState {
                        step_index: step.step_index,
                        admission_id: step.admission_id.clone(),
                        state: step.state.clone(),
                        destructive: false,
                        admission_report_sha256: None,
                        tool_receipt_sha256: None,
                        lease_id: None,
                    },
                )
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chio runtime orchestration planned step state: {error}"
                    ))
                })?;
        }
    }
    write_pretty_json(report, &plan, "Chio runtime orchestration plan")
}

pub(crate) fn cmd_chio_runtime_orchestrate_run(
    profile: &Path,
    run_contract: &Path,
    store: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let run_contract = load_runtime_run_contract(run_contract)?;
    let profile_sha256 =
        chio_runtime::runtime_orchestration_profile_sha256(&profile).map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime orchestration profile hash: {error}"))
        })?;
    let run_contract_sha256 =
        chio_runtime::runtime_run_contract_sha256(&run_contract).map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime run contract hash: {error}"))
        })?;
    let store = chio_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime orchestration store: {error}"))
    })?;
    ensure_runtime_evidence_dir(evidence_dir)?;
    let evidence = match chio_runtime::load_runtime_orchestration_evidence(evidence_dir) {
        Ok(evidence) => evidence,
        Err(error) => {
            let failure_code = error.code().to_string();
            store
                .record_run_state(
                    &run_contract.run_id,
                    "terminal_failure",
                    Some(&failure_code),
                    now_unix_ms,
                )
                .map_err(|store_error| {
                    CliError::cli_other_error(format!(
                        "Chio runtime orchestration failed run state: {store_error}"
                    ))
                })?;
            let report_value = chio_runtime::RuntimeOrchestrationRunReport {
                schema: chio_runtime::CHIO_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA.to_string(),
                run_id: run_contract.run_id,
                accepted: false,
                failure_code: Some(failure_code),
                status: "terminal_failure".to_string(),
                generated_at_unix_ms: now_unix_ms,
                profile_sha256,
                run_contract_sha256,
                workflow_run_report_sha256: None,
                evidence_manifest_sha256: None,
                proof_regeneration_report_sha256: None,
                verifier_report_sha256: None,
                step_states: Vec::new(),
                checks: vec!["runtime_orchestration.evidence_load_failed".to_string()],
            };
            return write_pretty_json(
                report,
                &report_value,
                "Chio runtime orchestration run report",
            );
        }
    };
    let mut accepted = evidence.proof_regeneration_report.accepted;
    let mut failure_code = evidence.proof_regeneration_report.failure_code.clone();
    if profile_sha256 != run_contract.profile_sha256 {
        accepted = false;
        failure_code = Some("runtime_orchestration_profile_hash_mismatch".to_string());
    } else if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        accepted = false;
        failure_code = Some("runtime_orchestration_profile_stale".to_string());
    } else if !chio_runtime::runtime_orchestration_evidence_is_fresh(
        &profile,
        &evidence,
        now_unix_ms,
    ) {
        accepted = false;
        failure_code = Some("runtime_orchestration_evidence_stale".to_string());
    } else if evidence.proof_regeneration_report.accepted {
        if let Err(failure) =
            chio_runtime::validate_runtime_orchestration_evidence_binding(&run_contract, &evidence)
        {
            accepted = false;
            failure_code = Some(failure.code().to_string());
        } else if !evidence.verifier_report_accepted {
            accepted = false;
            failure_code = Some(
                evidence
                    .verifier_report_failure_code
                    .clone()
                    .unwrap_or_else(|| {
                        "runtime_orchestration_verifier_report_rejected".to_string()
                    }),
            );
        }
    }
    let status = if accepted {
        "proof_accepted"
    } else {
        "terminal_failure"
    };
    store
        .record_run_state(
            &run_contract.run_id,
            status,
            failure_code.as_deref(),
            now_unix_ms,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime orchestration run state: {error}"))
        })?;
    let mut step_states = Vec::new();
    for step in evidence.workflow_run_report.step_evidence {
        let state = chio_runtime::RuntimeOrchestrationStepState {
            step_index: step.step_index,
            admission_id: step.admission_id,
            state: status.to_string(),
            destructive: step.destructive,
            admission_report_sha256: Some(step.admission_report_sha256),
            tool_receipt_sha256: Some(step.tool_receipt_sha256),
            lease_id: step.lease_id,
        };
        store
            .record_run_step_state(&run_contract.run_id, state.clone())
            .map_err(|error| {
                CliError::cli_other_error(format!("Chio runtime orchestration step state: {error}"))
            })?;
        step_states.push(state);
    }
    for entry in &evidence.manifest.entries {
        store
            .record_evidence_artifact(&run_contract.run_id, entry, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chio runtime orchestration evidence artifact: {error}"
                ))
            })?;
    }
    let report_value = chio_runtime::RuntimeOrchestrationRunReport {
        schema: chio_runtime::CHIO_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA.to_string(),
        run_id: run_contract.run_id,
        accepted,
        failure_code,
        status: status.to_string(),
        generated_at_unix_ms: now_unix_ms,
        profile_sha256,
        run_contract_sha256,
        workflow_run_report_sha256: Some(evidence.workflow_report_sha256),
        evidence_manifest_sha256: Some(evidence.manifest_sha256),
        proof_regeneration_report_sha256: Some(evidence.proof_report_sha256),
        verifier_report_sha256: evidence.verifier_report_sha256,
        step_states,
        checks: vec![
            "runtime_orchestration.evidence_sink_loaded".to_string(),
            "runtime_orchestration.proof_regeneration_bound".to_string(),
        ],
    };
    write_pretty_json(
        report,
        &report_value,
        "Chio runtime orchestration run report",
    )
}

pub(crate) fn cmd_chio_runtime_orchestrate_resume(
    profile: &Path,
    resume_plan: &Path,
    store: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let mut resolved: chio_runtime::RuntimeOrchestrationResumePlan = serde_json::from_str(
        &read_utf8_json_file(resume_plan, "Chio runtime orchestration resume plan")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio runtime orchestration resume plan parse: {error}"
        ))
    })?;
    chio_runtime::validate_runtime_orchestration_resume_plan(&resolved).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime orchestration resume plan: {error}"))
    })?;
    let _store = chio_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime orchestration store: {error}"))
    })?;
    ensure_runtime_evidence_dir(evidence_dir)?;
    resolved.schema = chio_runtime::CHIO_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA.to_string();
    resolved.generated_at_unix_ms = now_unix_ms;
    resolved
        .checks
        .push("runtime_orchestration.resume_inputs_loaded".to_string());
    let profile_stale =
        now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms;
    if profile_stale {
        resolved.accepted = false;
        resolved.failure_code = Some("runtime_orchestration_profile_stale".to_string());
        resolved.blocked = true;
        resolved.next_step_index = None;
        resolved.reusable_step_indices.clear();
        resolved
            .checks
            .push("runtime_orchestration.profile_window".to_string());
    }
    chio_runtime::validate_runtime_orchestration_resume_plan(&resolved).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime orchestration resume report: {error}"))
    })?;
    write_pretty_json(
        report,
        &resolved,
        "Chio runtime orchestration resume report",
    )
}

pub(crate) fn cmd_chio_runtime_orchestrate_status(
    profile: &Path,
    store: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let profile_sha256 =
        chio_runtime::runtime_orchestration_profile_sha256(&profile).map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime orchestration profile hash: {error}"))
        })?;
    let store = chio_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime orchestration store: {error}"))
    })?;
    let evidence_sink_healthy = runtime_orchestration_recorded_evidence_healthy(
        &profile,
        &store,
        evidence_dir,
        now_unix_ms,
    )?;
    let report_value = store
        .status_report(&profile, profile_sha256, now_unix_ms, evidence_sink_healthy)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime orchestration status: {error}"))
        })?;
    write_pretty_json(
        report,
        &report_value,
        "Chio runtime orchestration status report",
    )
}

fn runtime_orchestration_recorded_evidence_healthy(
    profile: &chio_runtime::RuntimeOrchestrationProfile,
    store: &chio_runtime::SqliteRuntimeOrchestrationStore,
    evidence_dir: &Path,
    now_unix_ms: u64,
) -> Result<bool, CliError> {
    let run_ids = store.recorded_run_ids().map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime orchestration recorded runs: {error}"))
    })?;
    if run_ids.len() <= 1 {
        return chio_runtime::runtime_orchestration_evidence_sink_healthy(
            profile,
            evidence_dir,
            now_unix_ms,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio runtime orchestration evidence health: {error}"
            ))
        });
    }
    for run_id in run_ids {
        let run_dir = evidence_dir.join(&run_id);
        if !chio_runtime::runtime_orchestration_evidence_sink_healthy(
            profile,
            &run_dir,
            now_unix_ms,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chio runtime orchestration evidence health for {run_id}: {error}"
            ))
        })? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn cmd_chio_runtime_orchestrate_drift(
    profile: &Path,
    runs_dir: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    if since_unix_ms > until_unix_ms {
        return Err(CliError::cli_other_error(
            "Chio runtime drift since-unix-ms must not exceed until-unix-ms".to_string(),
        ));
    }
    chio_runtime::validate_runtime_orchestration_profile_fresh(&profile, until_unix_ms).map_err(
        |error| CliError::cli_other_error(format!("Chio runtime proof drift profile: {error}")),
    )?;
    let mut runs_in_window = Vec::new();
    for run_dir in sorted_child_dirs(runs_dir)? {
        let evidence =
            chio_runtime::load_runtime_orchestration_evidence(&run_dir).map_err(|error| {
                CliError::cli_other_error(format!("Chio runtime orchestration evidence: {error}"))
            })?;
        if evidence.manifest.generated_at_unix_ms >= since_unix_ms
            && evidence.manifest.generated_at_unix_ms <= until_unix_ms
        {
            if !chio_runtime::runtime_orchestration_evidence_is_fresh(
                &profile,
                &evidence,
                until_unix_ms,
            ) {
                return Err(CliError::cli_other_error(
                    "Chio runtime drift evidence is outside the orchestration profile window"
                        .to_string(),
                ));
            }
            chio_runtime::validate_runtime_orchestration_evidence_integrity(&evidence).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "Chio runtime drift evidence integrity: {error}"
                    ))
                },
            )?;
            runs_in_window.push((evidence.manifest.generated_at_unix_ms, run_dir, evidence));
        }
    }
    runs_in_window.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    if runs_in_window.len() < 2 {
        return Err(CliError::cli_other_error(
            "Chio runtime drift requires at least two run directories inside the requested time window"
                .to_string(),
        ));
    }
    let (_, _, baseline) = runs_in_window.remove(0);
    let mut selected_drift = None;
    for (_, _, candidate) in runs_in_window {
        let drift = chio_runtime::generate_runtime_proof_drift_report(
            &baseline.manifest,
            &candidate.manifest,
            &baseline.proof_regeneration_report,
            &candidate.proof_regeneration_report,
            until_unix_ms,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime proof drift report: {error}"))
        })?;
        let drift_detected = !drift.accepted;
        selected_drift = Some(drift);
        if drift_detected {
            break;
        }
    }
    let Some(drift) = selected_drift else {
        return Err(CliError::cli_other_error(
            "Chio runtime drift requires a candidate run inside the requested time window"
                .to_string(),
        ));
    };
    write_pretty_json(report, &drift, "Chio runtime proof drift report")
}
