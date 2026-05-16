use crate::error::ChiodosRuntimeError;
use crate::schema::*;
use crate::types::*;
use std::collections::BTreeSet;

pub fn validate_runtime_orchestration_profile(
    profile: &RuntimeOrchestrationProfile,
) -> Result<(), ChiodosRuntimeError> {
    if profile.schema != CHIODOS_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_profile_schema",
            detail: format!(
                "runtime orchestration profile declared unsupported schema {}",
                profile.schema
            ),
        });
    }
    validate_non_empty(
        &profile.profile_id,
        "runtime_orchestration_profile_empty_id",
    )?;
    validate_non_empty(
        &profile.local_kernel_id,
        "runtime_orchestration_profile_empty_kernel",
    )?;
    validate_non_empty(
        &profile.verifier_id,
        "runtime_orchestration_profile_empty_verifier",
    )?;
    validate_state_label(&profile.mode, "runtime_orchestration_profile_invalid_mode")?;
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_profile_invalid_window",
            detail: "runtime orchestration profile issued time must precede expiry".to_string(),
        });
    }
    if profile.max_concurrent_runs == 0 {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_profile_zero_concurrency",
            detail: "runtime orchestration profile must allow at least one local run".to_string(),
        });
    }
    let mut codes = BTreeSet::new();
    for code in &profile.fail_closed_on {
        validate_state_label(
            code,
            "runtime_orchestration_profile_invalid_fail_closed_code",
        )?;
        if !codes.insert(code.as_str()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_orchestration_profile_duplicate_fail_closed_code",
                detail: format!("runtime orchestration fail-closed code {code} is duplicated"),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_orchestration_profile_fresh(
    profile: &RuntimeOrchestrationProfile,
    now_unix_ms: u64,
) -> Result<(), ChiodosRuntimeError> {
    validate_runtime_orchestration_profile(profile)?;
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_profile_stale",
            detail: "runtime orchestration profile is not fresh".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_run_contract(
    contract: &RuntimeRunContract,
) -> Result<(), ChiodosRuntimeError> {
    if contract.schema != CHIODOS_RUNTIME_RUN_CONTRACT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_run_contract_schema",
            detail: format!(
                "runtime run contract declared unsupported schema {}",
                contract.schema
            ),
        });
    }
    validate_non_empty(&contract.run_id, "runtime_run_contract_empty_run_id")?;
    ensure_sha256_hash(
        &contract.profile_sha256,
        "runtime_run_contract_invalid_profile_hash",
    )?;
    validate_non_empty(&contract.workflow_id, "runtime_run_contract_empty_workflow")?;
    validate_non_empty(&contract.store_id, "runtime_run_contract_empty_store")?;
    validate_non_empty(
        &contract.evidence_sink_id,
        "runtime_run_contract_empty_evidence_sink",
    )?;
    if contract.expected_step_count == 0 {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_run_contract_zero_steps",
            detail: "runtime run contract must expect at least one step".to_string(),
        });
    }
    if contract.admission_ids.len() != usize::try_from(contract.expected_step_count).unwrap_or(0) {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_run_contract_step_count_mismatch",
            detail: "runtime run contract admission ids must match expected step count".to_string(),
        });
    }
    let mut ids = BTreeSet::new();
    for id in &contract.admission_ids {
        validate_non_empty(id, "runtime_run_contract_empty_admission_id")?;
        if !ids.insert(id.as_str()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_run_contract_duplicate_admission_id",
                detail: format!("runtime run contract repeats admission id {id}"),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_orchestration_plan(
    plan: &RuntimeOrchestrationPlan,
) -> Result<(), ChiodosRuntimeError> {
    if plan.schema != CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_plan_schema",
            detail: format!(
                "runtime orchestration plan declared unsupported schema {}",
                plan.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        plan.accepted,
        plan.failure_code.as_deref(),
        "runtime_orchestration_plan_missing_failure_code",
        "runtime_orchestration_plan_unexpected_failure_code",
    )?;
    validate_non_empty(&plan.run_id, "runtime_orchestration_plan_empty_run_id")?;
    ensure_sha256_hash(
        &plan.profile_sha256,
        "runtime_orchestration_plan_invalid_profile_hash",
    )?;
    ensure_sha256_hash(
        &plan.run_contract_sha256,
        "runtime_orchestration_plan_invalid_contract_hash",
    )?;
    if plan.accepted && plan.planned_steps.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_plan_missing_steps",
            detail: "accepted runtime orchestration plan must carry planned steps".to_string(),
        });
    }
    validate_planned_steps(&plan.planned_steps)
}

pub fn validate_runtime_orchestration_run_report(
    report: &RuntimeOrchestrationRunReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_run_report_schema",
            detail: format!(
                "runtime orchestration run report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.run_id, "runtime_orchestration_run_empty_id")?;
    validate_state_label(&report.status, "runtime_orchestration_run_invalid_status")?;
    ensure_sha256_hash(
        &report.profile_sha256,
        "runtime_orchestration_run_invalid_profile_hash",
    )?;
    ensure_sha256_hash(
        &report.run_contract_sha256,
        "runtime_orchestration_run_invalid_contract_hash",
    )?;
    ensure_optional_sha256(
        report.workflow_run_report_sha256.as_deref(),
        "runtime_orchestration_run_invalid_workflow_hash",
    )?;
    ensure_optional_sha256(
        report.evidence_manifest_sha256.as_deref(),
        "runtime_orchestration_run_invalid_manifest_hash",
    )?;
    ensure_optional_sha256(
        report.proof_regeneration_report_sha256.as_deref(),
        "runtime_orchestration_run_invalid_proof_hash",
    )?;
    ensure_optional_sha256(
        report.verifier_report_sha256.as_deref(),
        "runtime_orchestration_run_invalid_verifier_hash",
    )?;
    if report.accepted && report.status != "proof_accepted" {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_run_accepted_without_proof",
            detail: "accepted runtime orchestration run must be proof_accepted".to_string(),
        });
    }
    if report.accepted
        && (report.workflow_run_report_sha256.is_none()
            || report.evidence_manifest_sha256.is_none()
            || report.proof_regeneration_report_sha256.is_none()
            || report.verifier_report_sha256.is_none())
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_run_missing_accepted_hash",
            detail: "accepted runtime orchestration run must bind proof artifacts".to_string(),
        });
    }
    if report.accepted && report.step_states.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_run_missing_steps",
            detail: "accepted runtime orchestration run must carry step states".to_string(),
        });
    }
    let mut step_indices = BTreeSet::new();
    for step in &report.step_states {
        validate_runtime_orchestration_step_state(step)?;
        if !step_indices.insert(step.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_orchestration_run_duplicate_step",
                detail: format!("runtime orchestration run repeats step {}", step.step_index),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_orchestration_resume_plan(
    plan: &RuntimeOrchestrationResumePlan,
) -> Result<(), ChiodosRuntimeError> {
    if plan.schema != CHIODOS_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_resume_plan_schema",
            detail: format!(
                "runtime orchestration resume plan declared unsupported schema {}",
                plan.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        plan.accepted,
        plan.failure_code.as_deref(),
        "runtime_orchestration_resume_missing_failure_code",
        "runtime_orchestration_resume_unexpected_failure_code",
    )?;
    validate_non_empty(&plan.run_id, "runtime_orchestration_resume_empty_run_id")?;
    if plan.accepted && plan.blocked {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_resume_accepted_blocked",
            detail: "accepted runtime orchestration resume plan cannot be blocked".to_string(),
        });
    }
    Ok(())
}

fn validate_acceptance_failure_code(
    accepted: bool,
    failure_code: Option<&str>,
    missing_code: &'static str,
    unexpected_code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if accepted && failure_code.is_some() {
        return Err(ChiodosRuntimeError::Rejected {
            code: unexpected_code,
            detail: "accepted runtime report cannot carry a failure code".to_string(),
        });
    }
    if !accepted && failure_code.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: missing_code,
            detail: "rejected runtime report must carry a failure code".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_orchestration_status_report(
    report: &RuntimeOrchestrationStatusReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_status_report_schema",
            detail: format!(
                "runtime orchestration status report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.profile_sha256,
        "runtime_orchestration_status_invalid_profile_hash",
    )?;
    ensure_sha256_hash(
        &report.store_path_sha256,
        "runtime_orchestration_status_invalid_store_hash",
    )?;
    validate_state_label(
        &report.store_backend,
        "runtime_orchestration_status_invalid_store_backend",
    )?;
    for status in report.run_counts.keys() {
        validate_state_label(status, "runtime_orchestration_status_invalid_run_state")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_orchestration_status_missing_failure_code",
        "runtime_orchestration_status_unexpected_failure_code",
    )?;
    if report.accepted && report.degraded {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_status_accepted_degraded",
            detail: "accepted runtime orchestration status cannot be degraded".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_proof_drift_report(
    report: &RuntimeProofDriftReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_DRIFT_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_drift_report_schema",
            detail: format!(
                "runtime proof drift report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(
        &report.baseline_run_id,
        "runtime_proof_drift_empty_baseline",
    )?;
    validate_non_empty(
        &report.candidate_run_id,
        "runtime_proof_drift_empty_candidate",
    )?;
    ensure_sha256_hash(
        &report.baseline_manifest_sha256,
        "runtime_proof_drift_invalid_baseline_manifest_hash",
    )?;
    ensure_sha256_hash(
        &report.candidate_manifest_sha256,
        "runtime_proof_drift_invalid_candidate_manifest_hash",
    )?;
    ensure_sha256_hash(
        &report.baseline_proof_regeneration_report_sha256,
        "runtime_proof_drift_invalid_baseline_proof_hash",
    )?;
    ensure_sha256_hash(
        &report.candidate_proof_regeneration_report_sha256,
        "runtime_proof_drift_invalid_candidate_proof_hash",
    )?;
    for drift in &report.semantic_drifts {
        validate_runtime_proof_drift(drift)?;
    }
    for drift in &report.verifier_drifts {
        validate_runtime_proof_drift(drift)?;
    }
    for drift in &report.artifact_drifts {
        validate_non_empty(&drift.role, "runtime_proof_drift_empty_artifact_role")?;
        validate_relative_evidence_path(&drift.path, "runtime_proof_drift_invalid_artifact_path")?;
        ensure_sha256_hash(
            &drift.baseline_sha256,
            "runtime_proof_drift_invalid_baseline_artifact_hash",
        )?;
        ensure_sha256_hash(
            &drift.candidate_sha256,
            "runtime_proof_drift_invalid_candidate_artifact_hash",
        )?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_drift_missing_failure_code",
        "runtime_proof_drift_unexpected_failure_code",
    )?;
    if report.accepted
        && (!report.semantic_drifts.is_empty()
            || !report.artifact_drifts.is_empty()
            || !report.verifier_drifts.is_empty())
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_drift_accepted_with_drifts",
            detail: "accepted runtime proof drift report cannot carry drift rows".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_supervisor_profile(
    profile: &RuntimeSupervisorProfile,
) -> Result<(), ChiodosRuntimeError> {
    if profile.schema != CHIODOS_RUNTIME_SUPERVISOR_PROFILE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_supervisor_profile_schema",
            detail: format!(
                "runtime supervisor profile declared unsupported schema {}",
                profile.schema
            ),
        });
    }
    validate_non_empty(&profile.profile_id, "runtime_supervisor_empty_profile_id")?;
    validate_non_empty(&profile.local_kernel_id, "runtime_supervisor_empty_kernel")?;
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_supervisor_invalid_window",
            detail: "runtime supervisor profile validity window is invalid".to_string(),
        });
    }
    if profile.max_concurrent_runs == 0
        || profile.run_lease_ttl_ms == 0
        || profile.stale_run_after_ms == 0
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_supervisor_invalid_limits",
            detail: "runtime supervisor profile limits must be positive".to_string(),
        });
    }
    for role in &profile.evidence_required_roles {
        validate_state_label(role, "runtime_supervisor_invalid_required_role")?;
    }
    for code in &profile.fail_closed_on {
        validate_state_label(code, "runtime_supervisor_invalid_fail_closed_code")?;
    }
    Ok(())
}

pub fn validate_runtime_run_lease(lease: &RuntimeRunLease) -> Result<(), ChiodosRuntimeError> {
    if lease.schema != CHIODOS_RUNTIME_RUN_LEASE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_run_lease_schema",
            detail: format!(
                "runtime run lease declared unsupported schema {}",
                lease.schema
            ),
        });
    }
    validate_non_empty(&lease.run_id, "runtime_run_lease_empty_run_id")?;
    validate_non_empty(&lease.lease_id, "runtime_run_lease_empty_lease_id")?;
    validate_non_empty(&lease.owner_id, "runtime_run_lease_empty_owner")?;
    validate_state_label(&lease.state, "runtime_run_lease_invalid_state")?;
    if lease.acquired_at_unix_ms > lease.heartbeat_at_unix_ms
        || lease.heartbeat_at_unix_ms > lease.expires_at_unix_ms
    {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_run_lease_invalid_time_order",
            detail: "runtime run lease timestamps are not ordered".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_scheduler_tick_report(
    report: &RuntimeSchedulerTickReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_scheduler_tick_report_schema",
            detail: format!(
                "runtime scheduler tick report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.tick_id, "runtime_scheduler_empty_tick_id")?;
    validate_non_empty(&report.owner_id, "runtime_scheduler_empty_owner")?;
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_scheduler_missing_failure_code",
        "runtime_scheduler_accepted_with_failure_code",
    )?;
    Ok(())
}

pub fn validate_runtime_evidence_sink_health_report(
    report: &RuntimeEvidenceSinkHealthReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_EVIDENCE_SINK_HEALTH_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_evidence_sink_health_report_schema",
            detail: format!(
                "runtime evidence sink health report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.run_id, "runtime_evidence_health_empty_run_id")?;
    ensure_sha256_hash(
        &report.evidence_root_sha256,
        "runtime_evidence_health_invalid_root_hash",
    )?;
    for role in &report.required_roles {
        validate_state_label(role, "runtime_evidence_health_invalid_required_role")?;
    }
    for path in report
        .missing_artifacts
        .iter()
        .chain(report.artifact_hash_mismatches.iter())
        .chain(report.artifact_byte_count_mismatches.iter())
        .chain(report.unexpected_paths.iter())
    {
        validate_relative_evidence_path(path, "runtime_evidence_health_invalid_path")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_evidence_health_missing_failure_code",
        "runtime_evidence_health_accepted_with_failure_code",
    )?;
    Ok(())
}

pub fn validate_runtime_recovery_drill_report(
    report: &RuntimeRecoveryDrillReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_recovery_drill_report_schema",
            detail: format!(
                "runtime recovery drill report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_non_empty(&report.run_id, "runtime_recovery_empty_run_id")?;
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_recovery_missing_failure_code",
        "runtime_recovery_unexpected_failure_code",
    )?;
    if report.accepted && report.blocked {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_recovery_accepted_blocked",
            detail: "accepted runtime recovery drill cannot be blocked".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_artifact_retention_profile(
    profile: &RuntimeArtifactRetentionProfile,
) -> Result<(), ChiodosRuntimeError> {
    if profile.schema != CHIODOS_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_retention_profile_schema",
            detail: format!(
                "runtime retention profile declared unsupported schema {}",
                profile.schema
            ),
        });
    }
    validate_non_empty(&profile.profile_id, "runtime_retention_empty_profile_id")?;
    validate_non_empty(&profile.local_kernel_id, "runtime_retention_empty_kernel")?;
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_retention_invalid_window",
            detail: "runtime retention profile validity window is invalid".to_string(),
        });
    }
    if !profile.dry_run_only {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_retention_mutation_not_allowed",
            detail: "runtime retention planning must be dry-run only".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_artifact_retention_plan(
    plan: &RuntimeArtifactRetentionPlan,
) -> Result<(), ChiodosRuntimeError> {
    if plan.schema != CHIODOS_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_retention_plan_schema",
            detail: format!(
                "runtime retention plan declared unsupported schema {}",
                plan.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        plan.accepted,
        plan.failure_code.as_deref(),
        "runtime_retention_plan_missing_failure_code",
        "runtime_retention_plan_unexpected_failure_code",
    )?;
    ensure_sha256_hash(
        &plan.retention_profile_sha256,
        "runtime_retention_invalid_profile_hash",
    )?;
    for action in &plan.candidate_actions {
        validate_non_empty(&action.run_id, "runtime_retention_empty_run_id")?;
        validate_state_label(&action.action, "runtime_retention_invalid_action")?;
        validate_state_label(&action.reason_code, "runtime_retention_invalid_reason")?;
    }
    Ok(())
}

pub fn validate_runtime_provider_bindings(
    document: &RuntimeProviderBindingsDocument,
) -> Result<(), ChiodosRuntimeError> {
    if document.schema != CHIODOS_RUNTIME_PROVIDER_BINDINGS_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_provider_bindings_schema",
            detail: format!(
                "runtime provider bindings declared unsupported schema {}",
                document.schema
            ),
        });
    }
    let mut provider_ids = BTreeSet::new();
    for binding in &document.bindings {
        validate_non_empty(&binding.provider_id, "runtime_provider_empty_id")?;
        validate_non_empty(&binding.local_kernel_id, "runtime_provider_empty_kernel")?;
        validate_non_empty(&binding.server_id, "runtime_provider_empty_server")?;
        validate_non_empty(&binding.tool_name, "runtime_provider_empty_tool")?;
        if !provider_ids.insert(binding.provider_id.as_str()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_provider_duplicate_id",
                detail: format!("runtime provider binding repeats {}", binding.provider_id),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_provider_health_report(
    report: &RuntimeProviderHealthReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_provider_health_report_schema",
            detail: format!(
                "runtime provider health report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.provider_bindings_sha256,
        "runtime_provider_health_invalid_bindings_hash",
    )?;
    for provider_id in &report.degraded_provider_ids {
        validate_non_empty(provider_id, "runtime_provider_health_empty_degraded_id")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_provider_health_missing_failure_code",
        "runtime_provider_health_unexpected_failure_code",
    )?;
    Ok(())
}

pub fn validate_runtime_ops_status_report(
    report: &RuntimeOpsStatusReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_OPS_STATUS_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_ops_status_report_schema",
            detail: format!(
                "runtime ops status report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.supervisor_profile_sha256,
        "runtime_ops_status_invalid_profile_hash",
    )?;
    for status in report.run_counts.keys() {
        validate_state_label(status, "runtime_ops_status_invalid_run_state")?;
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_ops_status_missing_failure_code",
        "runtime_ops_status_unexpected_failure_code",
    )?;
    if report.accepted && report.degraded {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_ops_status_accepted_degraded",
            detail: "accepted runtime ops status cannot be degraded".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_workflow_run_report(
    report: &RuntimeWorkflowRunReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_workflow_report_schema",
            detail: format!(
                "runtime workflow report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    if !is_sha256_hex(&report.admission_report_sha256) {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_workflow_invalid_admission_report_hash",
            detail: "runtime workflow report admission report hash is not sha256 hex".to_string(),
        });
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_workflow_missing_failure_code",
        "runtime_workflow_unexpected_failure_code",
    )?;
    if report.accepted && report.step_evidence.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_workflow_missing_step_evidence",
            detail: "accepted runtime workflow report must carry step evidence".to_string(),
        });
    }
    if report.accepted && report.proof_regeneration_report_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_workflow_missing_proof_regeneration_report",
            detail: "accepted runtime workflow report must bind proof regeneration report"
                .to_string(),
        });
    }
    if let Some(hash) = report.proof_regeneration_report_sha256.as_deref() {
        ensure_sha256_hash(hash, "runtime_workflow_invalid_proof_regeneration_hash")?;
    }
    let mut step_indices = BTreeSet::new();
    for step in &report.step_evidence {
        validate_runtime_step_evidence(step)?;
        if !step_indices.insert(step.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_workflow_duplicate_step_evidence",
                detail: format!("runtime workflow step {} is duplicated", step.step_index),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_evidence_manifest(
    manifest: &RuntimeEvidenceManifest,
) -> Result<(), ChiodosRuntimeError> {
    if manifest.schema != CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_evidence_manifest_schema",
            detail: format!(
                "runtime evidence manifest declared unsupported schema {}",
                manifest.schema
            ),
        });
    }
    ensure_sha256_hash(
        &manifest.workflow_run_report_sha256,
        "runtime_evidence_manifest_invalid_workflow_report_hash",
    )?;
    ensure_sha256_hash(
        &manifest.proof_regeneration_report_sha256,
        "runtime_evidence_manifest_invalid_proof_report_hash",
    )?;
    if manifest.entries.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_evidence_manifest_missing_entries",
            detail: "runtime evidence manifest must bind at least one artifact".to_string(),
        });
    }
    let mut paths = BTreeSet::new();
    for entry in &manifest.entries {
        validate_relative_evidence_path(&entry.path, "runtime_evidence_manifest_invalid_path")?;
        if entry.role.trim().is_empty() {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_evidence_manifest_empty_role",
                detail: "runtime evidence manifest entry role is empty".to_string(),
            });
        }
        if !paths.insert(entry.path.clone()) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_evidence_manifest_duplicate_path",
                detail: format!(
                    "runtime evidence manifest carries duplicate path {}",
                    entry.path
                ),
            });
        }
        ensure_sha256_hash(
            &entry.sha256,
            "runtime_evidence_manifest_invalid_artifact_hash",
        )?;
    }
    Ok(())
}

pub fn validate_runtime_proof_regeneration_input(
    input: &RuntimeProofRegenerationInput,
) -> Result<(), ChiodosRuntimeError> {
    if input.schema != CHIODOS_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_regeneration_input_schema",
            detail: format!(
                "runtime proof regeneration input declared unsupported schema {}",
                input.schema
            ),
        });
    }
    ensure_sha256_hash(
        &input.evidence_manifest_sha256,
        "runtime_proof_regeneration_input_invalid_manifest_hash",
    )?;
    ensure_sha256_hash(
        &input.workflow_run_report_sha256,
        "runtime_proof_regeneration_input_invalid_workflow_report_hash",
    )?;
    ensure_sha256_hash(
        &input.admission_report_sha256,
        "runtime_proof_regeneration_input_invalid_admission_hash",
    )?;
    ensure_sha256_hash(
        &input.trust_bundle_sha256,
        "runtime_proof_regeneration_input_invalid_trust_bundle_hash",
    )?;
    ensure_sha256_hash(
        &input.verification_context_sha256,
        "runtime_proof_regeneration_input_invalid_context_hash",
    )?;
    if input.source_records.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_input_missing_source_records",
            detail: "runtime proof regeneration input must carry source records".to_string(),
        });
    }
    validate_runtime_proof_source_records(&input.source_records)
}

pub fn validate_runtime_proof_regeneration_report(
    report: &RuntimeProofRegenerationReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_regeneration_report_schema",
            detail: format!(
                "runtime proof regeneration report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_regeneration_missing_failure_code",
        "runtime_proof_regeneration_unexpected_failure_code",
    )?;
    if report.accepted && report.source_records.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_source_records",
            detail: "accepted runtime proof regeneration report must carry source records"
                .to_string(),
        });
    }
    if report.accepted && report.proof_package_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_package_hash",
            detail: "accepted runtime proof regeneration report must bind proof package hash"
                .to_string(),
        });
    }
    if report.accepted && report.verifier_report_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_verifier_report_hash",
            detail: "accepted runtime proof regeneration report must bind verifier report hash"
                .to_string(),
        });
    }
    if report.accepted && report.workflow_receipt_sha256.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_regeneration_missing_workflow_receipt_hash",
            detail: "accepted runtime proof regeneration report must bind workflow receipt hash"
                .to_string(),
        });
    }
    if let Some(hash) = report.proof_package_sha256.as_deref() {
        ensure_sha256_hash(hash, "runtime_proof_regeneration_invalid_package_hash")?;
    }
    if let Some(hash) = report.verifier_report_sha256.as_deref() {
        ensure_sha256_hash(
            hash,
            "runtime_proof_regeneration_invalid_verifier_report_hash",
        )?;
    }
    if let Some(hash) = report.workflow_receipt_sha256.as_deref() {
        ensure_sha256_hash(
            hash,
            "runtime_proof_regeneration_invalid_workflow_receipt_hash",
        )?;
    }
    validate_runtime_proof_source_records(&report.source_records)?;
    Ok(())
}

pub fn validate_runtime_proof_parity_report(
    report: &RuntimeProofParityReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_RUNTIME_PROOF_PARITY_REPORT_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_proof_parity_report_schema",
            detail: format!(
                "runtime proof parity report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    ensure_sha256_hash(
        &report.static_proof_package_sha256,
        "runtime_proof_parity_invalid_static_package_hash",
    )?;
    ensure_sha256_hash(
        &report.runtime_proof_package_sha256,
        "runtime_proof_parity_invalid_runtime_package_hash",
    )?;
    ensure_sha256_hash(
        &report.static_verifier_report_sha256,
        "runtime_proof_parity_invalid_static_report_hash",
    )?;
    ensure_sha256_hash(
        &report.runtime_verifier_report_sha256,
        "runtime_proof_parity_invalid_runtime_report_hash",
    )?;
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_proof_parity_missing_failure_code",
        "runtime_proof_parity_unexpected_failure_code",
    )?;
    if report.compared_fields.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_parity_missing_compared_fields",
            detail: "runtime proof parity report must name compared fields".to_string(),
        });
    }
    if report.accepted && !report.mismatches.is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_proof_parity_accepted_with_mismatches",
            detail: "accepted runtime proof parity report cannot carry mismatches".to_string(),
        });
    }
    for mismatch in &report.mismatches {
        if mismatch.field.trim().is_empty() {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_proof_parity_empty_mismatch_field",
                detail: "runtime proof parity mismatch field is empty".to_string(),
            });
        }
        ensure_sha256_hash(
            &mismatch.static_value_sha256,
            "runtime_proof_parity_invalid_static_value_hash",
        )?;
        ensure_sha256_hash(
            &mismatch.runtime_value_sha256,
            "runtime_proof_parity_invalid_runtime_value_hash",
        )?;
    }
    Ok(())
}

fn validate_runtime_proof_source_records(
    source_records: &[RuntimeProofSourceRecord],
) -> Result<(), ChiodosRuntimeError> {
    let mut step_indices = BTreeSet::new();
    for record in source_records {
        if !step_indices.insert(record.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_proof_regeneration_duplicate_source_record",
                detail: format!(
                    "runtime proof source record step {} is duplicated",
                    record.step_index
                ),
            });
        }
        ensure_sha256_hash(
            &record.admission_report_sha256,
            "runtime_proof_regeneration_invalid_admission_hash",
        )?;
        ensure_sha256_hash(
            &record.tool_receipt_sha256,
            "runtime_proof_regeneration_invalid_tool_receipt_hash",
        )?;
        ensure_sha256_hash(
            &record.bilateral_dsse_sha256,
            "runtime_proof_regeneration_invalid_dsse_hash",
        )?;
        ensure_sha256_hash(
            &record.workflow_step_sha256,
            "runtime_proof_regeneration_invalid_workflow_step_hash",
        )?;
    }
    Ok(())
}

pub(crate) fn validate_relative_evidence_path(
    path: &str,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || trimmed != path
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.contains("//")
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ChiodosRuntimeError::Rejected {
            code,
            detail: format!("runtime evidence path {path:?} is not a safe relative path"),
        });
    }
    Ok(())
}

fn validate_runtime_step_evidence(step: &RuntimeStepEvidence) -> Result<(), ChiodosRuntimeError> {
    if step.schema != CHIODOS_RUNTIME_STEP_EVIDENCE_SCHEMA {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_step_evidence_schema",
            detail: format!(
                "runtime step evidence declared unsupported schema {}",
                step.schema
            ),
        });
    }
    if step.admission_id.trim().is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_admission_id",
            detail: "runtime step evidence must bind admission id".to_string(),
        });
    }
    ensure_sha256_hash(
        &step.admission_report_sha256,
        "runtime_step_evidence_invalid_admission_hash",
    )?;
    ensure_sha256_hash(
        &step.tool_receipt_sha256,
        "runtime_step_evidence_invalid_tool_receipt_hash",
    )?;
    ensure_sha256_hash(
        &step.output_sha256,
        "runtime_step_evidence_invalid_output_hash",
    )?;
    ensure_sha256_hash(
        &step.bilateral_dsse_sha256,
        "runtime_step_evidence_invalid_dsse_hash",
    )?;
    ensure_sha256_hash(
        &step.workflow_step_sha256,
        "runtime_step_evidence_invalid_workflow_step_hash",
    )?;
    if let Some(parent) = step.parent_receipt_sha256.as_deref() {
        ensure_sha256_hash(parent, "runtime_step_evidence_invalid_parent_hash")?;
    }
    if step.consistency_anchor.trim().is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_consistency_anchor",
            detail: "runtime step evidence must bind consistency anchor".to_string(),
        });
    }
    if step.destructive && step.governance_receipt_id.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_step_evidence_missing_governance",
            detail: "destructive runtime step evidence must bind governance receipt".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn rejected<T>(code: &'static str, detail: &str) -> Result<T, ChiodosRuntimeError> {
    Err(ChiodosRuntimeError::Rejected {
        code,
        detail: detail.to_string(),
    })
}

pub(crate) fn ensure_sha256_hash(
    hash: &str,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if is_sha256_hex(hash) {
        return Ok(());
    }
    Err(ChiodosRuntimeError::Rejected {
        code,
        detail: format!("runtime evidence hash {hash} is not sha256 hex"),
    })
}

fn ensure_optional_sha256(
    hash: Option<&str>,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if let Some(hash) = hash {
        ensure_sha256_hash(hash, code)?;
    }
    Ok(())
}

pub(crate) fn validate_non_empty(
    value: &str,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if value.trim().is_empty() {
        return Err(ChiodosRuntimeError::Rejected {
            code,
            detail: "runtime orchestration field must not be empty".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn validate_state_label(
    value: &str,
    code: &'static str,
) -> Result<(), ChiodosRuntimeError> {
    if value.trim().is_empty()
        || value.trim() != value
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(ChiodosRuntimeError::Rejected {
            code,
            detail: format!("runtime orchestration label {value:?} is invalid"),
        });
    }
    Ok(())
}

fn validate_planned_steps(
    steps: &[RuntimeOrchestrationPlannedStep],
) -> Result<(), ChiodosRuntimeError> {
    let mut indices = BTreeSet::new();
    for step in steps {
        if !indices.insert(step.step_index) {
            return Err(ChiodosRuntimeError::Rejected {
                code: "runtime_orchestration_plan_duplicate_step",
                detail: format!(
                    "runtime orchestration plan repeats step {}",
                    step.step_index
                ),
            });
        }
        validate_non_empty(
            &step.admission_id,
            "runtime_orchestration_plan_empty_admission_id",
        )?;
        validate_state_label(&step.state, "runtime_orchestration_plan_invalid_step_state")?;
    }
    Ok(())
}

pub(crate) fn validate_runtime_orchestration_step_state(
    state: &RuntimeOrchestrationStepState,
) -> Result<(), ChiodosRuntimeError> {
    validate_non_empty(
        &state.admission_id,
        "runtime_orchestration_step_empty_admission_id",
    )?;
    validate_state_label(&state.state, "runtime_orchestration_step_invalid_state")?;
    ensure_optional_sha256(
        state.admission_report_sha256.as_deref(),
        "runtime_orchestration_step_invalid_admission_hash",
    )?;
    ensure_optional_sha256(
        state.tool_receipt_sha256.as_deref(),
        "runtime_orchestration_step_invalid_receipt_hash",
    )?;
    if state.destructive && state.lease_id.is_none() {
        return Err(ChiodosRuntimeError::Rejected {
            code: "runtime_orchestration_step_missing_destructive_lease",
            detail: "destructive runtime orchestration step must bind lease id".to_string(),
        });
    }
    Ok(())
}

fn validate_runtime_proof_drift(drift: &RuntimeProofDrift) -> Result<(), ChiodosRuntimeError> {
    validate_non_empty(&drift.field, "runtime_proof_drift_empty_field")?;
    ensure_sha256_hash(
        &drift.baseline_value_sha256,
        "runtime_proof_drift_invalid_baseline_value_hash",
    )?;
    ensure_sha256_hash(
        &drift.candidate_value_sha256,
        "runtime_proof_drift_invalid_candidate_value_hash",
    )?;
    validate_state_label(&drift.severity, "runtime_proof_drift_invalid_severity")
}

pub(crate) fn is_sha256_hex(hash: &str) -> bool {
    hash.len() == 64 && hash.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

pub(crate) fn required_string_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<String, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value
            .get(*field)
            .and_then(|item| item.as_str())
            .filter(|item| !item.trim().is_empty())
        {
            return Ok(item.to_string());
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}

pub(crate) fn required_u64_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<u64, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value.get(*field).and_then(|item| item.as_u64()) {
            return Ok(item);
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}

pub(crate) fn required_f64_any(
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<f64, ChiodosRuntimeError> {
    for field in fields {
        if let Some(item) = value.get(*field).and_then(|item| item.as_f64()) {
            return Ok(item);
        }
    }
    Err(ChiodosRuntimeError::Rejected {
        code: "invalid_pheromone_query_report",
        detail: format!(
            "runtime pheromone advisory is missing {}",
            fields.join(" or ")
        ),
    })
}
