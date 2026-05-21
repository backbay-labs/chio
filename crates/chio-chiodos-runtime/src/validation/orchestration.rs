use std::collections::BTreeSet;

use crate::error::ChiodosRuntimeError;
use crate::schema::{
    CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA, CHIODOS_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA,
    CHIODOS_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA,
    CHIODOS_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA,
    CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA, CHIODOS_RUNTIME_RUN_CONTRACT_SCHEMA,
    CHIO_RUNTIME_ORCHESTRATION_PLAN_SCHEMA, CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA,
    CHIO_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA, CHIO_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA,
    CHIO_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA, CHIO_RUNTIME_RUN_CONTRACT_SCHEMA,
};
use crate::types::{
    RuntimeOrchestrationPlan, RuntimeOrchestrationPlannedStep, RuntimeOrchestrationProfile,
    RuntimeOrchestrationResumePlan, RuntimeOrchestrationRunReport,
    RuntimeOrchestrationStatusReport, RuntimeOrchestrationStepState, RuntimeRunContract,
};
use crate::validation::common::{
    ensure_optional_sha256, ensure_sha256_hash, validate_acceptance_failure_code,
    validate_non_empty, validate_state_label,
};

pub fn validate_runtime_orchestration_profile(
    profile: &RuntimeOrchestrationProfile,
) -> Result<(), ChiodosRuntimeError> {
    if !is_runtime_orchestration_profile_schema(&profile.schema) {
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
    if !is_runtime_run_contract_schema(&contract.schema) {
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
    if !is_runtime_orchestration_plan_schema(&plan.schema) {
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
    if !is_runtime_orchestration_run_report_schema(&report.schema) {
        return Err(ChiodosRuntimeError::Rejected {
            code: "unsupported_runtime_orchestration_run_report_schema",
            detail: format!(
                "runtime orchestration run report declared unsupported schema {}",
                report.schema
            ),
        });
    }
    validate_acceptance_failure_code(
        report.accepted,
        report.failure_code.as_deref(),
        "runtime_orchestration_run_missing_failure_code",
        "runtime_orchestration_run_unexpected_failure_code",
    )?;
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
    if !is_runtime_orchestration_resume_plan_schema(&plan.schema) {
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

pub fn validate_runtime_orchestration_status_report(
    report: &RuntimeOrchestrationStatusReport,
) -> Result<(), ChiodosRuntimeError> {
    if !is_runtime_orchestration_status_report_schema(&report.schema) {
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

fn is_runtime_orchestration_plan_schema(schema: &str) -> bool {
    matches!(
        schema,
        CHIO_RUNTIME_ORCHESTRATION_PLAN_SCHEMA | CHIODOS_RUNTIME_ORCHESTRATION_PLAN_SCHEMA
    )
}

fn is_runtime_orchestration_profile_schema(schema: &str) -> bool {
    matches!(
        schema,
        CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA | CHIODOS_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA
    )
}

fn is_runtime_run_contract_schema(schema: &str) -> bool {
    matches!(
        schema,
        CHIO_RUNTIME_RUN_CONTRACT_SCHEMA | CHIODOS_RUNTIME_RUN_CONTRACT_SCHEMA
    )
}

fn is_runtime_orchestration_run_report_schema(schema: &str) -> bool {
    matches!(
        schema,
        CHIO_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA
            | CHIODOS_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA
    )
}

fn is_runtime_orchestration_resume_plan_schema(schema: &str) -> bool {
    matches!(
        schema,
        CHIO_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA
            | CHIODOS_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA
    )
}

fn is_runtime_orchestration_status_report_schema(schema: &str) -> bool {
    matches!(
        schema,
        CHIO_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA
            | CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA
    )
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
