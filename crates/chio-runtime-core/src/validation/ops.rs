use std::collections::BTreeSet;

use crate::error::ChioRuntimeError;
use crate::schema::{
    CHIO_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA, CHIO_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA,
    CHIO_RUNTIME_OPS_STATUS_REPORT_SCHEMA, CHIO_RUNTIME_PROVIDER_BINDINGS_SCHEMA,
    CHIO_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA, CHIO_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA,
    CHIO_RUNTIME_RUN_LEASE_SCHEMA, CHIO_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA,
    CHIO_RUNTIME_SUPERVISOR_PROFILE_SCHEMA,
};
use crate::types::{
    RuntimeArtifactRetentionPlan, RuntimeArtifactRetentionProfile, RuntimeOpsStatusReport,
    RuntimeProviderBindingsDocument, RuntimeProviderHealthReport, RuntimeRecoveryDrillReport,
    RuntimeRunLease, RuntimeSchedulerTickReport, RuntimeSupervisorProfile,
};
use crate::validation::common::{
    ensure_sha256_hash, validate_acceptance_failure_code, validate_non_empty, validate_state_label,
};

pub fn validate_runtime_supervisor_profile(
    profile: &RuntimeSupervisorProfile,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_supervisor_profile_schema(&profile.schema) {
        return Err(ChioRuntimeError::Rejected {
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
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_supervisor_invalid_window",
            detail: "runtime supervisor profile validity window is invalid".to_string(),
        });
    }
    if profile.max_concurrent_runs == 0
        || profile.run_lease_ttl_ms == 0
        || profile.stale_run_after_ms == 0
    {
        return Err(ChioRuntimeError::Rejected {
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

pub fn validate_runtime_run_lease(lease: &RuntimeRunLease) -> Result<(), ChioRuntimeError> {
    if !is_runtime_run_lease_schema(&lease.schema) {
        return Err(ChioRuntimeError::Rejected {
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
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_run_lease_invalid_time_order",
            detail: "runtime run lease timestamps are not ordered".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_scheduler_tick_report(
    report: &RuntimeSchedulerTickReport,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_scheduler_tick_report_schema(&report.schema) {
        return Err(ChioRuntimeError::Rejected {
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

pub fn validate_runtime_recovery_drill_report(
    report: &RuntimeRecoveryDrillReport,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_recovery_drill_report_schema(&report.schema) {
        return Err(ChioRuntimeError::Rejected {
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
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_recovery_accepted_blocked",
            detail: "accepted runtime recovery drill cannot be blocked".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_artifact_retention_profile(
    profile: &RuntimeArtifactRetentionProfile,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_artifact_retention_profile_schema(&profile.schema) {
        return Err(ChioRuntimeError::Rejected {
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
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_retention_invalid_window",
            detail: "runtime retention profile validity window is invalid".to_string(),
        });
    }
    if !profile.dry_run_only {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_retention_mutation_not_allowed",
            detail: "runtime retention planning must be dry-run only".to_string(),
        });
    }
    Ok(())
}

pub fn validate_runtime_artifact_retention_plan(
    plan: &RuntimeArtifactRetentionPlan,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_artifact_retention_plan_schema(&plan.schema) {
        return Err(ChioRuntimeError::Rejected {
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
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_provider_bindings_schema(&document.schema) {
        return Err(ChioRuntimeError::Rejected {
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
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_provider_duplicate_id",
                detail: format!("runtime provider binding repeats {}", binding.provider_id),
            });
        }
    }
    Ok(())
}

pub fn validate_runtime_provider_health_report(
    report: &RuntimeProviderHealthReport,
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_provider_health_report_schema(&report.schema) {
        return Err(ChioRuntimeError::Rejected {
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
) -> Result<(), ChioRuntimeError> {
    if !is_runtime_ops_status_report_schema(&report.schema) {
        return Err(ChioRuntimeError::Rejected {
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
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_ops_status_accepted_degraded",
            detail: "accepted runtime ops status cannot be degraded".to_string(),
        });
    }
    Ok(())
}

fn is_runtime_run_lease_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_RUN_LEASE_SCHEMA)
}

fn is_runtime_supervisor_profile_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_SUPERVISOR_PROFILE_SCHEMA)
}

fn is_runtime_artifact_retention_profile_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_ARTIFACT_RETENTION_PROFILE_SCHEMA)
}

fn is_runtime_provider_bindings_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_PROVIDER_BINDINGS_SCHEMA)
}

fn is_runtime_scheduler_tick_report_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA)
}

fn is_runtime_recovery_drill_report_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_RECOVERY_DRILL_REPORT_SCHEMA)
}

fn is_runtime_artifact_retention_plan_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_ARTIFACT_RETENTION_PLAN_SCHEMA)
}

fn is_runtime_provider_health_report_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA)
}

fn is_runtime_ops_status_report_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_OPS_STATUS_REPORT_SCHEMA)
}
