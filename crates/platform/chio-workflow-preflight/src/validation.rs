use std::collections::{BTreeMap, BTreeSet};

use super::types::{
    WorkflowPreflightCheck, WorkflowPreflightError, WorkflowPreflightPlan, WorkflowPreflightScope,
    WORKFLOW_PREFLIGHT_PLAN_SCHEMA,
};

pub(super) fn validate_plan_shape(
    plan: &WorkflowPreflightPlan,
) -> Result<(), WorkflowPreflightError> {
    if plan.schema != WORKFLOW_PREFLIGHT_PLAN_SCHEMA {
        return Err(WorkflowPreflightError::UnsupportedSchema {
            field: "workflow preflight plan",
            schema: plan.schema.clone(),
        });
    }
    require_non_empty(&plan.id, "id")?;
    require_non_empty(&plan.issued_at, "issued_at")?;
    require_non_empty(&plan.parent_task.task_id, "parent_task.task_id")?;
    validate_scope(&plan.parent_task.scope, "parent_task.scope")?;
    if plan.child_tasks.is_empty() {
        return Err(WorkflowPreflightError::InvalidPlan(
            "child_tasks must not be empty".to_string(),
        ));
    }
    for child in &plan.child_tasks {
        require_non_empty(&child.task_id, "child_tasks.task_id")?;
        require_non_empty(&child.parent_task_id, "child_tasks.parent_task_id")?;
        validate_scope(&child.requested_scope, "child_tasks.requested_scope")?;
    }
    require_non_empty(&plan.budget_pool.currency, "budget_pool.currency")?;
    require_non_empty(&plan.revocation.epoch_id, "revocation.epoch_id")?;
    validate_sha256_hex(&plan.revocation.root_sha256, "revocation.root_sha256")?;
    require_non_empty(&plan.revocation.status, "revocation.status")?;
    Ok(())
}

pub(super) fn collect_plan_gate_checks(
    plan: &WorkflowPreflightPlan,
    checks: &mut Vec<WorkflowPreflightCheck>,
) {
    collect_route_checks(plan, checks);
    collect_approval_checks(plan, checks);
    collect_registry_checks(plan, checks);
    collect_budget_checks(plan, checks);
    collect_revocation_checks(plan, checks);
    collect_planning_artifact_checks(plan, checks);
}

fn collect_route_checks(plan: &WorkflowPreflightPlan, checks: &mut Vec<WorkflowPreflightCheck>) {
    let mut seen_route_support = BTreeMap::new();
    for route in &plan.route_plans {
        if let Some(previous_supported) =
            seen_route_support.insert(route.route_ref.as_str(), route.supported)
        {
            if previous_supported != route.supported {
                checks.push(WorkflowPreflightCheck::new(
                    "workflow_preflight_route_conflict",
                    format!(
                        "route ref {} has conflicting support entries",
                        route.route_ref
                    ),
                    None,
                ));
            }
        }
    }

    let route_support = plan
        .route_plans
        .iter()
        .map(|route| (route.route_ref.as_str(), route.supported))
        .collect::<BTreeMap<_, _>>();

    for child in &plan.child_tasks {
        for route_ref in &child.requested_scope.route_refs {
            if route_support.get(route_ref.as_str()) != Some(&true) {
                checks.push(WorkflowPreflightCheck::new(
                    "workflow_preflight_route_not_supported",
                    format!(
                        "child task {} requested unsupported route ref {}",
                        child.task_id, route_ref
                    ),
                    Some(child.task_id.clone()),
                ));
            }
        }
    }
}

fn collect_approval_checks(plan: &WorkflowPreflightPlan, checks: &mut Vec<WorkflowPreflightCheck>) {
    let mut seen_approval_status = BTreeMap::new();
    for approval in &plan.approvals {
        if let Some(previous_status) =
            seen_approval_status.insert(approval.approval_ref.as_str(), approval.status.as_str())
        {
            if previous_status != approval.status {
                checks.push(WorkflowPreflightCheck::new(
                    "workflow_preflight_approval_conflict",
                    format!(
                        "approval ref {} has conflicting status entries",
                        approval.approval_ref
                    ),
                    None,
                ));
            }
        }
    }

    let approval_status = plan
        .approvals
        .iter()
        .map(|approval| (approval.approval_ref.as_str(), approval.status.as_str()))
        .collect::<BTreeMap<_, _>>();

    for child in &plan.child_tasks {
        for approval_ref in &child.requested_scope.approval_refs {
            if approval_status.get(approval_ref.as_str()) != Some(&"approved") {
                checks.push(WorkflowPreflightCheck::new(
                    "workflow_preflight_approval_not_ready",
                    format!(
                        "child task {} requested approval ref {} before approval was ready",
                        child.task_id, approval_ref
                    ),
                    Some(child.task_id.clone()),
                ));
            }
        }
    }
}

fn collect_registry_checks(plan: &WorkflowPreflightPlan, checks: &mut Vec<WorkflowPreflightCheck>) {
    let supported = plan
        .registry_support
        .supported_schemas
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    for schema in &plan.parent_task.scope.required_schemas {
        if !supported.contains(schema.as_str()) {
            checks.push(WorkflowPreflightCheck::new(
                "workflow_preflight_schema_not_supported",
                format!("parent task requested unsupported schema {schema}"),
                Some(plan.parent_task.task_id.clone()),
            ));
        }
    }
    for child in &plan.child_tasks {
        for schema in &child.requested_scope.required_schemas {
            if !supported.contains(schema.as_str()) {
                checks.push(WorkflowPreflightCheck::new(
                    "workflow_preflight_schema_not_supported",
                    format!(
                        "child task {} requested unsupported schema {}",
                        child.task_id, schema
                    ),
                    Some(child.task_id.clone()),
                ));
            }
        }
    }
}

fn collect_budget_checks(plan: &WorkflowPreflightPlan, checks: &mut Vec<WorkflowPreflightCheck>) {
    if plan.parent_task.scope.currency != plan.budget_pool.currency {
        checks.push(WorkflowPreflightCheck::new(
            "workflow_preflight_budget_currency_mismatch",
            format!(
                "parent task currency {} does not match budget pool currency {}",
                plan.parent_task.scope.currency, plan.budget_pool.currency
            ),
            Some(plan.parent_task.task_id.clone()),
        ));
    }
    if plan.parent_task.scope.budget_minor > plan.budget_pool.total_minor {
        checks.push(WorkflowPreflightCheck::new(
            "workflow_preflight_budget_pool_exceeded",
            format!(
                "parent task budget {} exceeds budget pool {}",
                plan.parent_task.scope.budget_minor, plan.budget_pool.total_minor
            ),
            Some(plan.parent_task.task_id.clone()),
        ));
    }

    let mut child_total = 0_u64;
    for child in &plan.child_tasks {
        if child.requested_scope.currency != plan.budget_pool.currency {
            checks.push(WorkflowPreflightCheck::new(
                "workflow_preflight_budget_currency_mismatch",
                format!(
                    "child task {} currency {} does not match budget pool currency {}",
                    child.task_id, child.requested_scope.currency, plan.budget_pool.currency
                ),
                Some(child.task_id.clone()),
            ));
        }
        match child_total.checked_add(child.requested_scope.budget_minor) {
            Some(total) => child_total = total,
            None => checks.push(WorkflowPreflightCheck::new(
                "workflow_preflight_budget_pool_exceeded",
                "child task budgets overflowed u64 accounting",
                Some(child.task_id.clone()),
            )),
        }
    }

    if child_total > plan.budget_pool.total_minor {
        checks.push(WorkflowPreflightCheck::new(
            "workflow_preflight_budget_pool_exceeded",
            format!(
                "child task budget total {} exceeds budget pool {}",
                child_total, plan.budget_pool.total_minor
            ),
            None,
        ));
    }
}

fn collect_revocation_checks(
    plan: &WorkflowPreflightPlan,
    checks: &mut Vec<WorkflowPreflightCheck>,
) {
    if plan.revocation.status != "fresh" {
        checks.push(WorkflowPreflightCheck::new(
            "workflow_preflight_revocation_not_fresh",
            format!(
                "revocation epoch {} has status {}",
                plan.revocation.epoch_id, plan.revocation.status
            ),
            None,
        ));
    }
}

fn collect_planning_artifact_checks(
    plan: &WorkflowPreflightPlan,
    checks: &mut Vec<WorkflowPreflightCheck>,
) {
    for artifact in &plan.planning_artifacts {
        if !artifact.satisfies_claims.is_empty() {
            checks.push(WorkflowPreflightCheck::new(
                "workflow_preflight_planning_artifact_claims_authority",
                format!(
                    "planning artifact {} with class {} cannot satisfy live authority claims",
                    artifact.artifact_ref, artifact.artifact_class
                ),
                None,
            ));
        }
    }
}

fn validate_scope(
    scope: &WorkflowPreflightScope,
    field: &'static str,
) -> Result<(), WorkflowPreflightError> {
    if scope.actions.is_empty() {
        return Err(WorkflowPreflightError::InvalidPlan(format!(
            "{field}.actions must not be empty"
        )));
    }
    if scope.resources.is_empty() {
        return Err(WorkflowPreflightError::InvalidPlan(format!(
            "{field}.resources must not be empty"
        )));
    }
    validate_scope_entries(&scope.actions, field, "actions")?;
    validate_scope_entries(&scope.resources, field, "resources")?;
    validate_scope_entries(&scope.route_refs, field, "route_refs")?;
    validate_scope_entries(&scope.approval_refs, field, "approval_refs")?;
    validate_scope_entries(&scope.required_schemas, field, "required_schemas")?;
    require_non_empty(&scope.currency, "scope.currency")?;
    Ok(())
}

fn validate_scope_entries(
    entries: &[String],
    scope_field: &'static str,
    entry_field: &'static str,
) -> Result<(), WorkflowPreflightError> {
    for entry in entries {
        if entry.trim().is_empty() {
            return Err(WorkflowPreflightError::InvalidPlan(format!(
                "{scope_field}.{entry_field} entry must not be empty"
            )));
        }
    }
    Ok(())
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), WorkflowPreflightError> {
    if value.trim().is_empty() {
        Err(WorkflowPreflightError::InvalidPlan(format!(
            "{field} must not be empty"
        )))
    } else {
        Ok(())
    }
}

fn validate_sha256_hex(value: &str, field: &'static str) -> Result<(), WorkflowPreflightError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(WorkflowPreflightError::InvalidPlan(format!(
            "{field} must be a 64-character hex SHA-256 digest"
        )));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(WorkflowPreflightError::InvalidPlan(format!(
            "{field} must use lowercase hex"
        )));
    }
    Ok(())
}
