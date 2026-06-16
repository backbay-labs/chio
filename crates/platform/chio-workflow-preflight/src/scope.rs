use std::collections::BTreeSet;

use super::types::{WorkflowPreflightCheck, WorkflowPreflightPlan};

const CHILD_SCOPE_EXCEEDS_PARENT: &str = "workflow_preflight_child_scope_exceeds_parent";

pub(super) fn collect_child_scope_checks(
    plan: &WorkflowPreflightPlan,
    checks: &mut Vec<WorkflowPreflightCheck>,
) {
    let parent_scope = &plan.parent_task.scope;
    let mut child_budget_total = 0_u64;
    let mut child_budget_overflowed = false;

    for child in &plan.child_tasks {
        if child.parent_task_id != plan.parent_task.task_id {
            checks.push(WorkflowPreflightCheck::new(
                CHILD_SCOPE_EXCEEDS_PARENT,
                format!(
                    "child task {} references parent {} but preflight parent is {}",
                    child.task_id, child.parent_task_id, plan.parent_task.task_id
                ),
                Some(child.task_id.clone()),
            ));
        }

        collect_missing_values(
            checks,
            &child.task_id,
            "action",
            &parent_scope.actions,
            &child.requested_scope.actions,
        );
        collect_missing_values(
            checks,
            &child.task_id,
            "resource",
            &parent_scope.resources,
            &child.requested_scope.resources,
        );
        collect_missing_values(
            checks,
            &child.task_id,
            "route ref",
            &parent_scope.route_refs,
            &child.requested_scope.route_refs,
        );
        collect_missing_values(
            checks,
            &child.task_id,
            "approval ref",
            &parent_scope.approval_refs,
            &child.requested_scope.approval_refs,
        );
        collect_missing_values(
            checks,
            &child.task_id,
            "schema",
            &parent_scope.required_schemas,
            &child.requested_scope.required_schemas,
        );

        if child.requested_scope.currency != parent_scope.currency {
            checks.push(WorkflowPreflightCheck::new(
                CHILD_SCOPE_EXCEEDS_PARENT,
                format!(
                    "child task {} requested currency {} outside parent currency {}",
                    child.task_id, child.requested_scope.currency, parent_scope.currency
                ),
                Some(child.task_id.clone()),
            ));
        }
        if child.requested_scope.budget_minor > parent_scope.budget_minor {
            checks.push(WorkflowPreflightCheck::new(
                CHILD_SCOPE_EXCEEDS_PARENT,
                format!(
                    "child task {} requested budget {} outside parent budget {}",
                    child.task_id, child.requested_scope.budget_minor, parent_scope.budget_minor
                ),
                Some(child.task_id.clone()),
            ));
        }
        match child_budget_total.checked_add(child.requested_scope.budget_minor) {
            Some(total) => child_budget_total = total,
            None => child_budget_overflowed = true,
        }
    }

    if child_budget_overflowed || child_budget_total > parent_scope.budget_minor {
        checks.push(WorkflowPreflightCheck::new(
            CHILD_SCOPE_EXCEEDS_PARENT,
            format!(
                "child task budget total {} exceeds parent budget {}",
                child_budget_total, parent_scope.budget_minor
            ),
            None,
        ));
    }
}

fn collect_missing_values(
    checks: &mut Vec<WorkflowPreflightCheck>,
    task_id: &str,
    label: &str,
    parent_values: &[String],
    child_values: &[String],
) {
    let parent = parent_values
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if parent.contains("*") {
        return;
    }

    for value in child_values {
        if !parent.contains(value.as_str()) {
            checks.push(WorkflowPreflightCheck::new(
                CHILD_SCOPE_EXCEEDS_PARENT,
                format!("child task {task_id} requested {label} {value} outside parent scope"),
                Some(task_id.to_string()),
            ));
        }
    }
}
