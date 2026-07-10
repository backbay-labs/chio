//! Read-only workflow preflight validation.

mod scope;
mod types;
mod validation;

pub use types::{
    WorkflowApprovalPreflight, WorkflowBudgetPool, WorkflowPlanningArtifact,
    WorkflowPreflightCheck, WorkflowPreflightChildTask, WorkflowPreflightError,
    WorkflowPreflightParentTask, WorkflowPreflightPlan, WorkflowPreflightReport,
    WorkflowPreflightScope, WorkflowPreflightVerdict, WorkflowRegistrySupport,
    WorkflowRevocationPreflight, WorkflowRoutePlanPreflight, WORKFLOW_PREFLIGHT_PLAN_SCHEMA,
    WORKFLOW_PREFLIGHT_REPORT_SCHEMA,
};

use scope::collect_child_scope_checks;
use validation::{collect_plan_gate_checks, validate_plan_shape};

const CLAIM_PREFLIGHT_CHILD_SCOPE_BOUNDED: &str = "claim.workflow.preflight_child_scope_bounded";
const CLAIM_PREFLIGHT_PLANNING_ONLY: &str = "claim.workflow.preflight_planning_only";

pub fn evaluate_workflow_preflight(
    plan: &WorkflowPreflightPlan,
) -> Result<WorkflowPreflightReport, WorkflowPreflightError> {
    validate_plan_shape(plan)?;

    let mut rejected_checks = Vec::new();
    collect_child_scope_checks(plan, &mut rejected_checks);
    collect_plan_gate_checks(plan, &mut rejected_checks);

    let verdict = if rejected_checks.is_empty() {
        WorkflowPreflightVerdict::Accepted
    } else {
        WorkflowPreflightVerdict::Rejected
    };
    let verified_claims = if verdict == WorkflowPreflightVerdict::Accepted {
        vec![
            CLAIM_PREFLIGHT_CHILD_SCOPE_BOUNDED.to_string(),
            CLAIM_PREFLIGHT_PLANNING_ONLY.to_string(),
        ]
    } else {
        Vec::new()
    };

    Ok(WorkflowPreflightReport {
        schema: WORKFLOW_PREFLIGHT_REPORT_SCHEMA.to_string(),
        id: format!("workflow-preflight-report-{}", plan.id),
        issued_at: plan.issued_at.clone(),
        plan_id: plan.id.clone(),
        verdict,
        evidence_class: "planning".to_string(),
        verified_claims,
        rejected_checks,
        live_authority_claims: Vec::new(),
    })
}
