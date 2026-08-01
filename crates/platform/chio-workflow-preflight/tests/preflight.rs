use std::error::Error;
use std::fs;
use std::path::PathBuf;

use chio_workflow_preflight::{
    evaluate_workflow_preflight, WorkflowPreflightError, WorkflowPreflightPlan,
    WorkflowPreflightVerdict,
};

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|platform_dir| platform_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .ok_or("workspace root is parent of crates/platform/chio-workflow-preflight")?
        .to_path_buf();
    Ok(root)
}

fn fixture_path(case_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    Ok(workspace_root()?.join(format!(
        "fixtures/proof-room/workflow-preflight/{case_name}/preflight-plan.json"
    )))
}

fn load_plan(case_name: &str) -> Result<WorkflowPreflightPlan, Box<dyn Error>> {
    let bytes = fs::read(fixture_path(case_name)?)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[test]
fn workflow_preflight_accepts_planning_fixture() -> Result<(), Box<dyn Error>> {
    let plan = load_plan("valid-child-scope")?;
    let report = evaluate_workflow_preflight(&plan)?;

    assert_eq!(report.schema, "chio.workflow.preflight-report.v1");
    assert_eq!(report.plan_id, "workflow-preflight-valid-child-scope");
    assert_eq!(report.verdict, WorkflowPreflightVerdict::Accepted);
    assert_eq!(report.evidence_class, "planning");
    assert!(report.live_authority_claims.is_empty());
    assert!(report
        .verified_claims
        .iter()
        .any(|claim| { claim == "claim.workflow.preflight_child_scope_bounded" }));
    assert!(report
        .verified_claims
        .iter()
        .any(|claim| { claim == "claim.workflow.preflight_planning_only" }));
    Ok(())
}

#[test]
fn workflow_preflight_rejects_broader_child_scope() -> Result<(), Box<dyn Error>> {
    let plan = load_plan("broader-child-scope")?;
    let report = evaluate_workflow_preflight(&plan)?;

    assert_eq!(report.verdict, WorkflowPreflightVerdict::Rejected);
    assert!(report.rejected_checks.iter().any(|check| {
        check.code == "workflow_preflight_child_scope_exceeds_parent"
            && check
                .message
                .contains("child task task-child-payment requested action payment.capture")
    }));
    assert!(report.live_authority_claims.is_empty());
    Ok(())
}

#[test]
fn workflow_preflight_rejects_aggregate_child_budget_over_parent() -> Result<(), Box<dyn Error>> {
    let mut plan = load_plan("valid-child-scope")?;
    plan.budget_pool.total_minor = 10_000;
    plan.child_tasks[0].requested_scope.budget_minor = 4_000;
    let mut second_child = plan.child_tasks[0].clone();
    second_child.task_id = "task-child-inventory".to_string();
    second_child.requested_scope.budget_minor = 4_000;
    plan.child_tasks.push(second_child);

    let report = evaluate_workflow_preflight(&plan)?;

    assert_eq!(report.verdict, WorkflowPreflightVerdict::Rejected);
    assert!(report.rejected_checks.iter().any(|check| {
        check.code == "workflow_preflight_child_scope_exceeds_parent"
            && check
                .message
                .contains("child task budget total 8000 exceeds parent budget 5000")
    }));
    assert!(report.live_authority_claims.is_empty());
    Ok(())
}

#[test]
fn workflow_preflight_rejects_blank_child_action() -> Result<(), Box<dyn Error>> {
    let mut plan = load_plan("valid-child-scope")?;
    plan.child_tasks[0].requested_scope.actions = vec!["".to_string()];

    let Err(error) = evaluate_workflow_preflight(&plan) else {
        panic!("blank child action must reject preflight shape");
    };

    assert!(matches!(
        error,
        WorkflowPreflightError::InvalidPlan(message)
            if message.contains("child_tasks.requested_scope.actions entry must not be empty")
    ));
    Ok(())
}

#[test]
fn workflow_preflight_rejects_blank_child_resource() -> Result<(), Box<dyn Error>> {
    let mut plan = load_plan("valid-child-scope")?;
    plan.child_tasks[0].requested_scope.resources = vec!["".to_string()];

    let Err(error) = evaluate_workflow_preflight(&plan) else {
        panic!("blank child resource must reject preflight shape");
    };

    assert!(matches!(
        error,
        WorkflowPreflightError::InvalidPlan(message)
            if message.contains("child_tasks.requested_scope.resources entry must not be empty")
    ));
    Ok(())
}

#[test]
fn workflow_preflight_rejects_planning_artifact_claiming_authority() -> Result<(), Box<dyn Error>> {
    let plan = load_plan("planning-artifact-claims-authority")?;
    let report = evaluate_workflow_preflight(&plan)?;

    assert_eq!(report.verdict, WorkflowPreflightVerdict::Rejected);
    assert!(report.rejected_checks.iter().any(|check| {
        check.code == "workflow_preflight_planning_artifact_claims_authority"
            && check
                .message
                .contains("cannot satisfy live authority claims")
    }));
    assert!(report.live_authority_claims.is_empty());
    Ok(())
}

#[test]
fn workflow_preflight_rejects_live_authority_claim_in_planning_artifact(
) -> Result<(), Box<dyn Error>> {
    let mut plan = load_plan("valid-child-scope")?;
    plan.planning_artifacts[0].artifact_class = "live_authority".to_string();
    plan.planning_artifacts[0].satisfies_claims =
        vec!["claim.runtime.authority_granted".to_string()];

    let report = evaluate_workflow_preflight(&plan)?;

    assert_eq!(report.verdict, WorkflowPreflightVerdict::Rejected);
    assert!(report.rejected_checks.iter().any(|check| {
        check.code == "workflow_preflight_planning_artifact_claims_authority"
            && check
                .message
                .contains("cannot satisfy live authority claims")
    }));
    assert!(report.live_authority_claims.is_empty());
    Ok(())
}
