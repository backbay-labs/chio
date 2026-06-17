use std::error::Error;
use std::fs;
use std::path::PathBuf;

use chio_workflow::preflight::{
    evaluate_workflow_preflight, WorkflowPreflightPlan, WorkflowPreflightVerdict,
};

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|platform_dir| platform_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .ok_or("workspace root is parent of crates/platform/chio-workflow")?
        .to_path_buf();
    Ok(root)
}

#[test]
fn workflow_preflight_reexport_accepts_planning_fixture() -> Result<(), Box<dyn Error>> {
    let path = workspace_root()?
        .join("fixtures/proof-room/workflow-preflight/valid-child-scope/preflight-plan.json");
    let bytes = fs::read(path)?;
    let plan: WorkflowPreflightPlan = serde_json::from_slice(&bytes)?;
    let report = evaluate_workflow_preflight(&plan)?;

    assert_eq!(report.verdict, WorkflowPreflightVerdict::Accepted);
    assert!(report
        .verified_claims
        .iter()
        .any(|claim| claim == "claim.workflow.preflight_child_scope_bounded"));
    assert!(report
        .verified_claims
        .iter()
        .any(|claim| claim == "claim.workflow.preflight_planning_only"));
    Ok(())
}
