use serde::{Deserialize, Serialize};

pub const WORKFLOW_PREFLIGHT_PLAN_SCHEMA: &str = "chio.workflow.preflight-plan.v1";
pub const WORKFLOW_PREFLIGHT_REPORT_SCHEMA: &str = "chio.workflow.preflight-report.v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkflowPreflightError {
    #[error("unsupported workflow preflight schema for {field}: {schema}")]
    UnsupportedSchema { field: &'static str, schema: String },
    #[error("invalid workflow preflight plan: {0}")]
    InvalidPlan(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPreflightPlan {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub parent_task: WorkflowPreflightParentTask,
    pub child_tasks: Vec<WorkflowPreflightChildTask>,
    pub route_plans: Vec<WorkflowRoutePlanPreflight>,
    pub approvals: Vec<WorkflowApprovalPreflight>,
    pub registry_support: WorkflowRegistrySupport,
    pub budget_pool: WorkflowBudgetPool,
    pub revocation: WorkflowRevocationPreflight,
    pub planning_artifacts: Vec<WorkflowPlanningArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPreflightParentTask {
    pub task_id: String,
    pub scope: WorkflowPreflightScope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPreflightChildTask {
    pub task_id: String,
    pub parent_task_id: String,
    pub requested_scope: WorkflowPreflightScope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPreflightScope {
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    pub route_refs: Vec<String>,
    pub approval_refs: Vec<String>,
    pub required_schemas: Vec<String>,
    pub budget_minor: u64,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRoutePlanPreflight {
    pub route_ref: String,
    pub supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowApprovalPreflight {
    pub approval_ref: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRegistrySupport {
    pub supported_schemas: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowBudgetPool {
    pub currency: String,
    pub total_minor: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRevocationPreflight {
    pub epoch_id: String,
    pub root_sha256: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPlanningArtifact {
    pub artifact_ref: String,
    pub artifact_class: String,
    pub satisfies_claims: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowPreflightVerdict {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPreflightReport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub plan_id: String,
    pub verdict: WorkflowPreflightVerdict,
    pub evidence_class: String,
    pub verified_claims: Vec<String>,
    pub rejected_checks: Vec<WorkflowPreflightCheck>,
    pub live_authority_claims: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPreflightCheck {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

impl WorkflowPreflightCheck {
    pub(super) fn new(
        code: &'static str,
        message: impl Into<String>,
        task_id: Option<String>,
    ) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            task_id,
        }
    }
}
