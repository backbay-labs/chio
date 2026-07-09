//! Workflow authority -- validates each step against declared scope and budget.
//!
//! The `WorkflowAuthority` manages the lifecycle of a skill execution:
//! beginning, step validation, step recording, and finalization into a
//! signed `WorkflowReceipt`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use tracing::debug;

use crate::grant::SkillGrant;
use crate::manifest::{SkillManifest, SkillStep};
use crate::receipt::{
    StepOutcome, StepRecord, WorkflowOutcome, WorkflowReceipt, WorkflowReceiptBody,
    WORKFLOW_RECEIPT_SCHEMA,
};

/// Errors from the workflow authority.
#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    /// The skill grant does not authorize the requested skill.
    #[error("skill grant does not authorize skill '{skill_id}' version '{version}'")]
    UnauthorizedSkill { skill_id: String, version: String },

    /// A step is not authorized by the skill grant.
    #[error("step {step_index} ({server}:{tool}) is not authorized")]
    UnauthorizedStep {
        step_index: usize,
        server: String,
        tool: String,
    },

    /// A step is out of order (when strict ordering is required).
    #[error("step {step_index} is out of order (expected step {expected})")]
    StepOutOfOrder { step_index: usize, expected: usize },

    /// The workflow budget has been exceeded.
    #[error("budget exceeded: spent {spent_units} of {limit_units} {currency}")]
    BudgetExceeded {
        limit_units: u64,
        spent_units: u64,
        currency: String,
    },

    /// A step reported cost in a currency that does not match the declared budget.
    #[error("budget currency mismatch: expected {expected_currency}, got {actual_currency}")]
    BudgetCurrencyMismatch {
        expected_currency: String,
        actual_currency: String,
    },

    /// The workflow time limit has been exceeded.
    #[error("time limit exceeded: {elapsed_secs}s of {limit_secs}s allowed")]
    TimeLimitExceeded { elapsed_secs: u64, limit_secs: u64 },

    /// The maximum number of executions has been reached.
    #[error("execution limit reached: {limit} executions")]
    ExecutionLimitReached { limit: u32 },

    /// The workflow is in an invalid state for the requested operation.
    #[error("workflow is in invalid state: {0}")]
    InvalidState(String),

    /// Receipt signing failed.
    #[error("receipt signing failed: {0}")]
    SigningFailed(String),
}

/// A workflow execution in progress.
///
/// Created by `WorkflowAuthority::begin()` and consumed by `finalize()`.
#[derive(Debug)]
pub struct WorkflowExecution {
    /// Unique execution ID (becomes the receipt ID).
    pub id: String,
    /// Skill ID from the manifest.
    pub skill_id: String,
    /// Skill version.
    pub skill_version: String,
    /// Agent performing the execution.
    pub agent_id: String,
    /// Session binding.
    pub session_id: Option<String>,
    /// Capability ID.
    pub capability_id: String,
    /// Whether this execution reserved capacity from a limited grant.
    limited_execution_reserved: bool,
    /// Unix timestamp when execution started.
    pub started_at: u64,
    /// Steps completed so far.
    pub step_records: Vec<StepRecord>,
    /// Budget spent so far (in policy currency minor units).
    pub budget_spent: u64,
    /// Budget limit from grant or manifest.
    pub budget_limit: Option<MonetaryAmount>,
    /// Time limit in seconds.
    pub time_limit_secs: Option<u64>,
    /// Whether the execution is still active.
    pub active: bool,
    /// Explicit terminal outcome for fail-closed aborts that do not map to
    /// completed step state.
    terminal_outcome: Option<WorkflowOutcome>,
}

pub struct StepExecutionRecordInput {
    pub outcome: StepOutcome,
    pub duration_ms: u64,
    pub cost: Option<MonetaryAmount>,
    pub tool_receipt_id: Option<String>,
    pub output_hash: Option<String>,
}

#[derive(Debug, Default)]
struct LimitedExecutionCount {
    completed: u32,
    in_flight: u32,
}

impl WorkflowExecution {
    /// Return the number of completed steps.
    #[must_use]
    pub fn completed_steps(&self) -> usize {
        self.step_records
            .iter()
            .filter(|s| s.outcome == StepOutcome::Success)
            .count()
    }
}

/// Workflow authority that validates and manages skill executions.
pub struct WorkflowAuthority {
    signing_key: Keypair,
    /// Number of workflow executions successfully started.
    execution_count: AtomicU32,
    /// Per-capability reservations for grants with an execution limit.
    limited_execution_counts: Mutex<HashMap<String, LimitedExecutionCount>>,
    /// Monotonic counter incremented on every `begin()` call. Used to
    /// disambiguate execution ids when multiple `begin()` invocations land
    /// in the same wall-clock second on the same authority. Stored as an
    /// atomic so `begin()` can keep its `&self` receiver.
    begin_counter: AtomicU64,
}

impl WorkflowAuthority {
    /// Create a new workflow authority with the given signing key.
    pub fn new(signing_key: Keypair) -> Self {
        Self {
            signing_key,
            execution_count: AtomicU32::new(0),
            limited_execution_counts: Mutex::new(HashMap::new()),
            begin_counter: AtomicU64::new(0),
        }
    }

    /// Begin a new workflow execution.
    ///
    /// Validates the grant against the manifest before starting.
    pub fn begin(
        &self,
        manifest: &SkillManifest,
        grant: &SkillGrant,
        agent_id: String,
        capability_id: String,
        session_id: Option<String>,
    ) -> Result<WorkflowExecution, WorkflowError> {
        if grant.skill_id != manifest.skill_id || grant.skill_version != manifest.version {
            return Err(WorkflowError::UnauthorizedSkill {
                skill_id: manifest.skill_id.clone(),
                version: manifest.version.clone(),
            });
        }

        for step in &manifest.steps {
            if !grant.authorizes_step(&step.server_id, &step.tool_name) {
                return Err(WorkflowError::UnauthorizedStep {
                    step_index: step.index,
                    server: step.server_id.clone(),
                    tool: step.tool_name.clone(),
                });
            }
        }

        let limited_execution_reserved =
            self.reserve_execution(&capability_id, grant.max_executions)?;
        self.execution_count.fetch_add(1, Ordering::AcqRel);

        let budget_limit = grant
            .budget_envelope
            .clone()
            .or_else(|| manifest.budget_envelope.clone());

        let time_limit_secs = grant.max_duration_secs.or(manifest.max_duration_secs);

        let now = current_unix_secs();

        debug!(
            skill_id = %manifest.skill_id,
            agent_id = %agent_id,
            "beginning workflow execution"
        );

        // Mix a monotonic per-call counter and the agent id into the id so
        // that multiple `begin()` calls within the same wall-clock second
        // on the same authority do not collide. Receipts are downstream-
        // keyed off this id; collisions would let one execution shadow
        // another. We use an atomic so `begin()` can keep `&self`, and
        // increment per call (not per finalize) so back-to-back `begin()`
        // calls before any `finalize()` still produce distinct ids.
        let seq = self.begin_counter.fetch_add(1, Ordering::Relaxed);
        let id = format!("wf-{now}-{seq}-{agent_id}");
        Ok(WorkflowExecution {
            id,
            skill_id: manifest.skill_id.clone(),
            skill_version: manifest.version.clone(),
            agent_id,
            session_id,
            capability_id,
            limited_execution_reserved,
            started_at: now,
            step_records: Vec::new(),
            budget_spent: 0,
            budget_limit,
            time_limit_secs,
            active: true,
            terminal_outcome: None,
        })
    }

    /// Validate a step before execution.
    ///
    /// Checks authorization, ordering, budget, and time constraints.
    pub fn validate_step(
        &self,
        execution: &WorkflowExecution,
        step: &SkillStep,
        grant: &SkillGrant,
    ) -> Result<(), WorkflowError> {
        if !execution.active {
            return Err(WorkflowError::InvalidState(
                "workflow is no longer active".to_string(),
            ));
        }

        if !grant.authorizes_step(&step.server_id, &step.tool_name) {
            return Err(WorkflowError::UnauthorizedStep {
                step_index: step.index,
                server: step.server_id.clone(),
                tool: step.tool_name.clone(),
            });
        }

        let completed_steps = execution.completed_steps();
        if !grant.is_step_in_order(step.index, completed_steps) {
            return Err(WorkflowError::StepOutOfOrder {
                step_index: step.index,
                expected: completed_steps,
            });
        }

        validate_time_limit(execution)?;

        Ok(())
    }

    /// Record the result of a step execution.
    pub fn record_step(
        &self,
        execution: &mut WorkflowExecution,
        step: &SkillStep,
        input: StepExecutionRecordInput,
    ) -> Result<(), WorkflowError> {
        if !execution.active {
            return Err(WorkflowError::InvalidState(
                "workflow is no longer active".to_string(),
            ));
        }

        let time_limit_exceeded = match validate_time_limit(execution) {
            Ok(()) => None,
            Err(WorkflowError::TimeLimitExceeded {
                elapsed_secs,
                limit_secs,
            }) => Some((elapsed_secs, limit_secs)),
            Err(err) => return Err(err),
        };

        let budget_currency_mismatch = input.cost.as_ref().and_then(|cost| {
            if let Some(ref limit) = step.budget_limit {
                if cost.currency != limit.currency {
                    return Some((
                        limit.currency.clone(),
                        cost.currency.clone(),
                        format!(
                            "step cost currency {} does not match budget currency {}",
                            cost.currency, limit.currency
                        ),
                    ));
                }
            }
            if let Some(ref limit) = execution.budget_limit {
                if cost.currency != limit.currency {
                    return Some((
                        limit.currency.clone(),
                        cost.currency.clone(),
                        format!(
                            "step cost currency {} does not match budget currency {}",
                            cost.currency, limit.currency
                        ),
                    ));
                }
            }
            None
        });

        let step_budget_exceeded = if budget_currency_mismatch.is_none() {
            input.cost.as_ref().and_then(|cost| {
                step.budget_limit.as_ref().and_then(|limit| {
                    if cost.units > limit.units {
                        Some((limit.units, cost.units, limit.currency.clone()))
                    } else {
                        None
                    }
                })
            })
        } else {
            None
        };

        if budget_currency_mismatch.is_none() {
            if let Some(ref c) = input.cost {
                execution.budget_spent = execution.budget_spent.saturating_add(c.units);
            }
        }

        // Always record the step so the audit trail is complete, even when
        // the budget is exceeded on this step.
        let record = StepRecord {
            step_index: step.index,
            server_id: step.server_id.clone(),
            tool_name: step.tool_name.clone(),
            allowed: matches!(input.outcome, StepOutcome::Success | StepOutcome::Failed),
            tool_receipt_id: input.tool_receipt_id,
            outcome: input.outcome.clone(),
            duration_ms: input.duration_ms,
            cost: input.cost,
            output_hash: input.output_hash,
            bilateral_dsse_sha256: None,
            governance_receipt_id: None,
            parent_receipt_sha256: None,
            consistency_anchor: None,
            destructive: None,
        };

        execution.step_records.push(record);

        if let Some((expected_currency, actual_currency, reason)) = budget_currency_mismatch {
            execution.active = false;
            execution.terminal_outcome = Some(WorkflowOutcome::Denied { reason });
            return Err(WorkflowError::BudgetCurrencyMismatch {
                expected_currency,
                actual_currency,
            });
        }

        if let Some((limit_units, spent_units, currency)) = step_budget_exceeded {
            execution.active = false;
            execution.terminal_outcome = Some(WorkflowOutcome::BudgetExceeded {
                limit_units,
                spent_units,
                currency: currency.clone(),
            });
            execution.budget_limit = Some(MonetaryAmount {
                units: limit_units,
                currency: currency.clone(),
            });
            return Err(WorkflowError::BudgetExceeded {
                limit_units,
                spent_units,
                currency,
            });
        }

        // Check budget envelope after recording so that finalize() includes
        // the offending step in the receipt.
        if let Some(ref limit) = execution.budget_limit {
            if execution.budget_spent > limit.units {
                execution.active = false;
                execution.terminal_outcome = Some(WorkflowOutcome::BudgetExceeded {
                    limit_units: limit.units,
                    spent_units: execution.budget_spent,
                    currency: limit.currency.clone(),
                });
                return Err(WorkflowError::BudgetExceeded {
                    limit_units: limit.units,
                    spent_units: execution.budget_spent,
                    currency: limit.currency.clone(),
                });
            }
        }

        if let Some((elapsed_secs, limit_secs)) = time_limit_exceeded {
            execution.active = false;
            execution.terminal_outcome = Some(WorkflowOutcome::TimedOut {
                limit_secs,
                elapsed_secs,
            });
            return Err(WorkflowError::TimeLimitExceeded {
                elapsed_secs,
                limit_secs,
            });
        }

        if input.outcome == StepOutcome::Failed || input.outcome == StepOutcome::Denied {
            execution.active = false;
        }

        Ok(())
    }

    /// Finalize a workflow execution and produce a signed receipt.
    pub fn finalize(
        &self,
        mut execution: WorkflowExecution,
    ) -> Result<WorkflowReceipt, WorkflowError> {
        execution.active = false;
        let capability_id = execution.capability_id.clone();

        let completed_at = current_unix_secs();
        let duration_ms = completed_at
            .saturating_sub(execution.started_at)
            .saturating_mul(1000);
        let has_recorded_failure = execution
            .step_records
            .iter()
            .any(|step| matches!(step.outcome, StepOutcome::Failed | StepOutcome::Denied));
        if execution.terminal_outcome.is_none() && !has_recorded_failure {
            if let Some(limit_secs) = execution.time_limit_secs {
                let elapsed_secs = completed_at.saturating_sub(execution.started_at);
                if elapsed_secs >= limit_secs {
                    execution.terminal_outcome = Some(WorkflowOutcome::TimedOut {
                        limit_secs,
                        elapsed_secs,
                    });
                }
            }
        }

        let outcome = determine_outcome(&execution);

        let total_cost = if execution.budget_spent > 0 {
            execution.budget_limit.as_ref().map(|limit| MonetaryAmount {
                units: execution.budget_spent,
                currency: limit.currency.clone(),
            })
        } else {
            None
        };

        let body = WorkflowReceiptBody {
            id: execution.id.clone(),
            schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
            started_at: execution.started_at,
            completed_at,
            skill_id: execution.skill_id,
            skill_version: execution.skill_version,
            agent_id: execution.agent_id,
            session_id: execution.session_id,
            capability_id: execution.capability_id,
            outcome,
            steps: execution.step_records,
            total_cost,
            duration_ms,
            kernel_key: self.signing_key.public_key(),
        };

        let receipt = WorkflowReceipt::sign(body, &self.signing_key)
            .map_err(|e| WorkflowError::SigningFailed(e.to_string()))?;

        debug!(
            receipt_id = %receipt.id,
            skill_id = %receipt.skill_id,
            "workflow receipt signed"
        );

        if execution.limited_execution_reserved {
            self.complete_execution(&capability_id)?;
        }

        Ok(receipt)
    }

    /// Return the number of workflow executions successfully started.
    #[must_use]
    pub fn execution_count(&self) -> u32 {
        self.execution_count.load(Ordering::Acquire)
    }

    fn reserve_execution(
        &self,
        capability_id: &str,
        max_executions: Option<u32>,
    ) -> Result<bool, WorkflowError> {
        let Some(limit) = max_executions else {
            return Ok(false);
        };
        let mut counts = self
            .limited_execution_counts
            .lock()
            .map_err(|_| WorkflowError::InvalidState("execution counters are poisoned".into()))?;
        let count = counts.entry(capability_id.to_string()).or_default();
        if count.completed.saturating_add(count.in_flight) >= limit {
            return Err(WorkflowError::ExecutionLimitReached { limit });
        }
        count.in_flight = count.in_flight.saturating_add(1);
        Ok(true)
    }

    fn complete_execution(&self, capability_id: &str) -> Result<(), WorkflowError> {
        let mut counts = self
            .limited_execution_counts
            .lock()
            .map_err(|_| WorkflowError::InvalidState("execution counters are poisoned".into()))?;
        let Some(count) = counts.get_mut(capability_id) else {
            return Ok(());
        };
        if count.in_flight > 0 {
            count.in_flight = count.in_flight.saturating_sub(1);
        }
        count.completed = count.completed.saturating_add(1);
        Ok(())
    }
}

fn determine_outcome(execution: &WorkflowExecution) -> WorkflowOutcome {
    for step in &execution.step_records {
        if step.outcome == StepOutcome::Failed {
            return WorkflowOutcome::StepFailed {
                step_index: step.step_index,
                reason: "step execution failed".to_string(),
            };
        }
        if step.outcome == StepOutcome::Denied {
            return WorkflowOutcome::StepFailed {
                step_index: step.step_index,
                reason: "step denied by policy".to_string(),
            };
        }
    }

    if let Some(outcome) = execution.terminal_outcome.clone() {
        return outcome;
    }

    if let Some(ref limit) = execution.budget_limit {
        if execution.budget_spent > limit.units {
            return WorkflowOutcome::BudgetExceeded {
                limit_units: limit.units,
                spent_units: execution.budget_spent,
                currency: limit.currency.clone(),
            };
        }
    }

    WorkflowOutcome::Completed
}

fn validate_time_limit(execution: &WorkflowExecution) -> Result<(), WorkflowError> {
    if let Some(limit_secs) = execution.time_limit_secs {
        let elapsed = current_unix_secs().saturating_sub(execution.started_at);
        if elapsed >= limit_secs {
            return Err(WorkflowError::TimeLimitExceeded {
                elapsed_secs: elapsed,
                limit_secs,
            });
        }
    }
    Ok(())
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{IoContract, SkillStep};

    fn make_manifest() -> SkillManifest {
        SkillManifest::new(
            "search-summarize".to_string(),
            "1.0.0".to_string(),
            "Search and Summarize".to_string(),
            vec![
                SkillStep {
                    index: 0,
                    server_id: "search-srv".to_string(),
                    tool_name: "search".to_string(),
                    label: Some("Search".to_string()),
                    input_contract: None,
                    output_contract: Some(IoContract {
                        required_fields: vec![],
                        produced_fields: vec!["results".to_string()],
                        optional_fields: vec![],
                        json_schema: None,
                    }),
                    budget_limit: None,
                    retryable: false,
                    max_retries: None,
                },
                SkillStep {
                    index: 1,
                    server_id: "llm-srv".to_string(),
                    tool_name: "summarize".to_string(),
                    label: Some("Summarize".to_string()),
                    input_contract: Some(IoContract {
                        required_fields: vec!["results".to_string()],
                        produced_fields: vec![],
                        optional_fields: vec![],
                        json_schema: None,
                    }),
                    output_contract: Some(IoContract {
                        required_fields: vec![],
                        produced_fields: vec!["summary".to_string()],
                        optional_fields: vec![],
                        json_schema: None,
                    }),
                    budget_limit: None,
                    retryable: false,
                    max_retries: None,
                },
            ],
        )
    }

    fn make_grant() -> SkillGrant {
        let mut grant = SkillGrant::new(
            "search-summarize".to_string(),
            "1.0.0".to_string(),
            vec![
                "search-srv:search".to_string(),
                "llm-srv:summarize".to_string(),
            ],
        );
        grant.budget_envelope = Some(MonetaryAmount {
            units: 1000,
            currency: "USD".to_string(),
        });
        grant
    }

    #[test]
    fn successful_workflow_execution() {
        let manifest = make_manifest();
        let grant = make_grant();
        let authority = WorkflowAuthority::new(Keypair::generate());

        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                Some("sess-1".to_string()),
            )
            .unwrap();

        // Validate and record step 0
        authority
            .validate_step(&execution, &manifest.steps[0], &grant)
            .unwrap();
        authority
            .record_step(
                &mut execution,
                &manifest.steps[0],
                StepExecutionRecordInput {
                    outcome: StepOutcome::Success,
                    duration_ms: 100,
                    cost: Some(MonetaryAmount {
                        units: 50,
                        currency: "USD".to_string(),
                    }),
                    tool_receipt_id: Some("rcpt-0".to_string()),
                    output_hash: None,
                },
            )
            .unwrap();

        // Validate and record step 1
        authority
            .validate_step(&execution, &manifest.steps[1], &grant)
            .unwrap();
        authority
            .record_step(
                &mut execution,
                &manifest.steps[1],
                StepExecutionRecordInput {
                    outcome: StepOutcome::Success,
                    duration_ms: 200,
                    cost: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    }),
                    tool_receipt_id: Some("rcpt-1".to_string()),
                    output_hash: None,
                },
            )
            .unwrap();

        let receipt = authority.finalize(execution).unwrap();
        assert!(receipt.is_complete());
        assert_eq!(receipt.successful_steps(), 2);
        assert!(receipt.verify().unwrap());
        assert_eq!(authority.execution_count(), 1);
    }

    #[test]
    fn unauthorized_skill_rejected() {
        let manifest = make_manifest();
        let mut grant = make_grant();
        grant.skill_id = "wrong-skill".to_string();

        let authority = WorkflowAuthority::new(Keypair::generate());
        let result = authority.begin(
            &manifest,
            &grant,
            "agent-1".to_string(),
            "cap-1".to_string(),
            None,
        );
        assert!(matches!(
            result,
            Err(WorkflowError::UnauthorizedSkill { .. })
        ));
    }

    #[test]
    fn missing_step_authorization_rejected() {
        let manifest = make_manifest();
        let grant = SkillGrant::new(
            "search-summarize".to_string(),
            "1.0.0".to_string(),
            vec!["search-srv:search".to_string()],
            // Missing llm-srv:summarize
        );

        let authority = WorkflowAuthority::new(Keypair::generate());
        let result = authority.begin(
            &manifest,
            &grant,
            "agent-1".to_string(),
            "cap-1".to_string(),
            None,
        );
        assert!(matches!(
            result,
            Err(WorkflowError::UnauthorizedStep { .. })
        ));
    }

    #[test]
    fn budget_exceeded_during_execution() {
        let manifest = make_manifest();
        let mut grant = make_grant();
        grant.budget_envelope = Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        });

        let authority = WorkflowAuthority::new(Keypair::generate());
        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        // Step 0 costs 80 out of 100 budget
        authority
            .record_step(
                &mut execution,
                &manifest.steps[0],
                StepExecutionRecordInput {
                    outcome: StepOutcome::Success,
                    duration_ms: 100,
                    cost: Some(MonetaryAmount {
                        units: 80,
                        currency: "USD".to_string(),
                    }),
                    tool_receipt_id: None,
                    output_hash: None,
                },
            )
            .unwrap();

        // Step 1 costs 50, pushing over budget
        let result = authority.record_step(
            &mut execution,
            &manifest.steps[1],
            StepExecutionRecordInput {
                outcome: StepOutcome::Success,
                duration_ms: 100,
                cost: Some(MonetaryAmount {
                    units: 50,
                    currency: "USD".to_string(),
                }),
                tool_receipt_id: None,
                output_hash: None,
            },
        );
        assert!(matches!(result, Err(WorkflowError::BudgetExceeded { .. })));

        // The offending step should still be recorded for audit completeness.
        assert_eq!(execution.step_records.len(), 2);
        assert_eq!(execution.step_records[1].step_index, 1);
    }

    #[test]
    fn step_budget_limit_is_enforced_when_recording_step_cost() {
        let mut manifest = make_manifest();
        manifest.steps[0].budget_limit = Some(MonetaryAmount {
            units: 25,
            currency: "USD".to_string(),
        });
        let mut grant = make_grant();
        grant.budget_envelope = Some(MonetaryAmount {
            units: 1_000,
            currency: "USD".to_string(),
        });

        let authority = WorkflowAuthority::new(Keypair::generate());
        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        let result = authority.record_step(
            &mut execution,
            &manifest.steps[0],
            StepExecutionRecordInput {
                outcome: StepOutcome::Success,
                duration_ms: 100,
                cost: Some(MonetaryAmount {
                    units: 50,
                    currency: "USD".to_string(),
                }),
                tool_receipt_id: None,
                output_hash: None,
            },
        );

        assert!(matches!(
            result,
            Err(WorkflowError::BudgetExceeded {
                limit_units: 25,
                spent_units: 50,
                ..
            })
        ));
        assert_eq!(execution.step_records.len(), 1);
        assert!(!execution.active);

        let receipt = authority.finalize(execution).unwrap();
        assert!(matches!(
            receipt.outcome,
            WorkflowOutcome::BudgetExceeded {
                limit_units: 25,
                spent_units: 50,
                ..
            }
        ));
    }

    #[test]
    fn mismatched_budget_currency_fails_without_spending_units() {
        let manifest = make_manifest();
        let grant = make_grant();
        let authority = WorkflowAuthority::new(Keypair::generate());
        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        let result = authority.record_step(
            &mut execution,
            &manifest.steps[0],
            StepExecutionRecordInput {
                outcome: StepOutcome::Success,
                duration_ms: 100,
                cost: Some(MonetaryAmount {
                    units: 50,
                    currency: "EUR".to_string(),
                }),
                tool_receipt_id: None,
                output_hash: None,
            },
        );

        assert!(matches!(
            result,
            Err(WorkflowError::BudgetCurrencyMismatch {
                expected_currency,
                actual_currency
            }) if expected_currency == "USD" && actual_currency == "EUR"
        ));
        assert_eq!(execution.budget_spent, 0);
        assert_eq!(execution.step_records.len(), 1);
        assert_eq!(execution.step_records[0].step_index, 0);
        assert_eq!(
            execution.step_records[0]
                .cost
                .as_ref()
                .map(|cost| cost.currency.as_str()),
            Some("EUR")
        );
        assert!(!execution.active);

        let receipt = authority.finalize(execution).unwrap();
        assert!(matches!(receipt.outcome, WorkflowOutcome::Denied { .. }));
        assert_eq!(receipt.steps.len(), 1);
        assert!(receipt.total_cost.is_none());
    }

    #[test]
    fn record_step_rejects_elapsed_time_limit() {
        let manifest = make_manifest();
        let mut grant = make_grant();
        grant.max_duration_secs = Some(1);
        let authority = WorkflowAuthority::new(Keypair::generate());
        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();
        execution.started_at = current_unix_secs().saturating_sub(2);

        let result = authority.record_step(
            &mut execution,
            &manifest.steps[0],
            StepExecutionRecordInput {
                outcome: StepOutcome::Success,
                duration_ms: 100,
                cost: None,
                tool_receipt_id: None,
                output_hash: None,
            },
        );

        assert!(matches!(
            result,
            Err(WorkflowError::TimeLimitExceeded { limit_secs: 1, .. })
        ));
        assert_eq!(execution.step_records.len(), 1);
        assert_eq!(execution.step_records[0].step_index, 0);
        assert!(!execution.active);

        let receipt = authority.finalize(execution).unwrap();
        assert!(matches!(
            receipt.outcome,
            WorkflowOutcome::TimedOut { limit_secs: 1, .. }
        ));
        assert_eq!(receipt.steps.len(), 1);
    }

    #[test]
    fn step_order_enforcement() {
        let manifest = make_manifest();
        let grant = make_grant();
        let authority = WorkflowAuthority::new(Keypair::generate());

        let execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        // Try step 1 before step 0
        let result = authority.validate_step(&execution, &manifest.steps[1], &grant);
        assert!(matches!(result, Err(WorkflowError::StepOutOfOrder { .. })));
    }

    #[test]
    fn step_failure_deactivates_workflow() {
        let manifest = make_manifest();
        let grant = make_grant();
        let authority = WorkflowAuthority::new(Keypair::generate());

        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        // Record a failed step
        authority
            .record_step(
                &mut execution,
                &manifest.steps[0],
                StepExecutionRecordInput {
                    outcome: StepOutcome::Failed,
                    duration_ms: 50,
                    cost: None,
                    tool_receipt_id: None,
                    output_hash: None,
                },
            )
            .unwrap();

        // Workflow should be deactivated
        assert!(!execution.active);

        // Trying to validate next step should fail
        let result = authority.validate_step(&execution, &manifest.steps[1], &grant);
        assert!(matches!(result, Err(WorkflowError::InvalidState(_))));
    }

    #[test]
    fn failed_step_finalized_late_preserves_step_failed_outcome() {
        let manifest = make_manifest();
        let mut grant = make_grant();
        grant.max_duration_secs = Some(1);
        let authority = WorkflowAuthority::new(Keypair::generate());

        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        authority
            .record_step(
                &mut execution,
                &manifest.steps[0],
                StepExecutionRecordInput {
                    outcome: StepOutcome::Failed,
                    duration_ms: 50,
                    cost: None,
                    tool_receipt_id: Some("tool-receipt-1".to_string()),
                    output_hash: Some("output-hash-1".to_string()),
                },
            )
            .unwrap();

        execution.started_at = current_unix_secs().saturating_sub(2);

        let receipt = authority.finalize(execution).unwrap();
        assert!(matches!(
            receipt.outcome,
            WorkflowOutcome::StepFailed { step_index: 0, .. }
        ));
        assert_eq!(receipt.steps.len(), 1);
        assert_eq!(
            receipt.steps[0].tool_receipt_id.as_deref(),
            Some("tool-receipt-1")
        );
    }

    #[test]
    fn single_step_workflow() {
        let manifest = SkillManifest::new(
            "simple".to_string(),
            "1.0.0".to_string(),
            "Simple Task".to_string(),
            vec![SkillStep {
                index: 0,
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                label: Some("Do thing".to_string()),
                input_contract: None,
                output_contract: None,
                budget_limit: None,
                retryable: false,
                max_retries: None,
            }],
        );
        let grant = SkillGrant::new(
            "simple".to_string(),
            "1.0.0".to_string(),
            vec!["srv:tool".to_string()],
        );
        let authority = WorkflowAuthority::new(Keypair::generate());

        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        authority
            .validate_step(&execution, &manifest.steps[0], &grant)
            .unwrap();
        authority
            .record_step(
                &mut execution,
                &manifest.steps[0],
                StepExecutionRecordInput {
                    outcome: StepOutcome::Success,
                    duration_ms: 50,
                    cost: None,
                    tool_receipt_id: None,
                    output_hash: None,
                },
            )
            .unwrap();

        let receipt = authority.finalize(execution).unwrap();
        assert!(receipt.is_complete());
        assert_eq!(receipt.successful_steps(), 1);
        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn execution_limit_denies_reuse_after_finalize() {
        let manifest = SkillManifest::new(
            "limited".to_string(),
            "1.0.0".to_string(),
            "Limited".to_string(),
            vec![SkillStep {
                index: 0,
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                label: None,
                input_contract: None,
                output_contract: None,
                budget_limit: None,
                retryable: false,
                max_retries: None,
            }],
        );
        let mut grant = SkillGrant::new(
            "limited".to_string(),
            "1.0.0".to_string(),
            vec!["srv:tool".to_string()],
        );
        grant.max_executions = Some(1);

        let authority = WorkflowAuthority::new(Keypair::generate());

        // First execution should work
        let mut execution = authority
            .begin(&manifest, &grant, "a".to_string(), "c".to_string(), None)
            .unwrap();
        authority
            .record_step(
                &mut execution,
                &manifest.steps[0],
                StepExecutionRecordInput {
                    outcome: StepOutcome::Success,
                    duration_ms: 10,
                    cost: None,
                    tool_receipt_id: None,
                    output_hash: None,
                },
            )
            .unwrap();
        authority.finalize(execution).unwrap();

        // Finalize completes the lifetime execution, so reuse is denied.
        let result = authority.begin(&manifest, &grant, "a".to_string(), "c".to_string(), None);
        assert!(matches!(
            result,
            Err(WorkflowError::ExecutionLimitReached { .. })
        ));
    }

    #[test]
    fn execution_limit_reserved_at_begin() {
        let manifest = SkillManifest::new(
            "limited".to_string(),
            "1.0.0".to_string(),
            "Limited".to_string(),
            vec![SkillStep {
                index: 0,
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                label: None,
                input_contract: None,
                output_contract: None,
                budget_limit: None,
                retryable: false,
                max_retries: None,
            }],
        );
        let mut grant = SkillGrant::new(
            "limited".to_string(),
            "1.0.0".to_string(),
            vec!["srv:tool".to_string()],
        );
        grant.max_executions = Some(1);

        let authority = WorkflowAuthority::new(Keypair::generate());

        let _execution = authority
            .begin(&manifest, &grant, "a".to_string(), "c".to_string(), None)
            .unwrap();

        let result = authority.begin(&manifest, &grant, "a".to_string(), "c".to_string(), None);
        assert!(
            matches!(result, Err(WorkflowError::ExecutionLimitReached { .. })),
            "limit must be consumed when begin starts, not only after finalize"
        );
    }

    #[test]
    fn execution_limit_tracks_completed_and_in_flight_executions() {
        let manifest = SkillManifest::new(
            "limited".to_string(),
            "1.0.0".to_string(),
            "Limited".to_string(),
            vec![SkillStep {
                index: 0,
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                label: None,
                input_contract: None,
                output_contract: None,
                budget_limit: None,
                retryable: false,
                max_retries: None,
            }],
        );
        let mut grant = SkillGrant::new(
            "limited".to_string(),
            "1.0.0".to_string(),
            vec!["srv:tool".to_string()],
        );
        grant.max_executions = Some(2);

        let authority = WorkflowAuthority::new(Keypair::generate());

        let execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-a".to_string(),
                "cap-reused".to_string(),
                None,
            )
            .unwrap();

        let execution_2 = authority
            .begin(
                &manifest,
                &grant,
                "agent-b".to_string(),
                "cap-reused".to_string(),
                None,
            )
            .unwrap();

        let blocked = authority.begin(
            &manifest,
            &grant,
            "agent-c".to_string(),
            "cap-reused".to_string(),
            None,
        );
        assert!(matches!(
            blocked,
            Err(WorkflowError::ExecutionLimitReached { .. })
        ));

        authority.finalize(execution).unwrap();

        let still_blocked = authority.begin(
            &manifest,
            &grant,
            "agent-d".to_string(),
            "cap-reused".to_string(),
            None,
        );
        assert!(matches!(
            still_blocked,
            Err(WorkflowError::ExecutionLimitReached { .. })
        ));

        authority.finalize(execution_2).unwrap();

        let exhausted = authority.begin(
            &manifest,
            &grant,
            "agent-e".to_string(),
            "cap-reused".to_string(),
            None,
        );
        assert!(matches!(
            exhausted,
            Err(WorkflowError::ExecutionLimitReached { .. })
        ));
    }

    #[test]
    fn unlimited_finalize_does_not_release_limited_reservation() {
        let manifest = SkillManifest::new(
            "limited".to_string(),
            "1.0.0".to_string(),
            "Limited".to_string(),
            vec![SkillStep {
                index: 0,
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                label: None,
                input_contract: None,
                output_contract: None,
                budget_limit: None,
                retryable: false,
                max_retries: None,
            }],
        );
        let unlimited_grant = SkillGrant::new(
            "limited".to_string(),
            "1.0.0".to_string(),
            vec!["srv:tool".to_string()],
        );
        let mut limited_grant = SkillGrant::new(
            "limited".to_string(),
            "1.0.0".to_string(),
            vec!["srv:tool".to_string()],
        );
        limited_grant.max_executions = Some(1);

        let authority = WorkflowAuthority::new(Keypair::generate());

        let unlimited_execution = authority
            .begin(
                &manifest,
                &unlimited_grant,
                "agent-a".to_string(),
                "cap-shared".to_string(),
                None,
            )
            .unwrap();

        authority
            .begin(
                &manifest,
                &limited_grant,
                "agent-b".to_string(),
                "cap-shared".to_string(),
                None,
            )
            .unwrap();

        authority.finalize(unlimited_execution).unwrap();

        let result = authority.begin(
            &manifest,
            &limited_grant,
            "agent-b".to_string(),
            "cap-shared".to_string(),
            None,
        );
        assert!(matches!(
            result,
            Err(WorkflowError::ExecutionLimitReached { .. })
        ));
        assert_eq!(authority.execution_count(), 2);
    }

    #[test]
    fn budget_exactly_at_limit_passes() {
        let manifest = make_manifest();
        let mut grant = make_grant();
        grant.budget_envelope = Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        });

        let authority = WorkflowAuthority::new(Keypair::generate());
        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        // Spend exactly the limit (100)
        authority
            .record_step(
                &mut execution,
                &manifest.steps[0],
                StepExecutionRecordInput {
                    outcome: StepOutcome::Success,
                    duration_ms: 100,
                    cost: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    }),
                    tool_receipt_id: None,
                    output_hash: None,
                },
            )
            .unwrap();

        // Spending 0 more should still be fine (100 <= 100)
        authority
            .record_step(
                &mut execution,
                &manifest.steps[1],
                StepExecutionRecordInput {
                    outcome: StepOutcome::Success,
                    duration_ms: 100,
                    cost: Some(MonetaryAmount {
                        units: 0,
                        currency: "USD".to_string(),
                    }),
                    tool_receipt_id: None,
                    output_hash: None,
                },
            )
            .unwrap();
    }

    #[test]
    fn record_step_on_inactive_workflow_errors() {
        let manifest = make_manifest();
        let grant = make_grant();
        let authority = WorkflowAuthority::new(Keypair::generate());

        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        // Manually deactivate
        execution.active = false;

        let result = authority.record_step(
            &mut execution,
            &manifest.steps[0],
            StepExecutionRecordInput {
                outcome: StepOutcome::Success,
                duration_ms: 10,
                cost: None,
                tool_receipt_id: None,
                output_hash: None,
            },
        );
        assert!(matches!(result, Err(WorkflowError::InvalidState(_))));
    }

    #[test]
    fn denied_step_deactivates_workflow() {
        let manifest = make_manifest();
        let grant = make_grant();
        let authority = WorkflowAuthority::new(Keypair::generate());

        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        authority
            .record_step(
                &mut execution,
                &manifest.steps[0],
                StepExecutionRecordInput {
                    outcome: StepOutcome::Denied,
                    duration_ms: 50,
                    cost: None,
                    tool_receipt_id: None,
                    output_hash: None,
                },
            )
            .unwrap();

        assert!(!execution.active);
    }

    #[test]
    fn execution_ids_do_not_collide_within_a_single_second() {
        // Regression guard: `begin()` MUST use sub-second resolution so two calls in the same second produce distinct ids; second-resolution ids collide and produce shadowed receipts.
        let manifest = make_manifest();
        let grant = make_grant();
        let authority = WorkflowAuthority::new(Keypair::generate());

        let exec_a = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();
        // Finalize to bump the execution counter without invoking the
        // sleep that would otherwise change `now`.
        let _ = authority.finalize(exec_a).unwrap();

        let exec_b = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-2".to_string(),
                None,
            )
            .unwrap();
        let exec_c = authority
            .begin(
                &manifest,
                &grant,
                "agent-2".to_string(),
                "cap-3".to_string(),
                None,
            )
            .unwrap();

        assert_ne!(
            exec_b.id, exec_c.id,
            "executions started in the same second must not share an id"
        );
    }

    #[test]
    fn rapid_begin_calls_produce_distinct_ids_for_same_agent() {
        // Two back-to-back `begin()` calls for the same agent within one
        // second, with no intervening `finalize()`, must not collide: `now`
        // and `execution_count` (incremented only in `finalize()`) are both
        // unchanged across the pair. The atomic per-call counter ensures
        // every `begin()` produces a fresh id regardless of finalize ordering.
        let manifest = make_manifest();
        let grant = make_grant();
        let authority = WorkflowAuthority::new(Keypair::generate());

        let exec_a = authority
            .begin(
                &manifest,
                &grant,
                "same-agent".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();
        let exec_b = authority
            .begin(
                &manifest,
                &grant,
                "same-agent".to_string(),
                "cap-2".to_string(),
                None,
            )
            .unwrap();
        let exec_c = authority
            .begin(
                &manifest,
                &grant,
                "same-agent".to_string(),
                "cap-3".to_string(),
                None,
            )
            .unwrap();

        assert_ne!(exec_a.id, exec_b.id);
        assert_ne!(exec_b.id, exec_c.id);
        assert_ne!(exec_a.id, exec_c.id);
    }
}
