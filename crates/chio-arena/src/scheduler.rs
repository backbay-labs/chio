//! Deterministic scheduler for multi-agent arena scenarios.
//!
//! The scheduler produces a totally-ordered sequence of `(virtual_time,
//! agent_id, intra_agent_step)` entries from the scenario step list. The
//! ordering is fully derived from scenario contents:
//!
//!   1. Steps appear in scenario declaration order.
//!   2. Each step is assigned a virtual time equal to its sequence index.
//!   3. Two steps that ever land at the same `(virtual_time, agent_id)` slot
//!      are broken by their `intra_agent_step` counter, which is the order
//!      they appear within that agent's stream of steps.
//!
//! No thread-local randomness is consulted. The arena RNG is the
//! only entropy source available to higher-level schedulers, and the
//! deterministic scheduler does not consume from it; the RNG is kept reserved
//! for the adversary populations.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::scenario::Scenario;

/// A scheduled step ready for dispatch by the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledStep {
    /// Scenario step id.
    pub step_id: String,
    /// Owning agent id.
    pub agent_id: String,
    /// Virtual-time slot (sequence index of the step in declaration order).
    pub virtual_time: u64,
    /// Position of the step within the owning agent's stream.
    pub intra_agent_step: u64,
}

/// Deterministic scheduler.
#[derive(Debug, Clone)]
pub struct DeterministicScheduler {
    schedule: Vec<ScheduledStep>,
}

impl DeterministicScheduler {
    /// Build a schedule from the scenario.
    pub fn from_scenario(scenario: &Scenario) -> Result<Self, SchedulerError> {
        let mut intra_counters: BTreeMap<&str, u64> = BTreeMap::new();
        let mut schedule = Vec::with_capacity(scenario.steps.len());
        let mut known_agents: BTreeMap<&str, ()> = BTreeMap::new();
        for agent in &scenario.agents {
            known_agents.insert(agent.id.as_str(), ());
        }
        for (index, step) in scenario.steps.iter().enumerate() {
            if !known_agents.contains_key(step.agent.as_str()) {
                return Err(SchedulerError::UnknownAgent {
                    step_id: step.id.clone(),
                    agent_id: step.agent.clone(),
                });
            }
            let counter = intra_counters.entry(step.agent.as_str()).or_insert(0);
            let intra_agent_step = *counter;
            *counter += 1;
            schedule.push(ScheduledStep {
                step_id: step.id.clone(),
                agent_id: step.agent.clone(),
                virtual_time: index as u64,
                intra_agent_step,
            });
        }
        // Final stable sort on (virtual_time, agent_id, intra_agent_step) so
        // the schedule is canonical regardless of input order.
        schedule.sort_by(|a, b| {
            a.virtual_time
                .cmp(&b.virtual_time)
                .then_with(|| a.agent_id.cmp(&b.agent_id))
                .then_with(|| a.intra_agent_step.cmp(&b.intra_agent_step))
        });
        Ok(Self { schedule })
    }

    /// Borrow the canonical schedule.
    pub fn schedule(&self) -> &[ScheduledStep] {
        &self.schedule
    }

    /// Consume the scheduler and return the ordered step list.
    pub fn into_schedule(self) -> Vec<ScheduledStep> {
        self.schedule
    }
}

/// Errors raised by [`DeterministicScheduler`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchedulerError {
    /// Step references an agent the scenario does not declare.
    #[error("step {step_id} references unknown agent {agent_id}")]
    UnknownAgent {
        /// Step id.
        step_id: String,
        /// Missing agent id.
        agent_id: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::parse_scenario_str;

    fn two_agent_scenario() -> &'static str {
        r#"
schema_version = "chio.arena.scenario/v1"
id = "two_agent_simple"
title = "Two agents alternating"
rng_seed = 1
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 1
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "single-agent-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/a.txt"

[[agents]]
id = "agent-b"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/b.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/a-1.txt" }
expect_verdict = "allow"

[[steps]]
id = "step-2"
agent = "agent-b"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/b-1.txt" }
expect_verdict = "allow"

[[steps]]
id = "step-3"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/a-2.txt" }
expect_verdict = "allow"
"#
    }

    #[test]
    fn schedule_is_deterministic_and_intra_agent_counts() -> Result<(), Box<dyn std::error::Error>>
    {
        let scenario = parse_scenario_str(two_agent_scenario())?;
        let scheduler = DeterministicScheduler::from_scenario(&scenario)?;
        let steps = scheduler.schedule();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].step_id, "step-1");
        assert_eq!(steps[0].virtual_time, 0);
        assert_eq!(steps[0].intra_agent_step, 0);
        assert_eq!(steps[1].step_id, "step-2");
        assert_eq!(steps[1].virtual_time, 1);
        assert_eq!(steps[1].intra_agent_step, 0);
        assert_eq!(steps[2].step_id, "step-3");
        assert_eq!(steps[2].virtual_time, 2);
        assert_eq!(steps[2].intra_agent_step, 1);
        Ok(())
    }
}
