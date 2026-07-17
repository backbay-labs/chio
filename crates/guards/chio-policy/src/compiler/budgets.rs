use super::{CompileError, PipelineBuilder};
use crate::models::HushSpec;

use chio_guards::{agent_velocity::AgentVelocityConfig, AgentVelocityGuard};

// ---------------------------------------------------------------------------
// Budget-driven guards (12)
// ---------------------------------------------------------------------------

pub(super) fn compile_budget_guards(
    policy: &HushSpec,
    builder: &mut PipelineBuilder,
    memory_budget: &chio_kernel::MemoryBudgetConfig,
) -> Result<(), CompileError> {
    let Some(extensions) = &policy.extensions else {
        return Ok(());
    };
    let Some(origins) = &extensions.origins else {
        return Ok(());
    };

    // 12. origin budgets -> AgentVelocityGuard
    //
    // The most restrictive `tool_calls` budget across all profiles becomes the
    // per-agent request ceiling within a 60-second window. The mapping is
    // coarse: it collapses per-origin granularity into one ceiling rather than
    // emitting a per-origin guard.
    let mut tightest_tool_calls: Option<u32> = None;
    for profile in &origins.profiles {
        let Some(budgets) = &profile.budgets else {
            continue;
        };
        if let Some(tool_calls) = budgets.tool_calls {
            let as_u32 = u32::try_from(tool_calls).unwrap_or(u32::MAX);
            tightest_tool_calls = Some(match tightest_tool_calls {
                Some(current) => current.min(as_u32),
                None => as_u32,
            });
        }
    }

    if let Some(limit) = tightest_tool_calls {
        let config = AgentVelocityConfig {
            max_requests_per_agent: Some(limit),
            max_requests_per_session: None,
            window_secs: 60,
            burst_factor: 1.0,
        };
        // Thread the CONFIGURED process memory budget so a lowered
        // `velocity_bucket_cap` bounds this origin-budget guard's agent/session
        // bucket maps instead of them growing unbounded.
        builder.add(AgentVelocityGuard::from_memory_budget(
            config,
            memory_budget,
        ));
    }

    Ok(())
}
