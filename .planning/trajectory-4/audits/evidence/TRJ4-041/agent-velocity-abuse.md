# TRJ4-041 agent velocity abuse

- Test: `crates/chio-conformance/tests/threats/agent_velocity_abuse.rs`
- Coverage: direct `AgentVelocityGuard` exercise.
- Negative case: repeated requests from the same agent exceed the per-agent token bucket and return `Verdict::Deny`.
- Isolation case: a different agent keeps an independent bucket and remains allowed.
