use chio_runtime_core::*;

pub fn supervisor_profile() -> RuntimeSupervisorProfile {
    RuntimeSupervisorProfile {
        schema: CHIO_RUNTIME_SUPERVISOR_PROFILE_SCHEMA.to_string(),
        profile_id: "runtime-supervisor-local".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        max_concurrent_runs: 2,
        run_lease_ttl_ms: 60_000,
        stale_run_after_ms: 300_000,
        evidence_required_roles: vec![
            "workflow_run_report".to_string(),
            "proof_regeneration_report".to_string(),
        ],
        fail_closed_on: vec!["evidence_hash_mismatch".to_string()],
    }
}
