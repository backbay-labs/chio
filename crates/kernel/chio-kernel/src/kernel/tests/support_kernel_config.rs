fn make_config() -> KernelConfig {
    KernelConfig {
        keypair: make_keypair(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "test-policy-hash".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: crate::MemoryBudgetConfig::defaults(),
        deadlines: crate::HotPathDeadlineConfig::default(),
    }
}

fn make_kernel(config: KernelConfig) -> ChioKernel {
    let mut kernel = ChioKernel::new(config);
    kernel.enable_unsafe_ephemeral_financial_dispatch_for_development();
    kernel
}
