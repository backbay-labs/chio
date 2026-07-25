use crate::execution_nonce::{
    mint_execution_nonce, verify_execution_nonce, ExecutionNonceConfig, ExecutionNonceError,
    InMemoryExecutionNonceStore, NonceBinding,
};

fn kernel_with_nonce() -> (ChioKernel, Keypair, ChioScope, ExecutionNonceConfig) {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    let store = Box::new(InMemoryExecutionNonceStore::from_config(&cfg));
    kernel.set_execution_nonce_store(cfg.clone(), store);
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    (kernel, agent_kp, scope, cfg)
}

fn binding_for_request(cap: &CapabilityToken, request: &ToolCallRequest) -> NonceBinding {
    let parameter_hash =
        chio_core::receipt::decision::ToolCallAction::from_parameters(request.arguments.clone())
            .unwrap()
            .parameter_hash;
    NonceBinding {
        subject_id: cap.subject.to_hex(),
        request_id: request.request_id.clone(),
        capability_id: cap.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        parameter_hash,
    }
}

fn mint_nonce_for_request(
    kernel: &ChioKernel,
    cap: &CapabilityToken,
    request: &ToolCallRequest,
    cfg: &ExecutionNonceConfig,
) -> crate::execution_nonce::SignedExecutionNonce {
    let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
    mint_execution_nonce(
        &kernel.config.keypair,
        binding_for_request(cap, request),
        cfg,
        now,
    )
    .unwrap()
}
