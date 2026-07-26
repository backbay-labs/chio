#[test]
fn session_operation_rejects_nonce_bound_to_another_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut kernel, agent, scope, mut config) = kernel_with_nonce();
    config.require_nonce = true;
    kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&config)),
    );

    let capability = make_capability(&kernel, &agent, scope, 300);
    let bound_request = make_request(
        "session-nonce-bound-request",
        &capability,
        "read_file",
        "srv-a",
    );
    let preflight = kernel.evaluate_tool_call_blocking(&bound_request)?;
    let nonce = preflight
        .execution_nonce
        .ok_or_else(|| std::io::Error::other("strict preflight nonce missing"))?;

    let session_id = kernel.open_session(
        agent.public_key().to_hex(),
        vec![capability.clone()],
    )?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "session-current-request",
        &agent.public_key().to_hex(),
    );
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability,
        server_id: bound_request.server_id,
        tool_name: bound_request.tool_name,
        arguments: bound_request.arguments,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: Some(serde_json::to_value(nonce)?),
        model_metadata: None,
        extra_metadata: None,
    }));

    let response = session_tool_call(kernel.evaluate_session_operation(&context, &operation)?)
        .ok_or_else(|| std::io::Error::other("tool-call response missing"))?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(|reason| {
        reason.contains("execution nonce binding mismatch on field request_id")
    }));
    Ok(())
}
