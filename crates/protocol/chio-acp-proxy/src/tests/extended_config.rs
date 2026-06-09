#[test]
fn config_builder_defaults() {
    let config = AcpProxyConfig::new("agent-cmd", "pubkey-hex");
    assert_eq!(config.agent_command(), "agent-cmd");
    assert_eq!(config.public_key(), "pubkey-hex");
    assert!(config.allowed_path_prefixes().is_empty());
    assert!(config.allowed_commands().is_empty());
    assert!(config.agent_args().is_empty());
    assert!(config.agent_env().is_empty());
    assert_eq!(config.server_id(), "chio-acp-proxy");
}

#[test]
fn config_builder_chaining() {
    let config = AcpProxyConfig::new("agent", "key")
        .with_allowed_path_prefix("/home")
        .with_allowed_path_prefix("/tmp")
        .with_allowed_command("cargo")
        .with_allowed_command("npm")
        .with_server_id("my-proxy")
        .with_agent_args(vec!["--flag".to_string()])
        .with_agent_env(vec![("KEY".to_string(), "VAL".to_string())]);

    assert_eq!(config.allowed_path_prefixes().len(), 2);
    assert_eq!(config.allowed_commands().len(), 2);
    assert_eq!(config.server_id(), "my-proxy");
    assert_eq!(config.agent_args().len(), 1);
    assert_eq!(config.agent_env().len(), 1);
}

#[test]
fn proxy_start_with_nonexistent_command_fails() {
    let config =
        AcpProxyConfig::new("/nonexistent/path/to/fake-agent-binary-xyz123", "deadbeef");
    let result = AcpProxy::start(config);
    assert!(
        result.is_err(),
        "starting with a nonexistent command should fail"
    );
}

#[test]
fn proxy_interceptor_exposes_config() {
    let config = test_config();
    let interceptor = MessageInterceptor::new(config);
    assert_eq!(interceptor.config().agent_command(), "echo");
    assert_eq!(interceptor.config().allowed_path_prefixes().len(), 1);
    assert_eq!(interceptor.config().allowed_commands().len(), 2);
}

// ================================================================
// 8. Serialization round-trip tests
// ================================================================
