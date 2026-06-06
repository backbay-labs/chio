use super::*;
use serde_json::json;

fn test_config() -> AcpProxyConfig {
    AcpProxyConfig::new("echo", "deadbeef")
        .with_allowed_path_prefix("/home/user/project")
        .with_allowed_command("cargo")
        .with_allowed_command("npm")
}

// ================================================================
// 1. Protocol Parsing Edge Cases
// ================================================================
