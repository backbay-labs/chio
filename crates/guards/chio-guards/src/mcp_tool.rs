//! MCP tool guard -- restricts which MCP tools an agent may invoke.
//!
//! The guard supports allow/block lists, a default action, and a maximum
//! argument size limit.

use std::collections::HashSet;
use std::io;

#[cfg(test)]
use chio_kernel::Verdict;
use chio_kernel::{GuardContext, GuardDecision, KernelError};

use crate::action::{extract_action_checked, ToolAction};

/// Default behavior when a tool is not in either list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum McpDefaultAction {
    #[default]
    Allow,
    Block,
}

/// Configuration for `McpToolGuard`.
pub struct McpToolConfig {
    /// Enable/disable this guard.
    pub enabled: bool,
    /// Allowed tool names. When non-empty, only these tools may be invoked
    /// (allowlist mode).
    pub allow: Vec<String>,
    /// Blocked tool names. Takes precedence over `allow`.
    pub block: Vec<String>,
    /// Default action when a tool is not in either list.
    pub default_action: McpDefaultAction,
    /// Maximum serialized argument size in bytes.
    pub max_args_size: Option<usize>,
}

fn default_max_args_size() -> usize {
    1024 * 1024 // 1 MB
}

fn json_size_bytes(value: &serde_json::Value) -> Result<usize, serde_json::Error> {
    struct CountingWriter {
        count: usize,
    }

    impl io::Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.count += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut w = CountingWriter { count: 0 };
    serde_json::to_writer(&mut w, value)?;
    Ok(w.count)
}

impl Default for McpToolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow: vec![],
            block: vec![
                "shell_exec".to_string(),
                "run_command".to_string(),
                "raw_file_write".to_string(),
                "raw_file_delete".to_string(),
            ],
            default_action: McpDefaultAction::Allow,
            max_args_size: Some(default_max_args_size()),
        }
    }
}

/// Decision for a single tool invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolDecision {
    Allow,
    Block,
}

/// Guard that controls which MCP tools an agent may invoke.
///
/// Evaluation order:
/// 1. If the tool is in the block list, deny.
/// 2. If an allowlist is configured (non-empty `allow`), only tools in the
///    allowlist pass; everything else is denied.
/// 3. Fall back to `default_action`.
pub struct McpToolGuard {
    enabled: bool,
    allow_set: HashSet<String>,
    block_set: HashSet<String>,
    default_action: McpDefaultAction,
    max_args_size: usize,
}

impl McpToolGuard {
    pub fn new() -> Self {
        Self::with_config(McpToolConfig::default())
    }

    pub fn with_config(config: McpToolConfig) -> Self {
        let allow_set: HashSet<String> = config.allow.into_iter().collect();
        let block_set: HashSet<String> = config.block.into_iter().collect();

        Self {
            enabled: config.enabled,
            allow_set,
            block_set,
            default_action: config.default_action,
            max_args_size: config.max_args_size.unwrap_or(default_max_args_size()),
        }
    }

    /// Determine whether a tool name is allowed.
    pub fn is_allowed(&self, tool_name: &str) -> ToolDecision {
        // Block list takes precedence.
        if self.block_set.contains(tool_name) {
            return ToolDecision::Block;
        }

        // Allowlist mode: only listed tools pass.
        if !self.allow_set.is_empty() {
            return if self.allow_set.contains(tool_name) {
                ToolDecision::Allow
            } else {
                ToolDecision::Block
            };
        }

        // Default action.
        if self.default_action == McpDefaultAction::Block {
            ToolDecision::Block
        } else {
            ToolDecision::Allow
        }
    }
}

impl Default for McpToolGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl chio_kernel::Guard for McpToolGuard {
    fn name(&self) -> &str {
        "mcp-tool"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if !self.enabled {
            return Ok(GuardDecision::allow());
        }

        let action = match extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments) {
            Ok(action) => action,
            Err(_) => return Ok(GuardDecision::deny(Vec::new())),
        };

        let (tool_name, args) = match &action {
            ToolAction::McpTool(name, args) => (name.as_str(), args),
            _ => return Ok(GuardDecision::allow()),
        };

        // Check argument size limit.
        let args_size = json_size_bytes(args)
            .map_err(|e| KernelError::GuardDenied(format!("failed to serialize tool args: {e}")))?;

        if args_size > self.max_args_size {
            return Ok(GuardDecision::deny(Vec::new()));
        }

        match self.is_allowed(tool_name) {
            ToolDecision::Allow => Ok(GuardDecision::allow()),
            ToolDecision::Block => Ok(GuardDecision::deny(Vec::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_kernel::Guard;

    #[test]
    fn default_blocked_tools() {
        let guard = McpToolGuard::new();
        assert_eq!(guard.is_allowed("shell_exec"), ToolDecision::Block);
        assert_eq!(guard.is_allowed("run_command"), ToolDecision::Block);
        assert_eq!(guard.is_allowed("raw_file_write"), ToolDecision::Block);
        assert_eq!(guard.is_allowed("raw_file_delete"), ToolDecision::Block);
    }

    #[test]
    fn default_allows_normal_tools() {
        let guard = McpToolGuard::new();
        assert_eq!(guard.is_allowed("read_file"), ToolDecision::Allow);
        assert_eq!(guard.is_allowed("list_directory"), ToolDecision::Allow);
    }

    #[test]
    fn allowlist_mode() {
        let config = McpToolConfig {
            enabled: true,
            allow: vec!["safe_tool".to_string()],
            block: vec![],
            default_action: McpDefaultAction::Block,
            max_args_size: Some(1024),
        };
        let guard = McpToolGuard::with_config(config);

        assert_eq!(guard.is_allowed("safe_tool"), ToolDecision::Allow);
        assert_eq!(guard.is_allowed("other_tool"), ToolDecision::Block);
    }

    #[test]
    fn block_takes_precedence_over_allow() {
        let config = McpToolConfig {
            enabled: true,
            allow: vec!["tool_a".to_string()],
            block: vec!["tool_a".to_string()],
            default_action: McpDefaultAction::Allow,
            max_args_size: None,
        };
        let guard = McpToolGuard::with_config(config);

        // Block list wins over allow list.
        assert_eq!(guard.is_allowed("tool_a"), ToolDecision::Block);
    }

    #[test]
    fn default_action_block() {
        let config = McpToolConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            default_action: McpDefaultAction::Block,
            max_args_size: None,
        };
        let guard = McpToolGuard::with_config(config);

        assert_eq!(guard.is_allowed("any_tool"), ToolDecision::Block);
    }

    #[test]
    fn disabled_guard_allows_everything() {
        let config = McpToolConfig {
            enabled: false,
            allow: vec![],
            block: vec!["shell_exec".to_string()],
            default_action: McpDefaultAction::Block,
            max_args_size: None,
        };
        let guard = McpToolGuard::with_config(config);

        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::scope::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();

        let cap_body = chio_core::capability::token::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        let cap =
            chio_core::capability::token::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "shell_exec".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({"command": "rm -rf /"}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let ctx = chio_kernel::GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Allow);
    }

    #[test]
    fn evaluate_blocks_tool_via_guard_trait() {
        let guard = McpToolGuard::new();

        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::scope::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();

        let cap_body = chio_core::capability::token::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        let cap =
            chio_core::capability::token::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        // "shell_exec" is blocked by default.
        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap.clone(),
            tool_name: "shell_exec".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let ctx = chio_kernel::GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Deny);

        // "read_file" is allowed by default.
        let request2 = chio_kernel::ToolCallRequest {
            request_id: "req-test-2".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({"path": "/app/main.rs"}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let ctx2 = chio_kernel::GuardContext {
            request: &request2,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result2 = guard.evaluate(&ctx2).expect("evaluate should not error");
        assert_eq!(result2, Verdict::Allow);
    }

    #[test]
    fn args_size_limit() {
        let config = McpToolConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            default_action: McpDefaultAction::Allow,
            max_args_size: Some(100),
        };
        let guard = McpToolGuard::with_config(config);

        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::scope::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();

        let cap_body = chio_core::capability::token::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        let cap =
            chio_core::capability::token::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let large_args = serde_json::json!({"data": "x".repeat(200)});
        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "some_tool".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: large_args,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let ctx = chio_kernel::GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx).expect("evaluate should not error");
        assert_eq!(result, Verdict::Deny);
    }
}
