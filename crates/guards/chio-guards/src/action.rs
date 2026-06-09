//! Tool action extraction from Chio tool call requests.
//!
//! Guards need to know *what kind of action* a tool call performs (file access,
//! shell command, network egress, etc.).  This module provides a `ToolAction`
//! enum that guards match on, plus extraction logic that derives the action
//! from `ToolCallRequest.tool_name` and `ToolCallRequest.arguments`.

use serde_json::Value;

/// A categorized action derived from a tool call request.
///
/// The action is produced by inspecting `ToolCallRequest` fields rather than
/// being supplied directly.
#[derive(Clone, Debug)]
pub enum ToolAction {
    /// File system read (path).
    FileAccess(String),
    /// File system write (path, content bytes).
    FileWrite(String, Vec<u8>),
    /// Network egress (host, port).
    NetworkEgress(String, u16),
    /// Shell command execution (command line).
    ShellCommand(String),
    /// MCP tool invocation (tool_name, args).
    McpTool(String, Value),
    /// Patch application (file, diff).
    Patch(String, String),
    /// Code execution via an interpreter (language, code snippet).
    CodeExecution { language: String, code: String },
    /// Browser automation action (verb, optional target URL).
    BrowserAction {
        verb: String,
        target: Option<String>,
    },
    /// Database query (database/engine identifier, raw query text).
    DatabaseQuery { database: String, query: String },
    /// External API call (service name, endpoint/path).
    ExternalApiCall { service: String, endpoint: String },
    /// Agent memory write (store/collection id, key).
    MemoryWrite { store: String, key: String },
    /// Agent memory read (store/collection id, optional key).
    MemoryRead { store: String, key: Option<String> },
    /// Unknown / not categorized -- guards that don't match should allow.
    Unknown,
}

/// A recognized tool-action shape with missing or mistyped arguments.
///
/// Guard boundaries must treat this as deny. The plain [`extract_action`]
/// helper preserves its historical best-effort `ToolAction` return type for
/// non-guard callers; guards and guard-like host enrichers should use
/// [`extract_action_checked`] instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MalformedAction {
    pub tool_name: String,
    pub field: String,
    pub expected: &'static str,
}

impl ToolAction {
    /// Return the path targeted by clearly filesystem-shaped actions.
    pub fn filesystem_path(&self) -> Option<&str> {
        match self {
            Self::FileAccess(path) | Self::FileWrite(path, _) | Self::Patch(path, _) => {
                Some(path.as_str())
            }
            _ => None,
        }
    }
}

mod extractor;

#[cfg(test)]
use extractor::{string_arg, StringArgViolation};

/// Extract a `ToolAction` from a tool name and its arguments.
///
/// This uses a best-effort heuristic based on common tool naming conventions.
/// Recognized but malformed action shapes map to `ToolAction::Unknown` to
/// preserve the historical return type. Guard-boundary code should call
/// [`extract_action_checked`] and deny malformed-action errors.
pub fn extract_action(tool_name: &str, arguments: &Value) -> ToolAction {
    extractor::extract_action(tool_name, arguments)
}

/// Extract a `ToolAction`, failing closed on recognized malformed action shapes.
pub fn extract_action_checked(
    tool_name: &str,
    arguments: &Value,
) -> Result<ToolAction, MalformedAction> {
    extractor::extract_action_checked(tool_name, arguments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn malformed_field(tool_name: &str, args: &Value) -> String {
        match extract_action_checked(tool_name, args) {
            Ok(action) => panic!("expected malformed action, got: {action:?}"),
            Err(err) => err.field,
        }
    }

    // Compile-time tripwire: this match has no `_` arm, so adding a
    // `ToolAction` variant breaks the build here and forces an audit of every
    // guard's action dispatch (each guard matches its domain variants and
    // passes the rest; a new variant must be classified, not silently allowed).
    #[test]
    fn tool_action_dispatch_is_exhaustive() {
        fn classify(action: &ToolAction) {
            match action {
                ToolAction::FileAccess(_)
                | ToolAction::FileWrite(_, _)
                | ToolAction::NetworkEgress(_, _)
                | ToolAction::ShellCommand(_)
                | ToolAction::McpTool(_, _)
                | ToolAction::Patch(_, _)
                | ToolAction::CodeExecution { .. }
                | ToolAction::BrowserAction { .. }
                | ToolAction::DatabaseQuery { .. }
                | ToolAction::ExternalApiCall { .. }
                | ToolAction::MemoryWrite { .. }
                | ToolAction::MemoryRead { .. }
                | ToolAction::Unknown => {}
            }
        }
        classify(&ToolAction::Unknown);
    }

    #[test]
    fn extract_file_access() {
        let args = serde_json::json!({"path": "/etc/shadow"});
        let action = extract_action("read_file", &args);
        assert!(matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/shadow"));
    }

    #[test]
    fn string_arg_preserves_key_priority_and_rejects_non_strings() {
        let args = serde_json::json!({
            "path": "/tmp/from-path",
            "file": "/tmp/from-file",
            "filename": "/tmp/from-filename"
        });

        assert_eq!(
            string_arg(&args, &["path", "file", "filename"]),
            Ok(Some("/tmp/from-path"))
        );

        let args = serde_json::json!({
            "path": 42,
            "file": "/tmp/from-file",
            "filename": "/tmp/from-filename"
        });

        assert_eq!(
            string_arg(&args, &["path", "file", "filename"]),
            Err(StringArgViolation::Malformed { field: "path" })
        );
        assert_eq!(
            string_arg(&args, &["missing", "path"]),
            Err(StringArgViolation::Malformed { field: "path" })
        );
        assert_eq!(string_arg(&args, &["missing"]), Ok(None));
    }

    #[test]
    fn extract_file_write() {
        let args = serde_json::json!({"path": "/tmp/out.txt", "content": "hello"});
        let action = extract_action("write_file", &args);
        assert!(matches!(action, ToolAction::FileWrite(ref p, _) if p == "/tmp/out.txt"));
    }

    #[test]
    fn extract_shell_command() {
        let args = serde_json::json!({"command": "ls -la"});
        let action = extract_action("bash", &args);
        assert!(matches!(action, ToolAction::ShellCommand(ref c) if c == "ls -la"));
    }

    #[test]
    fn shell_command_rejects_malformed_primary_alias() {
        let args = serde_json::json!({"command": ["rm", "-rf", "/"], "cmd": "echo safe"});
        assert_eq!(malformed_field("bash", &args), "command");
    }

    #[test]
    fn extract_network_egress() {
        let args = serde_json::json!({"url": "https://evil.com/api"});
        let action = extract_action("http_request", &args);
        assert!(matches!(action, ToolAction::NetworkEgress(ref h, 443) if h == "evil.com"));
    }

    #[test]
    fn network_tool_with_filesystem_shaped_arguments_stays_network_egress() {
        let args = serde_json::json!({
            "url": "http://169.254.169.254/latest",
            "path": "/tmp/cache-entry",
            "action": "delete"
        });
        let action = extract_action("http_request", &args);
        assert!(
            matches!(action, ToolAction::NetworkEgress(ref h, 80) if h == "169.254.169.254"),
            "expected NetworkEgress for http_request, got: {action:?}"
        );
    }

    #[test]
    fn network_rejects_malformed_primary_alias() {
        let args =
            serde_json::json!({"url": {"host": "169.254.169.254"}, "uri": "https://example.com"});
        assert_eq!(malformed_field("http_request", &args), "url");
    }

    #[test]
    fn network_rejects_unparseable_url() {
        let args = serde_json::json!({"url": "not-a-host"});
        assert_eq!(malformed_field("http_request", &args), "url");
    }

    #[test]
    fn network_rejects_invalid_explicit_port() {
        let args = serde_json::json!({"url": "http://127.0.0.1:notaport/latest"});
        assert_eq!(malformed_field("http_request", &args), "url");
    }

    #[test]
    fn network_rejects_ambiguous_unbracketed_ipv6() {
        let args = serde_json::json!({"url": "http://fd00:ec2::254/latest"});
        assert_eq!(malformed_field("http_request", &args), "url");
    }

    #[test]
    fn extract_network_with_port() {
        let args = serde_json::json!({"url": "http://localhost:8080/health"});
        let action = extract_action("fetch", &args);
        assert!(matches!(action, ToolAction::NetworkEgress(ref h, 8080) if h == "localhost"));
    }

    #[test]
    fn extract_network_with_scheme_relative_url() {
        let args = serde_json::json!({"url": "//169.254.169.254/latest"});
        let action = extract_action("http_request", &args);
        assert!(matches!(action, ToolAction::NetworkEgress(ref h, 443) if h == "169.254.169.254"));
    }

    #[test]
    fn extract_network_with_mixed_case_scheme() {
        let args = serde_json::json!({"url": "HTTPS://Example.COM/api"});
        let action = extract_action("fetch", &args);
        assert!(matches!(action, ToolAction::NetworkEgress(ref h, 443) if h == "example.com"));
    }

    #[test]
    fn extract_network_strips_userinfo_and_ipv6_brackets() {
        let userinfo_args = serde_json::json!({"url": "https://user:pass@evil.com/path"});
        let userinfo_action = extract_action("http_request", &userinfo_args);
        assert!(
            matches!(userinfo_action, ToolAction::NetworkEgress(ref h, 443) if h == "evil.com")
        );

        let ipv6_args = serde_json::json!({"url": "https://[fd00:ec2::254]/latest"});
        let ipv6_action = extract_action("http_request", &ipv6_args);
        assert!(
            matches!(ipv6_action, ToolAction::NetworkEgress(ref h, 443) if h == "fd00:ec2::254")
        );
    }

    #[test]
    fn extract_network_strips_query_and_fragment_from_authority() {
        let query_args = serde_json::json!({"url": "https://metadata.google.internal?x=1"});
        let query_action = extract_action("http_request", &query_args);
        assert!(matches!(
            query_action,
            ToolAction::NetworkEgress(ref h, 443) if h == "metadata.google.internal"
        ));

        let fragment_args = serde_json::json!({"url": "https://metadata.google.internal#anchor"});
        let fragment_action = extract_action("fetch", &fragment_args);
        assert!(matches!(
            fragment_action,
            ToolAction::NetworkEgress(ref h, 443) if h == "metadata.google.internal"
        ));
    }

    #[test]
    fn unknown_tool_becomes_mcp_tool() {
        let args = serde_json::json!({"foo": "bar"});
        let action = extract_action("custom_tool", &args);
        assert!(matches!(action, ToolAction::McpTool(_, _)));
    }

    #[test]
    fn unknown_tool_with_path_still_becomes_mcp_tool() {
        let args = serde_json::json!({"path": "/etc/shadow"});
        let action = extract_action("custom_tool", &args);
        assert!(matches!(action, ToolAction::McpTool(_, _)));
    }

    #[test]
    fn filesystem_tool_read_by_default() {
        let args = serde_json::json!({"path": "/etc/shadow"});
        let action = extract_action("filesystem", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/shadow"),
            "expected FileAccess for filesystem tool with path-only params, got: {action:?}"
        );
    }

    #[test]
    fn filesystem_tool_rejects_malformed_primary_path_alias() {
        let args = serde_json::json!({
            "path": 42,
            "file": "/home/user/project/src/main.rs"
        });
        assert_eq!(malformed_field("filesystem", &args), "path");
    }

    #[test]
    fn filesystem_tool_rejects_missing_path() {
        let args = serde_json::json!({"action": "read"});
        assert_eq!(malformed_field("filesystem", &args), "path");
    }

    #[test]
    fn filesystem_tool_rejects_malformed_action() {
        let args = serde_json::json!({"path": "/tmp/out.txt", "action": ["write"]});
        assert_eq!(malformed_field("filesystem", &args), "action");
    }

    #[test]
    fn filesystem_write_rejects_malformed_content() {
        let args = serde_json::json!({"path": "/tmp/out.txt", "content": {"bytes": "hi"}});
        assert_eq!(malformed_field("write_file", &args), "content");
    }

    #[test]
    fn recognized_extractors_reject_malformed_higher_priority_aliases() {
        let cases = [
            (
                "python",
                serde_json::json!({"code": ["print('unsafe')"], "source": "print('safe')"}),
                "code",
            ),
            (
                "eval",
                serde_json::json!({"code": "console.log(1)", "language": ["javascript"], "lang": "python"}),
                "language",
            ),
            (
                "browser",
                serde_json::json!({"action": ["click"], "verb": "navigate"}),
                "action",
            ),
            (
                "browser",
                serde_json::json!({"action": "click", "url": ["https://evil.example"], "selector": "#safe"}),
                "url",
            ),
            (
                "sql",
                serde_json::json!({"query": {"raw": "DROP TABLE users"}, "sql": "SELECT 1"}),
                "query",
            ),
            (
                "postgres",
                serde_json::json!({"query": "SELECT 1", "database": ["prod"], "db": "readonly"}),
                "database",
            ),
            (
                "vector_upsert",
                serde_json::json!({"collection": ["sensitive"], "store": "safe"}),
                "collection",
            ),
            (
                "vector_query",
                serde_json::json!({"collection": "facts", "id": ["secret"], "key": "safe"}),
                "id",
            ),
            (
                "slack_send_message",
                serde_json::json!({"endpoint": ["chat.postMessage"], "path": "chat.safe"}),
                "endpoint",
            ),
        ];

        for (tool_name, args, expected_field) in cases {
            assert_eq!(
                malformed_field(tool_name, &args),
                expected_field,
                "tool {tool_name} should reject malformed {expected_field}"
            );
        }
    }

    #[test]
    fn filesystem_tool_explicit_read_action() {
        let args = serde_json::json!({"path": "/etc/shadow", "action": "read"});
        let action = extract_action("filesystem", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/shadow"),
            "expected FileAccess for filesystem tool with action=read, got: {action:?}"
        );
    }

    #[test]
    fn filesystem_tool_write_action() {
        let args = serde_json::json!({"path": "/tmp/out.txt", "action": "write", "content": "hi"});
        let action = extract_action("filesystem", &args);
        assert!(
            matches!(action, ToolAction::FileWrite(ref p, _) if p == "/tmp/out.txt"),
            "expected FileWrite for filesystem tool with action=write, got: {action:?}"
        );
    }

    #[test]
    fn filesystem_tool_write_inferred_from_content() {
        let args = serde_json::json!({"path": "/tmp/out.txt", "content": "data"});
        let action = extract_action("filesystem", &args);
        assert!(
            matches!(action, ToolAction::FileWrite(ref p, _) if p == "/tmp/out.txt"),
            "expected FileWrite for filesystem tool with content field, got: {action:?}"
        );
    }

    #[test]
    fn fs_tool_alias() {
        let args = serde_json::json!({"path": "/etc/passwd"});
        let action = extract_action("fs", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/passwd"),
            "expected FileAccess for fs tool alias, got: {action:?}"
        );
    }

    #[test]
    fn acp_fs_read_text_file_classifies_as_file_access() {
        let args = serde_json::json!({"path": "/etc/shadow", "sessionId": "sess-1"});
        let action = extract_action("fs/read_text_file", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/shadow"),
            "expected FileAccess for ACP fs/read_text_file, got: {action:?}"
        );
    }

    #[test]
    fn acp_fs_write_text_file_classifies_as_file_write() {
        let args = serde_json::json!({
            "path": "/workspace/out.txt",
            "content": "hello",
            "sessionId": "sess-1"
        });
        let action = extract_action("fs/write_text_file", &args);
        assert!(
            matches!(action, ToolAction::FileWrite(ref p, ref content)
                if p == "/workspace/out.txt" && content == b"hello"),
            "expected FileWrite for ACP fs/write_text_file, got: {action:?}"
        );
    }

    #[test]
    fn fs_prefix_stat_classifies_as_file_access() {
        let args = serde_json::json!({"path": "/workspace/file.txt"});
        let action = extract_action("fs_stat", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/workspace/file.txt"),
            "expected FileAccess for fs_stat, got: {action:?}"
        );
    }

    #[test]
    fn file_tool_alias() {
        let args = serde_json::json!({"path": "/etc/passwd"});
        let action = extract_action("file", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/passwd"),
            "expected FileAccess for file tool alias, got: {action:?}"
        );
    }

    #[test]
    fn patch_tool_rejects_malformed_diff_alias() {
        let action = extract_action(
            "apply_patch",
            &serde_json::json!({"path": "/repo/src/lib.rs", "diff": ["@@ -1 +1 @@"], "patch": "@@ -1 +1 @@"}),
        );
        assert!(matches!(action, ToolAction::Unknown));

        let err_field = malformed_field(
            "apply_patch",
            &serde_json::json!({"path": "/repo/src/lib.rs", "diff": ["@@ -1 +1 @@"], "patch": "@@ -1 +1 @@"}),
        );
        assert_eq!(err_field, "diff");
    }

    #[test]
    fn extract_code_execution_python() {
        let args = serde_json::json!({"code": "import os; os.listdir('.')"});
        let action = extract_action("python", &args);
        match action {
            ToolAction::CodeExecution { language, code } => {
                assert_eq!(language, "python");
                assert!(code.contains("os.listdir"));
            }
            other => panic!("expected CodeExecution, got: {other:?}"),
        }
    }

    #[test]
    fn extract_code_execution_explicit_language() {
        let args = serde_json::json!({"source": "console.log(1)", "language": "javascript"});
        let action = extract_action("eval", &args);
        match action {
            ToolAction::CodeExecution { language, code } => {
                assert_eq!(language, "javascript");
                assert_eq!(code, "console.log(1)");
            }
            other => panic!("expected CodeExecution, got: {other:?}"),
        }
    }

    #[test]
    fn extract_browser_navigate() {
        let args = serde_json::json!({"url": "https://example.com"});
        let action = extract_action("navigate", &args);
        match action {
            ToolAction::BrowserAction { verb, target } => {
                assert_eq!(verb, "navigate");
                assert_eq!(target.as_deref(), Some("https://example.com"));
            }
            other => panic!("expected BrowserAction, got: {other:?}"),
        }
    }

    #[test]
    fn extract_browser_click_with_selector() {
        let args = serde_json::json!({"action": "click", "selector": "#submit"});
        let action = extract_action("browser", &args);
        match action {
            ToolAction::BrowserAction { verb, target } => {
                assert_eq!(verb, "click");
                assert_eq!(target.as_deref(), Some("#submit"));
            }
            other => panic!("expected BrowserAction, got: {other:?}"),
        }
    }

    #[test]
    fn extract_database_query() {
        let args = serde_json::json!({"query": "SELECT * FROM users", "database": "prod"});
        let action = extract_action("sql", &args);
        match action {
            ToolAction::DatabaseQuery { database, query } => {
                assert_eq!(database, "prod");
                assert!(query.contains("SELECT"));
            }
            other => panic!("expected DatabaseQuery, got: {other:?}"),
        }
    }

    #[test]
    fn extract_database_query_default_db() {
        let args = serde_json::json!({"query": "SELECT 1"});
        let action = extract_action("postgres", &args);
        match action {
            ToolAction::DatabaseQuery { database, .. } => {
                assert_eq!(database, "postgres");
            }
            other => panic!("expected DatabaseQuery, got: {other:?}"),
        }
    }

    #[test]
    fn extract_memory_write() {
        let args = serde_json::json!({"collection": "agent-notes", "id": "mem-42"});
        let action = extract_action("vector_upsert", &args);
        match action {
            ToolAction::MemoryWrite { store, key } => {
                assert_eq!(store, "agent-notes");
                assert_eq!(key, "mem-42");
            }
            other => panic!("expected MemoryWrite, got: {other:?}"),
        }
    }

    #[test]
    fn extract_memory_read_with_key() {
        let args = serde_json::json!({"namespace": "session-1", "id": "fact-7"});
        let action = extract_action("recall", &args);
        match action {
            ToolAction::MemoryRead { store, key } => {
                assert_eq!(store, "session-1");
                assert_eq!(key.as_deref(), Some("fact-7"));
            }
            other => panic!("expected MemoryRead, got: {other:?}"),
        }
    }

    #[test]
    fn extract_memory_read_without_key() {
        let args = serde_json::json!({"collection": "facts"});
        let action = extract_action("vector_query", &args);
        match action {
            ToolAction::MemoryRead { store, key } => {
                assert_eq!(store, "facts");
                assert!(key.is_none());
            }
            other => panic!("expected MemoryRead, got: {other:?}"),
        }
    }

    #[test]
    fn extract_external_api_call_slack() {
        let args = serde_json::json!({"endpoint": "chat.postMessage"});
        let action = extract_action("slack_send_message", &args);
        match action {
            ToolAction::ExternalApiCall { service, endpoint } => {
                assert_eq!(service, "slack");
                assert_eq!(endpoint, "chat.postMessage");
            }
            other => panic!("expected ExternalApiCall, got: {other:?}"),
        }
    }

    #[test]
    fn extract_external_api_call_stripe_default_endpoint() {
        let args = serde_json::json!({});
        let action = extract_action("stripe_create_charge", &args);
        match action {
            ToolAction::ExternalApiCall { service, endpoint } => {
                assert_eq!(service, "stripe");
                assert_eq!(endpoint, "stripe_create_charge");
            }
            other => panic!("expected ExternalApiCall, got: {other:?}"),
        }
    }

    #[test]
    fn filesystem_tool_actions_expose_target_path() {
        let read = extract_action(
            "filesystem",
            &serde_json::json!({"path": "/repo/src/lib.rs"}),
        );
        let write = extract_action(
            "filesystem",
            &serde_json::json!({"path": "/repo/src/lib.rs", "action": "write", "content": "hi"}),
        );
        let patch = extract_action(
            "apply_patch",
            &serde_json::json!({"path": "/repo/src/lib.rs", "patch": "@@ -1 +1 @@"}),
        );

        assert_eq!(read.filesystem_path(), Some("/repo/src/lib.rs"));
        assert_eq!(write.filesystem_path(), Some("/repo/src/lib.rs"));
        assert_eq!(patch.filesystem_path(), Some("/repo/src/lib.rs"));
    }
}
