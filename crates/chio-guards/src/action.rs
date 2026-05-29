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

/// Extract a `ToolAction` from a tool name and its arguments.
///
/// This uses a best-effort heuristic based on common tool naming conventions.
/// Guards that receive `ToolAction::Unknown` should return `Verdict::Allow`
/// (the guard simply does not apply to that action type).
pub fn extract_action(tool_name: &str, arguments: &Value) -> ToolAction {
    let tool = tool_name.to_lowercase();

    // File read tools
    if matches!(
        tool.as_str(),
        "read_file" | "read" | "file_read" | "get_file" | "cat"
    ) {
        if let Some(path) = extract_path(arguments) {
            return ToolAction::FileAccess(path);
        }
    }

    // File write tools
    if matches!(
        tool.as_str(),
        "write_file" | "write" | "file_write" | "create_file" | "put_file" | "edit_file" | "edit"
    ) {
        if let Some(path) = extract_path(arguments) {
            let content = arguments
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .as_bytes()
                .to_vec();
            return ToolAction::FileWrite(path, content);
        }
    }

    // Generic filesystem tools -- disambiguate read vs write by inspecting
    // the `action` parameter or the presence of `content`.
    if matches!(tool.as_str(), "filesystem" | "fs" | "file") {
        if let Some(path) = extract_path(arguments) {
            let is_write = arguments
                .get("action")
                .and_then(|v| v.as_str())
                .map(|a| {
                    let a = a.to_lowercase();
                    a == "write" || a == "create" || a == "append"
                })
                .unwrap_or(false)
                || arguments.get("content").is_some();

            if is_write {
                let content = arguments
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .as_bytes()
                    .to_vec();
                return ToolAction::FileWrite(path, content);
            } else {
                return ToolAction::FileAccess(path);
            }
        }
    }

    // Patch / apply diff tools
    if matches!(tool.as_str(), "apply_patch" | "patch" | "apply_diff") {
        if let Some(path) = extract_path(arguments) {
            let diff = arguments
                .get("diff")
                .or_else(|| arguments.get("patch"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            return ToolAction::Patch(path, diff);
        }
    }

    // Shell / command execution tools
    if matches!(
        tool.as_str(),
        "bash" | "shell" | "run_command" | "exec" | "execute" | "run" | "shell_exec" | "terminal"
    ) {
        if let Some(cmd) = arguments
            .get("command")
            .or_else(|| arguments.get("cmd"))
            .or_else(|| arguments.get("input"))
            .and_then(|v| v.as_str())
        {
            return ToolAction::ShellCommand(cmd.to_string());
        }
    }

    // Network / HTTP tools
    if matches!(
        tool.as_str(),
        "http_request" | "fetch" | "curl" | "http" | "request" | "web_request"
    ) {
        if let Some(url) = arguments
            .get("url")
            .or_else(|| arguments.get("uri"))
            .and_then(|v| v.as_str())
        {
            if let Some((host, port)) = parse_host_port(url) {
                return ToolAction::NetworkEgress(host, port);
            }
        }
    }

    // Code execution via interpreter (Python/JS eval, notebook cell, REPL).
    if matches!(
        tool.as_str(),
        "python"
            | "python_exec"
            | "run_python"
            | "eval"
            | "evaluate"
            | "code_exec"
            | "exec_code"
            | "run_code"
            | "notebook"
            | "notebook_cell"
            | "repl"
            | "jupyter"
            | "ipython"
    ) {
        let code = arguments
            .get("code")
            .or_else(|| arguments.get("source"))
            .or_else(|| arguments.get("snippet"))
            .or_else(|| arguments.get("script"))
            .or_else(|| arguments.get("input"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let language = arguments
            .get("language")
            .or_else(|| arguments.get("lang"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| infer_language_from_tool(&tool));
        return ToolAction::CodeExecution { language, code };
    }

    // Browser automation.
    if matches!(
        tool.as_str(),
        "browser"
            | "browser_action"
            | "browser_navigate"
            | "navigate"
            | "goto"
            | "click"
            | "type"
            | "screenshot"
            | "browser_click"
            | "browser_type"
            | "browser_screenshot"
            | "playwright"
            | "puppeteer"
            | "selenium"
    ) {
        let verb = arguments
            .get("action")
            .or_else(|| arguments.get("verb"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| tool.clone());
        let target = arguments
            .get("url")
            .or_else(|| arguments.get("target"))
            .or_else(|| arguments.get("href"))
            .or_else(|| arguments.get("selector"))
            .and_then(|v| v.as_str())
            .map(String::from);
        return ToolAction::BrowserAction { verb, target };
    }

    // Database queries (SQL and NoSQL). Detect by tool name and presence of
    // a query/statement argument.
    if matches!(
        tool.as_str(),
        "sql"
            | "query"
            | "db_query"
            | "database"
            | "execute_sql"
            | "run_sql"
            | "postgres"
            | "mysql"
            | "sqlite"
            | "snowflake"
            | "bigquery"
            | "redshift"
            | "mongo"
            | "mongodb"
            | "redis"
    ) {
        if let Some(q) = arguments
            .get("query")
            .or_else(|| arguments.get("sql"))
            .or_else(|| arguments.get("statement"))
            .or_else(|| arguments.get("command"))
            .and_then(|v| v.as_str())
        {
            let database = arguments
                .get("database")
                .or_else(|| arguments.get("db"))
                .or_else(|| arguments.get("connection"))
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| tool.clone());
            return ToolAction::DatabaseQuery {
                database,
                query: q.to_string(),
            };
        }
    }

    // Vector database / memory writes.
    if matches!(
        tool.as_str(),
        "memory_write"
            | "remember"
            | "store_memory"
            | "vector_upsert"
            | "vector_write"
            | "upsert"
            | "pinecone_upsert"
            | "weaviate_write"
            | "qdrant_upsert"
    ) {
        let store = arguments
            .get("collection")
            .or_else(|| arguments.get("index"))
            .or_else(|| arguments.get("namespace"))
            .or_else(|| arguments.get("store"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| tool.clone());
        let key = arguments
            .get("id")
            .or_else(|| arguments.get("key"))
            .or_else(|| arguments.get("memory_id"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_default();
        return ToolAction::MemoryWrite { store, key };
    }

    // Vector database / memory reads.
    if matches!(
        tool.as_str(),
        "memory_read"
            | "recall"
            | "retrieve_memory"
            | "vector_query"
            | "vector_search"
            | "similarity_search"
            | "pinecone_query"
            | "weaviate_search"
            | "qdrant_search"
    ) {
        let store = arguments
            .get("collection")
            .or_else(|| arguments.get("index"))
            .or_else(|| arguments.get("namespace"))
            .or_else(|| arguments.get("store"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| tool.clone());
        let key = arguments
            .get("id")
            .or_else(|| arguments.get("key"))
            .or_else(|| arguments.get("memory_id"))
            .and_then(|v| v.as_str())
            .map(String::from);
        return ToolAction::MemoryRead { store, key };
    }

    // External API calls with recognizable service prefixes.
    if let Some(service) = detect_api_service(&tool) {
        let endpoint = arguments
            .get("endpoint")
            .or_else(|| arguments.get("path"))
            .or_else(|| arguments.get("action"))
            .or_else(|| arguments.get("method"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| tool.clone());
        return ToolAction::ExternalApiCall { service, endpoint };
    }

    // MCP tool invocations (generic passthrough)
    if tool.starts_with("mcp_") || tool.contains("mcp") {
        return ToolAction::McpTool(tool_name.to_string(), arguments.clone());
    }

    // Fallback: treat as a generic MCP tool invocation so the MCP guard can
    // still apply its block/allow lists.
    ToolAction::McpTool(tool_name.to_string(), arguments.clone())
}

fn infer_language_from_tool(tool: &str) -> String {
    match tool {
        "python" | "python_exec" | "run_python" | "jupyter" | "ipython" | "notebook"
        | "notebook_cell" => "python".to_string(),
        "repl" => "javascript".to_string(),
        _ => "unknown".to_string(),
    }
}

fn detect_api_service(tool: &str) -> Option<String> {
    for prefix in [
        "slack_",
        "stripe_",
        "github_",
        "gitlab_",
        "jira_",
        "twilio_",
        "sendgrid_",
        "pagerduty_",
        "opsgenie_",
        "zendesk_",
        "salesforce_",
        "hubspot_",
        "notion_",
        "linear_",
        "intercom_",
    ] {
        if let Some(rest) = tool.strip_prefix(prefix) {
            if !rest.is_empty() {
                let service = prefix.trim_end_matches('_').to_string();
                return Some(service);
            }
        }
    }
    None
}

fn extract_path(arguments: &Value) -> Option<String> {
    arguments
        .get("path")
        .or_else(|| arguments.get("file"))
        .or_else(|| arguments.get("file_path"))
        .or_else(|| arguments.get("filename"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

fn parse_host_port(url: &str) -> Option<(String, u16)> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }

    let lowered = url.to_ascii_lowercase();
    if lowered.starts_with("data:")
        || lowered.starts_with("javascript:")
        || lowered.starts_with("about:")
        || lowered.starts_with("file:")
    {
        return None;
    }

    let (rest, default_port, parsed_as_url) = if lowered.starts_with("https://") {
        (&url["https://".len()..], 443, true)
    } else if lowered.starts_with("http://") {
        (&url["http://".len()..], 80, true)
    } else if let Some(rest) = url.strip_prefix("//") {
        (rest, 443, true)
    } else {
        (url, 443, false)
    };

    let host_with_port = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_without_userinfo = host_with_port
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(host_with_port);

    let (host, port) = if let Some(bracketed) = host_without_userinfo.strip_prefix('[') {
        let (host, remainder) = bracketed.split_once(']')?;
        let port = if remainder.is_empty() {
            default_port
        } else if let Some(port_str) = remainder.strip_prefix(':') {
            port_str.parse::<u16>().ok()?
        } else {
            return None;
        };
        (host.to_string(), port)
    } else {
        split_host_port(host_without_userinfo, default_port)
    };

    let host = host.trim_matches(|c: char| c == '/' || c == '.');
    let looks_like_host = host.contains('.') || host == "localhost" || host.contains(':');
    if host.is_empty() || (!parsed_as_url && !looks_like_host) {
        return None;
    }

    Some((host.to_ascii_lowercase(), port))
}

fn split_host_port(host_with_port: &str, default_port: u16) -> (String, u16) {
    if let Some((host, port_str)) = host_with_port.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (host_with_port.to_string(), default_port)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn extract_network_egress() {
        let args = serde_json::json!({"url": "https://evil.com/api"});
        let action = extract_action("http_request", &args);
        assert!(matches!(action, ToolAction::NetworkEgress(ref h, 443) if h == "evil.com"));
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
    fn filesystem_tool_read_by_default() {
        let args = serde_json::json!({"path": "/etc/shadow"});
        let action = extract_action("filesystem", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/shadow"),
            "expected FileAccess for filesystem tool with path-only params, got: {action:?}"
        );
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
    fn file_tool_alias() {
        let args = serde_json::json!({"path": "/etc/passwd"});
        let action = extract_action("file", &args);
        assert!(
            matches!(action, ToolAction::FileAccess(ref p) if p == "/etc/passwd"),
            "expected FileAccess for file tool alias, got: {action:?}"
        );
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
