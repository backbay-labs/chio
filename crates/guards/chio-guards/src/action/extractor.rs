use serde_json::Value;

use super::{MalformedAction, ToolAction};

type ActionExtraction = Result<Option<ToolAction>, MalformedAction>;

pub(super) fn extract_action(tool_name: &str, arguments: &Value) -> ToolAction {
    match extract_action_checked(tool_name, arguments) {
        Ok(action) => action,
        Err(_) => ToolAction::Unknown,
    }
}

pub(super) fn extract_action_checked(
    tool_name: &str,
    arguments: &Value,
) -> Result<ToolAction, MalformedAction> {
    ActionExtractor::new(tool_name, arguments).extract()
}

struct ActionExtractor<'a> {
    tool_name: &'a str,
    tool: String,
    normalized_tool: String,
    arguments: &'a Value,
}

impl<'a> ActionExtractor<'a> {
    fn new(tool_name: &'a str, arguments: &'a Value) -> Self {
        let tool = tool_name.to_lowercase();
        let normalized_tool = normalize_tool_name_for_classification(&tool);
        Self {
            tool_name,
            tool,
            normalized_tool,
            arguments,
        }
    }

    fn extract(&self) -> Result<ToolAction, MalformedAction> {
        macro_rules! try_extract {
            ($result:expr) => {
                match $result {
                    Ok(Some(action)) => return Ok(action),
                    Err(err) => return Err(err),
                    Ok(None) => {}
                }
            };
        }

        try_extract!(self.extract_network_action());
        try_extract!(self.extract_filesystem_action());
        try_extract!(self.extract_shell_action());
        try_extract!(self.extract_code_execution_action());
        try_extract!(self.extract_browser_action());
        try_extract!(self.extract_database_action());
        try_extract!(self.extract_memory_write_action());
        try_extract!(self.extract_memory_read_action());
        try_extract!(self.extract_external_api_action());

        Ok(ToolAction::McpTool(
            self.tool_name.to_string(),
            self.arguments.clone(),
        ))
    }

    fn extract_filesystem_action(&self) -> ActionExtraction {
        let patch_tool = is_patch_tool(&self.normalized_tool);
        let write_tool = is_filesystem_write_tool(&self.normalized_tool);
        let read_tool = is_filesystem_read_tool(&self.normalized_tool);
        let namespace_tool = is_filesystem_namespace_tool(&self.normalized_tool);

        if !(patch_tool || write_tool || read_tool || namespace_tool) {
            return Ok(None);
        }

        let path = self.required_string(&["path", "file", "file_path", "filename"])?;

        if patch_tool {
            let diff = self.required_string(&["diff", "patch"])?;
            return Ok(Some(ToolAction::Patch(path.to_string(), diff.to_string())));
        }

        if write_tool || self.filesystem_action_argument_is_write()? {
            let content = self
                .optional_string(&["content"])?
                .map(str::as_bytes)
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            return Ok(Some(ToolAction::FileWrite(path.to_string(), content)));
        }

        if read_tool || namespace_tool {
            return Ok(Some(ToolAction::FileAccess(path.to_string())));
        }

        Ok(None)
    }

    fn extract_shell_action(&self) -> ActionExtraction {
        if !matches!(
            self.tool.as_str(),
            "bash"
                | "shell"
                | "run_command"
                | "exec"
                | "execute"
                | "run"
                | "shell_exec"
                | "terminal"
        ) {
            return Ok(None);
        }

        let command = self.required_string(&["command", "cmd", "input"])?;
        Ok(Some(ToolAction::ShellCommand(command.to_string())))
    }

    fn extract_network_action(&self) -> ActionExtraction {
        if !matches!(
            self.tool.as_str(),
            "http_request" | "fetch" | "curl" | "http" | "request" | "web_request"
        ) {
            return Ok(None);
        }

        let url = self.required_string(&["url", "uri"])?;
        match parse_host_port(url) {
            Some((host, port)) => Ok(Some(ToolAction::NetworkEgress(host, port))),
            None => Err(self.malformed_field("url")),
        }
    }

    fn extract_code_execution_action(&self) -> ActionExtraction {
        if !matches!(
            self.tool.as_str(),
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
            return Ok(None);
        }

        let code = self.required_string(&["code", "source", "snippet", "script", "input"])?;
        let language = self
            .optional_string(&["language", "lang"])?
            .map(str::to_string)
            .unwrap_or_else(|| infer_language_from_tool(&self.tool));
        Ok(Some(ToolAction::CodeExecution {
            language,
            code: code.to_string(),
        }))
    }

    fn extract_browser_action(&self) -> ActionExtraction {
        if !matches!(
            self.tool.as_str(),
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
            return Ok(None);
        }

        let verb = self
            .optional_string(&["action", "verb"])?
            .map(str::to_string)
            .unwrap_or_else(|| self.tool.clone());
        let target = self
            .optional_string(&["url", "target", "href", "selector"])?
            .map(str::to_string);
        Ok(Some(ToolAction::BrowserAction { verb, target }))
    }

    fn extract_database_action(&self) -> ActionExtraction {
        if !matches!(
            self.tool.as_str(),
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
            return Ok(None);
        }

        let query = self.required_string(&["query", "sql", "statement", "command"])?;
        let database = self
            .optional_string(&["database", "db", "connection"])?
            .map(str::to_string)
            .unwrap_or_else(|| self.tool.clone());
        Ok(Some(ToolAction::DatabaseQuery {
            database,
            query: query.to_string(),
        }))
    }

    fn extract_memory_write_action(&self) -> ActionExtraction {
        if !matches!(
            self.tool.as_str(),
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
            return Ok(None);
        }

        let store = self
            .optional_string(&["collection", "index", "namespace", "store"])?
            .map(str::to_string)
            .unwrap_or_else(|| self.tool.clone());
        let key = self
            .optional_string(&["id", "key", "memory_id"])?
            .map(str::to_string)
            .unwrap_or_default();
        Ok(Some(ToolAction::MemoryWrite { store, key }))
    }

    fn extract_memory_read_action(&self) -> ActionExtraction {
        if !matches!(
            self.tool.as_str(),
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
            return Ok(None);
        }

        let store = self
            .optional_string(&["collection", "index", "namespace", "store"])?
            .map(str::to_string)
            .unwrap_or_else(|| self.tool.clone());
        let key = self
            .optional_string(&["id", "key", "memory_id"])?
            .map(str::to_string);
        Ok(Some(ToolAction::MemoryRead { store, key }))
    }

    fn extract_external_api_action(&self) -> ActionExtraction {
        let Some(service) = detect_api_service(&self.tool) else {
            return Ok(None);
        };
        let endpoint = self
            .optional_string(&["endpoint", "path", "action", "method"])?
            .map(str::to_string)
            .unwrap_or_else(|| self.tool.clone());
        Ok(Some(ToolAction::ExternalApiCall { service, endpoint }))
    }

    fn filesystem_action_argument_is_write(&self) -> Result<bool, MalformedAction> {
        let action_is_write = self
            .optional_string(&["action"])?
            .map(|action| {
                matches!(
                    action.to_ascii_lowercase().as_str(),
                    "write" | "create" | "append" | "delete" | "remove"
                )
            })
            .unwrap_or(false);
        Ok(action_is_write || self.arguments.get("content").is_some())
    }

    fn optional_string(&self, keys: &[&'static str]) -> Result<Option<&'a str>, MalformedAction> {
        string_arg(self.arguments, keys).map_err(|err| malformed_action(self.tool_name, err))
    }

    fn required_string(&self, keys: &[&'static str]) -> Result<&'a str, MalformedAction> {
        required_string_arg(self.arguments, keys)
            .map_err(|err| malformed_action(self.tool_name, err))
    }

    fn malformed_field(&self, field: &'static str) -> MalformedAction {
        malformed_field(self.tool_name, field)
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StringArgViolation {
    Missing { field: &'static str },
    Malformed { field: &'static str },
}

impl StringArgViolation {
    fn field(self) -> &'static str {
        match self {
            Self::Missing { field } | Self::Malformed { field } => field,
        }
    }
}

fn malformed_action(tool_name: &str, violation: StringArgViolation) -> MalformedAction {
    malformed_field(tool_name, violation.field())
}

fn malformed_field(tool_name: &str, field: &'static str) -> MalformedAction {
    MalformedAction {
        tool_name: tool_name.to_string(),
        field: field.to_string(),
        expected: "string",
    }
}

pub(super) fn string_arg<'a>(
    arguments: &'a Value,
    keys: &[&'static str],
) -> Result<Option<&'a str>, StringArgViolation> {
    for key in keys {
        let Some(value) = arguments.get(*key) else {
            continue;
        };
        let Some(value) = value.as_str() else {
            return Err(StringArgViolation::Malformed { field: key });
        };
        return Ok(Some(value));
    }
    Ok(None)
}

fn required_string_arg<'a>(
    arguments: &'a Value,
    keys: &[&'static str],
) -> Result<&'a str, StringArgViolation> {
    match string_arg(arguments, keys)? {
        Some(value) => Ok(value),
        None => Err(StringArgViolation::Missing { field: keys[0] }),
    }
}

fn normalize_tool_name_for_classification(tool: &str) -> String {
    tool.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn is_filesystem_read_tool(tool: &str) -> bool {
    matches!(
        tool,
        "read_file" | "read" | "file_read" | "get_file" | "cat"
    ) || tool.contains("read_file")
        || tool.contains("read_text_file")
        || tool.contains("list_dir")
        || tool.contains("list_directory")
        || (tool.starts_with("fs_") && (tool.contains("_read") || tool.contains("_stat")))
}

fn is_filesystem_write_tool(tool: &str) -> bool {
    matches!(
        tool,
        "write_file" | "write" | "file_write" | "create_file" | "put_file" | "edit_file" | "edit"
    ) || tool.contains("write_file")
        || tool.contains("write_text_file")
        || tool.contains("create_file")
        || tool.contains("delete_file")
        || tool.contains("remove_file")
        || (tool.starts_with("fs_")
            && (tool.contains("_write")
                || tool.contains("_create")
                || tool.contains("_append")
                || tool.contains("_delete")
                || tool.contains("_remove")))
}

fn is_patch_tool(tool: &str) -> bool {
    matches!(tool, "apply_patch" | "patch" | "apply_diff") || tool.contains("apply_patch")
}

fn is_filesystem_namespace_tool(tool: &str) -> bool {
    matches!(tool, "filesystem" | "fs" | "file") || tool.starts_with("fs_")
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
        split_host_port(host_without_userinfo, default_port)?
    };

    let host = host.trim_matches(|c: char| c == '/' || c == '.');
    let looks_like_host = host.contains('.') || host == "localhost" || host.contains(':');
    if host.is_empty() || (!parsed_as_url && !looks_like_host) {
        return None;
    }

    Some((host.to_ascii_lowercase(), port))
}

fn split_host_port(host_with_port: &str, default_port: u16) -> Option<(String, u16)> {
    let colon_count = host_with_port.bytes().filter(|byte| *byte == b':').count();
    if colon_count > 1 {
        return None;
    }
    if colon_count == 1 {
        let (host, port_str) = host_with_port.rsplit_once(':')?;
        if host.is_empty() || port_str.is_empty() {
            return None;
        }
        let port = port_str.parse::<u16>().ok()?;
        return Some((host.to_string(), port));
    }
    Some((host_with_port.to_string(), default_port))
}
