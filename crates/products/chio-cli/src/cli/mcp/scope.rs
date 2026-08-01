// Per-tool capability scope inference for `chio mcp wrap`.
//
// The MCP `tools/list` response carries a free-form JSON Schema and
// (optionally) a set of annotations such as `readOnlyHint` and
// `destructiveHint`. We turn each tool entry into a best-effort
// capability shape that the user reviews before promoting:
//
// - Read-only tools (`readOnlyHint == true`) classify as `Read`.
// - Tools whose annotations claim `destructiveHint == true` classify as
//   `Destructive`.
// - Schemas that mention path-shaped properties (e.g. `path`, `dir`,
//   `file`) classify as `FileSystem`.
// - Schemas that mention URL/host-shaped properties (`url`, `host`,
//   `endpoint`) classify as `Network`.
// - Everything else falls through to `Generic` so the user still sees the
//   tool listed in the scaffold.
//
// The classifier is deterministic and pure: same `tools/list` input
// produces the same output, so the scaffold is hash-stable and the IDE
// config emit can fingerprint it.

/// Coarse capability classes inferred from `tools/list` shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InferredScope {
    Read,
    FileSystem,
    Network,
    Destructive,
    Generic,
}

impl InferredScope {
    pub(crate) fn as_urn(&self) -> &'static str {
        match self {
            InferredScope::Read => "urn:chio:scope:tool:read",
            InferredScope::FileSystem => "urn:chio:scope:tool:filesystem",
            InferredScope::Network => "urn:chio:scope:tool:network",
            InferredScope::Destructive => "urn:chio:scope:tool:destructive",
            InferredScope::Generic => "urn:chio:scope:tool:generic",
        }
    }
}

/// A single inferred capability scope for a tool. The user reviews the
/// scaffold and flips `allow` to `true` to promote.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct InferredCapability {
    pub tool: String,
    pub scope: InferredScope,
    pub urn: String,
    pub description: Option<String>,
    /// Default-deny: every inferred capability ships disabled.
    pub allow: bool,
}

/// Infer the capability scope for a single MCP tool entry. Pure function;
/// safe to call from tests without spinning up a transport.
pub(crate) fn infer_scope_for_tool(
    info: &chio_mcp_adapter::edge::McpToolInfo,
) -> InferredCapability {
    let scope = classify_tool(info);
    InferredCapability {
        tool: info.name.clone(),
        scope,
        urn: scope.as_urn().to_string(),
        description: info.description.clone(),
        allow: false,
    }
}

/// Run the per-tool inference across the full `tools/list` payload.
pub(crate) fn infer_scopes(
    tools: &[chio_mcp_adapter::edge::McpToolInfo],
) -> Vec<InferredCapability> {
    let mut out: Vec<InferredCapability> = tools.iter().map(infer_scope_for_tool).collect();
    out.sort_by(|a, b| a.tool.cmp(&b.tool));
    out
}

fn classify_tool(info: &chio_mcp_adapter::edge::McpToolInfo) -> InferredScope {
    if let Some(annotations) = info.annotations.as_ref() {
        if annotations
            .get("destructiveHint")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            return InferredScope::Destructive;
        }
        if annotations
            .get("readOnlyHint")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            return InferredScope::Read;
        }
    }

    let schema_text = info.input_schema.to_string().to_lowercase();
    if schema_contains_any(
        &schema_text,
        &[
            "\"path\"",
            "\"file\"",
            "\"directory\"",
            "\"dir\"",
            "\"filename\"",
        ],
    ) {
        return InferredScope::FileSystem;
    }
    if schema_contains_any(
        &schema_text,
        &["\"url\"", "\"host\"", "\"endpoint\"", "\"uri\""],
    ) {
        return InferredScope::Network;
    }

    let name_lower = info.name.to_lowercase();
    if name_lower.starts_with("get")
        || name_lower.starts_with("list")
        || name_lower.contains("read")
    {
        return InferredScope::Read;
    }
    if name_lower.contains("delete") || name_lower.contains("remove") || name_lower.contains("drop")
    {
        return InferredScope::Destructive;
    }

    InferredScope::Generic
}

fn schema_contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}
