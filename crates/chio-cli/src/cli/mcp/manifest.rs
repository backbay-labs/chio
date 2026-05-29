// Default-deny manifest scaffold renderer for `chio mcp wrap`.
//
// Emits a TOML scaffold that the user reviews before promoting. The
// scaffold lives at `~/.config/chio/mcp/<server-id>.toml` by convention;
// the renderer is pure so tests can compare bytes.

use super::*;

use super::scope::{infer_scopes, InferredCapability, InferredScope};
use super::wrap::{split_wrapped_command, McpWrapArgs};

/// Render the inferred capability scaffold to a TOML string. The output
/// is deterministic: tools are sorted alphabetically, scopes are emitted
/// in a fixed order, and every capability ships with `allow = false`.
pub(crate) fn render_manifest_scaffold(
    server_id: &str,
    capabilities: &[InferredCapability],
) -> String {
    let mut out = String::new();
    out.push_str("# chio mcp wrap -- inferred capability manifest scaffold\n");
    out.push_str("# Review each tool below; flip `allow = true` to promote.\n");
    out.push_str("# Default is deny.\n\n");
    out.push_str(&format!("server_id = \"{}\"\n", escape_toml(server_id)));
    out.push_str("# TODO: review the inferred scopes below before promoting.\n\n");

    for cap in capabilities {
        out.push_str("[[capability]]\n");
        out.push_str(&format!("tool = \"{}\"\n", escape_toml(&cap.tool)));
        out.push_str(&format!("scope = \"{}\"\n", scope_label(cap.scope)));
        out.push_str(&format!("urn = \"{}\"\n", cap.urn));
        if let Some(desc) = cap.description.as_ref() {
            out.push_str(&format!("description = \"{}\"\n", escape_toml(desc)));
        }
        out.push_str(&format!("allow = {}\n", cap.allow));
        out.push_str("# TODO: review and promote\n\n");
    }
    out
}

fn scope_label(scope: InferredScope) -> &'static str {
    match scope {
        InferredScope::Read => "read",
        InferredScope::FileSystem => "filesystem",
        InferredScope::Network => "network",
        InferredScope::Destructive => "destructive",
        InferredScope::Generic => "generic",
    }
}

fn escape_toml(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Read a promoted manifest scaffold and return the set of tool names
/// flagged `allow = true`. The wrap loop's default verdict gate consults
/// this set; tools that are absent or set to `allow = false` deny.
pub(crate) fn load_manifest_allowlist(
    path: &std::path::Path,
) -> Result<std::collections::BTreeSet<String>, CliError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CliError::cli_io_error(format!("failed to read manifest {path:?}: {e}")))?;

    let value: toml::Value = toml::from_str(&raw).map_err(|e| {
        CliError::cli_other_error(format!("failed to parse manifest TOML at {path:?}: {e}"))
    })?;

    let mut out = std::collections::BTreeSet::new();
    let Some(capabilities) = value.get("capability").and_then(|c| c.as_array()) else {
        return Ok(out);
    };
    for capability in capabilities {
        let Some(table) = capability.as_table() else {
            continue;
        };
        let tool = table
            .get("tool")
            .and_then(toml::Value::as_str)
            .unwrap_or("")
            .to_string();
        let allow = table
            .get("allow")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if !tool.is_empty() && allow {
            out.insert(tool);
        }
    }
    Ok(out)
}

/// Print the inferred manifest scaffold to stdout. Used by
/// `chio mcp wrap --print-scopes`.
pub(crate) fn cmd_mcp_print_scopes(args: &McpWrapArgs) -> Result<(), CliError> {
    let tools = if let Some(fixture) = args.tools_fixture.as_ref() {
        load_tools_fixture(fixture)?
    } else {
        let (program, child_args) = split_wrapped_command(&args.command)?;
        let child_args_refs: Vec<&str> = child_args.iter().map(String::as_str).collect();
        let transport =
            chio_mcp_adapter::StdioMcpTransport::spawn(&program, &child_args_refs).map_err(
                |e| {
                    CliError::cli_other_error(format!(
                        "failed to spawn wrapped MCP server '{program}': {e}"
                    ))
                },
            )?;
        let tools = transport
            .list_tools()
            .map_err(|e| CliError::cli_other_error(format!("failed to list tools: {e}")))?;
        let _ = transport.shutdown();
        tools
    };

    let inferred = infer_scopes(&tools);
    let scaffold = render_manifest_scaffold(&args.server_id, &inferred);
    print!("{scaffold}");
    Ok(())
}
