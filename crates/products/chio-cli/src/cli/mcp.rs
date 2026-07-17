// Top-level glue for the `chio mcp wrap` subcommand.
//
// Per the workspace `include!()` pattern (mirrors `cli/replay.rs` +
// `cli/replay/*.rs`), this file is `include!`-d from `src/main.rs` and in
// turn brings in the `cli/mcp/*.rs` sibling files that hold the wrap,
// scope-inference, IDE config, and attestation modules.
//
// The sibling files are organized as plain code blocks rather than full
// modules so they compose with the rest of the CLI without re-importing the
// already in-scope helper types from `cli/types.rs` and `cli/runtime.rs`.

use super::*;

use chio_mcp_adapter::edge::McpTransport as _;

/// Dispatch entry-point for `chio mcp wrap`.
///
/// Wrapper-side of the native MCP adapter surface (`chio-mcp-adapter` and
/// `chio-hosted-mcp`). It runs the verdict gate over `tools/call`,
/// renders an inferred capability-scope manifest scaffold, and (when
/// `--emit-config` is supplied) emits a paste-ready IDE configuration blob
/// for Cursor / Claude Desktop / Continue / Zed.
pub(crate) fn cmd_mcp_wrap(args: &McpWrapArgs) -> Result<(), CliError> {
    if let Some(tool) = args.self_test_attestation.as_ref() {
        let header = build_chio_verified_header(tool);
        let mut payload = serde_json::json!({
            "content": [{ "type": "text", "text": "self-test" }]
        });
        attach_chio_verified_header(&mut payload, tool);
        let bundle = serde_json::json!({
            "header": header,
            "wrapped_response": payload,
        });
        let rendered = serde_json::to_string_pretty(&bundle)
            .map_err(|e| CliError::cli_other_error(format!("self-test render: {e}")))?;
        println!("{rendered}");
        return Ok(());
    }

    if let Some(fixture) = args.e2e_fixture.as_ref() {
        return cmd_mcp_wrap_e2e_fixture(args, fixture);
    }

    if let Some(ide) = args.emit_config.as_ref() {
        if args.command.is_empty() {
            return Err(CliError::cli_other_error(
                "chio mcp wrap --emit-config requires a wrapped command after `--`".to_string(),
            ));
        }
        return cmd_mcp_emit_config(args, *ide);
    }

    if args.print_scopes {
        if args.tools_fixture.is_none() && args.command.is_empty() {
            return Err(CliError::cli_other_error(
                "chio mcp wrap --print-scopes requires either --tools-fixture or a wrapped command"
                    .to_string(),
            ));
        }
        return cmd_mcp_print_scopes(args);
    }

    if args.command.is_empty() {
        return Err(CliError::cli_other_error(
            "chio mcp wrap requires a wrapped command after `--`".to_string(),
        ));
    }
    cmd_mcp_wrap_run(args)
}

/// Load a JSON `tools/list` fixture and decode it as a slice of
/// [`chio_mcp_adapter::edge::McpToolInfo`]. The fixture format is the same
/// shape MCP servers return, e.g. `{ "tools": [ ... ] }` or a bare
/// array.
pub(crate) fn load_tools_fixture(
    path: &std::path::Path,
) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, CliError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        CliError::cli_io_error(format!("failed to read tools fixture {path:?}: {e}"))
    })?;
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        CliError::cli_other_error(format!("failed to parse tools fixture {path:?}: {e}"))
    })?;
    let array = value
        .get("tools")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .or_else(|| value.as_array().cloned())
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "tools fixture {path:?} must be a tools array or object with a 'tools' field"
            ))
        })?;
    let tools: Vec<chio_mcp_adapter::edge::McpToolInfo> = serde_json::from_value(serde_json::Value::Array(
        array,
    ))
    .map_err(|e| {
        CliError::cli_other_error(format!("failed to decode tools fixture {path:?}: {e}"))
    })?;
    Ok(tools)
}

// The sibling `mcp/*.rs` files are real submodules wired in with
// `#[path] mod`; each begins with `use super::*;` to inherit the shared
// imports from this parent and `cli/types.rs`/`cli/runtime.rs`. Their
// crate-internal items are re-exported here so the parent (`mcp_cli` in
// `main.rs`) keeps exposing the same surface (e.g. `McpWrapArgs`,
// `cmd_mcp_wrap`).
#[path = "mcp/ide.rs"]
mod ide;
#[path = "mcp/scope.rs"]
mod scope;
#[path = "mcp/attestation.rs"]
mod attestation;
#[path = "mcp/manifest.rs"]
mod manifest;
#[path = "mcp/emit_config.rs"]
mod emit_config;
#[path = "mcp/payment_config.rs"]
pub mod payment_config;
#[path = "mcp/wrap.rs"]
mod wrap;
#[path = "mcp/governed_sim.rs"]
mod governed_sim;

pub(crate) use attestation::{attach_chio_verified_header, build_chio_verified_header};
pub(crate) use emit_config::cmd_mcp_emit_config;
pub(crate) use manifest::cmd_mcp_print_scopes;
pub(crate) use wrap::{
    cmd_mcp_wrap_e2e_fixture, cmd_mcp_wrap_run, McpWrapArgs,
};
pub(crate) use governed_sim::{cmd_mcp_governed_sim, GovernedSimArgs};
