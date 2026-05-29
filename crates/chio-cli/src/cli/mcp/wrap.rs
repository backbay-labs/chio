// `chio mcp wrap` -- stdio child orchestration with verdict gating per
// `tools/call`.
//
// Flow:
//
//   1. Spawn the user's MCP server via [`StdioMcpTransport::spawn`] (the
//      transport performs the `initialize` handshake and drives
//      newline-delimited JSON-RPC over stdio).
//   2. Pull `tools/list` once on warmup so we can render the inferred
//      capability scope manifest scaffold and the IDE config blobs.
//   3. Stream a JSON-RPC frame loop on stdin: each `tools/call` is gated
//      by [`VerdictGate`] before being forwarded to the wrapped child;
//      denials are surfaced as JSON-RPC errors with a deterministic
//      `urn:chio:` reason code.
//
// The verdict gate is a trait so the e2e test can inject a pure-Rust gate
// without spinning up the kernel.

use super::*;

use super::attestation::attach_chio_verified_header;
use super::ide::IdeTarget;
use super::manifest::load_manifest_allowlist;

const MCP_WRAP_PROTOCOL_VERSION: &str = "2025-11-25";
const MAX_MCP_WRAP_FRAME_BYTES: usize = 1024 * 1024;

/// Decision returned by a [`VerdictGate`] for a single `tools/call`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WrapVerdict {
    /// Forward the request to the wrapped MCP server.
    Allow,
    /// Reject the request; render a JSON-RPC error using the supplied
    /// `urn:chio:error:*` code and human-readable reason.
    Deny { code: String, reason: String },
}

/// Verdict gate consumed by [`run_wrap_with_gate`]. The default gate
/// applied by `chio mcp wrap` infers per-tool scopes from `tools/list`
/// and denies any tool that is not yet promoted in the user's manifest.
pub(crate) trait VerdictGate {
    fn evaluate(&self, tool_name: &str, arguments: &serde_json::Value) -> WrapVerdict;
}

/// Default-deny gate keyed off the manifest scaffold. Tools whose
/// capability has been promoted to `allow = true` pass; everything else
/// denies with `urn:chio:error:capability:scope-exceeded`.
pub(crate) struct ManifestVerdictGate {
    pub allowed: std::collections::BTreeSet<String>,
}

impl VerdictGate for ManifestVerdictGate {
    fn evaluate(&self, tool_name: &str, _arguments: &serde_json::Value) -> WrapVerdict {
        if self.allowed.contains(tool_name) {
            WrapVerdict::Allow
        } else {
            WrapVerdict::Deny {
                code: "urn:chio:error:capability:scope-exceeded".to_string(),
                reason: format!(
                    "tool '{tool_name}' is not promoted in the chio mcp wrap manifest scaffold"
                ),
            }
        }
    }
}

/// CLI argument bundle for `chio mcp wrap`.
#[derive(clap::Args, Debug)]
pub(crate) struct McpWrapArgs {
    /// Server ID to assign to the wrapped MCP server inside the inferred
    /// manifest scaffold.
    #[arg(long, default_value = "mcp")]
    pub(crate) server_id: String,

    /// Optional path to the user's manifest scaffold. When absent the
    /// command renders the inferred scaffold to stdout instead of running
    /// the wrap loop.
    #[arg(long)]
    pub(crate) manifest: Option<std::path::PathBuf>,

    /// Print the inferred capability-scope manifest scaffold and exit.
    #[arg(long, default_value_t = false)]
    pub(crate) print_scopes: bool,

    /// IDE target for `--emit-config`. When set, the command prints the
    /// paste-ready config for the requested IDE and exits without spawning
    /// the wrapped child.
    #[arg(long, value_enum)]
    pub(crate) emit_config: Option<IdeTarget>,

    /// Display name surfaced inside emitted IDE config blobs.
    #[arg(long)]
    pub(crate) display_name: Option<String>,

    /// Render the manifest scaffold from a JSON `tools/list` fixture file
    /// instead of spawning the wrapped child. Used by the scope inference
    /// and emit-config tests so they stay hermetic on shared CI runners.
    #[arg(long)]
    pub(crate) tools_fixture: Option<std::path::PathBuf>,

    /// Drive the wrap loop against an in-process JSON-RPC fixture (a
    /// JSON object with `tools` and `responses` arrays). Reads JSON-RPC
    /// frames from stdin and emits framed responses on stdout, gated by
    /// the manifest scaffold. Used by the e2e test so the
    /// stdio-orchestration round-trip can run without a real wrapped
    /// child.
    #[arg(long)]
    pub(crate) e2e_fixture: Option<std::path::PathBuf>,

    /// Self-test mode for the attestation header. Prints the
    /// "Chio-verified" attestation block for the given tool name as
    /// JSON and exits.
    #[arg(long)]
    pub(crate) self_test_attestation: Option<String>,

    /// The wrapped MCP server command and its arguments. Required unless
    /// `--tools-fixture` is supplied (the test-only path).
    #[arg(trailing_var_arg = true)]
    pub(crate) command: Vec<String>,
}

/// Render the wrap loop output for the dispatch arm. The default gate
/// reads the user's promoted manifest from disk; if no manifest is
/// supplied, every tool denies.
pub(crate) fn cmd_mcp_wrap_run(args: &McpWrapArgs) -> Result<(), CliError> {
    let allowed = match args.manifest.as_ref() {
        Some(path) => load_manifest_allowlist(path)?,
        None => std::collections::BTreeSet::new(),
    };
    let gate = ManifestVerdictGate { allowed };

    let (program, child_args) = split_wrapped_command(&args.command)?;
    let child_args_refs: Vec<&str> = child_args.iter().map(String::as_str).collect();
    let transport = chio_mcp_adapter::StdioMcpTransport::spawn(&program, &child_args_refs)
        .map_err(|e| {
            CliError::cli_other_error(format!(
                "failed to spawn wrapped MCP server '{program}': {e}"
            ))
        })?;

    let summary = run_wrap_with_gate(
        &transport,
        &gate,
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    )
    .map_err(|e| CliError::cli_other_error(format!("chio mcp wrap loop: {e}")))?;

    let _ = transport.shutdown();
    if summary.denied > 0 {
        tracing::warn!(
            target = "chio_cli::mcp::wrap",
            denied = summary.denied,
            allowed = summary.allowed,
            "chio mcp wrap loop exited with denied tool calls",
        );
    }
    Ok(())
}

/// Split the trailing `command` slice into the program plus its argv.
pub(crate) fn split_wrapped_command(
    command: &[String],
) -> Result<(String, Vec<String>), CliError> {
    let mut iter = command.iter();
    let program = iter.next().ok_or_else(|| {
        CliError::cli_other_error("chio mcp wrap requires a wrapped command".to_string())
    })?;
    Ok((program.clone(), iter.cloned().collect()))
}

/// Aggregate counters returned by [`run_wrap_with_gate`] so callers can
/// log totals after the loop drains.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WrapLoopSummary {
    pub allowed: usize,
    pub denied: usize,
    pub passthrough: usize,
}

/// Drive a JSON-RPC frame loop between the stdin reader and the wrapped
/// MCP server, gating each `tools/call` through `gate`.
///
/// The loop accepts newline-delimited JSON-RPC requests on `reader`,
/// forwards non-`tools/call` methods straight through to the wrapped
/// transport, and intercepts `tools/call` to consult the gate. Denials
/// produce a JSON-RPC error response on `writer`; allows forward to
/// the wrapped server and write the upstream response back. The loop
/// stops at EOF on `reader`.
pub(crate) fn run_wrap_with_gate<R, W, G>(
    transport: &dyn chio_mcp_adapter::McpTransport,
    gate: &G,
    reader: R,
    mut writer: W,
) -> Result<WrapLoopSummary, std::io::Error>
where
    R: std::io::BufRead,
    W: std::io::Write,
    G: VerdictGate + ?Sized,
{
    let mut summary = WrapLoopSummary::default();
    let mut reader = reader;
    while let Some(line) = read_bounded_line(&mut reader, MAX_MCP_WRAP_FRAME_BYTES)? {
        if line.trim().is_empty() {
            continue;
        }
        let frame: serde_json::Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                let frame = json_rpc_error(
                    None,
                    -32700,
                    "urn:chio:error:transport:invalid-request-shape",
                    &format!("malformed JSON frame: {error}"),
                );
                writeln!(writer, "{frame}")?;
                writer.flush()?;
                continue;
            }
        };

        let id = frame.get("id").cloned();
        let method = frame
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        match method {
            "tools/call" => {
                let arguments = frame
                    .get("params")
                    .and_then(|params| params.get("arguments"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let tool_name = frame
                    .get("params")
                    .and_then(|params| params.get("name"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string();

                match gate.evaluate(&tool_name, &arguments) {
                    WrapVerdict::Allow => {
                        summary.allowed += 1;
                        let response = match transport.call_tool(&tool_name, arguments) {
                            Ok(result) => {
                                let mut payload = serde_json::to_value(&result)
                                    .unwrap_or(serde_json::Value::Null);
                                attach_chio_verified_header(&mut payload, &tool_name);
                                serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": payload,
                                })
                            }
                            Err(error) => json_rpc_error(
                                id,
                                -32000,
                                "urn:chio:error:transport:upstream-failure",
                                &format!("upstream MCP error: {error}"),
                            ),
                        };
                        writeln!(writer, "{response}")?;
                    }
                    WrapVerdict::Deny { code, reason } => {
                        summary.denied += 1;
                        let response = json_rpc_error(id, -32001, &code, &reason);
                        writeln!(writer, "{response}")?;
                    }
                }
            }
            "tools/list" => {
                summary.passthrough += 1;
                let response = match transport.list_tools() {
                    Ok(tools) => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "tools": tools },
                    }),
                    Err(error) => json_rpc_error(
                        id,
                        -32000,
                        "urn:chio:error:transport:upstream-failure",
                        &format!("upstream MCP error: {error}"),
                    ),
                };
                writeln!(writer, "{response}")?;
            }
            // Notifications carry no `id` per JSON-RPC 2.0 and must not
            // receive a response. The MCP handshake notification
            // `notifications/initialized` falls in this bucket.
            method if id.is_none() => {
                summary.passthrough += 1;
                // Silently swallow the notification (the wrapped child has
                // already received it from the IDE-facing client in the
                // out-of-band initialize handshake driven by the transport).
            }
            // Well-known JSON-RPC handshake methods that the e2e fixture
            // transport does not implement directly. Returning a minimal
            // success keeps IDEs that re-issue these methods over our
            // wrapped stdio happy without lying about a generic passthrough.
            "ping" => {
                summary.passthrough += 1;
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {},
                });
                writeln!(writer, "{response}")?;
            }
            "initialize" => {
                summary.passthrough += 1;
                // Surface the wrapped child's tools/list capabilities so
                // re-initialization handshakes don't claim an empty server.
                let tools = transport.list_tools().unwrap_or_default();
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": MCP_WRAP_PROTOCOL_VERSION,
                        "serverInfo": {
                            "name": "chio-mcp-wrap",
                            "version": env!("CARGO_PKG_VERSION"),
                        },
                        "capabilities": {
                            "tools": { "listChanged": false },
                        },
                        "tools": tools,
                    },
                });
                writeln!(writer, "{response}")?;
            }
            other => {
                // Unknown methods get a JSON-RPC method-not-found error
                // (-32601) instead of a synthetic success. Returning a fake
                // success would mask client-side bugs and let unsupported
                // RPCs appear to work.
                summary.passthrough += 1;
                let response = json_rpc_error(
                    id,
                    -32601,
                    "urn:chio:error:transport:method-not-found",
                    &format!(
                        "MCP method `{other}` is not supported by `chio mcp wrap`; only \
                         `tools/list`, `tools/call`, `initialize`, `ping`, and \
                         JSON-RPC notifications are recognised"
                    ),
                );
                writeln!(writer, "{response}")?;
            }
        }
        writer.flush()?;
    }
    Ok(summary)
}

fn read_bounded_line<R: std::io::BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<String>, std::io::Error> {
    let mut bytes = Vec::new();
    loop {
        let (take, has_newline, exceeds_limit) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                if bytes.is_empty() {
                    return Ok(None);
                }
                break;
            }

            let take = match available.iter().position(|byte| *byte == b'\n') {
                Some(index) => index + 1,
                None => available.len(),
            };
            let has_newline = available.get(take.saturating_sub(1)) == Some(&b'\n');
            let exceeds_limit = bytes.len().saturating_add(take) > max_bytes;
            if !exceeds_limit {
                bytes.extend_from_slice(&available[..take]);
            }
            (take, has_newline, exceeds_limit)
        };

        reader.consume(take);
        if exceeds_limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("MCP JSON-RPC frame exceeded {max_bytes} bytes"),
            ));
        }

        if has_newline {
            break;
        }
    }

    String::from_utf8(bytes).map(Some).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("MCP JSON-RPC frame was not UTF-8: {error}"),
        )
    })
}

/// In-memory MCP transport backed by a JSON fixture. Used by CLI e2e tests
/// to exercise the full stdio orchestration loop without spawning a real MCP
/// child.
pub(crate) struct FixtureMcpTransport {
    tools: Vec<chio_mcp_adapter::McpToolInfo>,
    responses: std::collections::BTreeMap<String, chio_mcp_adapter::McpToolResult>,
}

impl chio_mcp_adapter::McpTransport for FixtureMcpTransport {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::McpToolInfo>, chio_mcp_adapter::AdapterError> {
        Ok(self.tools.clone())
    }

    fn call_tool(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
    ) -> Result<chio_mcp_adapter::McpToolResult, chio_mcp_adapter::AdapterError> {
        self.responses
            .get(tool_name)
            .cloned()
            .ok_or_else(|| chio_mcp_adapter::AdapterError::ToolNotFound(tool_name.to_string()))
    }
}

/// Drive the wrap loop against the supplied JSON fixture. Reads
/// JSON-RPC frames from stdin and writes responses to stdout. The
/// fixture shape is:
///
/// ```ignore
/// {
///   "tools": [ McpToolInfo, ... ],
///   "responses": { "<tool>": McpToolResult, ... },
///   "allow": ["<tool>", ...]   // promoted tools; everything else denies
/// }
/// ```
pub(crate) fn cmd_mcp_wrap_e2e_fixture(
    _args: &McpWrapArgs,
    path: &std::path::Path,
) -> Result<(), CliError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CliError::cli_io_error(format!("failed to read e2e fixture {path:?}: {e}")))?;
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        CliError::cli_other_error(format!("failed to parse e2e fixture {path:?}: {e}"))
    })?;

    let tools: Vec<chio_mcp_adapter::McpToolInfo> = serde_json::from_value(
        value.get("tools").cloned().unwrap_or(serde_json::json!([])),
    )
    .map_err(|e| CliError::cli_other_error(format!("failed to decode tools: {e}")))?;

    let mut responses: std::collections::BTreeMap<String, chio_mcp_adapter::McpToolResult> =
        std::collections::BTreeMap::new();
    if let Some(map) = value.get("responses").and_then(serde_json::Value::as_object) {
        for (key, val) in map.iter() {
            let result: chio_mcp_adapter::McpToolResult = serde_json::from_value(val.clone())
                .map_err(|e| {
                    CliError::cli_other_error(format!("failed to decode response for {key}: {e}"))
                })?;
            responses.insert(key.clone(), result);
        }
    }

    let mut allowed = std::collections::BTreeSet::new();
    if let Some(list) = value.get("allow").and_then(serde_json::Value::as_array) {
        for entry in list {
            if let Some(name) = entry.as_str() {
                allowed.insert(name.to_string());
            }
        }
    }

    let transport = FixtureMcpTransport { tools, responses };
    let gate = ManifestVerdictGate { allowed };

    run_wrap_with_gate(
        &transport,
        &gate,
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    )
    .map_err(|e| CliError::cli_other_error(format!("e2e wrap loop: {e}")))?;

    Ok(())
}

/// Build a JSON-RPC error envelope with a Chio-namespaced reason code in
/// the `data` slot so downstream consumers can pattern-match the error
/// without parsing the human message.
fn json_rpc_error(
    id: Option<serde_json::Value>,
    code: i64,
    chio_code: &str,
    message: &str,
) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
            "data": { "chio_code": chio_code },
        }
    })
}

#[cfg(test)]
mod wrap_tests {
    use super::*;

    #[test]
    fn wrap_loop_rejects_oversized_json_rpc_frame() {
        let input = format!("{}\n", "x".repeat(MAX_MCP_WRAP_FRAME_BYTES + 1));
        let transport = FixtureMcpTransport {
            tools: Vec::new(),
            responses: std::collections::BTreeMap::new(),
        };
        let gate = ManifestVerdictGate {
            allowed: std::collections::BTreeSet::new(),
        };
        let mut output = Vec::new();

        let error = match run_wrap_with_gate(&transport, &gate, input.as_bytes(), &mut output) {
            Ok(_) => panic!("oversized frame must fail closed"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
