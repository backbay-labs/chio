# Hermes action inventory

Inspected host: NousResearch/hermes-agent
`175054c14b54404663d8614a178280cffe6062eb`, v0.20.5 (2026.8.19), Python 3.11.3.
The supported candidate is the fixed one-shot CLI launcher. Gateway, Desktop,
TUI, ACP/Zed, interactive CLI commands, resumed sessions, and scheduled sessions
are not launcher entry points and remain unqualified. Confidence in inspected
source and observed CLI behavior is high; program acceptance is unresolved.

| Consequential path | Host surface and resource owner | Candidate enforcement / state |
| --- | --- | --- |
| Native file reads | `read_file`, `search_files`; local process / terminal backend | Not in `mcp-chio`; host validates model tool names before dispatch. Protected resource files are not mounted. Native name auto-repair may resolve to an allowed MCP tool, which still crosses the kernel. |
| Native file writes and patches | `write_file`, `patch`; local process / terminal backend | Native toolset disabled. The local write control proves the observer detects native effects. Chio-only hook mode is insufficient on callback/load failure. |
| Shell and descendants | `terminal`; configured shell/terminal backend | Native terminal absent. Forced native terminal with shell indirection was rejected by actual host and produced no marker. Trusted gateway subprocess is explicit infrastructure, not an agent shell capability. |
| Background processes | `process`, terminal background options | Tools absent; no model-accessible spawn/poll/kill interface. |
| Native network/browser | Web search/extract, browser, vision/audio/image tools | Toolsets absent. The host can reach only the exact launcher-owned HTTP gateway and model-relay loopback ports, not the kernel port, arbitrary external HTTPS or Unix sockets. Provider authentication stays in the parent relay. |
| Git | Native terminal or plugin tools | Native shell and legacy `chio_git_*` absent. External file editing does not promise local commit/push or test execution. |
| Custom code | `execute_code`, plugins, extension handlers | Code execution and custom toolsets absent; project plugins disabled; no enabled general plugins. Bundled providers may register at startup, but none of their action tools are exposed. |
| MCP tools | `mcp__<server>__<tool>` dispatcher | One server, `chio`, through fixed gateway. Exact raw names from private config: `read_text_file`, `write_file`, `edit_file`, `list_directory` in current qualification. |
| MCP resources/prompts | Synthesized `read_resource`, `get_prompt`, listing helpers | Gateway advertises only tools and rejects non-tool methods. Hermes `tools.include` alone does not filter these helpers, so direct unrestricted MCP is excluded. |
| Dynamic tool search | `tool_search`, `tool_describe`, `tool_call` | Explicitly disabled (`tools.tool_search.enabled: off`). Earlier useful run used host default and is recorded separately. |
| Delegation | `delegate_task`, agent-loop children, background delegation | Delegation toolsets absent; no child runtime is authorized. |
| Scheduled/external jobs | Cron, Kanban, gateway messaging | Toolsets and relevant entry points unavailable through launcher. No messages to people are part of qualification. |
| Config/plugin tampering | Native files, terminal, project plugins, `/plugins`, hooks | Native tools absent, project plugins off, one-shot query entry only. The host can write its isolated state; that state contains no authoritative kernel credential or gateway journal. Those operator paths are outside both host-readable roots and protected-resource write scope. Launcher refuses reused state, source drift, install `.env` and unqualified managed config. |
| Resume/retry/cancel | Session DB, MCP reconnect logic | Launcher does not expose conversation resume. The parent gateway retains operation identity and its private journal; kernel session fencing independently prevents silent redispatch of unknown effects. Supported operator recovery and same-authority retry/restart observations are retained in the final local record. |
| Host housekeeping | Session DB, logs, installed provider modules | Host writes its isolated profile and session data. Native terminal scanner bootstrap is explicitly disabled after historical runs showed eager downloads. These paths are not protected resource grants or model-controlled tools. |
| Resource effects | Official filesystem MCP server in separate container/volume | Only kernel reaches server. Hermes receives no volume mount or Docker socket. Inherited Seatbelt denies outbound Unix sockets and direct kernel access. The parent gateway owns kernel credentials and trusted delivery state. |

The pinned `agent/conversation_loop.py` checks `agent.valid_tool_names` before
invocation and repairs some unknown names against available tools. The plugin
dispatcher catches exceptions and continues. `model_tools.py` and
`agent/agent_runtime_helpers.py` also treat hook dispatcher exceptions as no
block. The launcher compatibility-checks these paths; retained CLI evidence
reproduces failure behavior.

Authoritative references checked 2026-09-09:

- [Pinned plugin dispatcher](https://github.com/NousResearch/hermes-agent/blob/175054c14b54404663d8614a178280cffe6062eb/hermes_cli/plugins.py)
- [Pinned tool validation](https://github.com/NousResearch/hermes-agent/blob/175054c14b54404663d8614a178280cffe6062eb/agent/conversation_loop.py)
- [Pinned MCP client](https://github.com/NousResearch/hermes-agent/blob/175054c14b54404663d8614a178280cffe6062eb/tools/mcp_tool.py)
- [Current hooks documentation](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/hooks.md)
- [Current plugin documentation](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/plugins.md)

Current upstream docs describe timeout handling absent from the installed
callback dispatcher. Do not substitute current docs for pinned host behavior.

The current macOS profile starts with default deny. It grants file-content reads
for pinned runtime/source assets, the query and isolated host state; only that
state and required device endpoints are writable. Kernel credentials, provider
credentials and the authoritative gateway journal must remain outside those
readable roots. The host receives ephemeral gateway/model tokens, which do not
grant direct kernel or operator access. Sysctl reads are explicitly scoped so
the host cannot read its parent's environment. There is no broad `/System` grant
that would expose the Data volume alias. Required Python bootstrap descendants
inherit the same boundary; Node runs only outside the agent sandbox.

The implementation is bound by [`restricted.py`](src/chio_hermes/restricted.py)
and [`GatewayTransport`](src/chio_hermes/gateway_transport.py). Actual direct and
descendant controls, native excluded tools, useful work and recovery are retained
in the [final local record](evidence/2026-09-10/static-kernel-native/README.md).
That record identifies the tested versions and its publication boundary.

Historical allow-default profiles and host-writable gateway journals were
rejected authority boundaries. Their narrow observations and omitted harness
source are retained in the [historical followup archive](evidence/2026-09-10/historical-followup/README.md).
Those observations do not qualify the current parent-owned architecture.
