# Hermes integration

Hermes integration acceptance is **unresolved**. The authoritative scope is
`docs/strategy/chio-direction/19-priority-agent-integrations.md` on branch
`codex/chio-strategy-design-20260908`. Source and package availability do not
establish host acceptance.

The current candidate is `chio-hermes-restricted`, a one-shot Hermes CLI mode
that exposes only Chio's execution gateway and isolated external file tools.
The kernel and resource service perform protected effects. The launcher
creates an isolated profile with the exact `mcp-chio` toolset and disables
native tools, other MCP servers, custom plugins, dynamic tool search,
delegation, subprocesses, and background sessions. The protected resource is
not mounted into Hermes and the agent receives no Docker socket.

See the maintained [installation and operation runbook](../../sdks/python/chio-hermes/README.md),
[host action inventory](../../sdks/python/chio-hermes/ACTION_INVENTORY.md), and
[acceptance record](../../sdks/python/chio-hermes/ACCEPTANCE.md).

The prior native Python plugin is not a complete mediation boundary. The
pinned host catches plugin callback exceptions and continues native execution;
real-host fault injection reproduced that effect. Native tools previously
bypassed the plugin's `chio_` filter. The 0.1.2 repair blocks nonregistered
tools while the hook is loaded, but does not repair host load-failure semantics.

The current Python SDK intentionally rejects all id-only
`evaluate_tool_call` authorizations. Restoring permissive advisory results or
performing unrestricted local I/O after a remote precheck would reopen the
security gap. The restricted mode instead uses an operator-prepared retained
kernel session, exact caller and authority bindings, signed execution evidence,
and the gateway's persistent operation journal. Legacy `chio start` and
`hermes chat -t chio,hermes-cli` quickstarts must not be used as acceptance
instructions.
