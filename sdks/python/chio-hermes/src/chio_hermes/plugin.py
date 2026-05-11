"""Hermes plugin entry-point.

`register(ctx)` is called once by Hermes when the plugin loads. It:

1. Builds a `RuntimeHandle` from process env (fail-soft; missing env
   yields a degraded handle that surfaces `chio_not_configured` JSON
   when tools are invoked but does NOT crash Hermes startup).
2. Iterates `TOOL_TABLE` and registers each tool under toolset `chio`
   with `is_async=True`.
3. Registers `pre_tool_call`, `post_tool_call`, `on_session_start`,
   and `on_session_end` hooks so policy pre-checks, receipt
   finalisation, and session-lifecycle flushes happen automatically.
4. Registers the `chio` CLI subcommand and `/chio` slash command.

`ChioHermesPlugin` is exported so tests and downstream tools can
introspect what `register` produced without re-running registration.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from chio_hermes import cli, commands, hooks
from chio_hermes.manifest import TOOL_TABLE
from chio_hermes.runtime import RuntimeHandle, build_runtime_handle

CHIO_TOOLSET = "chio"
"""Single Hermes toolset that owns all 12 chio_* tools."""

REQUIRED_ENV = ["CHIO_SIDECAR_URL", "CHIO_CAPABILITY_ID"]
"""Env vars Hermes prompts for via `requires_env` in plugin.yaml."""


@dataclass
class ChioHermesPlugin:
    """Snapshot of what `register(ctx)` produced.

    Returned by `register(ctx)` so test fixtures and `/chio status`
    helpers can introspect the live wiring without re-registering.
    """

    runtime: RuntimeHandle
    tool_names: list[str] = field(default_factory=list)
    hook_names: list[str] = field(default_factory=list)
    cli_command: str | None = None
    slash_command: str | None = None


def _make_check_fn(handle: RuntimeHandle) -> Callable[[], bool]:
    """Return a `check_fn` Hermes calls to gate tool exposure.

    Hermes hides the tool from the model when this returns False, so
    the model does not waste tokens trying a tool it cannot use.
    """

    def check() -> bool:
        return handle.is_configured()

    return check


def register(ctx: Any) -> ChioHermesPlugin:
    """Hermes plugin entry-point.

    Builds a `RuntimeHandle`, registers tools (`is_async=True`), four
    hooks, one CLI command, and one slash command. No network calls
    happen during registration; the `ChioClient` is connected lazily
    on the first tool dispatch. A construction failure does NOT crash
    Hermes: handlers short-circuit with `chio_not_configured` instead.
    """
    handle = build_runtime_handle()
    plugin = ChioHermesPlugin(runtime=handle)

    check_fn = _make_check_fn(handle)

    # ------------------------------------------------------------------
    # Tool surface (12 tools under toolset "chio").
    # ------------------------------------------------------------------
    for entry in TOOL_TABLE:
        handler = entry.factory(handle)
        ctx.register_tool(
            name=entry.name,
            toolset=CHIO_TOOLSET,
            schema=entry.schema,
            handler=handler,
            is_async=True,
            check_fn=check_fn,
            requires_env=REQUIRED_ENV,
            description=entry.description,
        )
        plugin.tool_names.append(entry.name)

    # ------------------------------------------------------------------
    # Hooks (4 total: pre/post tool call + session start/end).
    # ------------------------------------------------------------------
    pre_hook = hooks.make_pre_tool_call(handle)
    post_hook = hooks.make_post_tool_call(handle)
    start_hook = hooks.make_on_session_start(handle)
    end_hook = hooks.make_on_session_end(handle)
    ctx.register_hook("pre_tool_call", pre_hook)
    ctx.register_hook("post_tool_call", post_hook)
    ctx.register_hook("on_session_start", start_hook)
    ctx.register_hook("on_session_end", end_hook)
    plugin.hook_names.extend(
        [
            "pre_tool_call",
            "post_tool_call",
            "on_session_start",
            "on_session_end",
        ]
    )

    # ------------------------------------------------------------------
    # CLI subcommand: `hermes chio ...`
    # ------------------------------------------------------------------
    ctx.register_cli_command(
        name="chio",
        help="Manage Chio capabilities used by the Hermes plugin.",
        setup_fn=cli.setup,
        handler_fn=cli.handle,
        description="Manage Chio capabilities used by the Hermes plugin.",
    )
    plugin.cli_command = "chio"

    # ------------------------------------------------------------------
    # Slash command: `/chio ...`
    # ------------------------------------------------------------------
    slash_handler = commands.make_slash_handler(handle)
    ctx.register_command(
        name="chio",
        handler=slash_handler,
        description="Show Chio plugin status, recent receipts, and policy.",
        args_hint="[status|receipts|policy]",
    )
    plugin.slash_command = "chio"

    return plugin


__all__ = ["CHIO_TOOLSET", "REQUIRED_ENV", "ChioHermesPlugin", "register"]
