"""Hermes plugin entry point.

`register(ctx)` builds a :class:`RuntimeHandle` from process env
(fail-soft: missing env yields a degraded handle whose tools surface
`chio_not_configured` JSON), registers each `TOOL_TABLE` entry under
toolset `chio` with `is_async=True`, wires the four hooks, and adds
the `chio` CLI + slash command. No network calls happen during
registration.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from chio_hermes import cli, commands, hooks
from chio_hermes.manifest import TOOL_TABLE
from chio_hermes.runtime import RuntimeHandle, build_runtime_handle

CHIO_TOOLSET = "chio"
REQUIRED_ENV = ["CHIO_SIDECAR_URL", "CHIO_CAPABILITY_ID"]


@dataclass
class ChioHermesPlugin:
    """Snapshot of what `register(ctx)` produced."""

    runtime: RuntimeHandle
    tool_names: list[str] = field(default_factory=list)
    hook_names: list[str] = field(default_factory=list)
    cli_command: str | None = None
    slash_command: str | None = None


def _make_check_fn(handle: RuntimeHandle) -> Callable[[], bool]:
    """Return a `check_fn` Hermes calls to gate tool exposure.

    Hermes hides the tool from the model when this returns False, so
    the model does not waste tokens on a tool it cannot use.
    """

    def check() -> bool:
        return handle.is_configured()

    return check


def register(ctx: Any) -> ChioHermesPlugin:
    handle = build_runtime_handle()
    plugin = ChioHermesPlugin(runtime=handle)

    check_fn = _make_check_fn(handle)

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

    ctx.register_cli_command(
        name="chio",
        help="Manage Chio capabilities used by the Hermes plugin.",
        setup_fn=cli.setup,
        handler_fn=cli.handle,
        description="Manage Chio capabilities used by the Hermes plugin.",
    )
    plugin.cli_command = "chio"

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
