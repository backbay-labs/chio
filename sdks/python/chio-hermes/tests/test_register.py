"""Verify that `register(ctx)` wires the documented surface.

One call registers 12 async tools under toolset `chio` (all
`is_async=True`), four hooks (pre/post tool call + session
start/end), one CLI command, and one slash command.
"""

from __future__ import annotations

import pytest

from chio_hermes import register
from tests.conftest import FakePluginContext

EXPECTED_TOOLS = {
    "chio_file_read",
    "chio_file_write",
    "chio_file_edit",
    "chio_file_list",
    "chio_file_search",
    "chio_shell_run",
    "chio_git_status",
    "chio_git_diff",
    "chio_git_log",
    "chio_git_add",
    "chio_git_commit",
    "chio_git_run",
}


def test_register_registers_twelve_tools(
    fake_plugin_context: FakePluginContext, configured_env: None
) -> None:
    register(fake_plugin_context)
    assert len(fake_plugin_context.tools) == 12
    assert set(fake_plugin_context.tools.keys()) == EXPECTED_TOOLS


def test_register_registers_four_hooks(
    fake_plugin_context: FakePluginContext, configured_env: None
) -> None:
    register(fake_plugin_context)
    assert set(fake_plugin_context.hooks.keys()) == {
        "pre_tool_call",
        "post_tool_call",
        "on_session_start",
        "on_session_end",
    }


def test_register_registers_one_cli_command(
    fake_plugin_context: FakePluginContext, configured_env: None
) -> None:
    register(fake_plugin_context)
    assert list(fake_plugin_context.cli.keys()) == ["chio"]


def test_register_registers_one_slash_command(
    fake_plugin_context: FakePluginContext, configured_env: None
) -> None:
    register(fake_plugin_context)
    assert list(fake_plugin_context.cmds.keys()) == ["chio"]


@pytest.mark.parametrize("tool_name", sorted(EXPECTED_TOOLS))
def test_each_tool_uses_chio_toolset_and_is_async(
    tool_name: str,
    fake_plugin_context: FakePluginContext,
    configured_env: None,
) -> None:
    register(fake_plugin_context)
    tool = fake_plugin_context.tools[tool_name]
    assert tool.kwargs.get("toolset") == "chio", (
        f"{tool_name} must register under the single `chio` toolset"
    )
    assert tool.kwargs.get("is_async") is True, (
        f"{tool_name} must be is_async=True so Hermes awaits the handler "
        "instead of running it through the synchronous bridge"
    )


@pytest.mark.parametrize("tool_name", sorted(EXPECTED_TOOLS))
def test_each_tool_schema_is_a_valid_json_schema_dict(
    tool_name: str,
    fake_plugin_context: FakePluginContext,
    configured_env: None,
) -> None:
    """Hermes's `tools/registry.py:get_definitions` reads
    `schema.get("parameters")` for argument coercion. The JSON Schema
    body MUST live under `parameters`, with `name` and `description`
    sitting alongside it (OpenAI function-tool shape).
    """
    register(fake_plugin_context)
    tool = fake_plugin_context.tools[tool_name]
    schema = tool.kwargs.get("schema")
    assert isinstance(schema, dict), f"{tool_name} schema must be a dict"
    assert schema.get("name") == tool_name, (
        f"{tool_name} schema must declare its own name (Hermes registry shape)"
    )
    assert isinstance(schema.get("description"), str), (
        f"{tool_name} schema must include a top-level description"
    )
    parameters = schema.get("parameters")
    assert isinstance(parameters, dict), (
        f"{tool_name} schema must wrap the JSON Schema body in `parameters`; "
        "Hermes's registry calls schema.get('parameters') for arg coercion"
    )
    assert parameters.get("type") == "object", (
        f"{tool_name} parameters must be a JSON Schema object"
    )
    # additionalProperties: false rejects unexpected keys at parse time.
    assert parameters.get("additionalProperties") is False, (
        f"{tool_name} parameters must set `additionalProperties: false`"
    )


@pytest.mark.parametrize("tool_name", sorted(EXPECTED_TOOLS))
def test_each_tool_handler_is_callable(
    tool_name: str,
    fake_plugin_context: FakePluginContext,
    configured_env: None,
) -> None:
    register(fake_plugin_context)
    tool = fake_plugin_context.tools[tool_name]
    handler = tool.kwargs.get("handler")
    assert callable(handler)


def test_schemas_match_hermes_registry_function_shape() -> None:
    """Hermes builds OpenAI-style entries via
    `{"type": "function", "function": entry.schema}`. Each schema must
    therefore look like a `function` block: top-level `name` + optional
    `description` + a `parameters` JSON Schema object."""
    from chio_hermes.schemas import SCHEMAS

    for tool_name, schema in SCHEMAS.items():
        wrapped = {"type": "function", "function": schema}
        fn = wrapped["function"]
        assert fn["name"] == tool_name
        params = fn.get("parameters")
        assert isinstance(params, dict)
        # Argument coercion path Hermes actually uses; if this returns
        # None the registry skips coercion entirely.
        assert params.get("type") == "object"


def test_check_fn_returns_false_when_env_missing(
    fake_plugin_context: FakePluginContext, unconfigured_env: None
) -> None:
    """Hermes hides tools when `check_fn()` is False so the model does
    not call something that can only return `chio_not_configured`."""
    register(fake_plugin_context)
    for tool in fake_plugin_context.tools.values():
        check_fn = tool.kwargs.get("check_fn")
        assert callable(check_fn)
        assert check_fn() is False
