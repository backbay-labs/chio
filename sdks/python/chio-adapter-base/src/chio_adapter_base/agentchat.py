"""Modern AutoGen AgentChat tools backed by Chio MCP execution."""

from typing import Any

from chio_adapter_base.mcp import McpToolBinding


def mcp_tool(binding: McpToolBinding, *, schema: Any, description: str, name: str | None = None) -> Any:
    """Create autogen-core's native FunctionTool for an AgentChat agent.

    Install autogen-agentchat separately. Keep the MCP session open throughout
    agent.run; inspect binding.last_execution for receipt associations.
    """
    from autogen_core.tools import FunctionTool

    return FunctionTool(
        binding.function(schema, name=name, description=description, asynchronous=True),
        description=description,
        name=name or binding.tool_name,
    )
