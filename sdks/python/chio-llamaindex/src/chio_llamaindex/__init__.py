"""Chio LlamaIndex integration.

Wraps LlamaIndex's :class:`llama_index.core.tools.FunctionTool` and
:class:`llama_index.core.tools.QueryEngineTool` so every tool dispatch
flows through the Chio sidecar kernel for capability-scoped
authorization, guard enforcement, and signed receipts.

Public surface:

* :class:`ChioFunctionTool` -- :class:`FunctionTool` subclass that gates
  ``call`` / ``acall`` on a Chio allow verdict.
* :class:`ChioQueryEngineTool` -- :class:`QueryEngineTool` subclass that
  additionally scopes which vector collection may be queried.
* :class:`ChioAgentRunner` -- helper that binds a per-agent capability
  token to every Chio-governed tool on an :class:`AgentRunner`.
* :class:`ChioToolError` / :class:`ChioLlamaIndexConfigError` -- error
  types.
"""

from chio_llamaindex.agent_runner import ChioAgentRunner
from chio_llamaindex.errors import ChioLlamaIndexConfigError, ChioToolError
from chio_llamaindex.function_tool import ChioFunctionTool
from chio_llamaindex.query_engine_tool import ChioQueryEngineTool

__all__ = [
    "ChioAgentRunner",
    "ChioFunctionTool",
    "ChioLlamaIndexConfigError",
    "ChioQueryEngineTool",
    "ChioToolError",
]
