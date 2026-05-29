"""Chio CrewAI integration.

Wraps CrewAI's :class:`crewai.tools.BaseTool` and :class:`crewai.Crew`
so every tool invocation flows through the Chio sidecar for
capability-scoped authorization and signed receipts.

Public surface:

* :class:`ChioBaseTool` -- :class:`crewai.tools.BaseTool` subclass that
  gates ``_run`` on a Chio allow verdict.
* :class:`ChioCrew` -- :class:`crewai.Crew` subclass that accepts a
  per-role ``capability_scope`` mapping and mints scoped tokens.
* :class:`ChioToolError` / :class:`ChioCrewConfigError` -- error types.
"""

from chio_crewai.crew import ChioCrew
from chio_crewai.errors import ChioCrewConfigError, ChioToolError
from chio_crewai.tool import ChioBaseTool

__all__ = [
    "ChioBaseTool",
    "ChioCrew",
    "ChioCrewConfigError",
    "ChioToolError",
]
