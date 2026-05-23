"""Chio-governed CrewAI ``BaseTool`` wrapper.

This module wraps CrewAI's :class:`crewai.tools.BaseTool` so every
``_run`` invocation first flows through the Chio sidecar for capability
validation and guard evaluation. Only after an allow verdict does the
underlying tool implementation execute.

Two shapes are supported:

1. *Subclass* -- override :meth:`ChioBaseTool._execute` with the real
   tool body. ``_run`` is final in :class:`ChioBaseTool`.
2. *Delegate* -- pass ``executor=callable(**kwargs)`` to an
   :class:`ChioBaseTool` instance to wrap an existing callable.

The public ``name``, ``description``, ``args_schema``, ``result_as_answer``
and other CrewAI ``BaseTool`` fields are preserved unchanged.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt, ChioScope
from crewai.tools import BaseTool
from pydantic import ConfigDict, Field, PrivateAttr

from chio_crewai.errors import ChioToolError

logger = logging.getLogger(__name__)


# Callable shape accepted as ``executor``: may be sync or async.
ToolExecutor = Callable[..., Any]

# Anything that looks like an ``ChioClient`` -- we accept the real client
# and the ``MockChioClient`` from ``chio_sdk.testing`` interchangeably. A
# structural type alias keeps the annotation readable without importing
# the testing helpers in production code.
ChioClientLike = Any


class ChioBaseTool(BaseTool):
    """CrewAI tool whose every invocation is gated by the Chio sidecar.

    Parameters
    ----------
    name, description:
        Standard CrewAI ``BaseTool`` fields.
    server_id:
        The Chio tool server identifier this tool belongs to.
    capability_id:
        Capability token id that authorizes this invocation. Per-role
        scoping is applied by :class:`chio_crewai.ChioCrew` which rewrites
        this field on assignment.
    sidecar_url:
        Base URL of the Chio sidecar.
    chio_client:
        Optional pre-built :class:`chio_sdk.ChioClient` (or
        ``MockChioClient``) to use instead of constructing one per call.
        When supplied, the tool does not close the client.
    executor:
        Optional callable that implements the real tool body. When
        ``None`` (the default) subclasses must override :meth:`_execute`.
    scope:
        Optional :class:`ChioScope` describing what the tool requires.
        Recorded on the tool for :class:`ChioCrew` scoping checks; not
        sent to the sidecar directly.
    redaction_policy:
        Per-tool argument redaction policy applied right before parameters
        are forwarded to the sidecar so secret-bearing fields never land
        in the receipt log. Defaults to
        :meth:`RedactionPolicy.chio_default`; pass a custom
        :class:`RedactionPolicy` to extend with adapter or workspace
        specific tool names.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    server_id: str = ""
    capability_id: str = ""
    sidecar_url: str = "http://127.0.0.1:9090"
    scope: ChioScope | None = None

    # Implementation + runtime collaborators are kept in private attrs so
    # pydantic does not try to validate them and so the public
    # ``model_dump`` stays compact.
    _executor: ToolExecutor | None = PrivateAttr(default=None)
    _chio_client: ChioClientLike | None = PrivateAttr(default=None)
    _last_receipt: ChioReceipt | None = PrivateAttr(default=None)
    _redaction_policy: RedactionPolicy = PrivateAttr(
        default_factory=RedactionPolicy.chio_default
    )

    # Captured at construction so mypy/Pydantic do not shadow the base
    # class default when callers inspect the field.
    last_receipt: ChioReceipt | None = Field(default=None, exclude=True)

    def __init__(
        self,
        *,
        executor: ToolExecutor | None = None,
        chio_client: ChioClientLike | None = None,
        redaction_policy: RedactionPolicy | None = None,
        **data: Any,
    ) -> None:
        super().__init__(**data)
        self._executor = executor
        self._chio_client = chio_client
        if redaction_policy is not None:
            self._redaction_policy = redaction_policy

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def last_chio_receipt(self) -> ChioReceipt | None:
        """Most recent :class:`ChioReceipt` returned by the sidecar."""
        return self._last_receipt

    def bind_chio_client(self, client: ChioClientLike) -> None:
        """Attach an :class:`ChioClient` (or mock) to reuse across calls."""
        self._chio_client = client

    def bind_capability(self, capability_id: str) -> None:
        """Set the capability token id used on subsequent invocations.

        :class:`ChioCrew` calls this when it assigns per-role capabilities
        to agent-owned tools.
        """
        self.capability_id = capability_id

    # ------------------------------------------------------------------
    # CrewAI BaseTool contract
    # ------------------------------------------------------------------

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronous entry point required by CrewAI.

        CrewAI's :meth:`BaseTool.run` auto-awaits coroutines returned
        from ``_run`` via ``asyncio.run``, so we delegate to the async
        core. When an event loop is already running (e.g. the caller is
        inside an async framework) we return the coroutine directly so
        the caller can ``await`` it.
        """
        if args:
            raise TypeError(
                "ChioBaseTool only supports keyword arguments on _run; "
                "CrewAI dispatches tools with **kwargs."
            )
        coro = self._arun(**kwargs)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop -- block synchronously. CrewAI's own
            # BaseTool.run detects coroutines and does the same, but
            # doing it here keeps the sync contract explicit.
            return asyncio.run(coro)
        return coro

    async def _arun(self, **kwargs: Any) -> Any:
        """Evaluate the tool call with Chio and, on allow, run the body."""
        # Redact body fields (e.g. chio_file_write.content) before they
        # cross into the sidecar so the receipt log never carries the raw
        # secret bytes. The underlying executor still receives the real
        # kwargs via :meth:`_invoke_executor` below.
        recorded_kwargs = redact_args(
            self.name, kwargs, policy=self._redaction_policy
        )
        receipt = await self._evaluate(recorded_kwargs)
        self._last_receipt = receipt
        self.last_receipt = receipt

        if not receipt.is_allowed:
            decision = receipt.decision
            raise ChioToolError(
                decision.reason
                if decision is not None and decision.reason is not None
                else "non-authorizing Chio receipt",
                tool_name=self.name,
                server_id=self.server_id,
                guard=decision.guard if decision is not None else None,
                reason=decision.reason if decision is not None else None,
                receipt_id=receipt.id,
                decision=decision.model_dump(exclude_none=True)
                if decision is not None
                else None,
            )

        return await self._invoke_executor(kwargs)

    # ------------------------------------------------------------------
    # Extension point for subclasses
    # ------------------------------------------------------------------

    def _execute(self, **kwargs: Any) -> Any:
        """Override in a subclass to implement the real tool body.

        The default implementation raises ``NotImplementedError`` unless
        an ``executor`` callable was supplied at construction time.
        """
        if self._executor is None:
            raise NotImplementedError(
                "ChioBaseTool._execute must be overridden or an 'executor' "
                "callable must be provided at construction."
            )
        return self._executor(**kwargs)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _evaluate(self, parameters: dict[str, Any]) -> ChioReceipt:
        """Call the sidecar's ``evaluate_tool_call`` endpoint."""
        if not self.capability_id:
            raise ChioToolError(
                "no capability_id bound to tool",
                tool_name=self.name,
                server_id=self.server_id,
                reason="missing_capability",
            )

        client = self._chio_client
        owns_client = False
        if client is None:
            client = ChioClient(self.sidecar_url)
            owns_client = True

        try:
            return await client.evaluate_tool_call(
                capability_id=self.capability_id,
                tool_server=self.server_id,
                tool_name=self.name,
                parameters=parameters,
            )
        except ChioDeniedError as exc:
            raise ChioToolError(
                exc.message,
                tool_name=self.name,
                server_id=self.server_id,
                guard=exc.guard,
                reason=exc.reason,
                receipt_id=exc.receipt_id,
            ) from exc
        except ChioError:
            raise
        finally:
            if owns_client:
                await client.close()

    async def _invoke_executor(self, kwargs: dict[str, Any]) -> Any:
        """Run ``_execute`` / ``executor``, awaiting if it returned a coro."""
        result: Any = self._execute(**kwargs)
        if asyncio.iscoroutine(result) or isinstance(result, Awaitable):
            return await result
        return result


__all__ = [
    "ChioBaseTool",
    "ToolExecutor",
]
