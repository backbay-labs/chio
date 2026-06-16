"""Chio-governed LlamaIndex :class:`FunctionTool` wrapper.

This module wraps :class:`llama_index.core.tools.FunctionTool` so every
``call`` / ``acall`` dispatch first flows through the Chio sidecar for
capability validation and guard evaluation. Only after an allow verdict
does the underlying Python function execute.

The wrapper preserves LlamaIndex's contract:

* ``metadata`` (name, description, ``fn_schema``) is surfaced unchanged
  to planners and LLMs.
* ``call`` returns a :class:`ToolOutput` synchronously.
* ``acall`` returns a :class:`ToolOutput` coroutine.

On deny, the wrapper raises :class:`ChioToolError` so the agent loop
observes the denial rather than silently returning a misleading
``ToolOutput``. Callers who want to surface deny as a ``ToolOutput``
instead (some agent planners prefer that) can pass
``raise_on_deny=False`` and inspect :attr:`ChioFunctionTool.last_chio_receipt`.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from chio_adapter_base.redact import RedactionPolicy, bind_and_redact
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt, ChioScope
from llama_index.core.tools import FunctionTool, ToolOutput
from llama_index.core.tools.types import ToolMetadata
from pydantic import BaseModel

from chio_llamaindex.errors import ChioToolError

logger = logging.getLogger(__name__)

# Callable shape accepted as ``fn``: may be sync or async.
ToolCallable = Callable[..., Any]

# Anything that looks like an :class:`ChioClient` (the real client or a
# test double from :mod:`chio_sdk.testing`). Structural typing keeps the
# production code free of testing imports.
ChioClientLike = Any


class ChioFunctionTool(FunctionTool):
    """LlamaIndex :class:`FunctionTool` whose every call is gated by Chio.

    Parameters
    ----------
    fn:
        The synchronous Python callable to expose. May be omitted when
        ``async_fn`` is given.
    async_fn:
        The asynchronous callable variant. LlamaIndex routes ``acall``
        to this when provided; otherwise it adapts ``fn``.
    name, description:
        Standard :class:`ToolMetadata` fields. ``name`` defaults to the
        function ``__name__``.
    fn_schema:
        Optional Pydantic model that describes the tool's argument
        schema. LlamaIndex forwards this to the LLM as the JSON schema.
    server_id:
        The Chio tool server identifier this tool belongs to.
    capability_id:
        Capability token id that authorizes this invocation.
    sidecar_url:
        Base URL of the Chio sidecar.
    chio_client:
        Optional pre-built :class:`ChioClient` (or test double) to reuse
        across calls. When supplied the tool does not close the client.
    scope:
        Optional :class:`ChioScope` recorded on the tool for offline
        assertion helpers. Not sent to the sidecar directly; evaluation
        is driven by the capability token.
    raise_on_deny:
        When ``True`` (the default) a deny verdict raises
        :class:`ChioToolError`. When ``False`` the wrapper returns a
        :class:`ToolOutput` whose ``content`` announces the denial, which
        some LlamaIndex planners prefer to feed back to the LLM.
    redaction_policy:
        Per-tool argument redaction policy applied right before parameters
        are forwarded to the sidecar so secret-bearing fields never land
        in the receipt log. Defaults to
        :meth:`RedactionPolicy.chio_default`; pass a custom
        :class:`RedactionPolicy` to extend with adapter or workspace
        specific tool names.
    """

    def __init__(
        self,
        *,
        fn: ToolCallable | None = None,
        async_fn: Callable[..., Awaitable[Any]] | None = None,
        name: str | None = None,
        description: str | None = None,
        fn_schema: type[BaseModel] | None = None,
        metadata: ToolMetadata | None = None,
        server_id: str = "",
        capability_id: str = "",
        sidecar_url: str = "http://127.0.0.1:9090",
        chio_client: ChioClientLike | None = None,
        scope: ChioScope | None = None,
        raise_on_deny: bool = True,
        redaction_policy: RedactionPolicy | None = None,
    ) -> None:
        if fn is None and async_fn is None:
            raise ValueError("ChioFunctionTool requires 'fn' or 'async_fn'")

        resolved_metadata = metadata or _build_metadata(
            fn=fn or async_fn,
            name=name,
            description=description,
            fn_schema=fn_schema,
        )

        super().__init__(
            fn=fn,
            metadata=resolved_metadata,
            async_fn=async_fn,
        )

        self._server_id = server_id
        self._capability_id = capability_id
        self._sidecar_url = sidecar_url
        self._chio_client = chio_client
        self._scope = scope
        self._raise_on_deny = bool(raise_on_deny)
        self._redaction_policy = (
            redaction_policy
            if redaction_policy is not None
            else RedactionPolicy.chio_default()
        )
        self._last_receipt: ChioReceipt | None = None
        self._tool_callable = fn or async_fn

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def server_id(self) -> str:
        """Chio tool-server identifier associated with this tool."""
        return self._server_id

    @property
    def capability_id(self) -> str:
        """Capability token id used on evaluate calls."""
        return self._capability_id

    @property
    def sidecar_url(self) -> str:
        """Base URL of the Chio sidecar the tool will talk to."""
        return self._sidecar_url

    @property
    def scope(self) -> ChioScope | None:
        """Optional :class:`ChioScope` recorded for assertion helpers."""
        return self._scope

    @scope.setter
    def scope(self, value: ChioScope | None) -> None:
        self._scope = value

    @property
    def last_chio_receipt(self) -> ChioReceipt | None:
        """Most recent :class:`ChioReceipt` returned by the sidecar."""
        return self._last_receipt

    def bind_chio_client(self, client: ChioClientLike) -> None:
        """Attach an :class:`ChioClient` (or mock) to reuse across calls."""
        self._chio_client = client

    def bind_capability(self, capability_id: str) -> None:
        """Set the capability token id used on subsequent invocations.

        :class:`chio_llamaindex.ChioAgentRunner` calls this when it binds a
        per-agent capability to tools registered on a runner.
        """
        self._capability_id = capability_id

    # ------------------------------------------------------------------
    # LlamaIndex BaseTool contract
    # ------------------------------------------------------------------

    def call(self, *args: Any, **kwargs: Any) -> ToolOutput:
        """Synchronous entry point.

        Delegates to :meth:`acall` and blocks. If an event loop is
        already running we raise: LlamaIndex's own ``FunctionTool``
        exhibits the same limitation because sync ``call`` cannot
        bridge into a running async context safely.
        """
        import asyncio

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.acall(*args, **kwargs))
        raise RuntimeError(
            "ChioFunctionTool.call() cannot be used from a running event loop; "
            "await ChioFunctionTool.acall(...) instead."
        )

    async def acall(self, *args: Any, **kwargs: Any) -> ToolOutput:
        """Asynchronous entry point.

        Evaluates the call through Chio first. On allow, defers to the
        parent :meth:`FunctionTool.acall` so default schema handling,
        callbacks, and :class:`ToolOutput` construction match upstream.
        """
        # Bind-and-redact before values cross into the sidecar. The
        # underlying function still receives the real args via
        # ``super().acall(*args, **kwargs)`` below.
        recorded_parameters = _materialise_parameters(
            args,
            kwargs,
            fn=self._tool_callable,
            tool_name=self.metadata.name or "",
            policy=self._redaction_policy,
        )
        receipt = await self._evaluate(recorded_parameters)
        self._last_receipt = receipt

        if receipt.is_denied:
            return self._on_deny(receipt, recorded_parameters)

        return await super().acall(*args, **kwargs)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _evaluate(self, parameters: dict[str, Any]) -> ChioReceipt:
        """Call the sidecar's ``evaluate_tool_call`` endpoint."""
        if not self._capability_id:
            raise ChioToolError(
                "no capability_id bound to tool",
                tool_name=self.metadata.name,
                server_id=self._server_id,
                reason="missing_capability",
            )

        client = self._chio_client
        owns_client = False
        if client is None:
            client = ChioClient(self._sidecar_url)
            owns_client = True

        try:
            return await client.evaluate_tool_call(
                capability_id=self._capability_id,
                tool_server=self._server_id,
                tool_name=self.metadata.name or "",
                parameters=parameters,
            )
        except ChioDeniedError as exc:
            raise ChioToolError(
                exc.message,
                tool_name=self.metadata.name,
                server_id=self._server_id,
                guard=exc.guard,
                reason=exc.reason,
                receipt_id=exc.receipt_id,
            ) from exc
        except ChioError:
            raise
        finally:
            if owns_client:
                await client.close()

    def _on_deny(
        self,
        receipt: ChioReceipt,
        parameters: dict[str, Any],
    ) -> ToolOutput:
        """Translate a deny receipt into the configured outcome."""
        reason = receipt.decision.reason or "denied by Chio kernel"
        if self._raise_on_deny:
            raise ChioToolError(
                reason,
                tool_name=self.metadata.name,
                server_id=self._server_id,
                guard=receipt.decision.guard,
                reason=receipt.decision.reason,
                receipt_id=receipt.id,
                decision=receipt.decision.model_dump(exclude_none=True),
            )

        return ToolOutput(
            content=f"DENIED: {reason}",
            tool_name=self.metadata.name or "",
            raw_input={"kwargs": dict(parameters)},
            raw_output=reason,
            is_error=True,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_metadata(
    *,
    fn: Callable[..., Any] | None,
    name: str | None,
    description: str | None,
    fn_schema: type[BaseModel] | None,
) -> ToolMetadata:
    """Build a :class:`ToolMetadata` from conventional overrides.

    Mirrors the behaviour of :meth:`FunctionTool.from_defaults` so that
    callers can construct :class:`ChioFunctionTool` without reaching into
    LlamaIndex internals.
    """
    resolved_name = name or (fn.__name__ if fn is not None else "tool")
    resolved_description = description or (
        inspect.getdoc(fn) if fn is not None else None
    ) or resolved_name
    return ToolMetadata(
        name=resolved_name,
        description=resolved_description,
        fn_schema=fn_schema,
    )


def _materialise_parameters(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    fn: Callable[..., Any] | None,
    tool_name: str,
    policy: RedactionPolicy,
) -> dict[str, Any]:
    """Collapse ``(*args, **kwargs)`` into a kwargs dict for evaluation.

    LlamaIndex planners call tools with keyword arguments parsed from
    the LLM's JSON output, so positional arguments are rare. We still
    preserve them under a synthetic ``_args`` key so the sidecar's
    parameter hash reflects every value the tool saw.
    """
    redacted_args, redacted_kwargs = bind_and_redact(
        fn,
        args,
        kwargs,
        tool_name=tool_name,
        policy=policy,
    )
    if not redacted_args:
        return dict(redacted_kwargs)
    merged: dict[str, Any] = dict(redacted_kwargs)
    merged["_args"] = list(redacted_args)
    return merged


__all__ = [
    "ChioClientLike",
    "ChioFunctionTool",
    "ToolCallable",
]
