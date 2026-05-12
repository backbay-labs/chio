"""The :func:`chio_node` wrapper.

``chio_node`` takes a LangGraph node callable (sync or async) plus an
:class:`chio_sdk.ChioScope` and returns a node callable that -- before the
wrapped body runs -- evaluates the node dispatch through the Chio sidecar.
A deny verdict raises :class:`ChioLangGraphError`; an allow verdict lets
the wrapped body run exactly as it would have otherwise.

Design notes
------------

* LangGraph nodes may be either plain functions returning a state
  update dict, or async coroutines. The wrapper preserves both shapes:
  it inspects the wrapped callable with :func:`asyncio.iscoroutinefunction`
  and returns the matching shape so LangGraph's state machine keeps
  working.
* The wrapper calls ``evaluate_tool_call`` on the :class:`chio_sdk.ChioClient`
  using ``tool_server=<server_id>`` and ``tool_name=<node_name>``. From
  the sidecar's perspective, a node dispatch is a tool call against a
  virtual tool; scope enforcement, receipt signing, and delegation all
  work the same way.
* When the config carries a ``configurable["chio_capability_id"]``, that
  id overrides the token resolved from the :class:`ChioGraphConfig`.
  This lets supervisor nodes hand a narrower capability to a child
  subgraph via LangGraph's standard config propagation.
* The wrapper refuses to invoke a node whose scope is broader than the
  parent graph's ceiling -- :func:`enforce_subgraph_ceiling` is called
  at wrap time so configuration errors surface *before* any state moves.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt, ChioScope

from chio_langgraph.errors import ChioLangGraphError
from chio_langgraph.scoping import ChioGraphConfig, enforce_subgraph_ceiling

logger = logging.getLogger(__name__)


# LangGraph node shapes: either ``fn(state)`` or ``fn(state, config)``,
# sync or async. The wrapper auto-detects which by introspection.
NodeCallable = Callable[..., Any]
NodeResult = Any


def chio_node(
    fn: NodeCallable,
    *,
    scope: ChioScope,
    config: ChioGraphConfig,
    name: str | None = None,
    tool_server: str = "langgraph",
    redaction_policy: RedactionPolicy | None = None,
) -> NodeCallable:
    """Wrap a LangGraph node with Chio capability enforcement.

    Parameters
    ----------
    fn:
        The underlying node callable. May be sync or async, and may
        accept either ``(state)`` or ``(state, config)`` in the usual
        LangGraph style. The wrapper preserves the original arity and
        async contract.
    scope:
        The :class:`ChioScope` this node operates under. The scope must
        be a subset of the parent graph's effective ceiling
        (enforced at wrap time via
        :func:`chio_langgraph.scoping.enforce_subgraph_ceiling`).
    config:
        The enclosing :class:`ChioGraphConfig`. The wrapper looks up the
        capability token minted for ``name`` (falling back to the
        workflow-level token) and sends each node dispatch through
        ``config.chio_client``.
    name:
        Name under which to register the node. Defaults to
        ``fn.__name__``. Also used as the ``tool_name`` sent to the
        sidecar so receipts correlate with the graph topology.
    tool_server:
        Sidecar ``tool_server`` identifier. Defaults to
        ``"langgraph"``; override when a single kernel fronts several
        distinct graphs and needs per-graph receipt filtering.
    redaction_policy:
        Optional :class:`RedactionPolicy` applied to the
        state-derived parameters before sidecar evaluation. Defaults
        to :meth:`RedactionPolicy.chio_default`.

    Returns
    -------
    A new node callable that evaluates the dispatch via the sidecar
    before invoking ``fn``.

    Raises
    ------
    ChioLangGraphConfigError
        If ``scope`` exceeds the graph ceiling.
    """
    node_name: str = name or str(getattr(fn, "__name__", "node"))

    # Enforce the ceiling at wrap time so the error surfaces during
    # graph construction, not at first invocation. Also register the
    # node scope on the config so provisioning picks it up.
    enforce_subgraph_ceiling(config, node_name, scope)
    config.node_scopes.setdefault(node_name, scope)

    is_async = asyncio.iscoroutinefunction(fn)
    sig = inspect.signature(fn) if callable(fn) else None
    takes_config = _node_accepts_config(sig)
    effective_redaction_policy: RedactionPolicy = (
        redaction_policy
        if redaction_policy is not None
        else RedactionPolicy.chio_default()
    )

    async def _dispatch(state: Any, runtime_config: Any) -> NodeResult:
        """Core Chio dispatch: evaluate, then call the wrapped node."""
        cap_id = _resolve_capability_id(
            config=config,
            node_name=node_name,
            runtime_config=runtime_config,
        )
        if not cap_id:
            raise ChioLangGraphError(
                "no capability bound to node; call ChioGraphConfig.provision() "
                "before running the graph",
                node_name=node_name,
                tool_server=tool_server,
                tool_name=node_name,
                reason="missing_capability",
            )
        parameters = redact_args(
            node_name,
            _state_to_parameters(state),
            policy=effective_redaction_policy,
        )
        receipt = await _evaluate(
            chio_client=config.chio_client,
            capability_id=cap_id,
            tool_server=tool_server,
            tool_name=node_name,
            parameters=parameters,
        )
        if receipt.decision.is_denied:
            raise ChioLangGraphError(
                receipt.decision.reason or "denied by Chio kernel",
                node_name=node_name,
                tool_server=tool_server,
                tool_name=node_name,
                guard=receipt.decision.guard,
                reason=receipt.decision.reason,
                receipt_id=receipt.id,
                decision=receipt.decision.model_dump(exclude_none=True),
            )

        # Allow verdict: invoke the wrapped body preserving sync/async
        # and arity. LangGraph inspects the returned value and treats
        # it as the state update.
        if takes_config:
            result = fn(state, runtime_config)
        else:
            result = fn(state)
        if isinstance(result, Awaitable):
            return await result
        return result

    if is_async:

        async def async_wrapper(
            state: Any, runtime_config: Any = None
        ) -> NodeResult:
            return await _dispatch(state, runtime_config)

        _copy_metadata(fn, async_wrapper, node_name)
        async_wrapper.__chio_scope__ = scope  # type: ignore[attr-defined]
        async_wrapper.__chio_node_name__ = node_name  # type: ignore[attr-defined]
        return async_wrapper

    def sync_wrapper(state: Any, runtime_config: Any = None) -> NodeResult:
        coro = _dispatch(state, runtime_config)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        # Inside a running loop we *must* return the coroutine; LangGraph's
        # async pipeline awaits it directly.
        return coro

    _copy_metadata(fn, sync_wrapper, node_name)
    sync_wrapper.__chio_scope__ = scope  # type: ignore[attr-defined]
    sync_wrapper.__chio_node_name__ = node_name  # type: ignore[attr-defined]
    return sync_wrapper


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _evaluate(
    *,
    chio_client: Any,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
) -> ChioReceipt:
    """Send a sidecar evaluation and translate deny-on-wire errors."""
    try:
        return await chio_client.evaluate_tool_call(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
    except ChioDeniedError as exc:
        raise ChioLangGraphError(
            exc.message,
            tool_server=tool_server,
            tool_name=tool_name,
            guard=exc.guard,
            reason=exc.reason,
            receipt_id=exc.receipt_id,
        ) from exc
    except ChioError:
        raise


def _resolve_capability_id(
    *,
    config: ChioGraphConfig,
    node_name: str,
    runtime_config: Any,
) -> str | None:
    """Pick the capability id for this dispatch.

    Priority order:

    1. ``runtime_config["configurable"]["chio_capability_id"]`` -- lets a
       supervisor node hand a narrower token to a child node via
       standard LangGraph config propagation.
    2. The token minted for ``node_name`` on the :class:`ChioGraphConfig`.
    3. The workflow-level token, if one was minted.
    """
    if isinstance(runtime_config, dict):
        configurable = runtime_config.get("configurable")
        if isinstance(configurable, dict):
            override = configurable.get("chio_capability_id")
            if isinstance(override, str) and override:
                return override
    token = config.token_for(node_name)
    if token is not None:
        return token.id
    workflow = config.workflow_token()
    if workflow is not None:
        return workflow.id
    return None


def _state_to_parameters(state: Any) -> dict[str, Any]:
    """Render a LangGraph state into a params dict for the sidecar.

    LangGraph states are typically ``TypedDict`` instances which are
    regular dicts at runtime. Pydantic models also show up; for those
    we emit the model dump. Anything else falls back to ``str(state)``
    under a single ``state`` key so the sidecar always receives a
    hashable payload.
    """
    if state is None:
        return {}
    if isinstance(state, dict):
        return dict(state)
    model_dump = getattr(state, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump(exclude_none=True)
        if isinstance(dumped, dict):
            return dumped
    return {"state": repr(state)}


def _node_accepts_config(sig: inspect.Signature | None) -> bool:
    """Return True when the node callable wants a ``config`` argument."""
    if sig is None:
        return False
    params = [
        p
        for p in sig.parameters.values()
        if p.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    return len(params) >= 2


def _copy_metadata(src: Any, dest: Any, node_name: str) -> None:
    """Copy ``__name__``/``__doc__`` so LangGraph introspection works."""
    try:
        dest.__name__ = node_name
    except (AttributeError, TypeError):
        pass
    if getattr(src, "__doc__", None):
        try:
            dest.__doc__ = src.__doc__
        except (AttributeError, TypeError):
            pass


__all__ = [
    "NodeCallable",
    "chio_node",
]
