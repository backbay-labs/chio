"""The :func:`chio_node` wrapper.

Wraps a LangGraph node so each dispatch is evaluated by the Chio
sidecar before the body runs. The sidecar treats node dispatch as a
tool call (``tool_name=<node_name>``); allow runs the body, deny raises
:class:`ChioLangGraphError`. Subgraph ceiling is enforced at wrap time.
A ``configurable["chio_capability_id"]`` in runtime config lets a
supervisor hand a narrower token to a child node.
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


# Sync or async; ``fn(state)`` or ``fn(state, config)``. Auto-detected.
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

    ``scope`` must be a subset of the parent graph's ceiling (enforced
    at wrap time). ``redaction_policy`` defaults to
    :meth:`RedactionPolicy.chio_default`.
    """
    node_name: str = name or str(getattr(fn, "__name__", "node"))

    # Enforce the ceiling at wrap time so config errors surface early.
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
        decision = receipt.decision
        if not receipt.is_allowed:
            raise ChioLangGraphError(
                decision.reason
                if decision is not None and decision.reason is not None
                else "non-authorizing Chio receipt",
                node_name=node_name,
                tool_server=tool_server,
                tool_name=node_name,
                guard=decision.guard if decision is not None else None,
                reason=decision.reason if decision is not None else None,
                receipt_id=receipt.id,
                decision=decision.model_dump(exclude_none=True)
                if decision is not None
                else None,
            )

        # Allow: invoke body preserving sync/async + arity.
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
        # Inside a running loop, return the coroutine for LangGraph to await.
        return coro

    _copy_metadata(fn, sync_wrapper, node_name)
    sync_wrapper.__chio_scope__ = scope  # type: ignore[attr-defined]
    sync_wrapper.__chio_node_name__ = node_name  # type: ignore[attr-defined]
    return sync_wrapper


async def _evaluate(
    *,
    chio_client: Any,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
) -> ChioReceipt:
    """Sidecar evaluate; translate HTTP-403 to :class:`ChioLangGraphError`."""
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
    """runtime override > node token > workflow token."""
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
    """Render LangGraph state to a sidecar params dict (dict / pydantic / repr)."""
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
