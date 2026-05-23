"""Chio-governed AutoGen function registration.

Wraps an agent's ``function_map`` so every tool dispatch is evaluated
by the Chio sidecar before the underlying callable runs. Use
:class:`ChioFunctionRegistry.register` or
:meth:`ChioFunctionRegistry.as_decorator`.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from typing import Any

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import CapabilityToken, ChioReceipt, ChioScope

from chio_autogen.errors import ChioAutogenConfigError, ChioToolError

logger = logging.getLogger(__name__)


# Real ChioClient or :class:`chio_sdk.testing.MockChioClient`.
ChioClientLike = Any

ToolExecutor = Callable[..., Any]

# Duck-typed; we avoid importing ConversableAgent at module scope.
AgentLike = Any


class ChioFunctionRegistry:
    """Per-agent registry of Chio-governed AutoGen functions."""

    def __init__(
        self,
        *,
        agent: AgentLike,
        chio_client: ChioClientLike,
        server_id: str,
        capability_id: str = "",
        role: str | None = None,
        sidecar_url: str = "http://127.0.0.1:9090",
        redaction_policy: RedactionPolicy | None = None,
    ) -> None:
        if agent is None:
            raise ChioAutogenConfigError("agent must not be None")
        if not server_id:
            raise ChioAutogenConfigError("server_id must not be empty")
        self._agent = agent
        self._chio_client = chio_client
        self._server_id = server_id
        self._capability_id = capability_id
        self._role = role or getattr(agent, "name", None)
        self._sidecar_url = sidecar_url
        self._scopes: dict[str, ChioScope] = {}
        self._receipts: dict[str, ChioReceipt] = {}
        self._redaction_policy = (
            redaction_policy
            if redaction_policy is not None
            else RedactionPolicy.chio_default()
        )

    @property
    def agent(self) -> AgentLike:
        return self._agent

    @property
    def role(self) -> str | None:
        return self._role

    @property
    def server_id(self) -> str:
        return self._server_id

    @property
    def capability_id(self) -> str:
        return self._capability_id

    def scope_for(self, name: str) -> ChioScope | None:
        return self._scopes.get(name)

    def last_receipt(self, name: str) -> ChioReceipt | None:
        return self._receipts.get(name)

    def bind_capability(self, capability: CapabilityToken | str) -> None:
        """Swap the capability token id used on subsequent invocations."""
        if isinstance(capability, str):
            self._capability_id = capability
        else:
            self._capability_id = capability.id

    def bind_chio_client(self, client: ChioClientLike) -> None:
        self._chio_client = client

    def register(
        self,
        name: str,
        func: ToolExecutor,
        *,
        scope: ChioScope | None = None,
        description: str | None = None,
        server_id: str | None = None,
    ) -> ToolExecutor:
        """Wrap ``func`` with Chio enforcement and install it on the agent.

        Preserves ``func``'s sync/async contract because AutoGen
        dispatches sync vs async functions down different code paths
        (``execute_function`` vs ``a_execute_function``).
        """
        if not name:
            raise ChioAutogenConfigError("function name must not be empty")
        effective_server = server_id or self._server_id
        if scope is not None:
            self._scopes[name] = scope

        wrapped = self._wrap(
            name=name,
            func=func,
            server_id=effective_server,
        )

        register_function = getattr(self._agent, "register_function", None)
        if callable(register_function):
            register_function(function_map={name: wrapped})
        else:
            # Fall back for duck-typed test agents.
            fmap = getattr(self._agent, "function_map", None)
            if isinstance(fmap, dict):
                fmap[name] = wrapped
            else:
                raise ChioAutogenConfigError(
                    "agent does not expose register_function or function_map"
                )

        # Best-effort LLM registration so the model can see the tool.
        if description is not None:
            reg_llm = getattr(self._agent, "register_for_llm", None)
            if callable(reg_llm) and getattr(self._agent, "llm_config", None):
                try:
                    reg_llm(name=name, description=description)(func)
                except Exception as exc:  # pragma: no cover - autogen quirks
                    logger.debug(
                        "register_for_llm failed for %r: %s", name, exc
                    )

        return wrapped

    def as_decorator(
        self,
        *,
        scope: ChioScope | None = None,
        description: str | None = None,
        server_id: str | None = None,
        name: str | None = None,
    ) -> Callable[[ToolExecutor], ToolExecutor]:
        """Return a decorator that registers the wrapped function."""

        def decorator(func: ToolExecutor) -> ToolExecutor:
            tool_name = name or func.__name__
            desc = description or (func.__doc__ or "").strip() or None
            return self.register(
                tool_name,
                func,
                scope=scope,
                description=desc,
                server_id=server_id,
            )

        return decorator

    def _wrap(
        self,
        *,
        name: str,
        func: ToolExecutor,
        server_id: str,
    ) -> ToolExecutor:
        if inspect.iscoroutinefunction(func):

            async def async_wrapper(**kwargs: Any) -> Any:
                recorded_kwargs = redact_args(
                    name, kwargs, policy=self._redaction_policy
                )
                receipt = await self._evaluate(
                    name=name,
                    server_id=server_id,
                    parameters=recorded_kwargs,
                )
                self._receipts[name] = receipt
                self._raise_if_denied(
                    name=name, server_id=server_id, receipt=receipt
                )
                return await func(**kwargs)

            async_wrapper.__name__ = getattr(func, "__name__", name)
            async_wrapper.__doc__ = func.__doc__
            return async_wrapper

        def sync_wrapper(**kwargs: Any) -> Any:
            recorded_kwargs = redact_args(
                name, kwargs, policy=self._redaction_policy
            )
            coro = self._evaluate(
                name=name,
                server_id=server_id,
                parameters=recorded_kwargs,
            )
            receipt = _run_sync(coro)
            self._receipts[name] = receipt
            self._raise_if_denied(
                name=name, server_id=server_id, receipt=receipt
            )
            result = func(**kwargs)
            if isinstance(result, Awaitable):
                # Sync declaration returned a coroutine; let AutoGen await it.
                return result
            return result

        sync_wrapper.__name__ = getattr(func, "__name__", name)
        sync_wrapper.__doc__ = func.__doc__
        return sync_wrapper

    async def _evaluate(
        self,
        *,
        name: str,
        server_id: str,
        parameters: dict[str, Any],
    ) -> ChioReceipt:
        if not self._capability_id:
            raise ChioToolError(
                "no capability_id bound to registry",
                tool_name=name,
                server_id=server_id,
                reason="missing_capability",
            )
        client = self._chio_client
        if client is None:
            raise ChioToolError(
                "no ChioClient bound to registry",
                tool_name=name,
                server_id=server_id,
                reason="missing_chio_client",
            )

        try:
            return await client.evaluate_tool_call(
                capability_id=self._capability_id,
                tool_server=server_id,
                tool_name=name,
                parameters=parameters,
            )
        except ChioDeniedError as exc:
            raise ChioToolError(
                exc.message,
                tool_name=name,
                server_id=server_id,
                guard=exc.guard,
                reason=exc.reason,
                receipt_id=exc.receipt_id,
            ) from exc
        except ChioError:
            raise

    @staticmethod
    def _raise_if_denied(
        *,
        name: str,
        server_id: str,
        receipt: ChioReceipt,
    ) -> None:
        if not receipt.is_denied:
            return
        raise ChioToolError(
            receipt.decision.reason or "denied by Chio kernel",
            tool_name=name,
            server_id=server_id,
            guard=receipt.decision.guard,
            reason=receipt.decision.reason,
            receipt_id=receipt.id,
            decision=receipt.decision.model_dump(exclude_none=True),
        )


def _run_sync(coro: Coroutine[Any, Any, Any]) -> Any:
    """Execute ``coro`` synchronously even when called from within a running loop.

    AutoGen's sync dispatch path normally runs outside any loop, but
    pytest-asyncio callers can reach this with one active; in that case
    we offload to a fresh loop on a worker thread.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, Any] = {}

    def _runner() -> None:
        loop = asyncio.new_event_loop()
        try:
            result["value"] = loop.run_until_complete(coro)
        except BaseException as exc:  # re-raise on caller thread
            result["error"] = exc
        finally:
            loop.close()

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()
    if "error" in result:
        raise result["error"]
    return result.get("value")


def attach_registry(agent: AgentLike, registry: ChioFunctionRegistry) -> None:
    """Attach ``registry`` to ``agent`` for later lookup by GroupChat."""
    try:
        agent._chio_registry = registry
    except Exception as exc:  # pragma: no cover - pydantic agents
        raise ChioAutogenConfigError(
            f"could not attach Chio registry to agent: {exc}"
        ) from exc


def registry_for(agent: AgentLike) -> ChioFunctionRegistry | None:
    reg = getattr(agent, "_chio_registry", None)
    if isinstance(reg, ChioFunctionRegistry):
        return reg
    return None


def iter_registries(
    agents: Mapping[str, AgentLike] | list[AgentLike] | None,
) -> list[ChioFunctionRegistry]:
    if agents is None:
        return []
    values = agents.values() if isinstance(agents, Mapping) else agents
    out: list[ChioFunctionRegistry] = []
    for a in values:
        reg = registry_for(a)
        if reg is not None:
            out.append(reg)
    return out


__all__ = [
    "ChioClientLike",
    "ChioFunctionRegistry",
    "ToolExecutor",
    "attach_registry",
    "iter_registries",
    "registry_for",
]
