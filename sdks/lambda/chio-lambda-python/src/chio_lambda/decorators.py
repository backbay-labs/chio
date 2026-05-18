"""Handler-level decorator that evaluates via the Chio Lambda Extension.

The :func:`chio_tool` decorator wraps a Lambda handler (or any Python callable)
so that every invocation first asks the extension at
``http://127.0.0.1:9090/v1/evaluate`` whether the call is allowed. If the
extension denies it, or is unreachable, the wrapped function is NOT called
and an :class:`ChioLambdaError` is raised -- this is the fail-closed contract.

Capability identifiers and request arguments are resolved at call time:

* ``capability_id`` can be supplied explicitly on each call, taken from the
  environment variable named by ``capability_env`` (default
  ``CHIO_CAPABILITY_ID``), or picked out of the event payload at
  ``capability_event_key``.
* ``arguments_extractor`` lets callers shape what the extension sees. By
  default the whole event dict is forwarded.

The decorator injects the resolved ``capability_id`` and ``verdict`` kwargs
into the wrapped function if it declares them in its signature.
"""

from __future__ import annotations

import functools
import inspect
import os
from collections.abc import Callable
from typing import Any, TypeVar, cast

from chio_lambda.client import ChioLambdaClient, ChioLambdaError, EvaluateVerdict

F = TypeVar("F", bound=Callable[..., Any])

DEFAULT_CAPABILITY_ENV = "CHIO_CAPABILITY_ID"
DEFAULT_CAPABILITY_EVENT_KEY = "chio_capability_id"


def chio_tool(
    *,
    scope: str,
    tool_server: str,
    tool_name: str,
    client: ChioLambdaClient | None = None,
    capability_env: str = DEFAULT_CAPABILITY_ENV,
    capability_event_key: str = DEFAULT_CAPABILITY_EVENT_KEY,
    arguments_extractor: Callable[[Any], dict[str, Any] | None] | None = None,
) -> Callable[[F], F]:
    """Wrap a Lambda handler with Chio capability evaluation.

    Parameters
    ----------
    scope:
        Capability scope name passed to the extension (e.g. ``"db:read"``).
    tool_server:
        Tool server identifier recorded on the receipt.
    tool_name:
        Tool name recorded on the receipt.
    client:
        Optional custom :class:`ChioLambdaClient`. The default is lazily
        constructed on first use and reused for the lifetime of the
        Lambda execution environment (warm-starts share it).
    capability_env:
        Name of the environment variable used as the fallback source for
        ``capability_id``.
    capability_event_key:
        Key in the Lambda ``event`` dict that carries the capability id if
        not passed explicitly.
    arguments_extractor:
        Function that receives the event and returns the dict to forward to
        the extension as ``arguments``. Default: the whole event if it is a
        mapping, else ``None``.

    Returns
    -------
    Callable
        Decorator. The wrapped function is only executed when the extension
        returns an authoritative allow result.
    """
    shared_client_slot: list[ChioLambdaClient] = [client] if client is not None else []

    def get_client() -> ChioLambdaClient:
        if not shared_client_slot:
            shared_client_slot.append(ChioLambdaClient())
        return shared_client_slot[0]

    def extract_arguments(event: Any) -> dict[str, Any] | None:
        if arguments_extractor is not None:
            return arguments_extractor(event)
        if isinstance(event, dict):
            return cast(dict[str, Any], event)
        return None

    def decorator(fn: F) -> F:
        signature = inspect.signature(fn)
        accepts_capability_id = "capability_id" in signature.parameters
        accepts_verdict = "verdict" in signature.parameters

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            event: Any = args[0] if args else kwargs.get("event")
            capability_id = _resolve_capability_id(
                kwargs.pop("capability_id", None),
                event,
                capability_env,
                capability_event_key,
            )
            if not capability_id:
                raise ChioLambdaError(
                    "capability_id is required: pass explicitly, set "
                    f"${capability_env}, or include it at "
                    f"event['{capability_event_key}']"
                )

            verdict = get_client().evaluate(
                capability_id=capability_id,
                tool_server=tool_server,
                tool_name=tool_name,
                scope=scope,
                arguments=extract_arguments(event),
            )
            if verdict.denied:
                raise ChioLambdaError(
                    f"capability denied by Chio: {verdict.reason or 'no reason provided'}"
                )

            if accepts_capability_id:
                kwargs["capability_id"] = capability_id
            if accepts_verdict:
                kwargs["verdict"] = verdict
            return fn(*args, **kwargs)

        return cast(F, wrapper)

    return decorator


def _resolve_capability_id(
    explicit: str | None,
    event: Any,
    capability_env: str,
    capability_event_key: str,
) -> str | None:
    if explicit:
        return explicit
    if isinstance(event, dict):
        candidate = event.get(capability_event_key)
        if isinstance(candidate, str) and candidate:
            return candidate
    env_value = os.environ.get(capability_env)
    if env_value:
        return env_value
    return None


__all__ = ["EvaluateVerdict", "chio_tool"]
