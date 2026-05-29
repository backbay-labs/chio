from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .models import TransportResponse
from .session import ChioSession

NestedBuilder = Callable[[dict[str, Any], ChioSession], dict[str, Any]]
TranscriptHook = Callable[[dict[str, Any]], None]


def rpc_result(message_id: int, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "result": result,
    }


def sampling_text_result(
    message: dict[str, Any],
    *,
    text: str,
    model: str,
    stop_reason: str = "end_turn",
) -> dict[str, Any]:
    return rpc_result(
        message["id"],
        {
            "role": "assistant",
            "content": {"type": "text", "text": text},
            "model": model,
            "stopReason": stop_reason,
        },
    )


def elicitation_accept_result(
    message: dict[str, Any],
    *,
    content: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"action": "accept"}
    if content is not None:
        result["content"] = content
    return rpc_result(message["id"], result)


def roots_list_result(
    message: dict[str, Any],
    *,
    roots: list[dict[str, Any]],
) -> dict[str, Any]:
    return rpc_result(message["id"], {"roots": roots})


@dataclass(slots=True)
class NestedRoute:
    step_suffix: str
    builder: NestedBuilder


class NestedCallbackRouter:
    def __init__(self, *, emit: TranscriptHook | None = None):
        self._emit = emit
        self._routes: dict[str, NestedRoute] = {}

    def register(
        self,
        method: str,
        *,
        step_suffix: str,
        builder: NestedBuilder,
    ) -> "NestedCallbackRouter":
        self._routes[method] = NestedRoute(step_suffix=step_suffix, builder=builder)
        return self

    def handle(
        self,
        message: dict[str, Any],
        session: ChioSession,
        *,
        step_prefix: str = "",
    ) -> TransportResponse | None:
        method = message.get("method")
        if method not in self._routes:
            return None
        route = self._routes[method]
        response = session.send_envelope(route.builder(message, session))
        if self._emit is not None:
            step = route.step_suffix if not step_prefix else f"{step_prefix}/{route.step_suffix}"
            self._emit(
                {
                    "step": step,
                    "request": response.request,
                    "httpStatus": response.status,
                    "messages": response.messages,
                }
            )
        return response
