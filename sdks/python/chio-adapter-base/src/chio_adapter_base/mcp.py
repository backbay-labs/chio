"""Execute framework tools through an application-owned Chio MCP session.

The remote host owns admission and execution. No local callable is authorized by
this module. Receipt associations identify records to retrieve and verify; they
are not signatures or independent proof that the remote peer is a Chio host.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any, cast


@dataclass(frozen=True)
class McpExecution:
    """One terminal tool result and its host-supplied receipt association."""

    tool_name: str
    receipt_id: str
    request_id: str
    is_error: bool
    content: tuple[dict[str, Any], ...]
    structured_content: Any = None

    @property
    def text(self) -> str:
        return "\n".join(
            item["text"]
            for item in self.content
            if item.get("type") == "text" and isinstance(item.get("text"), str)
        )


class McpToolError(RuntimeError):
    """A completed MCP call returned isError, with its receipt association.

    This may describe admission refusal or execution failure. Inspect the signed
    receipt to distinguish them. The wrapper does not retry either outcome.
    """

    def __init__(self, execution: McpExecution) -> None:
        self.execution = execution
        self.receipt_id = execution.receipt_id
        self.request_id = execution.request_id
        super().__init__(execution.text or "The Chio MCP host returned a tool error")


class McpOutcomeUnknown(RuntimeError):
    """Transport or result validation failed; an effect may already have occurred."""


class McpToolBinding:
    """Bind one named tool to an existing session, without owning its lifetime.

    Accepts the official MCP ClientSession.call_tool method or a synchronous
    application's call(name, arguments) method. Share a session for a run's
    allowance; use separately authorized sessions for distinct responsibilities.
    Full arguments go to the executing host. Redaction belongs at that host's
    evidence boundary, not in arguments used to execute the operation.
    """

    def __init__(self, session: Any, tool_name: str) -> None:
        if not tool_name or not isinstance(tool_name, str):
            raise ValueError("tool_name must be a non-empty string")
        method = getattr(session, "call_tool", None) or getattr(session, "call", None)
        if not callable(method):
            raise TypeError(
                "session must provide call_tool(name, arguments) or call(name, arguments)"
            )
        self._call = method
        self.tool_name = tool_name
        self.last_execution: McpExecution | None = None

    def _result(self, value: Any) -> McpExecution:
        if hasattr(value, "model_dump"):
            value = value.model_dump(by_alias=True, exclude_none=True)
        if not isinstance(value, dict):
            raise McpOutcomeUnknown(
                "MCP returned an invalid result; inspect the host before retrying"
            )
        meta = value.get("_meta", {})
        association = meta.get("chioReceipt", {}) if isinstance(meta, dict) else {}
        ids = (
            [association.get(key) for key in ("receiptId", "requestId")]
            if isinstance(association, dict)
            else []
        )
        if len(ids) != 2 or any(
            not isinstance(item, str) or not item or len(item) > 512 for item in ids
        ):
            raise McpOutcomeUnknown(
                "MCP result has no valid Chio receipt association; inspect the host before retrying"
            )
        content = value.get("content", [])
        if not isinstance(content, list) or any(not isinstance(item, dict) for item in content):
            raise McpOutcomeUnknown(
                "MCP returned invalid content; inspect the host before retrying"
            )
        if not isinstance(value.get("isError", False), bool):
            raise McpOutcomeUnknown(
                "MCP returned an invalid error flag; inspect the host before retrying"
            )
        execution = McpExecution(
            self.tool_name,
            cast(str, ids[0]),
            cast(str, ids[1]),
            value.get("isError", False),
            tuple(content),
            value.get("structuredContent"),
        )
        self.last_execution = execution
        if execution.is_error:
            raise McpToolError(execution)
        return execution

    async def aexecute(self, arguments: dict[str, Any]) -> McpExecution:
        self.last_execution = None
        try:
            if inspect.iscoroutinefunction(self._call):
                result = await self._call(self.tool_name, arguments)
            else:
                result = await asyncio.to_thread(self._call, self.tool_name, arguments)
                if inspect.isawaitable(result):
                    result = await result
        except asyncio.CancelledError:
            # Cancellation says nothing about whether a remote effect completed.
            # Preserve the caller's cancellation; never silently repeat the call.
            raise
        except Exception as error:
            raise McpOutcomeUnknown("MCP call failed; inspect the host before retrying") from error
        return self._result(result)

    def execute(self, arguments: dict[str, Any]) -> McpExecution:
        self.last_execution = None
        if inspect.iscoroutinefunction(self._call):
            raise TypeError(
                "Use aexecute with an asynchronous MCP session on its owning event loop"
            )
        try:
            result = self._call(self.tool_name, arguments)
        except Exception as error:
            raise McpOutcomeUnknown("MCP call failed; inspect the host before retrying") from error
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            raise McpOutcomeUnknown(
                "Use aexecute with this session; inspect the host before retrying"
            )
        return self._result(result)

    def function(
        self,
        schema: Any,
        *,
        name: str | None = None,
        description: str = "",
        asynchronous: bool = False,
    ) -> Callable[..., str | Coroutine[Any, Any, str]]:
        """Produce a schema-bearing callable for a framework's native tool API.

        schema is a Pydantic model class. Validation occurs before dispatch.
        Inspect last_execution for the exact result's receipt association.
        """

        def arguments(kwargs: dict[str, Any]) -> dict[str, Any]:
            return cast(dict[str, Any], schema.model_validate(kwargs).model_dump(mode="json", by_alias=True))

        def invoke(**kwargs: Any) -> str:
            return self.execute(arguments(kwargs)).text

        async def ainvoke(**kwargs: Any) -> str:
            return (await self.aexecute(arguments(kwargs))).text

        fn = ainvoke if asynchronous else invoke
        fn.__name__ = name or self.tool_name
        fn.__doc__ = description
        parameters = []
        for field_name, field in schema.model_fields.items():
            if field.default_factory is not None:
                raise ValueError("Use explicit defaults in framework tool schemas")
            default = inspect.Parameter.empty if field.is_required() else field.default
            parameters.append(
                inspect.Parameter(
                    field_name,
                    inspect.Parameter.KEYWORD_ONLY,
                    default=default,
                    annotation=field.annotation,
                )
            )
        setattr(fn, "__signature__", inspect.Signature(parameters, return_annotation=str))  # noqa: B010
        fn.__annotations__ = {
            field_name: field.annotation for field_name, field in schema.model_fields.items()
        }
        fn.__annotations__["return"] = str
        return fn
