"""Wrap Chio tools as LangChain Tool objects.

Each Chio tool server advertises tools via a manifest. This module wraps those
tools as LangChain ``BaseTool`` instances so they can be used in LangChain
agents, chains, and pipelines. All tool invocations flow through the Chio
sidecar kernel for capability validation, guard evaluation, and receipt signing.

Usage::

    from chio_langchain import ChioToolkit

    toolkit = ChioToolkit(
        capability_id="cap-123",
        sidecar_url="http://127.0.0.1:9090",
    )
    tools = await toolkit.get_tools()
    # tools is a list of LangChain Tool objects
"""

from __future__ import annotations

import json
from typing import Any

from chio_adapter_base.redact import RedactionPolicy, redact_args
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioDeniedError, ChioError
from chio_sdk.models import ChioReceipt
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field, create_model


class ChioTool(BaseTool):
    """A LangChain tool backed by a Chio tool server.

    Invocations are evaluated by the Chio sidecar kernel which validates
    capabilities, runs guards, and signs receipts.
    """

    name: str = ""
    description: str = ""
    server_id: str = ""
    capability_id: str = ""
    sidecar_url: str = "http://127.0.0.1:9090"

    # Store the input schema JSON from the manifest
    input_schema_def: dict[str, Any] = Field(default_factory=dict)

    # Per-tool argument redaction policy. Applied right before parameters
    # are forwarded to the sidecar so secret-bearing fields (e.g. the
    # ``content`` of ``chio_file_write``) never land in the receipt log.
    # Defaults to :meth:`RedactionPolicy.chio_default`; pass a custom
    # ``RedactionPolicy`` at construction time to extend with adapter or
    # workspace-specific tool names.
    redaction_policy: RedactionPolicy = Field(
        default_factory=RedactionPolicy.chio_default, exclude=True
    )

    # Last receipt from a tool invocation (for audit trail access)
    last_receipt: ChioReceipt | None = Field(default=None, exclude=True)

    model_config = {"arbitrary_types_allowed": True}

    def model_post_init(self, __context: Any) -> None:
        """Generate args_schema from input_schema_def after construction."""
        super().model_post_init(__context)
        schema = _build_args_schema(self.name, self.input_schema_def)
        if schema is not None:
            self.args_schema = schema  # type: ignore[assignment]

    def get_input_schema(self) -> type[BaseModel] | None:
        """Return the dynamically generated input schema, if any."""
        return _build_args_schema(self.name, self.input_schema_def)

    def _run(self, **kwargs: Any) -> str:
        """Synchronous invocation -- raises because Chio requires async."""
        raise NotImplementedError(
            "Chio tools require async invocation. Use _arun or ainvoke."
        )

    async def _arun(self, **kwargs: Any) -> str:
        """Invoke the Chio tool through the sidecar kernel.

        Returns the tool result as a JSON string. The signed receipt is
        stored in ``self.last_receipt``.
        """
        # Redact body fields (e.g. chio_file_write.content) before they
        # cross into the sidecar so the receipt log never carries the raw
        # secret bytes. Path / message fields pass through unchanged.
        recorded_args = redact_args(
            self.name, kwargs, policy=self.redaction_policy
        )
        async with ChioClient(self.sidecar_url) as client:
            try:
                receipt = await client.evaluate_tool_call(
                    capability_id=self.capability_id,
                    tool_server=self.server_id,
                    tool_name=self.name,
                    parameters=recorded_args,
                )
            except ChioDeniedError as exc:
                return json.dumps({
                    "error": "denied",
                    "guard": exc.guard,
                    "reason": exc.reason or str(exc),
                })
            except ChioError as exc:
                return json.dumps({
                    "error": "chio_error",
                    "message": str(exc),
                })

        self.last_receipt = receipt

        if not receipt.is_allowed:
            decision = receipt.decision
            return json.dumps({
                "error": "denied" if receipt.is_denied else "non_authorizing",
                "guard": decision.guard if decision is not None else None,
                "reason": decision.reason
                if decision is not None and decision.reason is not None
                else "non-authorizing Chio receipt",
            })

        return json.dumps({
            "status": "allowed",
            "receipt_id": receipt.id,
            "tool_server": receipt.tool_server,
            "tool_name": receipt.tool_name,
        })


class ChioToolkit:
    """Creates LangChain tools from Chio tool server manifests.

    Parameters
    ----------
    capability_id:
        Chio capability token ID that authorizes tool invocations.
    sidecar_url:
        Base URL of the Chio sidecar (default ``http://127.0.0.1:9090``).
    """

    def __init__(
        self,
        capability_id: str,
        sidecar_url: str = "http://127.0.0.1:9090",
        *,
        redaction_policy: RedactionPolicy | None = None,
    ) -> None:
        self._capability_id = capability_id
        self._sidecar_url = sidecar_url
        self._redaction_policy = (
            redaction_policy
            if redaction_policy is not None
            else RedactionPolicy.chio_default()
        )

    async def get_tools(
        self,
        server_id: str | None = None,
    ) -> list[ChioTool]:
        """Fetch available tools from the sidecar and wrap them as LangChain tools.

        Parameters
        ----------
        server_id:
            If provided, only return tools from this server. Otherwise
            return tools from all servers.
        """
        async with ChioClient(self._sidecar_url) as client:
            data = await client.health()
            servers = data.get("servers", [])

        tools: list[ChioTool] = []
        for server in servers:
            sid = server.get("server_id", "")
            if server_id is not None and sid != server_id:
                continue
            for tool_def in server.get("tools", []):
                tool = ChioTool(
                    name=tool_def.get("name", ""),
                    description=tool_def.get("description", ""),
                    server_id=sid,
                    capability_id=self._capability_id,
                    sidecar_url=self._sidecar_url,
                    input_schema_def=tool_def.get("input_schema", {}),
                    redaction_policy=self._redaction_policy,
                )
                tools.append(tool)

        return tools

    def create_tool(
        self,
        *,
        name: str,
        description: str,
        server_id: str,
        input_schema: dict[str, Any] | None = None,
    ) -> ChioTool:
        """Manually create a single Chio-backed LangChain tool.

        Use this when you know the tool definition ahead of time and do not
        need to discover it from the sidecar.
        """
        return ChioTool(
            name=name,
            description=description,
            server_id=server_id,
            capability_id=self._capability_id,
            sidecar_url=self._sidecar_url,
            input_schema_def=input_schema or {},
            redaction_policy=self._redaction_policy,
        )


def _build_args_schema(
    tool_name: str, input_schema_def: dict[str, Any]
) -> type[BaseModel] | None:
    """Build a Pydantic model from a JSON Schema definition."""
    if not input_schema_def:
        return None

    properties = input_schema_def.get("properties", {})
    required = set(input_schema_def.get("required", []))

    fields: dict[str, Any] = {}
    for prop_name, prop_def in properties.items():
        field_type = _json_type_to_python(prop_def.get("type", "string"))
        description = prop_def.get("description", "")
        if prop_name in required:
            fields[prop_name] = (field_type, Field(description=description))
        else:
            fields[prop_name] = (
                field_type | None,
                Field(default=None, description=description),
            )

    if not fields:
        return None

    return create_model(f"{tool_name}Input", **fields)  # type: ignore[call-overload]


def _json_type_to_python(json_type: str) -> type:
    """Map a JSON Schema type to a Python type."""
    mapping: dict[str, type] = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    return mapping.get(json_type, str)
