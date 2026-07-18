"""Small HTTP MCP gateway for the local Chio knowledge base."""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from chio_kb import query

app = FastAPI(title="Chio KB MCP", version="0.1.0")


TOOLS: dict[str, dict[str, Any]] = {
    "kb_manifest": {
        "description": "Return repository identity, index freshness, counts, evaluation, and capabilities.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    "kb_search_code": {
        "description": "Semantic search over indexed Chio code chunks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                "filters": {"type": "object"},
            },
            "required": ["query"],
        },
    },
    "kb_search_docs": {
        "description": "Semantic search over indexed Chio docs, specs, standards, and plans.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                "filters": {"type": "object"},
            },
            "required": ["query"],
        },
    },
    "kb_find_tests": {
        "description": "Find tests related to a path, crate, symbol, or concept.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path_or_symbol": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
            "required": ["path_or_symbol"],
        },
    },
    "kb_find_docs": {
        "description": "Find docs related to a path, crate, symbol, or concept.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path_or_crate": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
            "required": ["path_or_crate"],
        },
    },
    "kb_neighbors": {
        "description": "Return nearby Neo4j knowledge graph entities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity": {"type": "string"},
                "depth": {"type": "integer", "minimum": 1, "maximum": 4},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "required": ["entity"],
        },
    },
    "kb_subgraph": {
        "description": "Return a bounded subgraph with stable node IDs and reconstructable typed edges.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity": {"type": "string"},
                "depth": {"type": "integer", "minimum": 1, "maximum": 4},
                "node_limit": {"type": "integer", "minimum": 1, "maximum": 200},
                "edge_limit": {"type": "integer", "minimum": 1, "maximum": 400},
            },
            "required": ["entity"],
        },
    },
    "kb_context": {
        "description": "Return a 360-degree incoming and outgoing graph view for one entity or symbol.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "required": ["entity"],
        },
    },
    "kb_impact": {
        "description": "Estimate related components, tests, and docs for a path or crate.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path_or_crate": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "required": ["path_or_crate"],
        },
    },
    "kb_brief_feature": {
        "description": "Build an agent editing brief with code, docs, tests, graph impact, memory, and validation commands.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "feature_or_task": {"type": "string"},
                "focus_paths": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                "include_memory": {"type": "boolean"},
                "intent": {
                    "type": "string",
                    "enum": [
                        "auto",
                        "capability",
                        "revocation",
                        "receipt",
                        "guard-policy",
                        "mcp-adapter",
                        "sdk-conformance",
                        "release-qualification",
                        "compliance-certificate",
                        "mercury-product",
                        "planning-history",
                        "generic",
                    ],
                },
            },
            "required": ["feature_or_task"],
        },
    },
    "kb_eval": {
        "description": "Run fixed dogfood retrieval fixtures and return grade, metrics, and misses.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string"},
                "format": {"type": "string", "enum": ["json", "markdown"]},
                "suite": {"type": "string", "enum": ["core", "deep", "all"]},
            },
        },
    },
    "kb_add_episode": {
        "description": "Add a high-value temporal memory episode to Graphiti.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "body": {"type": "string"},
                "source_description": {"type": "string"},
            },
            "required": ["name", "body"],
        },
    },
}


def _rpc_result(request_id: Any, result: Any) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": result})


def _rpc_error(
    request_id: Any,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return JSONResponse(
        {"jsonrpc": "2.0", "id": request_id, "error": error},
        status_code=200,
    )


def _notification_accepted() -> Response:
    return Response(status_code=202)


def _rpc_result_or_notification(is_notification: bool, request_id: Any, result: Any) -> Response:
    if is_notification:
        return _notification_accepted()
    return _rpc_result(request_id, result)


def _rpc_error_or_notification(
    is_notification: bool,
    request_id: Any,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> Response:
    if is_notification:
        return _notification_accepted()
    return _rpc_error(request_id, code, message, data)


def _client_is_loopback(request: Request) -> bool:
    if request.client is None:
        return False
    try:
        return ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        return request.client.host == "localhost"


def _has_bearer_token(request: Request) -> bool:
    expected = os.environ.get("CHIO_KB_MCP_BEARER_TOKEN")
    if not expected:
        return False
    scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
    return scheme.lower() == "bearer" and hmac.compare_digest(supplied, expected)


def _write_tool_authorized(request: Request) -> bool:
    return _client_is_loopback(request) or _has_bearer_token(request)


def _tool_list() -> list[dict[str, Any]]:
    return [{"name": name, **metadata} for name, metadata in sorted(TOOLS.items())]


async def _call_tool(name: str, arguments: dict[str, Any]) -> Any:
    if name == "kb_manifest":
        return await query.manifest()
    if name == "kb_search_code":
        return await query.search_code(
            arguments["query"],
            limit=arguments.get("limit", 8),
            filters=arguments.get("filters"),
        )
    if name == "kb_search_docs":
        return await query.search_docs(
            arguments["query"],
            limit=arguments.get("limit", 8),
            filters=arguments.get("filters"),
        )
    if name == "kb_find_tests":
        return await query.find_tests(arguments["path_or_symbol"], limit=arguments.get("limit", 12))
    if name == "kb_find_docs":
        return await query.find_docs(arguments["path_or_crate"], limit=arguments.get("limit", 12))
    if name == "kb_neighbors":
        return await query.neighbors(
            arguments["entity"],
            depth=arguments.get("depth", 2),
            limit=arguments.get("limit", 50),
        )
    if name == "kb_subgraph":
        return await query.subgraph(
            arguments["entity"],
            depth=arguments.get("depth", 2),
            node_limit=arguments.get("node_limit", 80),
            edge_limit=arguments.get("edge_limit", 160),
        )
    if name == "kb_context":
        return await query.context(arguments["entity"], limit=arguments.get("limit", 50))
    if name == "kb_impact":
        return await query.impact(arguments["path_or_crate"], limit=arguments.get("limit", 50))
    if name == "kb_brief_feature":
        return await query.brief_feature(
            arguments["feature_or_task"],
            focus_paths=arguments.get("focus_paths"),
            limit=arguments.get("limit", 8),
            include_memory=arguments.get("include_memory", True),
            intent=arguments.get("intent", "auto"),
        )
    if name == "kb_eval":
        return await query.eval_knowledge_base(
            category=arguments.get("category"),
            output_format=arguments.get("format", "json"),
            suite=arguments.get("suite", "all"),
        )
    if name == "kb_add_episode":
        return await query.add_episode(
            arguments["name"],
            arguments["body"],
            source_description=arguments.get("source_description", "Chio KB user episode"),
        )
    raise KeyError(name)


@app.get("/health")
async def health() -> dict[str, Any]:
    return await query.health()


@app.get("/tools")
async def tools() -> dict[str, Any]:
    return {"tools": _tool_list()}


@app.post("/mcp/")
@app.post("/mcp")
async def mcp(request: Request) -> Response:
    try:
        payload = await request.json()
    except Exception:
        return _rpc_error(None, -32700, "Invalid JSON")

    if not isinstance(payload, dict):
        return _rpc_error(None, -32600, "Invalid Request")

    is_notification = "id" not in payload
    request_id = payload.get("id")
    method = payload.get("method")
    raw_params = payload.get("params", {})
    if raw_params is None:
        params: dict[str, Any] = {}
    elif isinstance(raw_params, dict):
        params = raw_params
    else:
        return _rpc_error_or_notification(is_notification, request_id, -32602, "Invalid params")

    try:
        if method == "initialize":
            return _rpc_result_or_notification(
                is_notification,
                request_id,
                {
                    "protocolVersion": "2025-03-26",
                    "serverInfo": {"name": "chio-kb-mcp", "version": "0.1.0"},
                    "capabilities": {"tools": {}},
                },
            )
        if method == "notifications/initialized":
            return _notification_accepted()
        if method == "ping":
            return _rpc_result_or_notification(is_notification, request_id, {})
        if method == "tools/list":
            return _rpc_result_or_notification(is_notification, request_id, {"tools": _tool_list()})
        if method == "tools/call":
            name = params.get("name")
            raw_arguments = params.get("arguments", {})
            if raw_arguments is None:
                arguments: dict[str, Any] = {}
            elif isinstance(raw_arguments, dict):
                arguments = raw_arguments
            else:
                return _rpc_error_or_notification(is_notification, request_id, -32602, "Invalid tool arguments")
            if name not in TOOLS:
                return _rpc_error_or_notification(is_notification, request_id, -32602, f"Unknown tool: {name}")
            if name == "kb_add_episode" and not _write_tool_authorized(request):
                return _rpc_error_or_notification(
                    is_notification,
                    request_id,
                    -32001,
                    "kb_add_episode requires loopback access or a bearer token",
                )
            result = await _call_tool(name, arguments)
            return _rpc_result_or_notification(
                is_notification,
                request_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": result if isinstance(result, str) else json.dumps(result, indent=2),
                        }
                    ]
                },
            )
    except KeyError as exc:
        return _rpc_error_or_notification(is_notification, request_id, -32602, f"Missing required argument: {exc}")
    except TimeoutError as exc:
        return _rpc_error_or_notification(
            is_notification, request_id, -32002, str(exc), {"kind": "timeout"}
        )
    except (ConnectionError, OSError) as exc:
        return _rpc_error_or_notification(
            is_notification, request_id, -32003, str(exc), {"kind": "unavailable"}
        )
    except Exception as exc:
        return _rpc_error_or_notification(
            is_notification, request_id, -32000, str(exc), {"kind": "internal"}
        )

    return _rpc_error_or_notification(is_notification, request_id, -32601, f"Unknown method: {method}")


@app.on_event("shutdown")
async def shutdown() -> None:
    await query.close()


def main() -> None:
    uvicorn.run(
        "chio_kb.mcp_server:app",
        host=os.environ.get("CHIO_KB_MCP_HOST", "127.0.0.1"),
        port=int(os.environ.get("CHIO_KB_MCP_PORT", "8111")),
    )


if __name__ == "__main__":
    main()
