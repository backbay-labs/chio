# chio-fastapi

FastAPI integration for the [Chio protocol](../../../spec/PROTOCOL.md).
Route decorators and dependency-injection helpers that enforce Chio
capability requirements on your endpoints and evaluate each request
through the Chio sidecar kernel.

## Install

```bash
uv pip install chio-fastapi
# or
pip install chio-fastapi
```

The package depends on `chio-sdk-python`, `chio-asgi`, and `fastapi`.

## Quickstart

```python
from fastapi import FastAPI, Request
from chio_fastapi import chio_requires

app = FastAPI()


@app.post("/search")
@chio_requires(server_id="search-srv", tool_name="search_documents")
async def search(request: Request, query: str) -> dict:
    return {"results": run_search(query)}
```

The request must carry a valid Chio capability token (via the
`X-Chio-Capability` header or the `chio_capability` query parameter) that
grants the required `server_id` / `tool_name` / operations. Requests
without a capability receive a `401`; denied requests receive a typed
error response.

## What is in the box

- Decorators -- `chio_requires` (capability enforcement on a route),
  `chio_approval` (human-in-the-loop approval gating), and `chio_budget`
  (monetary or quota budget enforcement).
- Dependencies -- `get_chio_client`, `get_chio_passthrough`,
  `get_chio_receipt`, and `get_caller_identity` for use with FastAPI's
  `Depends(...)`.
- Errors -- `ChioErrorCode` and `chio_error_response` for consistent,
  typed denial responses.

## Behaviour

Enforcement fails closed: a missing capability, a deny verdict, or an
unreachable sidecar results in a denial response rather than letting the
request through.

## License

Apache-2.0
