# Python SDK Reference

The `chio-sdk` distribution provides Python bindings for Chio hosted MCP
sessions, receipt queries, auth discovery helpers, and invariant verification.

## Installation

```bash
pip install chio-sdk
```

Import the package as `chio`:

```python
from chio import ChioClient, ReceiptQueryClient
```

## Public API

### Error Types

- `ChioError`: base SDK exception
- `ChioTransportError`: network or transport-level failure
- `ChioQueryError`: non-success HTTP response from the receipt query endpoint
- `ChioRpcError`: JSON-RPC error returned by the hosted MCP edge
- `ChioInvariantError`: invariant parsing or verification failure

### ChioClient

```python
from chio import ChioClient

client = ChioClient.with_static_bearer("http://localhost:8931", "token")
session = client.initialize()
```

`ChioClient.initialize()` creates an authenticated Chio MCP HTTP session and
returns an `ChioSession`.

### ChioSession

`ChioSession` exposes convenience helpers over the Streamable HTTP MCP surface:

- `list_tools()`
- `call_tool(name, arguments=None)`
- `list_resources()`
- `read_resource(uri)`
- `list_prompts()`
- `get_prompt(name, arguments=None)`
- `list_tasks()`
- `get_task(task_id)`
- `get_task_result(task_id)`
- `cancel_task(task_id)`
- `close()`

It also exposes `request()`, `request_result()`, `notification()`, and
`send_envelope()` for lower-level control.

### ReceiptQueryClient

`ReceiptQueryClient` wraps `GET /v1/receipts/query` and injects the `Bearer`
token automatically.

```python
from chio import ReceiptQueryClient

client = ReceiptQueryClient("http://localhost:8940", "token")
response = client.query({"toolServer": "wrapped-http-mock", "limit": 5})
```

Supported query parameters:

- `capabilityId`
- `toolServer`
- `toolName`
- `outcome`
- `since`
- `until`
- `minCost`
- `maxCost`
- `costCurrency`
- `agentSubject`
- `cursor`
- `limit`

Python integers preserve the full unsigned 64-bit cost domain. Either cost
bound requires `costCurrency` as a three-letter uppercase string.

Response shape:

```python
{
    "totalCount": 1,
    "nextCursor": 42,
    "receipts": [...],
}
```

Use `paginate()` to iterate automatically across pages:

```python
for page in client.paginate({"toolServer": "wrapped-http-mock"}):
    for receipt in page:
        print(receipt["id"])
```

## Invariants

The `chio.invariants` module exposes canonical JSON, SHA-256 hashing,
Ed25519 signing and verification, receipt verification, capability
verification, and signed-manifest verification helpers.

## Official Example

See [sdks/python/chio-py/examples/governed_hello.py](../../sdks/python/chio-py/examples/governed_hello.py).
