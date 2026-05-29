# chio-sdk-python

Python SDK for the [Chio protocol](../../../spec/PROTOCOL.md). A thin,
async HTTP client to the Chio sidecar kernel, plus the typed models for
capabilities, scopes, verdicts, and receipts that the higher-level
framework integrations (FastAPI, Django, LangChain, and others) build on.

The sidecar runs as a local process exposing a localhost HTTP API. This
package never signs or evaluates anything itself; it forwards requests to
the sidecar and returns typed results.

## Install

```bash
uv pip install chio-sdk-python
# or
pip install chio-sdk-python
```

The package depends only on `httpx` and `pydantic`.

## Quickstart

```python
from chio_sdk import ChioClient


async def main() -> None:
    # Defaults to the local sidecar at http://127.0.0.1:9090.
    async with ChioClient() as client:
        await client.health()

        # Returns a signed receipt on allow; raises ChioError on deny.
        receipt = await client.evaluate_tool_call(
            capability_id="cap-123",
            tool_server="search-srv",
            tool_name="search_documents",
            parameters={"query": "capability-based security"},
        )
        print(receipt.id)
```

Point the client at a non-default sidecar with `ChioClient(base_url=...)`.

## What is in the box

- `ChioClient` -- async client for sidecar health, capability minting and
  validation, attenuation, receipt verification, and tool-call evaluation.
- Typed models -- `CapabilityToken`, `ChioScope`, `ToolGrant`,
  `ResourceGrant`, `PromptGrant`, `Operation`, `Constraint`, `Decision`,
  `Verdict`, `ChioReceipt`, `HttpReceipt`, `CallerIdentity`, and the
  supporting types. See `chio_sdk.models`.
- Errors -- `ChioError` and the `ChioConnectionError`,
  `ChioDeniedError`, `ChioTimeoutError`, `ChioValidationError`
  subclasses. Errors fail closed: a denial or an unreachable sidecar
  raises rather than silently allowing.

## Testing

The SDK ships a drop-in `MockChioClient` via `chio_sdk.testing`, with
`allow_all()`, `deny_all()`, and `with_policy(...)` helpers so you can
exercise capability-checked code paths without a running sidecar:

```python
from chio_sdk.testing import allow_all, deny_all
```

## License

Apache-2.0
