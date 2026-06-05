# chio-langchain

LangChain integration for the [Chio protocol](../../../spec/PROTOCOL.md).
Wraps Chio-governed tools as LangChain `Tool` objects so each call can be
sent to the Chio sidecar for advisory evaluation. The current tool-call
sidecar route returns signed advisory receipts for audit; those receipts are
not execution authorization.

## Install

```bash
uv pip install chio-langchain
# or
pip install chio-langchain
```

The package depends on `chio-sdk-python`, `chio-adapter-base`, and
`langchain-core`.

## Quickstart

Discover the tools associated with a capability and hand them to an agent:

```python
from chio_langchain import ChioToolkit


async def build_tools() -> list:
    toolkit = ChioToolkit(
        capability_id="cap-123",
        sidecar_url="http://127.0.0.1:9090",
    )
    # Fetch tool definitions from the sidecar and wrap them.
    return await toolkit.get_tools(server_id="search-srv")
```

Or construct a single tool when you already know its definition:

```python
tool = toolkit.create_tool(
    name="search_documents",
    description="Search the corpus",
    server_id="search-srv",
)
```

## What is in the box

- `ChioToolkit` -- builds LangChain tools from Chio tool-server manifests.
  Use `get_tools(...)` to discover tools from the sidecar, or
  `create_tool(...)` to declare one explicitly.
- `ChioTool` -- a LangChain `BaseTool` whose invocation is evaluated through
  the sidecar for advisory audit and bound to a capability id.

## Behaviour

Tool calls fail closed for authorization: advisory evaluation never becomes a
successful execution authorization. `ChioTool` returns JSON error strings for
advisory denial, sidecar errors, and non-authorizing advisory observations
(for example `{"error": "non_authorizing", ...}`). Sensitive arguments are
redacted according to the toolkit's redaction policy (the Chio default unless
you override it).

## License

Apache-2.0
