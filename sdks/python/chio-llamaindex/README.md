# chio-llamaindex

## Execute through your Chio MCP host

Use `ChioFunctionTool.from_mcp(binding, fn_schema=CreateNoteInput, description="Save a note")`, where `binding` is `McpToolBinding(session, "createNote")`. This returns a native LlamaIndex FunctionTool with synchronous and asynchronous execution through the application's existing MCP session. `binding.last_execution` retains the terminal request and receipt association.

The complete [framework notes application](https://www.chio.computer/docs/examples/agent-framework-sdks) includes input models, host, launcher, role policies and an independent receipt verifier. Its bundled adapters are source candidates; installing an older registry distribution does not add these APIs.

Legacy local-executor and signerless-delegation APIs below have different authority requirements. An ID-only sidecar gate continues to refuse execution, and a sidecar without the parent subject signer cannot manufacture a delegated capability.


LlamaIndex integration for the [Chio protocol](../../../spec/PROTOCOL.md).
Wraps `llama_index.core.tools.FunctionTool` and
`llama_index.core.tools.QueryEngineTool` so every tool dispatch an
agent performs is evaluated by the Chio sidecar kernel for
capability-scoped authorization, guard enforcement, and signed
receipts.

## Install

```bash
uv pip install chio-llamaindex
# or
pip install chio-llamaindex
```

The package depends on `chio-sdk-python`, `llama-index-core>=0.11,<1`,
and `pydantic>=2.5`.

## Quickstart

```python
import asyncio

from chio_llamaindex import ChioAgentRunner, ChioFunctionTool, ChioQueryEngineTool
from chio_sdk.client import ChioClient
from chio_sdk.models import ChioScope, Constraint, Operation, ToolGrant
from llama_index.core.agent import AgentRunner
from llama_index.core.agent.openai.base import OpenAIAgentWorker
from llama_index.core.llms import MockLLM


def search_grant() -> ToolGrant:
    return ToolGrant(
        server_id="tools-srv",
        tool_name="search_documents",
        operations=[Operation.INVOKE],
    )


def rag_grant() -> ToolGrant:
    return ToolGrant(
        server_id="rag-srv",
        tool_name="query_prod-docs",
        operations=[Operation.INVOKE],
        constraints=[
            Constraint(type="memory_store_allowlist", value="prod-docs"),
        ],
    )


def search_documents(q: str) -> str:
    return f"hit for {q!r}"


search_tool = ChioFunctionTool(
    fn=search_documents,
    name="search_documents",
    description="Search the document index",
    server_id="tools-srv",
)

rag_tool = ChioQueryEngineTool(
    query_engine=my_index.as_query_engine(),  # type: ignore[name-defined]
    collection="prod-docs",
    server_id="rag-srv",
)


async def main() -> None:
    async with ChioClient("http://127.0.0.1:9090") as chio:
        worker = OpenAIAgentWorker.from_tools(
            [search_tool, rag_tool],
            llm=MockLLM(),
        )
        runner = AgentRunner(agent_worker=worker)

        chio_runner = ChioAgentRunner(
            runner=runner,
            capability_scope=ChioScope(grants=[search_grant(), rag_grant()]),
            chio_client=chio,
            agent_name="analyst",
        )
        await chio_runner.provision_capability()

        response = runner.chat("Summarise the Q4 filings.")
        print(response)


asyncio.run(main())
```

At runtime:

* Every `search_documents` call is evaluated by the Chio sidecar; a deny
  verdict raises `ChioToolError` (or returns an error `ToolOutput` if
  you pass `raise_on_deny=False`).
* Every RAG query is first checked against the `collection` allowlist
  in the agent's capability scope, then evaluated by the sidecar.
* Attempting to construct an `ChioQueryEngineTool` bound to a collection
  the capability does not cover is denied client-side before the
  retriever runs.

## Collection scoping

`ChioQueryEngineTool` enforces a two-layer check:

1. **Client-side allowlist.** The tool reads
   `Constraint(type="memory_store_allowlist", ...)` entries off the
   agent's `ChioScope` and only lets the call through if the bound
   `collection` is in the set. When no allowlist is provided, the
   client-side check is a no-op and the sidecar policy is the only
   gate. An explicit `capability_scope=ChioScope()` with no grants is
   fail-closed.
2. **Sidecar policy.** The sidecar receives `collection` and `query`
   in `parameters`, so kernel-level policies can veto based on any
   field (e.g. rate-limit per collection, block after a data-access
   violation).

```python
tool = ChioQueryEngineTool(
    query_engine=engine,
    collection="prod-docs",
    allowed_collections=["prod-docs", "qa-docs"],  # shortcut alternative
    capability_id="cap-analyst",
    server_id="rag-srv",
)
```

## Per-agent capability binding

`ChioAgentRunner` is a thin helper that mints one capability token for
an agent as a whole and binds it to every `ChioFunctionTool` /
`ChioQueryEngineTool` that the runner holds:

```python
chio_runner = ChioAgentRunner(
    runner=runner,
    capability_scope=ChioScope(grants=[search_grant()]),
    chio_client=chio,
    agent_name="analyst",
)
token = await chio_runner.provision_capability()

# Delegate to a narrower child capability for a nested/helper agent.
child = await chio_runner.attenuate(new_scope=ChioScope(grants=[search_grant()]))
```

`attenuate` enforces `child ⊆ parent`; the SDK raises
`ChioValidationError` if you try to broaden scope.

## Error types

* `ChioToolError` -- raised when the Chio kernel, or a client-side
  collection allowlist check, denies an invocation. Carries
  `tool_name`, `server_id`, `guard`, `reason`, `receipt_id`.
* `ChioLlamaIndexConfigError` -- raised on invalid SDK configuration
  (empty collection, missing capability before delegation, etc.).

## Reference

See
[`docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md`](../../../docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md)
section 7 for the full integration design (intercept points,
`QueryEngineTool` data access scoping, agent runner binding).

## Development

```bash
uv venv --python 3.11
uv pip install -e '.[dev]'
uv pip install -e ../chio-sdk-python

uv run pytest
uv run mypy src/
uv run ruff check src/ tests/
```
