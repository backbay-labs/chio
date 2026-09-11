# chio-autogen

## Execute through your Chio MCP host

Use `ChioFunctionRegistry.register_mcp(binding, schema=CreateNoteInput, description="Save a note")`, where `binding` is `McpToolBinding(session, "createNote")`, to register the operation with classic AutoGen's function map. The application's existing MCP session owns remote admission and execution; `binding.last_execution` retains the terminal request and receipt association. For modern AgentChat use `chio_adapter_base.agentchat.mcp_tool`.

The complete [framework notes application](https://www.chio.computer/docs/examples/agent-framework-sdks) includes input models, host, launcher, role policies and an independent receipt verifier. Its bundled adapters are source candidates; installing an older registry distribution does not add these APIs.

Legacy local-executor and signerless-delegation APIs below have different authority requirements. An ID-only sidecar gate continues to refuse execution, and a sidecar without the parent subject signer cannot manufacture a delegated capability.


AutoGen integration for the [Chio protocol](../../../spec/PROTOCOL.md). Wraps
AutoGen's `register_function` / `function_map` and `GroupChat` so every
registered function an agent attempts to call is evaluated by the Chio
sidecar kernel for capability-scoped authorization, guard enforcement,
and signed receipts.

## Install

```bash
uv pip install chio-autogen
# or
pip install chio-autogen
```

The package depends on `chio-sdk-python`, `pyautogen>=0.2,<0.3`, and
`pydantic>=2.5`. We pin the classic `pyautogen` 0.2.x line because it
exposes the stable `ConversableAgent` / `GroupChat` /
`register_function` surface targeted by this integration. The newer
`autogen-agentchat` 0.4+ redesign pivots to an async actor model that
does not surface a drop-in `GroupChat`; adapting to it is tracked as
future work.

## Quickstart

```python
import asyncio

from autogen import ConversableAgent
from chio_autogen import (
    ChioFunctionRegistry,
    ChioGroupChat,
    ChioGroupChatManager,
    attach_registry,
)
from chio_sdk.client import ChioClient
from chio_sdk.models import ChioScope, Operation, ToolGrant


def grant(name: str) -> ToolGrant:
    return ToolGrant(
        server_id="tools-srv",
        tool_name=name,
        operations=[Operation.INVOKE],
    )


researcher = ConversableAgent(name="researcher", llm_config=False)
writer = ConversableAgent(name="writer", llm_config=False)


async def main() -> None:
    async with ChioClient("http://127.0.0.1:9090") as chio:
        # Register Chio-governed functions on each agent.
        r_registry = ChioFunctionRegistry(
            agent=researcher, chio_client=chio, server_id="tools-srv"
        )

        @r_registry.as_decorator()
        def search(query: str) -> str:
            """Search the web."""
            return f"hits for {query!r}"

        attach_registry(researcher, r_registry)

        w_registry = ChioFunctionRegistry(
            agent=writer, chio_client=chio, server_id="tools-srv"
        )

        @w_registry.as_decorator()
        def write(path: str, content: str) -> str:
            """Write a file."""
            return f"wrote {path}"

        attach_registry(writer, w_registry)

        # Build the capability-scoped GroupChat.
        groupchat = ChioGroupChat(
            capability_scope={
                "researcher": ChioScope(grants=[grant("search")]),
                "writer": ChioScope(grants=[grant("write")]),
            },
            agents=[researcher, writer],
            messages=[],
            max_round=6,
        )
        manager = ChioGroupChatManager(
            groupchat=groupchat,
            chio_client=chio,
            llm_config=False,
        )
        await manager.provision_capabilities()

        # The researcher can call `search`, but any attempt to call
        # `write` is denied by the Chio kernel -- even if the LLM
        # hallucinates the call. The writer can call `write` but not
        # `search`.


asyncio.run(main())
```

## Nested chat attenuation

AutoGen supports nested chats where an agent spawns a sub-conversation.
Each nesting level narrows authority via
`register_nested_chats_with_attenuation`:

```python
from chio_autogen import register_nested_chats_with_attenuation

child_token = await register_nested_chats_with_attenuation(
    parent_agent=researcher,
    child_configs=[
        {"recipient": editor, "message": "handoff", "max_turns": 2},
    ],
    parent_capability=manager.token_for("researcher"),
    child_scope=ChioScope(grants=[grant("search")]),  # strict subset
    chio_client=chio,
)
```

The child capability is always `child ⊆ parent`; the SDK raises
`ChioValidationError` if you try to broaden scope.

## Error types

* `ChioToolError` -- raised when the Chio kernel denies an invocation.
  Carries `tool_name`, `server_id`, `guard`, `reason`, `receipt_id`.
* `ChioAutogenConfigError` -- raised on invalid configuration (missing
  scope for a role, empty scope map, delegator without a minted token).

## Reference

See
[`docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md`](../../../docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md)
section 6 for the full integration design (intercept points, scoping
model, nested delegation).

## Development

```bash
uv venv --python 3.11
uv pip install -e '.[dev]'
uv pip install -e ../chio-sdk-python

uv run pytest
uv run mypy src/
uv run ruff check src/ tests/
```
