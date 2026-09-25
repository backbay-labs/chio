# chio-crewai

## Execute through your Chio MCP host

Use `ChioBaseTool.from_mcp(session, tool_name="createNote", args_schema=CreateNoteInput, description="Save a note")` to build a native CrewAI tool around an existing application-owned MCP session. Full arguments reach the host that performs admission and execution. Keep the session open across the agent run; `last_mcp_execution` retains its request and receipt association. The binding never invokes an unrelated local executor.

The complete [framework notes application](https://www.chio.computer/docs/examples/agent-framework-sdks) includes input models, host, launcher, role policies and an independent receipt verifier. Its bundled adapters are source candidates; installing an older registry distribution does not add these APIs.

Legacy local-executor and signerless-delegation APIs below have different authority requirements. An ID-only sidecar gate continues to refuse execution, and a sidecar without the parent subject signer cannot manufacture a delegated capability.


CrewAI integration for the [Chio protocol](../../../spec/PROTOCOL.md). Wraps
`crewai.tools.BaseTool` so every tool invocation an agent attempts is
evaluated by the Chio sidecar kernel for capability-scoped authorization,
guard enforcement, and signed receipts.

## Install

```bash
uv pip install chio-crewai
# or
pip install chio-crewai
```

The package depends on `chio-sdk-python`, `crewai>=0.80,<1`, and
`pydantic>=2.5`.

## Quickstart

```python
import asyncio

from chio_crewai import ChioBaseTool, ChioCrew
from chio_sdk.client import ChioClient
from chio_sdk.models import ChioScope, Operation, ToolGrant
from crewai import Agent, Task


def search_grant() -> ToolGrant:
    return ToolGrant(
        server_id="tools-srv",
        tool_name="search",
        operations=[Operation.INVOKE],
    )


def write_grant() -> ToolGrant:
    return ToolGrant(
        server_id="tools-srv",
        tool_name="write",
        operations=[Operation.INVOKE],
    )


search_tool = ChioBaseTool(
    name="search",
    description="Search the web",
    server_id="tools-srv",
    executor=lambda q: {"results": [f"hit for {q!r}"]},
)

write_tool = ChioBaseTool(
    name="write",
    description="Write a file",
    server_id="tools-srv",
    executor=lambda path, content: {"ok": True, "path": path},
)

researcher = Agent(
    role="researcher",
    goal="Find accurate information",
    backstory="A careful researcher.",
    tools=[search_tool, write_tool],
)

writer = Agent(
    role="writer",
    goal="Produce clear prose",
    backstory="A technical writer.",
    tools=[search_tool, write_tool],
)

task = Task(
    description="Research then write.",
    expected_output="A short brief.",
    agent=researcher,
)


async def main() -> None:
    async with ChioClient("http://127.0.0.1:9090") as chio:
        crew = ChioCrew(
            capability_scope={
                "researcher": ChioScope(grants=[search_grant()]),
                "writer": ChioScope(grants=[write_grant()]),
            },
            chio_client=chio,
            agents=[researcher, writer],
            tasks=[task],
        )
        await crew.provision_capabilities()
        result = crew.kickoff()
        print(result)


asyncio.run(main())
```

At runtime:

* The researcher can call `search` but any attempt to call `write` is
  denied by the Chio kernel (even if the LLM hallucinates the call).
* The writer can call `write` but not `search`.
* Delegation between agents mints attenuated child tokens that are a
  strict subset of the delegator's scope.

## Delegation attenuation

```python
child = await crew.attenuate_for_delegation(
    delegator_role="writer",
    delegate_role="editor",
    new_scope=ChioScope(grants=[write_grant()]),
)
```

The child capability is always `child ⊆ parent`; the SDK raises
`ChioValidationError` if you try to broaden scope.

## Error types

* `ChioToolError` -- raised when the Chio kernel denies an invocation.
  Carries `tool_name`, `server_id`, `guard`, `reason`, `receipt_id`.
* `ChioCrewConfigError` -- raised on invalid crew configuration (missing
  scope for a role, empty scope map, delegator without a minted token).

## Reference

See
[`docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md`](../../../docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md)
section 5 for the full integration design (intercept points, scoping
model, delegation attenuation).

## Development

```bash
uv venv --python 3.11
uv pip install -e '.[dev]'
uv pip install -e ../chio-sdk-python

uv run pytest
uv run mypy src/
uv run ruff check src/ tests/
```
