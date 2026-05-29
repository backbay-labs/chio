# Agent Framework Integration: Universal Tool Execution Wrapping

> **Status**: Tier 1 -- proposed April 2026
> **Priority**: Critical -- multi-agent frameworks are the primary deployment
> surface for LLM tool use. Every framework listed here trusts tools by
> default. Chio adds capability-scoped, attested, auditable tool execution
> to all of them through a single integration pattern.

## 1. The Problem

Every major agent framework follows the same implicit-trust model:

1. An agent has a list of tools.
2. The LLM decides which tool to call.
3. The framework calls the tool.
4. Nobody verifies whether the agent was authorized to call that tool,
   with those parameters, at that cost, at this time.

Chio fixes this by inserting a capability check (evaluate) before execution
and a signed receipt (record) after. The integration pattern is the same
across all frameworks: **wrap the tool execution entry point**.

## 2. Universal Integration Pattern

Every framework has a single function where tool execution actually
happens. Chio wraps that function:

```
Framework dispatches tool call
        |
        v
  +-- Chio evaluate() --+
  |   capability check  |
  |   guard pipeline    |
  |   budget check      |
  +----+-------+--------+
       |       |
    ALLOWED  DENIED --> return error to agent
       |
       v
  Original tool executes
       |
       v
  +-- Chio record() ----+
  |   signed receipt    |
  |   budget decrement  |
  |   receipt chain     |
  +--------------------+
       |
       v
  Result returned to agent
```

The evaluate/record cycle maps to two calls on the Chio sidecar:

```python
# Before tool execution
receipt = await chio_client.evaluate_tool_call(
    capability_id=cap_id,
    tool_server=server_id,
    tool_name=tool_name,
    parameters=params,
)

if receipt.is_denied:
    return denied_response(receipt)

# After tool execution (record is implicit -- the sidecar signs the
# receipt during evaluate, which covers both the decision and the
# execution context)
```

The existing `chio-langchain` SDK (`ChioTool._arun`) implements exactly
this pattern. Every framework integration below follows the same
structure, adapted to that framework's tool abstraction.

## 3. SDK Dependency Tree

```
chio-sdk-python                  (base HTTP client to sidecar)
    |
    +-- chio-langchain           (LangChain BaseTool wrapping)
    |       |
    |       +-- chio-langgraph   (graph-level scoping, delegation)
    |
    +-- chio-crewai              (CrewAI BaseTool wrapping)
    +-- chio-autogen             (AutoGen function registration wrapping)
    +-- chio-llamaindex          (LlamaIndex FunctionTool wrapping)
    +-- chio-pydantic-ai         (Pydantic AI tool decorator wrapping)
    +-- chio-swarm               (OpenAI Swarm function wrapping)

@chio-protocol/sdk               (base TypeScript client to sidecar)
    |
    +-- @chio-protocol/ai-sdk    (Vercel AI SDK provider wrapping)

Chio.Protocol.Sdk                (base .NET client to sidecar)
    |
    +-- Chio.Protocol.SemanticKernel  (Semantic Kernel plugin wrapping)
```

All Python integrations depend on `chio-sdk-python` which provides the
`ChioClient` class. The evaluate/record pattern is identical; only the
framework-specific wrapper code differs.

## 4. Capability Scoping Model

Chio capability tokens carry an `ChioScope` containing `ToolGrant` entries.
Each grant specifies a server, tool, allowed operations, and constraints:

```rust
pub struct ToolGrant {
    pub server_id: String,            // which tool server
    pub tool_name: String,            // which tool (or "*")
    pub operations: Vec<Operation>,   // allowed operations
    pub constraints: Vec<Constraint>, // parameter constraints
    pub max_invocations: Option<u32>, // call budget
    pub max_cost_per_invocation: Option<MonetaryAmount>,
    pub max_total_cost: Option<MonetaryAmount>,
}
```

In multi-agent systems, the scoping model maps naturally:

| Framework concept | Chio concept |
|-------------------|-------------|
| Agent role | Capability token with role-scoped grants |
| Tool list | `ToolGrant` entries in the token's scope |
| Delegation / handoff | `attenuate_capability()` -- child token is subset of parent |
| Budget / rate limit | `max_invocations`, `max_total_cost` on the grant |
| Parameter restriction | `Constraint` variants (PathPrefix, DomainExact, RegexMatch) |

---

## 5. CrewAI

> **Priority**: Highest -- CrewAI is the most popular multi-agent framework.
> Its default trust model is fully open: every agent in a crew can call any
> tool assigned to it with no authorization check.

### 5.1 Framework Model

```
Crew
  +-- Agent (role, goal, backstory, tools)
  |     +-- Task (description, expected_output)
  |           +-- Tool.run(input)    <-- intercept point
  +-- Agent
        +-- Task
              +-- Tool.run(input)
```

CrewAI agents can also delegate tasks to other agents in the crew. This
is a natural capability delegation boundary.

### 5.2 Intercept Point

CrewAI tools extend `crewai.tools.BaseTool`. The `_run()` method is the
execution entry point:

```python
from crewai.tools import BaseTool as CrewAIBaseTool
from chio_sdk.client import ChioClient

class ChioCrewTool(CrewAIBaseTool):
    """CrewAI tool backed by Chio capability evaluation."""

    name: str = ""
    description: str = ""
    server_id: str = ""
    capability_id: str = ""
    sidecar_url: str = "http://127.0.0.1:9090"

    def _run(self, **kwargs) -> str:
        """Synchronous tool execution with Chio evaluate/record."""
        import asyncio
        return asyncio.run(self._chio_run(**kwargs))

    async def _chio_run(self, **kwargs) -> str:
        async with ChioClient(self.sidecar_url) as client:
            receipt = await client.evaluate_tool_call(
                capability_id=self.capability_id,
                tool_server=self.server_id,
                tool_name=self.name,
                parameters=kwargs,
            )

        if receipt.is_denied:
            return f"DENIED: {receipt.decision.reason}"

        # Tool is allowed -- execute the actual logic
        result = self._execute(**kwargs)

        return result
```

### 5.3 Per-Role Capability Scoping

Without Chio, a CrewAI crew assigns tools as a flat list. With Chio, each
agent role gets a scoped capability token:

```python
from chio_crewai import ChioCrew, chio_agent

crew = ChioCrew(
    sidecar_url="http://127.0.0.1:9090",
    workflow_scope="crew:research-writing",
)

researcher = chio_agent(
    role="Senior Researcher",
    goal="Find accurate information",
    tools=[search_tool, browse_tool],
    # Chio: this agent can only call search and browse
    scope="tools:search,tools:browse",
    budget={"max_calls": 50, "max_cost_usd": 1.00},
)

writer = chio_agent(
    role="Technical Writer",
    goal="Write clear documentation",
    tools=[write_tool, format_tool],
    # Chio: this agent can only call write and format
    scope="tools:write,tools:format",
    budget={"max_calls": 20},
)

# Even if the LLM hallucinates a tool call to `search_tool` inside
# the writer agent, Chio denies it -- the writer's capability token
# does not include tools:search.
```

### 5.4 Crew Delegation as Capability Attenuation

When one agent delegates a task to another, the delegating agent's
capability is attenuated (narrowed) for the delegate:

```python
from chio_crewai import ChioDelegationCallback

class ChioDelegationCallback:
    """CrewAI callback that attenuates capabilities on delegation."""

    async def on_delegation(self, delegator, delegate, task):
        chio = ChioClient(self.sidecar_url)
        parent_token = delegator.chio_capability

        # Child token is strictly narrower than parent
        child_token = await chio.attenuate_capability(
            parent_token,
            new_scope=delegate.chio_scope,
        )

        delegate.chio_capability = child_token
```

### 5.5 Package Structure

```
sdks/python/chio-crewai/
  pyproject.toml            # deps: chio-sdk-python, crewai>=0.80
  src/chio_crewai/
    __init__.py
    tool.py                 # ChioCrewTool -- BaseTool wrapper
    crew.py                 # ChioCrew -- capability-scoped crew
    agent.py                # chio_agent -- agent with Chio scope
    delegation.py           # ChioDelegationCallback
  tests/
    test_tool_wrapping.py
    test_role_scoping.py
    test_delegation.py
```

---

## 6. AutoGen / AG2

> **Priority**: High -- AutoGen's `ConversableAgent` model with registered
> functions and `GroupChat` is widely used for multi-agent conversations.
> Two distinct intercept points: function execution and agent handoff.

### 6.1 Framework Model

```
GroupChat
  +-- ConversableAgent (functions registered via @register)
  |     +-- function_call    <-- intercept point 1
  +-- ConversableAgent
  |     +-- function_call
  +-- agent-to-agent handoff <-- intercept point 2
```

### 6.2 Intercept Point 1: Function Execution

AutoGen agents register functions with `@register_for_execution` and
`@register_for_llm`. The execution decorator is the intercept point:

```python
from autogen import ConversableAgent
from chio_autogen import chio_function

agent = ConversableAgent(
    name="researcher",
    system_message="You are a research assistant.",
)

# Standard AutoGen registration, wrapped with Chio
@chio_function(
    agent=agent,
    capability_id="cap-researcher-001",
    server_id="research-tools",
)
def search_papers(query: str, max_results: int = 10) -> str:
    """Search academic papers."""
    # Original function body -- only reached if Chio allows
    return do_search(query, max_results)
```

The `chio_function` decorator wraps the registered function:

```python
from chio_sdk.client import ChioClient

def chio_function(agent, capability_id, server_id, sidecar_url="http://127.0.0.1:9090"):
    """Decorator that wraps an AutoGen registered function with Chio evaluation."""

    def decorator(fn):
        tool_name = fn.__name__

        async def wrapped(**kwargs):
            async with ChioClient(sidecar_url) as client:
                receipt = await client.evaluate_tool_call(
                    capability_id=capability_id,
                    tool_server=server_id,
                    tool_name=tool_name,
                    parameters=kwargs,
                )

            if receipt.is_denied:
                return f"DENIED by Chio: {receipt.decision.reason}"

            return fn(**kwargs)

        # Register with AutoGen
        agent.register_for_execution()(wrapped)
        agent.register_for_llm(description=fn.__doc__)(wrapped)

        return wrapped

    return decorator
```

### 6.3 Intercept Point 2: Agent-to-Agent Handoff

AutoGen's `GroupChat` routes messages between agents. When control passes
from one agent to another, Chio verifies the handoff is authorized:

```python
from autogen import GroupChat, GroupChatManager
from chio_autogen import ChioGroupChat

chat = ChioGroupChat(
    agents=[researcher, writer, reviewer],
    sidecar_url="http://127.0.0.1:9090",
    # Define which agents can hand off to which
    handoff_policy={
        "researcher": ["writer"],         # researcher can hand off to writer
        "writer": ["reviewer"],           # writer can hand off to reviewer
        "reviewer": ["researcher", "writer"],  # reviewer can send back
    },
)
```

### 6.4 Nested Chats as Recursive Delegation

AutoGen supports nested chats where an agent spawns a sub-conversation.
Each nesting level attenuates the capability:

```python
from chio_autogen import chio_nested_chat

# The inner chat gets an attenuated capability -- it can only use
# the tools explicitly delegated, not the full parent scope
@chio_nested_chat(
    parent_capability_id="cap-parent-001",
    delegated_scope="tools:search",
    budget={"max_calls": 10},
)
def research_subtask(agent, message):
    # This nested chat can only call search tools, even if the parent
    # agent has broader access
    return agent.initiate_chat(inner_agent, message=message)
```

### 6.5 Package Structure

```
sdks/python/chio-autogen/
  pyproject.toml            # deps: chio-sdk-python, pyautogen>=0.4
  src/chio_autogen/
    __init__.py
    function.py             # chio_function decorator
    group_chat.py           # ChioGroupChat -- handoff enforcement
    nested.py               # chio_nested_chat -- recursive delegation
  tests/
    test_function_wrapping.py
    test_handoff.py
    test_nested_delegation.py
```

---

## 7. LlamaIndex

> **Priority**: High -- LlamaIndex is the dominant RAG framework.
> `QueryEngineTool` wraps entire RAG pipelines as tools, making data
> access scoping critical. Chio can scope which indices, collections,
> and query patterns an agent is authorized to access.

### 7.1 Framework Model

```
AgentRunner
  +-- AgentWorker
        +-- run_step()       <-- intercept point
              +-- FunctionTool.call()
              +-- QueryEngineTool.call()
```

### 7.2 Intercept Point

LlamaIndex tools implement `BaseTool` with a `call()` method. The
`AgentRunner.run_step()` dispatches tool calls. Chio wraps at the tool
level:

```python
from llama_index.core.tools import FunctionTool, ToolOutput
from chio_llamaindex import ChioFunctionTool

# Wrap a function as a Chio-secured LlamaIndex tool
search_tool = ChioFunctionTool.from_defaults(
    fn=search_documents,
    name="search_documents",
    description="Search the document index",
    capability_id="cap-agent-001",
    server_id="doc-tools",
)
```

The wrapper intercepts `call()`:

```python
from llama_index.core.tools import FunctionTool, ToolOutput, adapt_to_async_tool
from chio_sdk.client import ChioClient

class ChioFunctionTool(FunctionTool):
    """LlamaIndex FunctionTool with Chio capability enforcement."""

    capability_id: str = ""
    server_id: str = ""
    sidecar_url: str = "http://127.0.0.1:9090"

    def call(self, *args, **kwargs) -> ToolOutput:
        """Synchronous call with Chio evaluation."""
        import asyncio
        return asyncio.run(self.acall(*args, **kwargs))

    async def acall(self, *args, **kwargs) -> ToolOutput:
        """Async call with Chio evaluation."""
        async with ChioClient(self.sidecar_url) as client:
            receipt = await client.evaluate_tool_call(
                capability_id=self.capability_id,
                tool_server=self.server_id,
                tool_name=self.metadata.name,
                parameters=kwargs,
            )

        if receipt.is_denied:
            return ToolOutput(
                content=f"DENIED: {receipt.decision.reason}",
                tool_name=self.metadata.name,
                raw_input=kwargs,
                raw_output=receipt.decision.reason,
            )

        # Capability check passed -- run the original function
        return await super().acall(*args, **kwargs)
```

### 7.3 QueryEngineTool: Data Access Scoping

`QueryEngineTool` wraps a RAG pipeline (retriever + LLM) as a callable
tool. This is where Chio adds data access controls that LlamaIndex does
not provide natively:

```python
from llama_index.core.tools import QueryEngineTool
from chio_llamaindex import ChioQueryEngineTool

# Wrap a query engine with Chio scoping
finance_qa = ChioQueryEngineTool.from_defaults(
    query_engine=finance_index.as_query_engine(),
    name="query_finance_docs",
    description="Query financial documents",
    capability_id="cap-analyst-001",
    server_id="rag-pipeline",
    # Chio constraints scope what data can be queried
    constraints={
        "collection": "finance-public",    # only public financials
        "date_range": "2024-01-01:",       # only recent data
    },
)
```

The constraint parameters are passed through to Chio's `Constraint`
system. For example, a `PathPrefix("/finance/public")` constraint
ensures the RAG pipeline only retrieves from authorized collections.

### 7.4 Package Structure

```
sdks/python/chio-llamaindex/
  pyproject.toml            # deps: chio-sdk-python, llama-index-core>=0.11
  src/chio_llamaindex/
    __init__.py
    tool.py                 # ChioFunctionTool -- FunctionTool wrapper
    query_engine.py         # ChioQueryEngineTool -- data access scoping
    agent.py                # ChioAgentRunner -- runner-level enforcement
  tests/
    test_function_tool.py
    test_query_engine.py
    test_agent_runner.py
```

---

## 8. Vercel AI SDK

> **Priority**: High -- the Vercel AI SDK is the dominant TypeScript
> framework for AI applications. Its `tool()` function with Zod schemas
> and streaming via `streamText()` are the primary integration surface.
> Streaming must not break.

### 8.1 Framework Model

```
generateText / streamText
  +-- tools: { toolName: tool({ ... }) }
        +-- execute(args)    <-- intercept point
```

### 8.2 Intercept Point

The Vercel AI SDK defines tools with `tool()`. Each tool has a `schema`
(Zod) and an `execute` function. Chio wraps `execute`:

```typescript
import { tool } from "ai";
import { z } from "zod";
import { chioTool } from "@chio-protocol/ai-sdk";

// Standard Vercel AI SDK tool, wrapped with Chio
const searchTool = chioTool(
  tool({
    description: "Search the web",
    parameters: z.object({
      query: z.string().describe("Search query"),
      maxResults: z.number().default(10),
    }),
    execute: async ({ query, maxResults }) => {
      return await searchWeb(query, maxResults);
    },
  }),
  {
    capabilityId: "cap-agent-001",
    serverId: "search-tools",
    toolName: "search_web",
  }
);
```

The `chioTool` wrapper:

```typescript
import { ChioClient } from "@chio-protocol/sdk";

interface ChioToolConfig {
  capabilityId: string;
  serverId: string;
  toolName: string;
  sidecarUrl?: string; // default http://127.0.0.1:9090
}

function chioTool<T>(innerTool: T, config: ChioToolConfig): T {
  const client = new ChioClient(config.sidecarUrl);
  const originalExecute = innerTool.execute;

  return {
    ...innerTool,
    execute: async (args: unknown) => {
      const receipt = await client.evaluateToolCall({
        capabilityId: config.capabilityId,
        toolServer: config.serverId,
        toolName: config.toolName,
        parameters: args,
      });

      if (receipt.isDenied) {
        throw new Error(`Chio denied: ${receipt.decision.reason}`);
      }

      // Original execute -- streaming continues to work because
      // we only wrap the entry point, not the return value
      return originalExecute(args);
    },
  };
}
```

### 8.3 Streaming Compatibility

The critical constraint: `streamText()` must continue to work. Because
Chio wraps only the `execute` entry point (a synchronous gate before the
tool runs), streaming is unaffected. The tool's return value flows back
through the Vercel AI SDK's streaming infrastructure unchanged.

```typescript
import { streamText } from "ai";

// This works identically with or without Chio wrapping
const result = streamText({
  model: openai("gpt-4o"),
  tools: { search: searchTool },  // Chio-wrapped tool
  maxSteps: 5,
  prompt: "Research quantum computing advances",
});

// Stream is unaffected -- Chio evaluation happens inside execute(),
// before the tool produces any output
for await (const chunk of result.textStream) {
  process.stdout.write(chunk);
}
```

### 8.4 Provider Wrapper Pattern

For applications with many tools, `@chio-protocol/ai-sdk` can wrap an
entire tool set:

```typescript
import { chioTools } from "@chio-protocol/ai-sdk";

const tools = chioTools(
  {
    search: searchTool,
    browse: browseTool,
    write: writeTool,
  },
  {
    capabilityId: "cap-agent-001",
    serverId: "all-tools",
    sidecarUrl: "http://127.0.0.1:9090",
  }
);

const result = await generateText({
  model: openai("gpt-4o"),
  tools,
  maxSteps: 10,
  prompt: "Write a report on AI safety",
});
```

### 8.5 Package Structure

```
sdks/typescript/packages/ai-sdk/
  package.json              # deps: @chio-protocol/sdk, ai
  src/
    index.ts
    tool.ts                 # chioTool -- single tool wrapper
    tools.ts                # chioTools -- batch tool wrapper
    client.ts               # re-export from @chio-protocol/sdk
  tests/
    tool.test.ts
    streaming.test.ts
```

---

## 9. Semantic Kernel

> **Priority**: Medium -- Semantic Kernel is Microsoft's agent framework
> for .NET (with Python and Java ports). Its Plugin/KernelFunction model
> and Planner abstraction introduce a unique integration point: Chio can
> evaluate an entire multi-step plan before any step executes.

### 9.1 Framework Model

```
Kernel
  +-- Plugins (collections of KernelFunctions)
  |     +-- KernelFunction
  |           +-- InvokeAsync()    <-- intercept point 1
  +-- Planner
        +-- CreatePlanAsync()
              +-- Plan (sequence of KernelFunction calls)
              +-- plan.InvokeAsync()  <-- intercept point 2
```

### 9.2 Intercept Point 1: KernelFunction Invocation

```csharp
using Chio.Protocol.SemanticKernel;
using Microsoft.SemanticKernel;

var kernel = Kernel.CreateBuilder()
    .AddChioCapability(new ChioConfig
    {
        SidecarUrl = "http://127.0.0.1:9090",
        CapabilityId = "cap-agent-001",
    })
    .Build();

// Functions registered normally -- Chio filter intercepts invocation
kernel.Plugins.AddFromType<SearchPlugin>();
kernel.Plugins.AddFromType<FilePlugin>();
```

Semantic Kernel supports `IFunctionInvocationFilter` which intercepts
every function call:

```csharp
public class ChioFunctionFilter : IFunctionInvocationFilter
{
    private readonly ChioClient _arc;
    private readonly string _capabilityId;

    public async Task OnFunctionInvocationAsync(
        FunctionInvocationContext context,
        Func<FunctionInvocationContext, Task> next)
    {
        // Evaluate before execution
        var receipt = await _arc.EvaluateToolCallAsync(
            capabilityId: _capabilityId,
            toolServer: context.Function.PluginName,
            toolName: context.Function.Name,
            parameters: context.Arguments.ToDictionary()
        );

        if (receipt.IsDenied)
        {
            context.Result = new FunctionResult(
                context.Function,
                $"DENIED by Chio: {receipt.Decision.Reason}"
            );
            return; // do not call next()
        }

        // Allowed -- proceed to actual function execution
        await next(context);
    }
}
```

### 9.3 Intercept Point 2: Plan-Level Evaluation

Semantic Kernel's planners (Handlebars, Stepwise) compose multi-step
plans. Chio can evaluate the entire plan before any step executes,
checking that all required capabilities exist and the aggregate budget
is sufficient:

```csharp
public class ChioPlanFilter : IFunctionInvocationFilter
{
    public async Task OnFunctionInvocationAsync(
        FunctionInvocationContext context,
        Func<FunctionInvocationContext, Task> next)
    {
        // Detect plan execution
        if (context.Function.Name == "InvokePlan")
        {
            var plan = context.Arguments["plan"] as Plan;
            var steps = plan.Steps.Select(s => new PlannedToolCall
            {
                ToolServer = s.PluginName,
                ToolName = s.Name,
                Parameters = s.Parameters.ToDictionary(),
            }).ToList();

            // Evaluate all steps as a batch -- checks aggregate budget,
            // ensures all required capabilities exist
            var planReceipt = await _arc.EvaluatePlanAsync(
                capabilityId: _capabilityId,
                steps: steps
            );

            if (planReceipt.IsDenied)
            {
                context.Result = new FunctionResult(
                    context.Function,
                    $"Plan DENIED by Chio: {planReceipt.Decision.Reason}"
                );
                return;
            }
        }

        await next(context);
    }
}
```

Plan-level evaluation is unique to Semantic Kernel among the frameworks
covered here. It allows Chio to reject an entire plan that would exceed
budget or require unauthorized tools, before any side effects occur.

### 9.4 Package Structure

```
sdks/dotnet/Chio.Protocol.SemanticKernel/
  Chio.Protocol.SemanticKernel.csproj
  src/
    ChioFunctionFilter.cs     # IFunctionInvocationFilter implementation
    ChioPlanFilter.cs          # Plan-level evaluation
    ChioConfig.cs              # Configuration
    KernelBuilderExtensions.cs # .AddChioCapability() extension
  tests/
    FunctionFilterTests.cs
    PlanEvaluationTests.cs
```

---

## 10. Pydantic AI

> **Priority**: Medium -- Pydantic AI's `RunContext` dependency injection
> is a natural fit for Chio. The capability token flows through the context
> that the framework already threads through every tool call.

### 10.1 Framework Model

```
Agent
  +-- @agent.tool
        +-- fn(ctx: RunContext, ...)    <-- intercept point
              ctx.deps contains the Chio capability token
```

### 10.2 Intercept Point

Pydantic AI tools receive a `RunContext` with typed dependencies. The
Chio capability token is injected as a dependency:

```python
from dataclasses import dataclass
from pydantic_ai import Agent, RunContext
from chio_sdk.client import ChioClient
from chio_sdk.models import CapabilityToken

@dataclass
class ChioDeps:
    """Dependencies injected into every tool call."""
    chio_client: ChioClient
    capability_id: str
    server_id: str

agent = Agent(
    "openai:gpt-4o",
    deps_type=ChioDeps,
)

@agent.tool
async def search_papers(
    ctx: RunContext[ChioDeps],
    query: str,
    max_results: int = 10,
) -> str:
    """Search academic papers."""
    # Chio evaluation happens inside the tool, using injected deps
    receipt = await ctx.deps.chio_client.evaluate_tool_call(
        capability_id=ctx.deps.capability_id,
        tool_server=ctx.deps.server_id,
        tool_name="search_papers",
        parameters={"query": query, "max_results": max_results},
    )

    if receipt.is_denied:
        return f"DENIED: {receipt.decision.reason}"

    return do_search(query, max_results)
```

### 10.3 The `chio_tool` Decorator

To avoid boilerplate in every tool, `chio-pydantic-ai` provides a
decorator that wraps the evaluate/record pattern:

```python
from chio_pydantic_ai import chio_tool

agent = Agent("openai:gpt-4o", deps_type=ChioDeps)

@chio_tool(agent, tool_name="search_papers")
async def search_papers(
    ctx: RunContext[ChioDeps],
    query: str,
    max_results: int = 10,
) -> str:
    """Search academic papers."""
    # Only reached if Chio allows -- the decorator handles evaluation
    return do_search(query, max_results)
```

The decorator extracts `capability_id`, `server_id`, and `chio_client`
from `ctx.deps` (which must be an `ChioDeps` instance or compatible
dataclass), calls evaluate before the function body, and returns a
denial message if the capability check fails.

### 10.4 Package Structure

```
sdks/python/chio-pydantic-ai/
  pyproject.toml            # deps: chio-sdk-python, pydantic-ai>=0.1
  src/chio_pydantic_ai/
    __init__.py
    decorator.py            # chio_tool decorator
    deps.py                 # ChioDeps dataclass
  tests/
    test_tool_decorator.py
    test_deps_injection.py
```

---

## 11. OpenAI Swarm

> **Priority**: Medium -- Swarm is minimal by design (agents are
> functions, handoffs transfer control). Its simplicity makes Chio
> integration straightforward: handoff = capability delegation.

### 11.1 Framework Model

```
Swarm.run()
  +-- Agent (instructions, functions)
        +-- function()           <-- intercept point 1
        +-- handoff() -> Agent   <-- intercept point 2
```

### 11.2 Intercept Point 1: Function Wrapping

Swarm agents define tools as plain Python functions. Chio wraps them:

```python
from swarm import Agent
from chio_swarm import chio_function, ChioSwarmContext

ctx = ChioSwarmContext(
    sidecar_url="http://127.0.0.1:9090",
    capability_id="cap-triage-001",
    server_id="support-tools",
)

@chio_function(ctx, tool_name="lookup_customer")
def lookup_customer(customer_id: str) -> str:
    """Look up customer details."""
    # Only reached if Chio allows
    return get_customer(customer_id)

triage_agent = Agent(
    name="Triage",
    instructions="Route customer issues to the right team.",
    functions=[lookup_customer, handoff_to_billing],
)
```

### 11.3 Intercept Point 2: Handoff as Capability Delegation

Swarm's `handoff()` transfers control from one agent to another. This
maps directly to Chio capability attenuation:

```python
from chio_swarm import chio_handoff

# The billing agent gets an attenuated capability -- it can only
# access billing tools, not the triage agent's full scope
@chio_handoff(
    parent_ctx=ctx,
    delegated_scope="tools:billing",
    budget={"max_calls": 10},
)
def handoff_to_billing():
    """Transfer to billing specialist."""
    return billing_agent
```

Under the hood, `chio_handoff` calls `chio_client.attenuate_capability()`
to produce a child token scoped to `tools:billing`, then attaches it to
the target agent's context.

### 11.4 Package Structure

```
sdks/python/chio-swarm/
  pyproject.toml            # deps: chio-sdk-python, openai-swarm
  src/chio_swarm/
    __init__.py
    function.py             # chio_function wrapper
    handoff.py              # chio_handoff -- delegation
    context.py              # ChioSwarmContext
  tests/
    test_function_wrapping.py
    test_handoff_delegation.py
```

---

## 12. Common Patterns

All seven integrations share the same structural elements:

### 12.1 The Wrapper Function

Every framework integration reduces to one function:

```python
async def chio_evaluate_and_run(
    chio_client: ChioClient,
    capability_id: str,
    server_id: str,
    tool_name: str,
    parameters: dict,
    execute_fn: Callable,
) -> Any:
    """Universal Chio tool execution wrapper."""
    receipt = await chio_client.evaluate_tool_call(
        capability_id=capability_id,
        tool_server=server_id,
        tool_name=tool_name,
        parameters=parameters,
    )

    if receipt.is_denied:
        return {"error": "denied", "reason": receipt.decision.reason}

    return execute_fn(**parameters)
```

The framework-specific code is just the glue that extracts `tool_name`
and `parameters` from the framework's tool abstraction and routes the
denial response back through the framework's error handling.

### 12.2 Delegation Chain

Frameworks with multi-agent delegation (CrewAI, AutoGen, Swarm,
LangGraph) all use the same Chio primitive:

```python
child_token = await chio_client.attenuate_capability(
    parent_token,
    new_scope=child_scope,  # must be subset of parent
)
```

The child token's scope is cryptographically bound to be a subset of
the parent's. The delegation chain is recorded in the token itself
(`delegation_chain: Vec<DelegationLink>`), creating an auditable
provenance trail.

### 12.3 Budget Enforcement

All frameworks support budget limits through `ToolGrant` fields:

| Budget type | ToolGrant field | Effect |
|-------------|-----------------|--------|
| Call count | `max_invocations` | Chio denies after N calls |
| Per-call cost | `max_cost_per_invocation` | Chio denies if single call exceeds limit |
| Total cost | `max_total_cost` | Chio denies if aggregate cost exceeds limit |

Budget is enforced at the sidecar, not in the framework SDK. The SDK
does not need to track call counts; the kernel does.

### 12.4 Receipt Correlation

Every framework can attach framework-specific metadata to Chio receipts
for cross-referencing:

| Framework | Correlation ID |
|-----------|---------------|
| CrewAI | `crewai.crew_id`, `crewai.agent_role`, `crewai.task_id` |
| AutoGen | `autogen.chat_id`, `autogen.agent_name` |
| LlamaIndex | `llamaindex.run_id`, `llamaindex.step_id` |
| Vercel AI SDK | `ai_sdk.call_id`, `ai_sdk.step` |
| Semantic Kernel | `semantic_kernel.plan_id`, `semantic_kernel.step_index` |
| Pydantic AI | `pydantic_ai.run_id` |
| Swarm | `swarm.agent_name`, `swarm.handoff_chain` |

## 13. Extending `chio-langchain` to New Frameworks

The existing `chio-langchain` SDK (`ChioTool`, `ChioToolkit`) is the
reference implementation. To add a new framework:

1. **Identify the tool abstraction.** Every framework has one: LangChain
   has `BaseTool`, CrewAI has `BaseTool`, LlamaIndex has `BaseTool`,
   Vercel AI SDK has `tool()`, Semantic Kernel has `KernelFunction`,
   Pydantic AI has `@agent.tool`, Swarm has plain functions.

2. **Find the execution entry point.** The single method or function
   where tool parameters go in and results come out: `_arun()`,
   `_run()`, `call()`, `execute()`, `InvokeAsync()`, the decorated
   function body.

3. **Wrap it with evaluate/record.** Insert `chio_client.evaluate_tool_call()`
   before the original execution. Check `receipt.is_denied`. If denied,
   return the framework's error format. If allowed, call the original.

4. **Map delegation.** If the framework has multi-agent handoff,
   map it to `chio_client.attenuate_capability()`.

5. **Package it.** Create `sdks/python/chio-<framework>/` (or
   `sdks/typescript/packages/<framework>/`) with a dependency on
   `chio-sdk-python` (or `@chio-protocol/sdk`).

The entire integration for a new framework is typically under 200 lines
of code. The Chio sidecar does the heavy lifting: capability validation,
guard evaluation, budget tracking, receipt signing. The SDK is just the
bridge.

## 14. Open Questions

1. **Sync vs async.** CrewAI and Swarm use synchronous tool execution.
   The Chio sidecar client is async. The current approach uses
   `asyncio.run()` for sync wrappers. Should the SDK provide a native
   sync client path to avoid event loop conflicts?

2. **Framework-native error types.** Each framework has its own error
   handling. Should denied responses return the framework's native error
   type (e.g., `ToolException` in LangChain) or a generic Chio denial?

3. **Hot-reload of capabilities.** If a capability token is revoked
   mid-conversation, the next tool call will be denied. Should the SDK
   proactively check token validity, or is fail-on-next-call sufficient?

4. **Batch evaluation.** Semantic Kernel's plan-level evaluation
   suggests a batch endpoint (`/v1/evaluate/batch`) that validates
   multiple tool calls atomically. Should this be added to the sidecar
   API for all frameworks, or kept as a Semantic Kernel specialization?

5. **Framework version compatibility.** All listed frameworks are
   pre-1.0 or rapidly evolving. Each SDK should pin a minimum version
   and document which APIs it depends on, to minimize breakage from
   upstream changes.
