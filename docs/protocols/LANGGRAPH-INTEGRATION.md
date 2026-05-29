# LangGraph Integration: Stateful Agent Graph Security

> **Status**: Tier 1 -- proposed April 2026
> **Priority**: High -- LangGraph is the stateful orchestration layer for
> multi-agent systems built on LangChain. Each node transition is a
> capability boundary. Extends the existing `chio-langchain` SDK.

## 1. Why LangGraph

Chio already ships `chio-langchain` which wraps Chio tools as LangChain
`BaseTool` instances. But LangChain is the tool layer; LangGraph is the
orchestration layer. LangGraph adds:

- **Stateful graphs** -- nodes (agents, tools, humans) connected by edges
  with conditional routing, cycles, and persistence
- **Human-in-the-loop** -- interrupt nodes that pause execution for approval
- **Multi-agent** -- supervisor/worker patterns, handoffs, parallel branches
- **Checkpointing** -- graph state persisted across invocations

Each of these creates a natural Chio enforcement point. A node transition
is a capability boundary. A human-in-the-loop interrupt maps to a Chio
approval guard. A supervisor dispatching to workers is a capability
delegation chain.

### What Chio Adds to LangGraph

| LangGraph alone | LangGraph + Chio |
|-----------------|-----------------|
| Graph structure defines control flow | Capability tokens scope what each node can do |
| Human-in-the-loop is UX-driven | Approval guards are policy-driven (human approval is one guard type) |
| Tool calls via LangChain tools | Tool calls attested with signed receipts |
| State checkpointed per thread | Receipt chain provides cryptographic audit trail |
| Multi-agent trust is implicit | Delegation creates scoped child capabilities |

## 2. Architecture

```
+------------------------------------------------------------------+
|  LangGraph                                                       |
|                                                                  |
|  [Supervisor Node]                                               |
|       |                                                          |
|       | Chio: delegate(scope="research:*")                        |
|       |                                                          |
|  +----v-----------+    +------------------+                      |
|  | Researcher Node|    | Writer Node      |                      |
|  | cap: research:*|    | cap: write:*     |                      |
|  |   |            |    |   |              |                      |
|  |   | tool_call  |    |   | tool_call    |                      |
|  |   v            |    |   v              |                      |
|  | [Chio evaluate] |    | [Chio evaluate]   |                      |
|  +----------------+    +------------------+                      |
|                                                                  |
+------------------------------------------------------------------+
         |                        |
         v                        v
  Chio Kernel Sidecar (shared, :9090)
  Capability | Guard | Receipt | Budget
```

### Node-Level Capability Scoping

Each node in the graph operates under a capability scope. When the graph
transitions from one node to another, the capability context changes:

```
Supervisor (cap: agent:supervisor)
    |
    +---> Researcher (cap: tools:search, tools:browse)
    |         |
    |         +---> [search tool] -- Chio evaluates against tools:search
    |         +---> [browse tool] -- Chio evaluates against tools:browse
    |         +---> [write tool]  -- Chio DENIES (not in researcher scope)
    |
    +---> Writer (cap: tools:write, tools:format)
              |
              +---> [write tool]  -- Chio evaluates against tools:write
              +---> [search tool] -- Chio DENIES (not in writer scope)
```

## 3. Integration Model

### 3.1 Graph-Level Configuration

```python
from langgraph.graph import StateGraph, START, END
from chio_langgraph import ChioGraphConfig, chio_node

# Define the graph with Chio capability scoping
graph = StateGraph(AgentState)

# Each node gets a capability scope
graph.add_node("supervisor", chio_node(
    supervisor_agent,
    scope="agent:supervisor",
    can_delegate=["tools:search", "tools:browse", "tools:write"],
))

graph.add_node("researcher", chio_node(
    researcher_agent,
    scope="tools:search,tools:browse",
    budget={"max_calls": 20, "max_cost_usd": 0.50},
))

graph.add_node("writer", chio_node(
    writer_agent,
    scope="tools:write,tools:format",
    budget={"max_calls": 10},
))

# Edges with capability-aware routing
graph.add_conditional_edges("supervisor", route_to_worker)
graph.add_edge("researcher", "supervisor")
graph.add_edge("writer", "supervisor")

graph.add_edge(START, "supervisor")

app = graph.compile(
    checkpointer=MemorySaver(),
    # Chio configuration applied to the compiled graph
    chio=ChioGraphConfig(
        sidecar_url="http://127.0.0.1:9090",
        # Workflow-level grant acquired on graph start
        workflow_scope="agent:full-pipeline",
    ),
)
```

### 3.2 The `chio_node` Wrapper

`chio_node` wraps any LangGraph node function with Chio capability context:

```python
from chio_langgraph import ChioNodeContext

def chio_node(fn, scope: str, budget: dict | None = None, can_delegate: list[str] | None = None):
    """Wrap a LangGraph node with Chio capability enforcement."""

    async def wrapper(state: AgentState, config: RunnableConfig) -> AgentState:
        chio_ctx = ChioNodeContext.from_config(config)

        # Enter the node's capability scope
        async with chio_ctx.scoped(scope, budget=budget) as node_ctx:
            # Inject Chio-aware tools into the agent
            state["chio_context"] = node_ctx

            result = await fn(state, config)

            # Record node completion receipt
            await node_ctx.record_node_completion(
                node_name=fn.__name__,
                input_hash=state.hash(),
                output_hash=result.hash() if hasattr(result, 'hash') else None,
            )

            return result

    wrapper.__name__ = fn.__name__
    return wrapper
```

### 3.3 Human-in-the-Loop as Approval Guard

LangGraph's `interrupt()` mechanism maps to Chio's approval guard:

```python
from langgraph.types import interrupt
from chio_langgraph import chio_approval_node

@chio_approval_node(
    scope="tools:dangerous",
    guard="human-approval",
    # Chio guard config -- who can approve, timeout, escalation
    approval_config={
        "approvers": ["admin@example.com"],
        "timeout_seconds": 3600,
        "escalation": "deny",  # deny if no approval within timeout
    },
)
async def dangerous_action(state: AgentState, config: RunnableConfig):
    """This node requires human approval via Chio guard before executing."""
    # If we reach here, the approval guard passed
    result = await execute_dangerous_tool(state["action"])
    return {"result": result}
```

Under the hood, `chio_approval_node` does:

1. Calls `chio.evaluate()` with the `human-approval` guard
2. If the guard returns `pending`, calls `interrupt()` to pause the graph
3. When the graph resumes (human approved), re-evaluates -- guard now passes
4. If the guard returns `denied` (human rejected or timeout), raises `NodeInterrupt`

### 3.4 Multi-Agent Delegation

When a supervisor delegates to a worker, the capability chain narrows:

```python
from chio_langgraph import ChioDelegation

async def supervisor_node(state: AgentState, config: RunnableConfig):
    chio_ctx = ChioNodeContext.from_config(config)

    # Supervisor decides which worker to route to
    decision = await supervisor_llm.invoke(state["messages"])

    if decision.worker == "researcher":
        # Create a delegated capability for the researcher
        # Scope is narrowed: supervisor has agent:supervisor,
        # researcher gets only tools:search,tools:browse
        delegation = await chio_ctx.delegate(
            target_node="researcher",
            scope="tools:search,tools:browse",
            budget={"max_calls": 20},
            # Delegation is recorded in the receipt chain
        )
        state["chio_delegation"] = delegation

    return {**state, "next": decision.worker}
```

### 3.5 Subgraph Isolation

LangGraph supports nested subgraphs. Each subgraph gets its own capability
boundary:

```python
# Inner graph -- research pipeline
research_graph = StateGraph(ResearchState)
research_graph.add_node("search", chio_node(search_fn, scope="tools:search"))
research_graph.add_node("analyze", chio_node(analyze_fn, scope="tools:analyze"))

# Outer graph -- uses research as a subgraph
outer_graph = StateGraph(AgentState)
outer_graph.add_node("plan", chio_node(plan_fn, scope="agent:plan"))
outer_graph.add_node("research", chio_node(
    research_graph.compile(),
    scope="tools:search,tools:analyze",  # ceiling for the entire subgraph
))
outer_graph.add_node("write", chio_node(write_fn, scope="tools:write"))
```

The subgraph's nodes cannot exceed the scope ceiling set by the outer graph.

## 4. Checkpoint and Receipt Correlation

LangGraph checkpoints graph state at each node. Chio receipts record each
tool invocation. These should cross-reference:

```python
class ChioCheckpointAdapter:
    """Wraps a LangGraph checkpointer to include Chio receipt metadata."""

    def __init__(self, inner_checkpointer, chio_client):
        self.inner = inner_checkpointer
        self.chio = chio_client

    async def aput(self, config, checkpoint, metadata):
        # Attach receipt IDs to checkpoint metadata
        receipt_ids = ChioNodeContext.from_config(config).receipt_ids
        metadata["chio_receipt_ids"] = receipt_ids
        metadata["chio_receipt_chain_head"] = receipt_ids[-1] if receipt_ids else None
        return await self.inner.aput(config, checkpoint, metadata)
```

### Querying

```
# Find all Chio receipts for a LangGraph thread
chio receipt list --meta langgraph.thread_id=<thread-id>

# Find receipts for a specific node execution
chio receipt list --meta langgraph.thread_id=<thread-id> --meta langgraph.node=researcher

# Replay graph execution from receipt chain
chio receipt chain <head-receipt-id> --format langgraph
```

## 5. Tool Binding

The existing `chio-langchain` `ChioToolkit` works inside LangGraph nodes.
The integration adds scope awareness:

```python
from chio_langchain import ChioToolkit

async def researcher_agent(state: AgentState, config: RunnableConfig):
    chio_ctx = ChioNodeContext.from_config(config)

    # ChioToolkit filters to only tools within this node's scope
    toolkit = ChioToolkit.from_context(chio_ctx)
    tools = toolkit.get_tools()  # only search, browse -- not write

    agent = create_react_agent(llm, tools)
    result = await agent.ainvoke({"messages": state["messages"]})

    return {"messages": result["messages"]}
```

## 6. Package Structure

```
sdks/python/chio-langgraph/
  pyproject.toml            # deps: chio-sdk-python, chio-langchain, langgraph
  src/chio_langgraph/
    __init__.py
    config.py               # ChioGraphConfig
    node.py                 # chio_node wrapper
    context.py              # ChioNodeContext
    delegation.py           # ChioDelegation, capability narrowing
    approval.py             # chio_approval_node, guard-to-interrupt bridge
    checkpoint.py           # ChioCheckpointAdapter
  tests/
    test_node_scoping.py
    test_delegation.py
    test_approval.py
    test_subgraph.py
```

## 7. Relationship to `chio-langchain`

```
chio-sdk-python          (base HTTP client to sidecar)
    |
chio-langchain           (ChioToolkit, ChioTool -- tool wrapping)
    |
chio-langgraph           (graph-level scoping, delegation, approvals)
```

`chio-langgraph` depends on `chio-langchain` for tool binding and adds the
graph orchestration layer. Users who only need tool wrapping without graph
orchestration use `chio-langchain` directly.

## 8. Open Questions

1. **LangGraph Platform.** LangGraph Cloud runs graphs as a managed service.
   The sidecar model requires the Chio kernel to run in the same environment.
   Should Chio support a remote kernel mode for managed LangGraph deployments?

2. **Streaming.** LangGraph streams node outputs. Should Chio receipts be
   emitted as stream events, or only on node completion?

3. **Time travel.** LangGraph supports replaying from a checkpoint. If the
   graph is replayed, should Chio re-evaluate capabilities (they may have
   been revoked since the checkpoint), or honor the original evaluation?

4. **CrewAI / AutoGen.** These frameworks serve a similar multi-agent
   orchestration role. Should the `chio_node` pattern be generalized into a
   framework-agnostic multi-agent adapter, or should each framework get
   its own integration?
