# Temporal Integration: Durable Agent Workflow Security

> **Status**: Tier 1 -- proposed April 2026
> **Priority**: High -- durable workflows are the emerging production pattern
> for multi-step agent systems. Temporal's Activity model maps directly to
> Chio's capability-bounded tool invocations.

## 1. Why Temporal

Temporal is becoming the default runtime for production agent orchestration.
Its programming model -- durable Workflows composed of retriable Activities --
maps naturally to the agent pattern of "plan a sequence of tool calls, execute
them with retry, roll back on failure."

Chio already has `chio-workflow` for ordered tool sequences with `SkillGrant`,
`WorkflowAuthority`, and `WorkflowReceipt`. Temporal provides the durable
execution substrate that `chio-workflow` does not: persistence, retry with
backoff, saga compensation, visibility, and multi-worker distribution.

The integration thesis: **every Temporal Activity that performs a tool call
should pass through the Chio kernel for capability validation and receipt
signing.** Workflow-level grants scope what the entire workflow can do;
Activity-level checks enforce it per step.

### What Chio Adds to Temporal

| Temporal alone | Temporal + Chio |
|----------------|----------------|
| Activities retry on failure | Activities denied before execution if capability revoked |
| Workflow history is append-only | Receipts are Merkle-committed and cryptographically signed |
| Authorization is per-namespace/queue | Authorization is per-tool, per-scope, time-bounded |
| Saga compensation is developer-defined | Revoked capabilities trigger automatic workflow cancellation |
| Visibility queries show workflow state | Receipt log provides cross-workflow audit trail |

## 2. Architecture

```
+------------------------------------------------------------------+
|  Temporal Cluster                                                |
|  +-----------------------------+  +----------------------------+ |
|  |  Workflow Worker             |  |  Activity Worker           | |
|  |                              |  |                            | |
|  |  @workflow.defn              |  |  @activity.defn            | |
|  |  class AgentWorkflow:        |  |  async def call_tool():    | |
|  |    await workflow.execute(   |  |    chio = ChioActivityCtx()  | |
|  |      call_tool, ...)         |  |    result = await chio(     | |
|  |                              |  |      tool, args, cap)      | |
|  +-----------------------------+  +-------------+--------------+ |
|                                                  |                |
+--------------------------------------------------+----------------+
                                                   |
                                          HTTP to sidecar
                                                   |
                                    +--------------v--------------+
                                    |       Chio Kernel Sidecar     |
                                    |  Capability | Guard | Receipt|
                                    +------------------------------+
```

### Deployment Topology

The Chio sidecar runs alongside the Activity worker (same pod in K8s, same
host in VM deployments). Workflow workers do not call the sidecar directly --
they orchestrate; Activity workers execute and are the enforcement point.

```
Pod / Host
+-----------------------------------------+
|  Activity Worker  <-->  Chio Sidecar      |
|  (port 7233)           (port 9090)       |
+-----------------------------------------+
```

## 3. Integration Model

### 3.1 Python SDK (`chio-temporal`)

The integration wraps Temporal's Activity context with Chio capability
validation. Two layers:

**Activity Interceptor** -- automatic, zero-code-change enforcement:

```python
from chio_temporal import ChioActivityInterceptor

worker = Worker(
    client,
    task_queue="agent-tasks",
    workflows=[AgentWorkflow],
    activities=[call_tool, read_database, send_email],
    interceptors=[ChioActivityInterceptor(
        sidecar_url="http://127.0.0.1:9090",
        # Map activity names to Chio tool scopes
        scope_map={
            "call_tool": "tools:invoke",
            "read_database": "db:read",
            "send_email": "email:send",
        },
    )],
)
```

**Explicit context** -- for fine-grained control within activities:

```python
from temporalio import activity
from chio_temporal import ChioActivityContext

@activity.defn
async def call_tool(tool_name: str, arguments: dict) -> dict:
    chio = ChioActivityContext.from_current()

    # Validates capability, runs guards, returns receipt
    result = await chio.invoke(
        tool=tool_name,
        arguments=arguments,
        scope="tools:invoke",
    )

    return result.payload
```

### 3.2 Workflow-Level Capability Grants

A `WorkflowGrant` scopes the entire workflow execution. Individual Activity
invocations must fall within this envelope.

```python
from chio_temporal import WorkflowGrant

@workflow.defn
class AgentWorkflow:
    @workflow.run
    async def run(self, task: AgentTask) -> AgentResult:
        # Acquire a workflow-scoped grant from the capability authority
        grant = await workflow.execute_activity(
            acquire_workflow_grant,
            args=[task.agent_id, task.requested_scopes],
            start_to_close_timeout=timedelta(seconds=30),
        )

        # All subsequent activities inherit this grant's scope ceiling
        # The interceptor attaches grant.token to each activity context
        workflow.set_query_handler("chio_grant", lambda: grant.token)

        result = await workflow.execute_activity(
            call_tool,
            args=["search", {"query": task.query}],
            start_to_close_timeout=timedelta(minutes=5),
        )

        return AgentResult(payload=result)
```

### 3.3 Capability Revocation and Workflow Cancellation

When a capability is revoked mid-workflow, the interceptor triggers Temporal's
cancellation mechanism:

```python
class ChioActivityInterceptor:
    async def execute_activity(self, input):
        # Check capability before execution
        verdict = await self.sidecar.evaluate(
            tool=input.activity_type,
            scope=self.scope_map.get(input.activity_type),
            token=self._get_grant_token(input),
        )

        if verdict.denied:
            # Raise ApplicationError so Temporal records the denial
            # in workflow history with full Chio context
            raise ApplicationError(
                f"Chio capability denied: {verdict.reason}",
                type="ChioCapabilityDenied",
                non_retryable=True,  # Do not retry denied activities
            )

        result = await self.next.execute_activity(input)

        # Attach receipt to activity completion
        activity.info().heartbeat(verdict.receipt_id)
        return result
```

### 3.4 Receipt Integration with Workflow History

Each Activity completion carries a Chio receipt ID. The workflow receipt
aggregates all step receipts into a single `WorkflowReceipt` on completion:

```python
@activity.defn
async def finalize_workflow_receipt(
    receipt_ids: list[str],
    workflow_id: str,
) -> str:
    chio = ChioActivityContext.from_current()
    workflow_receipt = await chio.finalize_workflow(
        step_receipt_ids=receipt_ids,
        workflow_id=workflow_id,
    )
    return workflow_receipt.receipt_id
```

## 4. Saga Compensation with Chio

Temporal sagas (compensating activities) integrate with Chio's revocation model:

```python
@workflow.defn
class TransferWorkflow:
    @workflow.run
    async def run(self, transfer: Transfer) -> TransferResult:
        compensations = []

        # Step 1: debit source
        debit = await workflow.execute_activity(
            debit_account,
            args=[transfer.source, transfer.amount],
            start_to_close_timeout=timedelta(seconds=30),
        )
        compensations.append(("credit_account", transfer.source, transfer.amount))

        # Step 2: credit destination -- if Chio denies this, compensate
        try:
            credit = await workflow.execute_activity(
                credit_account,
                args=[transfer.destination, transfer.amount],
                start_to_close_timeout=timedelta(seconds=30),
            )
        except ApplicationError as e:
            if e.type == "ChioCapabilityDenied":
                # Run compensations in reverse
                for comp in reversed(compensations):
                    await workflow.execute_activity(
                        comp[0], args=list(comp[1:]),
                        start_to_close_timeout=timedelta(seconds=30),
                    )
                raise

        return TransferResult(debit=debit, credit=credit)
```

## 5. Rust SDK (`chio-temporal-core`)

For Rust-native Temporal workers (via `temporal-sdk-core`):

```rust
use chio_temporal::ChioActivityMiddleware;

let worker = Worker::new(
    client,
    WorkerConfig::new("agent-tasks".to_string()),
)
.with_activity_middleware(ChioActivityMiddleware::new(
    "http://127.0.0.1:9090",
    ScopeMap::from([
        ("call_tool", "tools:invoke"),
        ("read_database", "db:read"),
    ]),
));
```

## 6. Observability Bridge

Temporal's visibility API and Chio's receipt log should cross-reference:

| Temporal Concept | Chio Concept | Bridge |
|------------------|-------------|--------|
| Workflow ID | WorkflowReceipt.workflow_id | 1:1 mapping |
| Activity ID | Receipt.invocation_id | Stored in receipt metadata |
| Run ID | WorkflowReceipt.run_id | Temporal-specific field |
| Search Attributes | Receipt tags | Synced via interceptor |
| Workflow History | Receipt Merkle chain | Receipt IDs in activity results |

### Querying

```
# Find all Chio receipts for a Temporal workflow
chio receipt list --meta temporal.workflow_id=<wf-id>

# Find the Temporal workflow for a Chio receipt
temporal workflow show --workflow-id $(chio receipt get <receipt-id> --field meta.temporal.workflow_id)
```

## 7. Package Structure

```
sdks/python/chio-temporal/
  pyproject.toml          # deps: chio-sdk-python, temporalio
  src/chio_temporal/
    __init__.py
    interceptor.py        # ChioActivityInterceptor
    context.py            # ChioActivityContext
    grant.py              # WorkflowGrant helpers
    receipt.py            # Workflow receipt aggregation
  tests/
    test_interceptor.py
    test_saga.py
    test_receipt.py
```

## 8. Open Questions

1. **Schedule-scoped grants.** Should a Temporal Schedule (cron) get a
   long-lived capability grant that covers all its spawned workflows, or
   should each workflow acquire its own?

2. **Child workflow delegation.** When a parent workflow spawns a child,
   should the child inherit the parent's grant or request its own with
   reduced scope (principle of least privilege)?

3. **Signal-triggered re-evaluation.** If a Temporal Signal delivers new
   context (e.g., user approval), should the interceptor re-evaluate
   guards with the updated context?

4. **Multi-cluster.** Temporal supports multi-cluster replication. Chio
   receipt logs are per-kernel. How do we handle receipt continuity across
   Temporal cluster failover?
