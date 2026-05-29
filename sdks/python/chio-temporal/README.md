# chio-temporal

Temporal integration for the [Chio protocol](../../../spec/PROTOCOL.md).
Plugs into Temporal's Python SDK so every Activity invocation is
capability-checked via the Chio sidecar kernel, denied activities raise
non-retryable `temporalio.exceptions.ApplicationError`, and each
workflow run emits an aggregate `WorkflowReceipt` on completion.

## Install

```bash
uv pip install chio-temporal
# or
pip install chio-temporal
```

The package depends on `chio-sdk-python`, `temporalio>=1.7,<2`, and
`pydantic>=2.5`.

## Quickstart

```python
import asyncio
from datetime import timedelta

from chio_sdk.client import ChioClient
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_temporal import ChioActivityInterceptor, WorkflowGrant, build_chio_worker
from temporalio import activity, workflow
from temporalio.client import Client


@activity.defn
async def send_email(to: str, body: str) -> str:
    return f"sent to {to}"


@workflow.defn
class NotifyWorkflow:
    @workflow.run
    async def run(self, to: str) -> str:
        return await workflow.execute_activity(
            send_email,
            args=[to, "hello"],
            start_to_close_timeout=timedelta(seconds=30),
        )


async def main() -> None:
    client = await Client.connect("localhost:7233")
    async with ChioClient("http://127.0.0.1:9090") as chio:
        worker, interceptor, grant = await build_chio_worker(
            client,
            task_queue="notify",
            activities=[send_email],
            workflows=[NotifyWorkflow],
            workflow_id="notify-wf-1",
            capability_id="",  # ignored when scope is supplied
            chio_client=chio,
            scope=ChioScope(
                grants=[
                    ToolGrant(
                        server_id="email-srv",
                        tool_name="send_email",
                        operations=[Operation.INVOKE],
                    )
                ]
            ),
            subject="agent:notify",
            tool_server="email-srv",
        )
        try:
            async with worker:
                handle = await client.start_workflow(
                    NotifyWorkflow.run,
                    "alice@example.com",
                    id="notify-wf-1",
                    task_queue="notify",
                )
                await handle.result()
        finally:
            receipt = interceptor.finalize_workflow(
                workflow_id="notify-wf-1", outcome="success"
            )
            await interceptor.flush_workflow_receipt(workflow_id="notify-wf-1")


asyncio.run(main())
```

At runtime:

* Each Activity execution is evaluated by the Chio sidecar with the
  workflow's `capability_id` before the activity body runs.
* Activities whose tool the grant does not authorise raise
  `ApplicationError(type="ChioCapabilityDenied", non_retryable=True)` --
  Temporal records the denial in workflow history and does not retry.
* Per-activity receipts are aggregated into a single `WorkflowReceipt`
  and forwarded to the configured `receipt_sink` on completion.

## Attenuated activity-scoped grants

The default `WorkflowGrant` applies to every activity in the workflow.
For finer-grained control, attenuate the grant for a specific activity
type and register it as an override:

```python
from chio_temporal import WorkflowGrant

child_scope = ChioScope(grants=[
    ToolGrant(
        server_id="email-srv",
        tool_name="send_email",
        operations=[Operation.INVOKE],
    ),
])
child_grant = await grant.attenuate_for_activity(chio, new_scope=child_scope)

interceptor.register_activity_grant_override(
    "send_email", lambda _info: child_grant
)
```

The child capability is always `child ⊆ parent`; the SDK raises
`ChioValidationError` if you try to broaden scope, and the interceptor
re-checks the subset invariant before evaluating.

## WorkflowReceipt envelope

The aggregate emitted on workflow completion is a stable JSON envelope
(version `chio-temporal/v1`):

```json
{
  "version": "chio-temporal/v1",
  "workflow_id": "notify-wf-1",
  "run_id": "...",
  "parent_workflow_ids": [],
  "started_at": 1713225600,
  "completed_at": 1713225612,
  "outcome": "success",
  "step_count": 2,
  "allow_count": 2,
  "deny_count": 0,
  "steps": [
    {"activity_type": "send_email", "activity_id": "act-1", "attempt": 1, "receipt": {...}},
    ...
  ],
  "metadata": {}
}
```

`to_json()` returns this payload with sorted keys so Merkle chaining
and content-hash verification are deterministic across runs.

## Error types

* `ChioTemporalError` -- raised when the Chio kernel denies an Activity.
  Carries `activity_type`, `activity_id`, `workflow_id`, `run_id`,
  `guard`, `reason`, `receipt_id`. The interceptor wraps this in a
  non-retryable `ApplicationError` before handing control back to
  Temporal.
* `ChioTemporalConfigError` -- raised on invalid configuration (no
  `WorkflowGrant` for a workflow_id, empty `capability_id`, attenuation
  beyond the parent grant's scope).

## HITL approval path

Human-in-the-loop approval support (pause Activity on a pending
approval guard, resume via Temporal Signal) lands in a future release.
This v1 release implements the synchronous allow/deny path only.

## Reference

See
[`docs/protocols/TEMPORAL-INTEGRATION.md`](../../../docs/protocols/TEMPORAL-INTEGRATION.md)
for the full integration design (intercept points, grant topology,
receipt aggregation, saga compensation).

## Development

```bash
uv venv --python 3.11
uv pip install -e '.[dev]'
uv pip install -e ../chio-sdk-python

uv run pytest
uv run mypy src/
uv run ruff check src/ tests/
```
